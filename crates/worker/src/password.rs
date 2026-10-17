use crate::{
    auth::{AuthContext, require_authorized, sha256_hex},
    auth_admission::{self, PasswordProof},
    db::Db,
    http::{ApiError, ApiResult, iso_at, json, now_iso, random_id, read_json},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ratchet_core::{
    message::is_uuid,
    password::{Credential, PASSWORD_ITERATIONS, derive_verifier, verify_password_uniform},
};
use serde::Deserialize;
use serde_json::{Value, json};
use worker::{D1PreparedStatement, Date, Env, Request, Response};

#[derive(Deserialize)]
struct Login {
    login_name: String,
    password: String,
    device: Device,
    proof: Option<PasswordProof>,
}
#[derive(Deserialize)]
#[serde(tag = "mode", rename_all = "lowercase")]
pub(crate) enum Device {
    Existing {
        device_id: String,
    },
    New {
        device_id: String,
        display_name: String,
        crypto_identity_public_key: String,
    },
}
impl Device {
    pub(crate) fn fields(&self) -> ApiResult<(&str, Option<&str>, Option<&str>)> {
        let (id, name, key) = match self {
            Self::Existing { device_id } => (device_id.as_str(), None, None),
            Self::New {
                device_id,
                display_name,
                crypto_identity_public_key,
            } => {
                let name = display_name.trim();
                if !(1..=120).contains(&name.encode_utf16().count())
                    || !(32..=4096).contains(&crypto_identity_public_key.encode_utf16().count())
                {
                    return Err(ApiError::domain("VALIDATION_ERROR", 422));
                }
                (
                    device_id.as_str(),
                    Some(name),
                    Some(crypto_identity_public_key.as_str()),
                )
            }
        };
        if !is_uuid(id) {
            return Err(ApiError::domain("VALIDATION_ERROR", 422));
        }
        Ok((id, name, key))
    }
}
#[derive(Deserialize)]
struct LoginCredential {
    user_id: String,
    user_status: String,
    #[serde(flatten)]
    credential: Credential,
}
#[derive(Deserialize)]
struct DeviceRow {
    device_id: String,
    authorized_at: Option<String>,
    revoked_at: Option<String>,
}

fn validate_password(value: &str) -> ApiResult<()> {
    if !(15..=256).contains(&value.encode_utf16().count()) {
        return Err(ApiError::domain("VALIDATION_ERROR", 422));
    }
    Ok(())
}

pub async fn prepare_credential(db: &Db, principal: &str, password: &str) -> ApiResult<Credential> {
    validate_password(password)?;
    let mut salt = [0; 16];
    getrandom::fill(&mut salt).map_err(|_| ApiError::domain("RANDOM_SOURCE_FAILED", 503))?;
    let permit = auth_admission::reserve_write(db, principal).await?;
    let checked = permit.before_kdf().and_then(|()| {
        derive_verifier(password, &salt, PASSWORD_ITERATIONS).map_err(ApiError::from)
    });
    permit.release(db).await?;
    let verifier = checked?;
    Ok(Credential {
        algorithm: "PBKDF2-SHA256".into(),
        iterations: PASSWORD_ITERATIONS,
        salt: URL_SAFE_NO_PAD.encode(salt),
        verifier: URL_SAFE_NO_PAD.encode(verifier.as_slice()),
    })
}

pub(crate) async fn record_failure(
    db: &Db,
    user: Option<&str>,
    credential: Option<&Credential>,
) -> ApiResult<()> {
    let now = now_iso();
    let cutoff = iso_at(Date::now().as_millis() as f64 - 900_000.0);
    db.run("UPDATE password_credentials SET failed_attempts=CASE WHEN updated_at<?5 THEN 1 ELSE MIN(failed_attempts+1,20) END,next_allowed_at=NULL,updated_at=?2 WHERE user_id=?1 AND salt=?3 AND verifier=?4 AND algorithm=?6 AND iterations=?7", &[json!(user),json!(now),json!(credential.map(|c| &c.salt)),json!(credential.map(|c| &c.verifier)),json!(cutoff),json!(credential.map(|c| &c.algorithm)),json!(credential.map(|c| c.iterations))]).await?;
    Ok(())
}

fn guard_conflict(error: &worker::Error) -> bool {
    let message = error.to_string();
    message.contains("CHECK constraint failed") && message.contains("valid")
}

pub async fn login(request: &mut Request, env: &Env) -> ApiResult<Response> {
    let input: Login = read_json(request, 64 * 1024).await?;
    validate_password(&input.password)?;
    let login_name = auth_admission::normalize_login(&input.login_name)?;
    let (device_id, _, _) = input.device.fields()?;
    let db = Db(env.d1("DB")?);
    let now = now_iso();
    let permit =
        auth_admission::reserve_login(&db, request, &login_name, input.proof.as_ref()).await?;
    let checked = async {
        let credential=db.first::<LoginCredential>("SELECT pc.user_id,pc.algorithm,pc.iterations,pc.salt,pc.verifier,u.status AS user_status FROM password_credentials pc JOIN users u ON u.user_id=pc.user_id WHERE pc.login_name=?1 LIMIT 1",&[json!(login_name)]).await?;
        permit.before_kdf()?;
        let valid = verify_password_uniform(&input.password, credential.as_ref().map(|row| &row.credential));
        Ok::<_,ApiError>((credential,valid))
    }.await;
    permit.release(&db).await?;
    let (credential, valid) = checked?;
    if !valid {
        record_failure(
            &db,
            credential.as_ref().map(|r| r.user_id.as_str()),
            credential.as_ref().map(|r| &r.credential),
        )
        .await?;
    }
    let row = credential
        .filter(|r| valid && r.user_status == "ACTIVE")
        .ok_or_else(|| ApiError::domain("AUTHENTICATION_FAILED", 401))?;
    let mut writes: Vec<D1PreparedStatement> = vec![];
    let mode = match &input.device {
        Device::Existing { device_id } => {
            let device=db.first::<DeviceRow>("SELECT device_id,authorized_at,revoked_at FROM devices WHERE device_id=?1 AND user_id=?2 LIMIT 1",&[json!(device_id),json!(row.user_id)]).await?
                .filter(|d|d.revoked_at.is_none()).ok_or_else(||ApiError::domain("DEVICE_NOT_AVAILABLE",403))?;
            if device.authorized_at.is_none() {
                writes.push(db.statement("UPDATE devices SET authorized_at=?2 WHERE device_id=?1 AND authorized_at IS NULL",&[json!(device.device_id),json!(now)])?);
            }
            "existing"
        }
        Device::New {
            device_id,
            display_name,
            crypto_identity_public_key,
        } => {
            if db
                .first::<Value>(
                    "SELECT 1 FROM devices WHERE device_id=?1",
                    &[json!(device_id)],
                )
                .await?
                .is_some()
            {
                return Err(ApiError::domain("DEVICE_ID_CONFLICT", 409));
            }
            writes.push(db.statement("INSERT INTO devices(device_id,user_id,display_name,crypto_identity_public_key,created_at,authorized_at,last_seen_at) VALUES (?1,?2,?3,?4,?5,?5,?5)",&[json!(device_id),json!(row.user_id),json!(display_name.trim()),json!(crypto_identity_public_key),json!(now)])?);
            "new"
        }
    };
    let guard_id = random_id()?;
    let session_id = random_id()?;
    let mut secret = [0; 32];
    getrandom::fill(&mut secret).map_err(|_| ApiError::domain("RANDOM_SOURCE_FAILED", 503))?;
    let secret = URL_SAFE_NO_PAD.encode(secret);
    let expires = iso_at(Date::now().as_millis() as f64 + 30.0 * 24.0 * 60.0 * 60.0 * 1000.0);
    writes.insert(0,db.statement("INSERT INTO auth_commit_guards(assertion_id,valid) SELECT ?1,CASE WHEN EXISTS(SELECT 1 FROM password_credentials p JOIN users u ON u.user_id=p.user_id WHERE p.user_id=?2 AND p.salt=?3 AND p.verifier=?4 AND p.algorithm=?7 AND p.iterations=?8 AND u.status='ACTIVE') AND (?5='new' OR EXISTS(SELECT 1 FROM devices WHERE device_id=?6 AND user_id=?2 AND revoked_at IS NULL)) THEN 1 ELSE 0 END",&[json!(guard_id),json!(row.user_id),json!(row.credential.salt),json!(row.credential.verifier),json!(mode),json!(device_id),json!(row.credential.algorithm),json!(row.credential.iterations)])?);
    writes.push(db.statement("UPDATE password_credentials SET failed_attempts=0,next_allowed_at=NULL,updated_at=?2 WHERE user_id=?1",&[json!(row.user_id),json!(now)])?);
    writes.push(db.statement("INSERT INTO sessions(session_id,secret_hash,user_id,device_id,created_at,last_seen_at,expires_at,webauthn_verified_at) VALUES (?1,?2,?3,?4,?5,?5,?6,NULL)",&[json!(session_id),json!(sha256_hex(&secret)),json!(row.user_id),json!(device_id),json!(now),json!(expires)])?);
    writes.push(db.statement(
        "DELETE FROM auth_commit_guards WHERE assertion_id=?1",
        &[json!(guard_id)],
    )?);
    if let Err(error) = db.0.batch(writes).await {
        if guard_conflict(&error) {
            return Err(ApiError::domain("AUTHENTICATION_FAILED", 401));
        }
        if mode == "new"
            && db
                .first::<Value>(
                    "SELECT 1 FROM devices WHERE device_id=?1",
                    &[json!(device_id)],
                )
                .await?
                .is_some()
        {
            return Err(ApiError::domain("DEVICE_ID_CONFLICT", 409));
        }
        return Err(error.into());
    }
    let mut response = json(
        &json!({"session_id":session_id,"user_id":row.user_id,"device_id":device_id,"device_state":"AUTHORIZED"}),
    )?;
    response.headers_mut().set(
        "Set-Cookie",
        &format!(
            "__Host-session={secret}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=2592000"
        ),
    )?;
    Ok(response)
}

pub async fn reauthenticate(
    request: &mut Request,
    env: &Env,
    auth: &AuthContext,
) -> ApiResult<Response> {
    require_authorized(auth)?;
    #[derive(Deserialize)]
    struct Input {
        password: String,
    }
    let input: Input = read_json(request, 64 * 1024).await?;
    validate_password(&input.password)?;
    let db = Db(env.d1("DB")?);
    let permit = auth_admission::reserve_reauth(&db, request, auth).await?;
    let checked = async {
        let credential = db.first::<Credential>(
            "SELECT algorithm,iterations,salt,verifier FROM password_credentials WHERE user_id=?1",
            &[json!(auth.user_id)],
        ).await?;
        permit.before_kdf()?;
        let valid = verify_password_uniform(&input.password, credential.as_ref());
        Ok::<_, ApiError>((credential, valid))
    }
    .await;
    permit.release(&db).await?;
    let (credential, valid) = checked?;
    if !valid {
        record_failure(&db, Some(&auth.user_id), credential.as_ref()).await?;
        return Err(ApiError::domain("AUTHENTICATION_FAILED", 401));
    }
    let credential = credential.ok_or_else(|| ApiError::domain("AUTHENTICATION_FAILED", 401))?;
    let now = now_iso();
    let guard_id = random_id()?;
    let result=db.0.batch(vec![
        db.statement("INSERT INTO auth_commit_guards(assertion_id,valid) SELECT ?1,CASE WHEN EXISTS(SELECT 1 FROM password_credentials p JOIN users u ON u.user_id=p.user_id JOIN sessions s ON s.user_id=p.user_id JOIN devices d ON d.device_id=s.device_id AND d.user_id=s.user_id WHERE p.user_id=?2 AND p.salt=?3 AND p.verifier=?4 AND p.algorithm=?7 AND p.iterations=?8 AND u.status='ACTIVE' AND s.session_id=?5 AND s.revoked_at IS NULL AND s.expires_at>?6 AND d.revoked_at IS NULL AND d.authorized_at IS NOT NULL) THEN 1 ELSE 0 END",&[json!(guard_id),json!(auth.user_id),json!(credential.salt),json!(credential.verifier),json!(auth.session_id),json!(now),json!(credential.algorithm),json!(credential.iterations)])?,
        db.statement("UPDATE password_credentials SET failed_attempts=0,next_allowed_at=NULL WHERE user_id=?1",&[json!(auth.user_id)])?,
        db.statement("UPDATE sessions SET authenticator_verified_at=?2 WHERE session_id=?1 AND user_id=?3 AND revoked_at IS NULL",&[json!(auth.session_id),json!(now),json!(auth.user_id)])?,
        db.statement("DELETE FROM auth_commit_guards WHERE assertion_id=?1",&[json!(guard_id)])?
    ]).await;
    if let Err(error) = result {
        if guard_conflict(&error) {
            return Err(ApiError::domain("AUTHENTICATION_FAILED", 401));
        }
        return Err(error.into());
    }
    json(&json!({"verified":true,"verified_at":now}))
}
