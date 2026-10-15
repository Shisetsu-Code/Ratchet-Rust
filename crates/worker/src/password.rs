use crate::{
    auth::{AuthContext, require_authorized, sha256_hex},
    db::Db,
    http::{ApiError, ApiResult, iso_at, json, now_iso, random_id, read_json},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ratchet_core::{
    message::is_uuid,
    password::{Credential, PASSWORD_ITERATIONS, derive_verifier, verify_password},
};
use serde::Deserialize;
use serde_json::{Value, json};
use worker::{D1PreparedStatement, Date, Env, Request, Response};

#[derive(Deserialize)]
struct Login {
    login_name: String,
    password: String,
    device: Device,
}
#[derive(Deserialize)]
#[serde(tag = "mode", rename_all = "lowercase")]
enum Device {
    Existing {
        device_id: String,
    },
    New {
        device_id: String,
        display_name: String,
        crypto_identity_public_key: String,
    },
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

pub async fn prepare_credential(password: &str) -> ApiResult<Credential> {
    validate_password(password)?;
    let mut salt = [0; 16];
    getrandom::fill(&mut salt).map_err(|_| ApiError::domain("RANDOM_SOURCE_FAILED", 503))?;
    let verifier = derive_verifier(password, &salt, PASSWORD_ITERATIONS)?;
    Ok(Credential {
        algorithm: "PBKDF2-SHA256".into(),
        iterations: PASSWORD_ITERATIONS,
        salt: URL_SAFE_NO_PAD.encode(salt),
        verifier: URL_SAFE_NO_PAD.encode(verifier.as_slice()),
    })
}

async fn reserve_attempt(db: &Db, user: &str, now: &str) -> ApiResult<()> {
    let reserved=db.first::<Value>("UPDATE password_credentials SET failed_attempts=MIN(failed_attempts+1,20),next_allowed_at=strftime('%Y-%m-%dT%H:%M:%fZ',?2,printf('+%d seconds',CASE WHEN failed_attempts<4 THEN 0 ELSE MIN(1 << MIN(failed_attempts-4,10),900) END)),updated_at=?2 WHERE user_id=?1 AND (next_allowed_at IS NULL OR next_allowed_at<=?2) RETURNING user_id",&[json!(user),json!(now)]).await?;
    if reserved.is_none() {
        return Err(ApiError::domain("AUTHENTICATION_FAILED", 401));
    }
    Ok(())
}

fn guard_conflict(error: &worker::Error) -> bool {
    let message = error.to_string();
    message.contains("CHECK constraint failed") && message.contains("valid")
}

pub async fn login(request: &mut Request, env: &Env) -> ApiResult<Response> {
    let request: Login = read_json(request, 64 * 1024).await?;
    validate_password(&request.password)?;
    let login_name = request.login_name.trim().to_lowercase();
    if login_name.is_empty() || login_name.encode_utf16().count() > 64 {
        return Err(ApiError::domain("VALIDATION_ERROR", 422));
    }
    let device_id = match &request.device {
        Device::Existing { device_id } | Device::New { device_id, .. } => device_id,
    };
    if !is_uuid(device_id) {
        return Err(ApiError::domain("VALIDATION_ERROR", 422));
    }
    if let Device::New {
        display_name,
        crypto_identity_public_key,
        ..
    } = &request.device
        && (!(1..=120).contains(&display_name.trim().encode_utf16().count())
            || !(32..=4096).contains(&crypto_identity_public_key.encode_utf16().count()))
    {
        return Err(ApiError::domain("VALIDATION_ERROR", 422));
    }
    let db = Db(env.d1("DB")?);
    let now = now_iso();
    let credential=db.first::<LoginCredential>("SELECT pc.user_id,pc.algorithm,pc.iterations,pc.salt,pc.verifier,u.status AS user_status FROM password_credentials pc JOIN users u ON u.user_id=pc.user_id WHERE pc.login_name=?1 LIMIT 1",&[json!(login_name)]).await?;
    if let Some(ref row) = credential {
        reserve_attempt(&db, &row.user_id, &now).await?;
    }
    let dummy = Credential {
        algorithm: "PBKDF2-SHA256".into(),
        iterations: PASSWORD_ITERATIONS,
        salt: "AAAAAAAAAAAAAAAAAAAAAA".into(),
        verifier: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
    };
    let valid = verify_password(
        &request.password,
        credential.as_ref().map(|c| &c.credential).unwrap_or(&dummy),
    );
    let row = credential
        .filter(|r| valid && r.user_status == "ACTIVE")
        .ok_or_else(|| ApiError::domain("AUTHENTICATION_FAILED", 401))?;
    let mut writes: Vec<D1PreparedStatement> = vec![];
    let mode = match &request.device {
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
    writes.insert(0,db.statement("INSERT INTO auth_commit_guards(assertion_id,valid) SELECT ?1,CASE WHEN EXISTS(SELECT 1 FROM password_credentials p JOIN users u ON u.user_id=p.user_id WHERE p.user_id=?2 AND p.salt=?3 AND p.verifier=?4 AND u.status='ACTIVE') AND (?5='new' OR EXISTS(SELECT 1 FROM devices WHERE device_id=?6 AND user_id=?2 AND revoked_at IS NULL)) THEN 1 ELSE 0 END",&[json!(guard_id),json!(row.user_id),json!(row.credential.salt),json!(row.credential.verifier),json!(mode),json!(device_id)])?);
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
    let credential = db
        .first::<Credential>(
            "SELECT algorithm,iterations,salt,verifier FROM password_credentials WHERE user_id=?1",
            &[json!(auth.user_id)],
        )
        .await?;
    if credential.is_some() {
        reserve_attempt(&db, &auth.user_id, &now_iso()).await?;
    }
    let credential = credential.ok_or_else(|| ApiError::domain("AUTHENTICATION_FAILED", 401))?;
    if !verify_password(&input.password, &credential) {
        return Err(ApiError::domain("AUTHENTICATION_FAILED", 401));
    }
    let now = now_iso();
    let guard_id = random_id()?;
    let result=db.0.batch(vec![
        db.statement("INSERT INTO auth_commit_guards(assertion_id,valid) SELECT ?1,CASE WHEN EXISTS(SELECT 1 FROM password_credentials p JOIN users u ON u.user_id=p.user_id JOIN sessions s ON s.user_id=p.user_id JOIN devices d ON d.device_id=s.device_id WHERE p.user_id=?2 AND p.salt=?3 AND p.verifier=?4 AND u.status='ACTIVE' AND s.session_id=?5 AND s.revoked_at IS NULL AND s.expires_at>?6 AND d.revoked_at IS NULL) THEN 1 ELSE 0 END",&[json!(guard_id),json!(auth.user_id),json!(credential.salt),json!(credential.verifier),json!(auth.session_id),json!(now)])?,
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
