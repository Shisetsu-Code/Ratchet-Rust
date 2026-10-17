use crate::{
    auth::{self, AuthContext},
    auth_admission,
    db::Db,
    http::{self, ApiError, ApiResult},
    password::Device,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ratchet_core::{
    message::is_uuid,
    signatures::{portable_signature_message, verify_ed25519},
};
use serde::Deserialize;
use serde_json::{Value, json};
use worker::{Date, Env, Request, Response};

#[derive(Deserialize)]
struct Prepare {
    key_id: String,
    device: Option<Device>,
}
#[derive(Deserialize)]
struct Complete {
    challenge_id: String,
    signature: String,
}
#[derive(Deserialize)]
struct Challenge {
    challenge_id: String,
    challenge: String,
    key_id: String,
    user_id: Option<String>,
    pending_device_id: Option<String>,
    pending_device_name: Option<String>,
    pending_crypto_identity_public_key: Option<String>,
    expires_at: String,
    consumed: Option<String>,
}

fn random_secret() -> ApiResult<String> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).map_err(|_| ApiError::domain("RANDOM_SOURCE_FAILED", 503))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}
fn invalid() -> ApiError {
    ApiError::domain("PORTABLE_KEY_VERIFICATION_FAILED", 403)
}

pub async fn prepare(request: &mut Request, env: &Env, reauth: bool) -> ApiResult<Response> {
    let actor = if reauth {
        let a = auth::require_session(request, env).await?;
        auth::require_authorized(&a)?;
        Some(a)
    } else {
        None
    };
    let input: Prepare = http::read_json(request, 64 * 1024).await?;
    if !is_uuid(&input.key_id) {
        return Err(ApiError::domain("VALIDATION_ERROR", 422));
    }
    let db = Db(env.d1("DB")?);
    let credential=db.first::<Value>("SELECT p.user_id FROM portable_key_credentials p JOIN users u ON u.user_id=p.user_id AND u.status='ACTIVE' WHERE p.key_id=?1 AND p.revoked_at IS NULL",&[json!(input.key_id)]).await?;
    let user = credential.as_ref().and_then(|v| v["user_id"].as_str());
    if let Some(actor) = &actor
        && user != Some(actor.user_id.as_str())
    {
        return Err(invalid());
    }
    let (device, name, key) = if reauth {
        (None, None, None)
    } else {
        let fields = input
            .device
            .as_ref()
            .ok_or_else(|| ApiError::domain("VALIDATION_ERROR", 422))?
            .fields()?;
        (Some(fields.0), fields.1, fields.2)
    };
    let purpose = if reauth {
        "REAUTHENTICATION"
    } else {
        "AUTHENTICATION"
    };
    let id = http::random_id()?;
    let challenge = random_secret()?;
    let now = http::now_iso();
    let admission =
        auth_admission::challenge_statement(&db, request, actor.as_ref(), &input.key_id).await?;
    db.0.batch(vec![admission,db.statement("INSERT INTO portable_key_challenges(challenge_id,kind,challenge,key_id,user_id,pending_device_id,pending_device_name,pending_crypto_identity_public_key,created_at,expires_at,admission_origin) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
        &[json!(id),json!(purpose),json!(challenge),json!(input.key_id),json!(user),json!(device),json!(name),json!(key),json!(now),json!(http::iso_at(Date::now().as_millis() as f64+300_000.0)),json!(auth_admission::origin_hash(request)?)])?]).await.map_err(auth_admission::admission_error)?;
    let mut result = json!({"challenge_id":id,"challenge":challenge,"purpose":purpose,"key_id":input.key_id,"origin":env.var("RP_ORIGIN")?.to_string()});
    if let Some(device) = device {
        result["device_id"] = json!(device);
    }
    http::json(&result)
}

pub async fn complete(request: &mut Request, env: &Env, reauth: bool) -> ApiResult<Response> {
    let actor: Option<AuthContext> = if reauth {
        let a = auth::require_session(request, env).await?;
        auth::require_authorized(&a)?;
        Some(a)
    } else {
        None
    };
    let input: Complete = http::read_json(request, 64 * 1024).await?;
    if !is_uuid(&input.challenge_id) || input.signature.len() != 86 {
        return Err(ApiError::domain("VALIDATION_ERROR", 422));
    }
    let db = Db(env.d1("DB")?);
    let purpose = if reauth {
        "REAUTHENTICATION"
    } else {
        "AUTHENTICATION"
    };
    let row=db.first::<Challenge>("SELECT c.*,x.challenge_id AS consumed FROM portable_key_challenges c LEFT JOIN portable_key_challenge_consumptions x ON x.challenge_id=c.challenge_id WHERE c.challenge_id=?1 AND c.kind=?2",&[json!(input.challenge_id),json!(purpose)]).await?.ok_or_else(||ApiError::domain("CHALLENGE_NOT_FOUND",404))?;
    if row.consumed.is_some() {
        return Err(ApiError::domain("CHALLENGE_CONSUMED", 409));
    }
    if row.expires_at <= http::now_iso() {
        return Err(ApiError::domain("CHALLENGE_EXPIRED", 410));
    }
    let user = row.user_id.as_deref().ok_or_else(invalid)?;
    if let Some(actor) = &actor
        && user != actor.user_id
    {
        return Err(invalid());
    }
    let credential=db.first::<Value>("SELECT p.public_key FROM portable_key_credentials p JOIN users u ON u.user_id=p.user_id AND u.status='ACTIVE' WHERE p.key_id=?1 AND p.user_id=?2 AND p.revoked_at IS NULL",&[json!(row.key_id),json!(user)]).await?.ok_or_else(invalid)?;
    let public_text = credential["public_key"].as_str().ok_or_else(invalid)?;
    let public: [u8; 32] = URL_SAFE_NO_PAD
        .decode(public_text)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(invalid)?;
    let signature: [u8; 64] = URL_SAFE_NO_PAD
        .decode(&input.signature)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(invalid)?;
    verify_ed25519(
        &public,
        &portable_signature_message(
            purpose,
            &row.challenge_id,
            &row.challenge,
            &env.var("RP_ORIGIN")?.to_string(),
            &row.key_id,
        ),
        &signature,
    )
    .map_err(|_| invalid())?;
    let now = http::now_iso();
    let guard = http::random_id()?;
    let session = http::random_id()?;
    let secret = random_secret()?;
    let mut writes = vec![];
    let (device, new_device) = if let Some(actor) = &actor {
        (actor.device_id.as_str(), false)
    } else {
        let device = row.pending_device_id.as_deref().ok_or_else(invalid)?;
        let new_device =
            row.pending_device_name.is_some() && row.pending_crypto_identity_public_key.is_some();
        let existing = db
            .first::<Value>(
                "SELECT user_id,revoked_at FROM devices WHERE device_id=?1",
                &[json!(device)],
            )
            .await?;
        if new_device {
            if existing.is_some() {
                return Err(ApiError::domain("DEVICE_ID_CONFLICT", 409));
            }
            writes.push(db.statement("INSERT INTO devices(device_id,user_id,display_name,crypto_identity_public_key,created_at,authorized_at,last_seen_at) VALUES(?1,?2,?3,?4,?5,?5,?5)",&[json!(device),json!(user),json!(row.pending_device_name),json!(row.pending_crypto_identity_public_key),json!(now)])?);
        } else {
            let existing = existing
                .filter(|v| v["user_id"] == user)
                .ok_or_else(|| ApiError::domain("DEVICE_NOT_FOUND", 404))?;
            if !existing["revoked_at"].is_null() {
                return Err(ApiError::domain("DEVICE_REVOKED", 403));
            }
            writes.push(db.statement("UPDATE devices SET authorized_at=COALESCE(authorized_at,?2),last_seen_at=?2 WHERE device_id=?1",&[json!(device),json!(now)])?);
        }
        (device, new_device)
    };
    let session_check = if reauth {
        "AND EXISTS(SELECT 1 FROM sessions s JOIN devices d ON d.device_id=s.device_id AND d.user_id=s.user_id WHERE s.session_id=?9 AND s.user_id=?3 AND s.revoked_at IS NULL AND s.expires_at>?7 AND d.revoked_at IS NULL AND d.authorized_at IS NOT NULL)"
    } else {
        ""
    };
    let check = format!(
        "INSERT INTO auth_commit_guards(assertion_id,valid) SELECT ?1,CASE WHEN EXISTS(SELECT 1 FROM portable_key_credentials p JOIN users u ON u.user_id=p.user_id WHERE p.key_id=?2 AND p.user_id=?3 AND p.public_key=?4 AND p.revoked_at IS NULL AND u.status='ACTIVE') AND EXISTS(SELECT 1 FROM portable_key_challenges c WHERE c.challenge_id=?5 AND c.kind=?6 AND c.expires_at>?7 AND NOT EXISTS(SELECT 1 FROM portable_key_challenge_consumptions x WHERE x.challenge_id=c.challenge_id)) AND (?8=1 OR EXISTS(SELECT 1 FROM devices WHERE device_id=?10 AND user_id=?3 AND revoked_at IS NULL)) {session_check} THEN 1 ELSE 0 END"
    );
    writes.insert(
        0,
        db.statement(
            &check,
            &[
                json!(guard),
                json!(row.key_id),
                json!(user),
                json!(public_text),
                json!(row.challenge_id),
                json!(purpose),
                json!(now),
                json!(new_device),
                json!(actor.as_ref().map(|a| &a.session_id)),
                json!(device),
            ],
        )?,
    );
    writes.push(db.statement(
        "INSERT INTO portable_key_challenge_consumptions(challenge_id,consumed_at) VALUES(?1,?2)",
        &[json!(row.challenge_id), json!(now)],
    )?);
    writes.push(db.statement(
        "UPDATE portable_key_credentials SET last_used_at=?2 WHERE key_id=?1",
        &[json!(row.key_id), json!(now)],
    )?);
    if let Some(actor) = &actor {
        writes.push(db.statement(
            "UPDATE sessions SET authenticator_verified_at=?2 WHERE session_id=?1",
            &[json!(actor.session_id), json!(now)],
        )?);
    } else {
        writes.push(db.statement("INSERT INTO sessions(session_id,secret_hash,user_id,device_id,created_at,last_seen_at,expires_at,webauthn_verified_at,authenticator_verified_at) VALUES(?1,?2,?3,?4,?5,?5,?6,NULL,?5)",&[json!(session),json!(auth::sha256_hex(&secret)),json!(user),json!(device),json!(now),json!(http::iso_at(Date::now().as_millis() as f64+2_592_000_000.0))])?);
    }
    writes.push(db.statement(
        "DELETE FROM auth_commit_guards WHERE assertion_id=?1",
        &[json!(guard)],
    )?);
    if let Err(error) = db.0.batch(writes).await {
        if db
            .first::<Value>(
                "SELECT 1 AS n FROM portable_key_challenge_consumptions WHERE challenge_id=?1",
                &[json!(row.challenge_id)],
            )
            .await?
            .is_some()
        {
            return Err(ApiError::domain("CHALLENGE_CONSUMED", 409));
        }
        if row.expires_at <= http::now_iso() {
            return Err(ApiError::domain("CHALLENGE_EXPIRED", 410));
        }
        if error.to_string().contains("CHECK constraint failed") {
            return Err(invalid());
        }
        return Err(error.into());
    }
    if reauth {
        return http::json(&json!({"verified":true,"verified_at":now}));
    }
    let mut response = http::json(
        &json!({"session_id":session,"user_id":user,"device_id":device,"device_state":"AUTHORIZED"}),
    )?;
    response.headers_mut().set(
        "Set-Cookie",
        &format!(
            "__Host-session={secret}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=2592000"
        ),
    )?;
    Ok(response)
}
