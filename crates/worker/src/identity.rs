use crate::{
    auth::{AuthContext, require_authorized, require_recent, require_session},
    db::Db,
    http::{ApiError, ApiResult, json, now_iso, random_id, read_json},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use worker::{Env, Method, Request, Response};
mod activation;
mod passkeys;
mod prekeys;

pub async fn handle(request: &mut Request, env: &Env) -> ApiResult<Option<Response>> {
    let path = request.path();
    if path == "/api/v1/auth/password/activate" && request.method() == Method::Post {
        return Ok(Some(activation::activate(request, env).await?));
    }
    if path.starts_with("/api/v1/auth/passkey/") {
        return passkeys::handle(request, env).await;
    }
    if path.starts_with("/api/v1/crypto/") {
        return prekeys::handle(request, env).await;
    }
    if !path.starts_with("/api/v1/devices") {
        return Ok(None);
    }
    if path == "/api/v1/devices" && request.method() == Method::Get {
        let auth = require_session(request, env).await?;
        let devices=Db(env.d1("DB")?).all("SELECT (SELECT certificate FROM device_certificates dc WHERE dc.device_id=d.device_id AND dc.revoked_at IS NULL ORDER BY dc.created_at DESC LIMIT 1) AS device_certificate,d.device_id,d.display_name,d.crypto_identity_public_key,d.created_at,d.authorized_at,d.revoked_at,d.last_seen_at,CASE WHEN b.device_id IS NULL THEN 0 ELSE 1 END AS crypto_ready,CASE WHEN EXISTS(SELECT 1 FROM device_certificates dc WHERE dc.device_id=d.device_id AND dc.revoked_at IS NULL) THEN 1 ELSE 0 END AS certified FROM devices d LEFT JOIN device_prekey_bundles b ON b.device_id=d.device_id WHERE d.user_id=?1 ORDER BY d.created_at DESC",&[json!(auth.user_id)]).await?;
        return Ok(Some(json(
            &json!({"devices":devices,"current_device_id":auth.device_id}),
        )?));
    }
    let segments: Vec<_> = path.split('/').collect();
    if segments.len() == 6
        && request.method() == Method::Post
        && matches!(segments[5], "certificate" | "approve")
    {
        if !ratchet_core::message::is_uuid(segments[4]) {
            return Err(ApiError::domain("VALIDATION_ERROR", 422));
        }
        let data = if segments[5] == "certificate" {
            read_json::<Value>(request, 32768).await?
        } else {
            json!({})
        };
        let operation = format!("identity.{}", segments[5]);
        return Ok(Some(
            crate::chat::control::domain(request, env, &operation, segments[4], data).await?,
        ));
    }
    Ok(None)
}

pub async fn prepare_control(
    env: &Env,
    auth: &AuthContext,
    operation: &str,
    target: &str,
    data: &Value,
) -> ApiResult<crate::chat::control::MutationPlan> {
    require_authorized(auth)?;
    require_recent(auth)?;
    let db = Db(env.d1("DB")?);
    let now = now_iso();
    let row=db.first::<Value>("SELECT d.crypto_identity_public_key,d.authorized_at,d.revoked_at,b.device_id AS bundle_device_id,(SELECT dc.device_id FROM device_certificates dc WHERE dc.device_id=d.device_id AND dc.revoked_at IS NULL LIMIT 1) AS certificate_device_id FROM devices d LEFT JOIN device_prekey_bundles b ON b.device_id=d.device_id WHERE d.device_id=?1 AND d.user_id=?2",&[json!(target),json!(auth.user_id)]).await?.filter(|v|v["revoked_at"].is_null()).ok_or_else(||ApiError::domain("DEVICE_NOT_FOUND",404))?;
    let mut statements = vec![];
    let response = match operation {
        "identity.certificate" => {
            let certificate = data["certificate"]
                .as_str()
                .filter(|s| (32..=16384).contains(&s.len()))
                .ok_or_else(|| ApiError::domain("VALIDATION_ERROR", 422))?;
            let invalid = || ApiError::domain("DEVICE_CERTIFICATE_INVALID", 409);
            let bytes = URL_SAFE_NO_PAD.decode(certificate).map_err(|_| invalid())?;
            let wire: Value = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
            let p = &wire["payload"];
            if p["protocol"] != "secure-device-certificate"
                || p["version"] != 1
                || p["user_id"] != auth.user_id
                || p["device_id"] != target
                || p["signer_device_id"] != auth.device_id
                || p["crypto_identity_public_key"] != row["crypto_identity_public_key"]
                || target == auth.device_id
                || URL_SAFE_NO_PAD
                    .decode(wire["signature"].as_str().unwrap_or(""))
                    .map_or(true, |s| s.len() != 64)
            {
                return Err(invalid());
            }
            // Certificates are opaque account-signed claims: clients verify their XEdDSA signatures.
            // The authenticated, recently verified signer and immutable identity fields bind this server-side approval.
            statements.push(db.statement("INSERT INTO device_certificates(certificate_id,device_id,signer_device_id,certificate,created_at) SELECT ?1,?2,?3,?4,?5 WHERE NOT EXISTS(SELECT 1 FROM device_certificates WHERE device_id=?2 AND signer_device_id=?3 AND certificate=?4 AND revoked_at IS NULL)",&[json!(random_id()?),json!(target),json!(auth.device_id),json!(certificate),json!(now)])?);
            json!({"device_id":target,"certified":true})
        }
        "identity.approve" => {
            if row["authorized_at"].is_null() {
                if row["bundle_device_id"].is_null() {
                    return Err(ApiError::domain("DEVICE_CRYPTO_NOT_READY", 409));
                }
                if row["certificate_device_id"].is_null() {
                    return Err(ApiError::domain("DEVICE_CERTIFICATE_REQUIRED", 409));
                }
                statements.push(db.statement("UPDATE devices SET authorized_at=?3 WHERE device_id=?1 AND user_id=?2 AND authorized_at IS NULL AND revoked_at IS NULL",&[json!(target),json!(auth.user_id),json!(now)])?);
                statements.push(db.statement("INSERT INTO durable_jobs(job_id,type,status,payload,attempts,next_attempt_at,created_at) VALUES (?1,'DEVICE_CHAT_RECONCILE','PENDING',?2,0,?3,?3)",&[json!(random_id()?),json!({"user_id":auth.user_id,"device_id":target,"action":"AUTHORIZED"}).to_string().into(),json!(now)])?);
            }
            json!({"device_id":target,"state":"AUTHORIZED"})
        }
        _ => return Err(ApiError::domain("NOT_FOUND", 404)),
    };
    Ok(crate::chat::control::MutationPlan {
        statements,
        affected_users: vec![auth.user_id.clone()],
        affected_chats: vec![],
        response,
        status: 200,
        clear_cookie: false,
    })
}
