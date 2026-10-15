use crate::{
    db::Db,
    http::{ApiError, ApiResult, iso_at, json, now_iso},
};
use ratchet_core::http_security::session_cookie;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use worker::{Date, Env, Request, Response, js_sys};

pub struct AuthContext {
    pub session_id: String,
    pub user_id: String,
    pub device_id: String,
    pub role: String,
    pub device_authorized: bool,
    pub webauthn_verified_at: Option<String>,
    pub authenticator_verified_at: Option<String>,
}

#[derive(Deserialize)]
struct SessionRow {
    session_id: String,
    user_id: String,
    device_id: String,
    role: String,
    user_status: String,
    authorized_at: Option<String>,
    device_revoked_at: Option<String>,
    revoked_at: Option<String>,
    expires_at: String,
    last_seen_at: String,
    webauthn_verified_at: Option<String>,
    authenticator_verified_at: Option<String>,
}

pub fn sha256_hex(input: &str) -> String {
    Sha256::digest(input.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub async fn require_session(request: &Request, env: &Env) -> ApiResult<AuthContext> {
    let header = request.headers().get("Cookie")?;
    let secret = session_cookie(header.as_deref())
        .ok_or_else(|| ApiError::domain("SESSION_REQUIRED", 401))?;
    let db = Db(env.d1("DB")?);
    let row=db.first::<SessionRow>("SELECT s.session_id,s.user_id,s.device_id,s.last_seen_at,s.expires_at,s.revoked_at,s.webauthn_verified_at,COALESCE(s.authenticator_verified_at,s.webauthn_verified_at) AS authenticator_verified_at,d.authorized_at,d.revoked_at AS device_revoked_at,u.role,u.status AS user_status FROM sessions s JOIN devices d ON d.device_id=s.device_id AND d.user_id=s.user_id JOIN users u ON u.user_id=s.user_id WHERE s.secret_hash=?1 LIMIT 1",&[json!(sha256_hex(secret))]).await?
        .ok_or_else(||ApiError::domain("SESSION_INVALID",401))?;
    if row.device_revoked_at.is_some() {
        return Err(ApiError::domain("DEVICE_REVOKED", 403));
    }
    let now = Date::now().as_millis() as f64;
    let expires = js_sys::Date::parse(&row.expires_at);
    let seen = js_sys::Date::parse(&row.last_seen_at);
    if row.revoked_at.is_some()
        || row.user_status != "ACTIVE"
        || !expires.is_finite()
        || expires <= now
        || !seen.is_finite()
        || !matches!(row.role.as_str(), "ADMIN" | "CUSTOMER")
    {
        return Err(ApiError::domain("SESSION_INVALID", 401));
    }
    if row.role == "ADMIN" && now - seen > 72.0 * 60.0 * 60.0 * 1000.0 {
        db.run(
            "UPDATE sessions SET revoked_at=?2 WHERE session_id=?1 AND revoked_at IS NULL",
            &[json!(row.session_id), json!(now_iso())],
        )
        .await?;
        return Err(ApiError::domain("SESSION_IDLE_EXPIRED", 401));
    }
    if now - seen >= 5.0 * 60.0 * 1000.0 {
        let timestamp = now_iso();
        let cutoff = iso_at(now - 5.0 * 60.0 * 1000.0);
        db.0.batch(vec![
            db.statement("UPDATE sessions SET last_seen_at=?2 WHERE session_id=?1 AND last_seen_at<?3",&[json!(row.session_id),json!(timestamp),json!(cutoff)])?,
            db.statement("UPDATE devices SET last_seen_at=?2 WHERE device_id=?1 AND (last_seen_at IS NULL OR last_seen_at<?3)",&[json!(row.device_id),json!(timestamp),json!(cutoff)])?
        ]).await?;
    }
    Ok(AuthContext {
        session_id: row.session_id,
        user_id: row.user_id,
        device_id: row.device_id,
        role: row.role,
        device_authorized: row.authorized_at.is_some(),
        webauthn_verified_at: row.webauthn_verified_at,
        authenticator_verified_at: row.authenticator_verified_at,
    })
}

pub fn require_authorized(auth: &AuthContext) -> ApiResult<()> {
    if !auth.device_authorized {
        return Err(ApiError::domain("DEVICE_PENDING_APPROVAL", 403));
    }
    Ok(())
}

pub async fn current_session(env: &Env, auth: &AuthContext) -> ApiResult<Response> {
    let db = Db(env.d1("DB")?);
    let workspace_ids=db.all("SELECT workspace_id FROM workspace_memberships WHERE user_id=?1 AND status='ACTIVE' AND revoked_at IS NULL ORDER BY created_at,workspace_id",&[json!(auth.user_id)]).await?
        .into_iter().map(|r|r["workspace_id"].clone()).collect::<Vec<Value>>();
    let staff = if auth.role == "ADMIN" {
        db.all("SELECT ws.workspace_id,ws.staff_role,ws.display_name FROM workspace_staff ws JOIN workspace_memberships wm ON wm.workspace_id=ws.workspace_id AND wm.user_id=ws.user_id AND wm.role='ADMIN' AND wm.status='ACTIVE' AND wm.revoked_at IS NULL JOIN users u ON u.user_id=ws.user_id AND u.role='ADMIN' AND u.status='ACTIVE' WHERE ws.user_id=?1 AND ws.revoked_at IS NULL ORDER BY ws.created_at,ws.workspace_id",&[json!(auth.user_id)]).await?
    } else {
        vec![]
    };
    json(
        &json!({"session_id":auth.session_id,"user_id":auth.user_id,"role":auth.role,"device_id":auth.device_id,
        "device_authorized":auth.device_authorized,"webauthn_verified_at":auth.webauthn_verified_at,
        "authenticator_verified_at":auth.authenticator_verified_at,"workspace_ids":workspace_ids,"staff_memberships":staff}),
    )
}

pub async fn list_sessions(env: &Env, auth: &AuthContext) -> ApiResult<Response> {
    let sessions=Db(env.d1("DB")?).all("SELECT session_id,device_id,created_at,last_seen_at,expires_at,revoked_at FROM sessions WHERE user_id=?1 ORDER BY created_at DESC",&[json!(auth.user_id)]).await?;
    json(&json!({"sessions":sessions,"current_session_id":auth.session_id}))
}
