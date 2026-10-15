//! Cloudflare runtime adapter. Domain code lives in ratchet-core.
mod auth;
mod bootstrap;
mod chat;
pub use chat::ChatRealtime;
mod admin;
mod db;
mod files;
mod http;
mod identity;
mod owner;
mod password;
mod portable;
mod provisioning;
use worker::*;

#[event(scheduled)]
pub async fn scheduled(_event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
    if files::maintenance(&env).await.is_err() {
        console_error!("Scheduled file cleanup failed");
    }
    let db = db::Db(match env.d1("DB") {
        Ok(db) => db,
        Err(_) => return,
    });
    if let Ok(rows)=db.all("SELECT * FROM chat_storage_attachment_claims WHERE created_at<?1 ORDER BY created_at LIMIT 100",&[serde_json::json!(http::iso_at(Date::now().as_millis() as f64-300_000.0))]).await {
        for row in rows {
            if let Some(id)=row["chat_id"].as_str(){
                let _=chat::routes::forward(&env,chat::Call{op:"attachments.reconcile".into(),authority:chat::authority::Authority{chat_id:id.into(),user_id:String::new(),device_id:String::new(),session_id:String::new()},data:row}).await;
            }
        }
    }
}

#[event(fetch)]
pub async fn main(mut request: Request, env: Env, _ctx: Context) -> Result<Response> {
    let id = http::random_id().map_err(|_| Error::RustError("Random source failed".into()))?;
    let path = request.path();
    let result = handle(&mut request, &env).await;
    let mut response = match result {
        Ok(r) => r,
        Err(e) => e.response(&id)?,
    };
    let headers = response.headers().clone();
    response = response.with_headers(headers);
    http::security_headers(&mut response, &path, &id)?;
    Ok(response)
}

async fn handle(request: &mut Request, env: &Env) -> http::ApiResult<Response> {
    if !request.path().starts_with("/api/") {
        return Ok(env
            .assets("ASSETS")?
            .fetch_request(request.clone()?)
            .await?);
    }
    http::same_origin(request, env)?;
    http::network_quota(request, env).await?;
    if let Some(response) = owner::handle(request, env).await? {
        return Ok(response);
    }
    if let Some(response) = identity::handle(request, env).await? {
        return Ok(response);
    }
    if let Some(response) = admin::handle(request, env).await? {
        return Ok(response);
    }
    if let Some(response) = files::handle(request, env).await? {
        return Ok(response);
    }
    if request.method() == Method::Get && request.path().trim_end_matches('/') == "/api/v1/chats" {
        return chat::metadata::list(request, env).await;
    }
    let path = request.path();
    if request.method() == Method::Post && path == "/api/v1/auth/logout" {
        return chat::control::public(request, env, "logout", "").await;
    }
    if request.method() == Method::Delete
        && let Some(target) = path.strip_prefix("/api/v1/sessions/")
    {
        return chat::control::public(request, env, "session.revoke", target).await;
    }
    if request.method() == Method::Delete
        && let Some(target) = path.strip_prefix("/api/v1/devices/")
    {
        return chat::control::public(request, env, "device.revoke", target).await;
    }
    if request.path().starts_with("/api/v1/chats/") {
        return chat::routes::handle(request, env).await;
    }
    if request.method() == Method::Post {
        match request.path().as_str() {
            "/api/v1/auth/portable-key/login/prepare" => {
                return portable::prepare(request, env, false).await;
            }
            "/api/v1/auth/portable-key/login/complete" => {
                return portable::complete(request, env, false).await;
            }
            "/api/v1/auth/portable-key/reauth/prepare" => {
                return portable::prepare(request, env, true).await;
            }
            "/api/v1/auth/portable-key/reauth/complete" => {
                return portable::complete(request, env, true).await;
            }
            "/api/v1/admin-provisioning/portable-key/prepare" => {
                return provisioning::prepare(request, env).await;
            }
            "/api/v1/admin-provisioning/portable-key/complete" => {
                return provisioning::complete(request, env).await;
            }
            "/api/v1/auth/password/login" => return password::login(request, env).await,
            "/api/v1/bootstrap/portable-key/prepare" => {
                return bootstrap::prepare(request, env).await;
            }
            "/api/v1/bootstrap/portable-key/complete" => {
                return bootstrap::complete(request, env).await;
            }
            "/api/v1/auth/password/reauth" => {
                let auth = auth::require_session(request, env).await?;
                return password::reauthenticate(request, env, &auth).await;
            }
            _ => {}
        }
    }
    if request.method() == Method::Get && request.path() == "/api/v1/health" {
        return http::json(&serde_json::json!({
            "status":"ok", "runtime":"rust-wasm", "migration_ready":true,
            "app_version":env.var("APP_VERSION").map(|v|v.to_string()).unwrap_or_else(|_|"0.1.0-rust".into())
        }));
    }
    if request.method() == Method::Get {
        match request.path().trim_end_matches('/') {
            "/api/v1/bootstrap/status" => return bootstrap::status(env).await,
            "/api/v1/sessions/current" => {
                let auth = auth::require_session(request, env).await?;
                return auth::current_session(env, &auth).await;
            }
            "/api/v1/sessions" => {
                let auth = auth::require_session(request, env).await?;
                return auth::list_sessions(env, &auth).await;
            }
            _ => {}
        }
    }
    Err(http::ApiError::domain("NOT_FOUND", 404))
}
