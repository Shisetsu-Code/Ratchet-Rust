//! Cloudflare runtime adapter. Domain code lives in ratchet-core.
mod auth;
mod bootstrap;
mod db;
mod http;
mod password;
use worker::*;

#[event(fetch)]
pub async fn main(mut request: Request, env: Env, _ctx: Context) -> Result<Response> {
    let id = http::random_id().map_err(|_| Error::RustError("Random source failed".into()))?;
    let path = request.path();
    let result = handle(&mut request, &env).await;
    let mut response = match result {
        Ok(r) => r,
        Err(e) => e.response(&id)?,
    };
    http::security_headers(&mut response, &path, &id)?;
    Ok(response)
}

async fn handle(request: &mut Request, env: &Env) -> http::ApiResult<Response> {
    http::same_origin(request, env)?;
    http::network_quota(request, env).await?;
    if request.method() == Method::Post {
        match request.path().as_str() {
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
            "status":"migration-in-progress", "runtime":"rust-wasm", "migration_ready":false,
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
