use futures_util::StreamExt;
use ratchet_core::{
    error::DomainError,
    http_security::{BodyBudget, check_origin},
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::json;
use worker::*;

pub type ApiResult<T> = std::result::Result<T, ApiError>;
pub enum ApiError {
    Domain(DomainError),
    Runtime(Error),
}
impl From<Error> for ApiError {
    fn from(e: Error) -> Self {
        Self::Runtime(e)
    }
}
impl From<DomainError> for ApiError {
    fn from(e: DomainError) -> Self {
        Self::Domain(e)
    }
}

impl ApiError {
    pub fn domain(code: &'static str, status: u16) -> Self {
        Self::Domain(DomainError::new(code, status))
    }
    pub fn response(self, id: &str) -> Result<Response> {
        let error = match self {
            Self::Domain(e) => e,
            Self::Runtime(cause) => {
                drop(cause);
                console_error!("Internal request failure, request_id={}", id);
                DomainError::new("INTERNAL_ERROR", 503)
            }
        };
        let mut value = serde_json::to_value(&error)
            .map_err(|_| Error::RustError("Problem serialization failed".into()))?;
        value["request_id"] = json!(id);
        let mut response = Response::from_json(&value)?.with_status(error.status);
        if error.status == 429 {
            response.headers_mut().set("Retry-After", "60")?;
        }
        Ok(response)
    }
}

pub fn json<T: Serialize>(value: &T) -> ApiResult<Response> {
    Ok(Response::from_json(value)?)
}
pub fn now_iso() -> String {
    js_sys::Date::new_0().to_iso_string().into()
}
pub fn iso_at(ms: f64) -> String {
    js_sys::Date::new(&ms.into()).to_iso_string().into()
}
pub fn random_id() -> ApiResult<String> {
    let mut bytes = [0; 16];
    getrandom::fill(&mut bytes).map_err(|_| ApiError::domain("RANDOM_SOURCE_FAILED", 503))?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(uuid::Uuid::from_bytes(bytes).to_string())
}

pub async fn read_json<T: DeserializeOwned>(request: &mut Request, limit: usize) -> ApiResult<T> {
    if request
        .headers()
        .get("Content-Length")?
        .and_then(|s| s.parse::<usize>().ok())
        .is_some_and(|n| n > limit)
    {
        return Err(ApiError::domain("REQUEST_TOO_LARGE", 413));
    }
    let mut stream = request
        .stream()
        .map_err(|_| ApiError::domain("VALIDATION_ERROR", 422))?;
    let mut budget = BodyBudget::new(limit);
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        budget.consume(chunk.len())?;
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|_| ApiError::domain("VALIDATION_ERROR", 422))
}

pub fn same_origin(request: &Request, env: &Env) -> ApiResult<()> {
    if matches!(
        request.method(),
        Method::Get | Method::Head | Method::Options
    ) {
        return Ok(());
    }
    let expected = Url::parse(&env.var("RP_ORIGIN")?.to_string())
        .map_err(|_| ApiError::domain("SERVER_CONFIGURATION_ERROR", 503))?;
    let origin = request.headers().get("Origin")?;
    let expected_origin = expected.origin().ascii_serialization();
    let actual = request.url()?;
    let host = |url: &Url| match url.port() {
        Some(port) => format!("{}:{port}", url.host_str().unwrap_or_default()),
        None => url.host_str().unwrap_or_default().to_string(),
    };
    check_origin(
        request.method().as_ref(),
        origin.as_deref(),
        &host(&actual),
        &expected_origin,
        &host(&expected),
    )?;
    Ok(())
}

pub async fn network_quota(request: &Request, env: &Env) -> ApiResult<()> {
    let path = request.path();
    let binding = if path == "/api/v1/health" || path == "/api/v1/bootstrap/status" {
        "PUBLIC_RATE_LIMITER"
    } else if path.starts_with("/api/v1/auth/")
        || path.starts_with("/api/v1/bootstrap/")
        || path.starts_with("/api/v1/owner-console/")
        || path.starts_with("/api/v1/admin-provisioning/")
    {
        "AUTH_RATE_LIMITER"
    } else if path.ends_with("/realtime") {
        "WS_RATE_LIMITER"
    } else {
        "API_RATE_LIMITER"
    };
    let key = request
        .headers()
        .get("CF-Connecting-IP")?
        .unwrap_or_else(|| "local-network".into());
    if !env.rate_limiter(binding)?.limit(key).await?.success {
        return Err(ApiError::domain("RATE_LIMITED", 429));
    }
    Ok(())
}

pub fn security_headers(response: &mut Response, path: &str, request_id: &str) -> Result<()> {
    let headers = response.headers_mut();
    for (name, value) in [
        (
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data: blob:; frame-src 'self' blob:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
        ),
        (
            "Strict-Transport-Security",
            "max-age=63072000; includeSubDomains; preload",
        ),
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "DENY"),
        ("Referrer-Policy", "no-referrer"),
        (
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=()",
        ),
        ("Cross-Origin-Opener-Policy", "same-origin"),
        ("Cross-Origin-Resource-Policy", "same-origin"),
        ("Origin-Agent-Cluster", "?1"),
    ] {
        headers.set(name, value)?;
    }
    headers.set("X-Request-ID", request_id)?;
    if path.starts_with("/api/") {
        for (name, value) in [
            ("Cache-Control", "no-store, max-age=0"),
            ("Pragma", "no-cache"),
            ("Expires", "0"),
            ("Cloudflare-CDN-Cache-Control", "no-store"),
        ] {
            headers.set(name, value)?;
        }
    }
    Ok(())
}
