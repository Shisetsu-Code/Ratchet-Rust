use super::{Call, authority::Authority};
use crate::{
    auth::{self, AuthContext},
    http::{self, ApiError, ApiResult},
};
use ratchet_core::message::{SendRequest, is_uuid};
use serde_json::{Value, json};
use worker::*;

pub fn authority(auth: &AuthContext, chat_id: &str) -> Authority {
    Authority {
        chat_id: chat_id.into(),
        session_id: auth.session_id.clone(),
        user_id: auth.user_id.clone(),
        device_id: auth.device_id.clone(),
    }
}

pub async fn forward(env: &Env, call: Call) -> ApiResult<Response> {
    let namespace = env.durable_object("CHAT_REALTIME")?;
    let stub = namespace
        .id_from_name(if call.op.starts_with("control.") {
            super::control::NAME
        } else {
            &call.authority.chat_id
        })?
        .get_stub()?;
    let mut init = RequestInit::new();
    let headers = Headers::new();
    if call.op == "open" {
        init.with_method(Method::Get);
        headers.set("Upgrade", "websocket")?;
        headers.set(
            "X-Ratchet-Call",
            &serde_json::to_string(&call).map_err(|_| ApiError::domain("VALIDATION_ERROR", 422))?,
        )?;
    } else {
        init.with_method(Method::Post);
        init.with_body(Some(
            serde_json::to_string(&call)
                .map_err(|_| ApiError::domain("VALIDATION_ERROR", 422))?
                .into(),
        ));
        headers.set("Content-Type", "application/json")?;
    }
    init.with_headers(headers);
    Ok(stub
        .fetch_with_request(Request::new_with_init("https://room.internal/", &init)?)
        .await?)
}

pub async fn handle(request: &mut Request, env: &Env) -> ApiResult<Response> {
    let auth = auth::require_session(request, env).await?;
    auth::require_authorized(&auth)?;
    let path = request.path();
    let parts: Vec<_> = path
        .trim_start_matches("/api/v1/chats/")
        .trim_end_matches('/')
        .split('/')
        .collect();
    let chat_id = parts
        .first()
        .copied()
        .filter(|id| is_uuid(id))
        .ok_or_else(|| ApiError::domain("VALIDATION_ERROR", 422))?;
    let meta = authority(&auth, chat_id);
    let method = request.method();
    let suffix = parts[1..].join("/");
    let (op, data) = match (method, suffix.as_str()) {
        (Method::Get, "realtime") => {
            if request.headers().get("Origin")?.as_deref()
                != Some(&env.var("RP_ORIGIN")?.to_string())
            {
                return Err(ApiError::domain("ORIGIN_MISMATCH", 403));
            }
            if request
                .headers()
                .get("Upgrade")?
                .as_deref()
                .map(str::to_lowercase)
                .as_deref()
                != Some("websocket")
            {
                return Err(ApiError::domain("UPGRADE_REQUIRED", 426));
            }
            ("open", json!(null))
        }
        (Method::Get, "messages/sender-sequence") => ("sequence", json!(null)),
        (Method::Get, "sync") => {
            let url = request.url()?;
            let parse = |name: &str, default: u64| -> ApiResult<u64> {
                url.query_pairs()
                    .find(|(key, _)| key == name)
                    .map(|(_, value)| {
                        value
                            .parse::<u64>()
                            .map_err(|_| ApiError::domain("VALIDATION_ERROR", 422))
                    })
                    .unwrap_or(Ok(default))
            };
            (
                "sync",
                json!({"after":parse("after_revision",0)?,"limit":parse("limit",200)?}),
            )
        }
        (Method::Get, s) if s.starts_with("messages/by-client-id/") => (
            "lookup",
            json!({"id":s.trim_start_matches("messages/by-client-id/")}),
        ),
        (Method::Post, "messages") => {
            let input: SendRequest = http::read_json(request, 2 * 1024 * 1024).await?;
            (
                "send",
                serde_json::to_value(input)
                    .map_err(|_| ApiError::domain("VALIDATION_ERROR", 422))?,
            )
        }
        (Method::Post, "receipts") | (Method::Post, "receipts/batch") => {
            let id = request
                .headers()
                .get("Idempotency-Key")?
                .filter(|id| is_uuid(id))
                .ok_or_else(|| ApiError::domain("VALIDATION_ERROR", 422))?;
            let body: Value = http::read_json(request, 2 * 1024 * 1024).await?;
            let entries = if suffix == "receipts" {
                json!([body])
            } else {
                body["receipts"].clone()
            };
            let mut response = forward(
                env,
                Call {
                    op: "receipts".into(),
                    authority: meta,
                    data: json!({"receipts":entries,"request_id":id}),
                },
            )
            .await?;
            if suffix == "receipts" && response.status_code() == 200 {
                let value: Value = response.json().await?;
                return http::json(&value["receipts"][0]);
            }
            return Ok(response);
        }
        _ => return Err(ApiError::domain("NOT_FOUND", 404)),
    };
    forward(
        env,
        Call {
            op: op.into(),
            authority: meta,
            data,
        },
    )
    .await
}
