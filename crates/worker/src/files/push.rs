use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use worker::{
    js_sys::{self, Array, Function, Reflect, Uint8Array},
    wasm_bindgen::{JsCast, JsValue},
    wasm_bindgen_futures::JsFuture,
};
fn decode(value: &str) -> ApiResult<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(value).map_err(|_| validation())
}
fn endpoint(raw: &str) -> ApiResult<worker::Url> {
    let u = worker::Url::parse(raw).map_err(|_| validation())?;
    let host = u.host_str().unwrap_or_default();
    if u.scheme() != "https"
        || !u.username().is_empty()
        || u.password().is_some()
        || u.fragment().is_some()
        || u.port().is_some_and(|p| p != 443)
        || !(matches!(
            host,
            "fcm.googleapis.com" | "updates.push.services.mozilla.com" | "web.push.apple.com"
        ) || host.ends_with(".notify.windows.com"))
    {
        return Err(validation());
    }
    Ok(u)
}
fn subscription(value: &Value) -> ApiResult<()> {
    let raw = text(value, "endpoint")?;
    if raw.len() > 4096 {
        return Err(validation());
    }
    endpoint(raw)?;
    let public = decode(text(&value["keys"], "p256dh")?)?;
    let auth = decode(text(&value["keys"], "auth")?)?;
    if public.len() != 65 || public[0] != 4 || auth.len() != 16 {
        return Err(validation());
    }
    if let Some(exp) = value.get("expirationTime")
        && !exp.is_null()
        && exp.as_f64().is_none_or(|n| !n.is_finite() || n < 0.0)
    {
        return Err(validation());
    }
    Ok(())
}
struct Vapid {
    public: String,
    private: String,
    subject: String,
}
fn credentials(env: &Env) -> Option<Vapid> {
    let read = |key| {
        env.secret(key)
            .ok()
            .map(|s| s.to_string())
            .or_else(|| env.var(key).ok().map(|s| s.to_string()))
    };
    let public = read("VAPID_PUBLIC_KEY")?;
    let private = read("VAPID_PRIVATE_KEY")?;
    let subject = read("VAPID_SUBJECT")?;
    let pk = decode(&public).ok()?;
    if pk.len() != 65
        || pk[0] != 4
        || decode(&private).ok()?.len() != 32
        || !matches!(
            worker::Url::parse(&subject).ok()?.scheme(),
            "https" | "mailto"
        )
    {
        return None;
    }
    Some(Vapid {
        public,
        private,
        subject,
    })
}
pub async fn handle(
    request: &mut Request,
    env: &Env,
    db: &Db,
    auth: &AuthContext,
    route: &[&str],
) -> ApiResult<Option<Response>> {
    match (&request.method(), route) {
        (Method::Get, [_, "config"]) => {
            let vapid = credentials(env);
            Ok(Some(json(
                &json!({"enabled":vapid.is_some(),"application_server_key":vapid.map(|v|v.public)}),
            )?))
        }
        (Method::Post, [_, "subscriptions"]) => {
            let mut input: Value = read_json(request, 8192).await?;
            subscription(&input)?;
            let url = endpoint(text(&input, "endpoint")?)?;
            input["endpoint"] = json!(url.as_str());
            let hash = auth::sha256_hex(url.as_str());
            let existing=db.first::<Value>("SELECT subscription_id,user_id,device_id FROM push_subscriptions WHERE endpoint_hash=?1",&[json!(hash)]).await?;
            let id = if let Some(row) = existing {
                if row["user_id"] != auth.user_id || row["device_id"] != auth.device_id {
                    return Err(ApiError::domain("PUSH_ENDPOINT_CONFLICT", 409));
                }
                let id = text(&row, "subscription_id")?.to_string();
                db.run("UPDATE push_subscriptions SET subscription_json=?2,revoked_at=NULL WHERE subscription_id=?1",&[json!(id),json!(input.to_string())]).await?;
                id
            } else {
                let id = crate::http::random_id()?;
                db.run("INSERT INTO push_subscriptions(subscription_id,user_id,device_id,endpoint_hash,subscription_json,created_at) VALUES(?1,?2,?3,?4,?5,?6)",&[json!(id),json!(auth.user_id),json!(auth.device_id),json!(hash),json!(input.to_string()),json!(now_iso())]).await?;
                id
            };
            Ok(Some(json(&json!({"subscription_id":id}))?.with_status(201)))
        }
        (Method::Delete, [_, "subscriptions", id]) => {
            uuid(id)?;
            db.run("UPDATE push_subscriptions SET revoked_at=COALESCE(revoked_at,?4) WHERE subscription_id=?1 AND user_id=?2 AND device_id=?3",&[json!(id),json!(auth.user_id),json!(auth.device_id),json!(now_iso())]).await?;
            Ok(Some(Response::empty()?.with_status(204)))
        }
        _ => Ok(None),
    }
}

// WebCrypto calls are made directly from Rust. There is no JavaScript runtime shim.
fn js_error(_: JsValue) -> ApiError {
    ApiError::retryable("PUSH_CRYPTO_FAILED", 503)
}
fn js(value: Value) -> ApiResult<JsValue> {
    js_sys::JSON::parse(&value.to_string()).map_err(js_error)
}
fn bytes(value: &[u8]) -> JsValue {
    Uint8Array::from(value).into()
}
fn property(value: &JsValue, name: &str) -> ApiResult<JsValue> {
    Reflect::get(value, &name.into()).map_err(js_error)
}
fn set(value: &JsValue, name: &str, data: &JsValue) -> ApiResult<()> {
    Reflect::set(value, &name.into(), data).map_err(js_error)?;
    Ok(())
}
async fn call(target: &JsValue, name: &str, args: &[JsValue]) -> ApiResult<JsValue> {
    let function = property(target, name)?
        .dyn_into::<Function>()
        .map_err(js_error)?;
    let arguments = Array::new();
    for arg in args {
        arguments.push(arg);
    }
    let promise = function
        .apply(target, &arguments)
        .map_err(js_error)?
        .dyn_into::<js_sys::Promise>()
        .map_err(js_error)?;
    JsFuture::from(promise).await.map_err(js_error)
}
fn subtle() -> ApiResult<JsValue> {
    property(&property(&js_sys::global(), "crypto")?, "subtle")
}
async fn import(raw: &[u8], algorithm: Value, usage: &str) -> ApiResult<JsValue> {
    call(
        &subtle()?,
        "importKey",
        &[
            "raw".into(),
            bytes(raw),
            js(algorithm)?,
            false.into(),
            js(json!([usage]))?,
        ],
    )
    .await
}
async fn hmac(key: &[u8], data: &[u8]) -> ApiResult<Vec<u8>> {
    let key = import(key, json!({"name":"HMAC","hash":"SHA-256"}), "sign").await?;
    let result = call(&subtle()?, "sign", &["HMAC".into(), key, bytes(data)]).await?;
    Ok(Uint8Array::new(&result).to_vec())
}
async fn encrypt(value: &Value, payload: &[u8]) -> ApiResult<Vec<u8>> {
    subscription(value)?;
    if payload.len() > 3993 {
        return Err(validation());
    }
    let ua = decode(text(&value["keys"], "p256dh")?)?;
    let auth_secret = decode(text(&value["keys"], "auth")?)?;
    let pair = call(
        &subtle()?,
        "generateKey",
        &[
            js(json!({"name":"ECDH","namedCurve":"P-256"}))?,
            true.into(),
            js(json!(["deriveBits"]))?,
        ],
    )
    .await?;
    let public = Uint8Array::new(
        &call(
            &subtle()?,
            "exportKey",
            &["raw".into(), property(&pair, "publicKey")?],
        )
        .await?,
    )
    .to_vec();
    let receiver = call(
        &subtle()?,
        "importKey",
        &[
            "raw".into(),
            bytes(&ua),
            js(json!({"name":"ECDH","namedCurve":"P-256"}))?,
            false.into(),
            js(json!([]))?,
        ],
    )
    .await?;
    let params = js(json!({"name":"ECDH"}))?;
    set(&params, "public", &receiver)?;
    set(&params, "$public", &receiver)?;
    let mut shared = Uint8Array::new(
        &call(
            &subtle()?,
            "deriveBits",
            &[params, property(&pair, "privateKey")?, 256.into()],
        )
        .await?,
    )
    .to_vec();
    let mut prk_key = hmac(&auth_secret, &shared).await?;
    let mut info = b"WebPush: info\0".to_vec();
    info.extend_from_slice(&ua);
    info.extend_from_slice(&public);
    info.push(1);
    let mut ikm = hmac(&prk_key, &info).await?;
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).map_err(|_| ApiError::domain("RANDOM_SOURCE_FAILED", 503))?;
    let mut prk = hmac(&salt, &ikm).await?;
    let mut cek = hmac(&prk, b"Content-Encoding: aes128gcm\0\x01").await?;
    let mut nonce = hmac(&prk, b"Content-Encoding: nonce\0\x01").await?;
    shared.fill(0);
    prk_key.fill(0);
    ikm.fill(0);
    prk.fill(0);
    let key = import(&cek[..16], json!({"name":"AES-GCM"}), "encrypt").await?;
    let params = js(json!({"name":"AES-GCM","tagLength":128}))?;
    set(&params, "iv", &bytes(&nonce[..12]))?;
    let mut record = payload.to_vec();
    record.push(2);
    let ciphertext =
        Uint8Array::new(&call(&subtle()?, "encrypt", &[params, key, bytes(&record)]).await?)
            .to_vec();
    cek.fill(0);
    nonce.fill(0);
    record.fill(0);
    let mut out = salt.to_vec();
    out.extend_from_slice(&4096u32.to_be_bytes());
    out.push(public.len() as u8);
    out.extend_from_slice(&public);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}
async fn jwt(url: &worker::Url, vapid: &Vapid) -> ApiResult<String> {
    let public = decode(&vapid.public)?;
    let jwk = json!({"kty":"EC","crv":"P-256","x":URL_SAFE_NO_PAD.encode(&public[1..33]),"y":URL_SAFE_NO_PAD.encode(&public[33..]),"d":vapid.private,"ext":true,"key_ops":["sign"]});
    let key = call(
        &subtle()?,
        "importKey",
        &[
            "jwk".into(),
            js(jwk)?,
            js(json!({"name":"ECDSA","namedCurve":"P-256"}))?,
            false.into(),
            js(json!(["sign"]))?,
        ],
    )
    .await?;
    let header = URL_SAFE_NO_PAD.encode(br#"{"typ":"JWT","alg":"ES256"}"#);
    let claims=URL_SAFE_NO_PAD.encode(json!({"aud":url.origin().ascii_serialization(),"exp":(worker::Date::now().as_millis()/1000)+43200,"sub":vapid.subject}).to_string());
    let input = format!("{header}.{claims}");
    let signature = Uint8Array::new(
        &call(
            &subtle()?,
            "sign",
            &[
                js(json!({"name":"ECDSA","hash":"SHA-256"}))?,
                key,
                bytes(input.as_bytes()),
            ],
        )
        .await?,
    )
    .to_vec();
    if signature.len() != 64 {
        return Err(ApiError::retryable("PUSH_CRYPTO_FAILED", 503));
    }
    Ok(format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature)))
}
async fn send(subscription: &Value, vapid: &Vapid) -> ApiResult<u16> {
    let url = endpoint(text(subscription, "endpoint")?)?;
    let ciphertext = encrypt(subscription, br#"{"type":"ratchet.changed"}"#).await?;
    let token = jwt(&url, vapid).await?;
    let mut init = worker::RequestInit::new();
    init.with_method(Method::Post)
        .with_redirect(worker::RequestRedirect::Error)
        .with_body(Some(bytes(&ciphertext)));
    let headers = worker::Headers::new();
    for (name, value) in [
        (
            "Authorization",
            format!("vapid t={token}, k={}", vapid.public),
        ),
        ("Content-Encoding", "aes128gcm".into()),
        ("Content-Type", "application/octet-stream".into()),
        ("TTL", "60".into()),
        ("Urgency", "normal".into()),
    ] {
        headers.set(name, &value)?;
    }
    let init = init.with_headers(headers);
    let request = Request::new_with_init(url.as_str(), init)?;
    let constructor = property(&js_sys::global(), "AbortSignal")?;
    let timeout = property(&constructor, "timeout")?
        .dyn_into::<Function>()
        .map_err(js_error)?;
    let signal = timeout
        .call1(&constructor, &10000.into())
        .map_err(js_error)?
        .dyn_into::<worker::web_sys::AbortSignal>()
        .map_err(js_error)?;
    let signal = worker::AbortSignal::from(signal);
    let response = worker::Fetch::Request(request)
        .send_with_signal(&signal)
        .await?;
    Ok(response.status_code())
}
/// Generic wakeup hints contain no chat identity or message contents.
pub async fn notify_push(env: &Env, chat: &str, sender_device: &str) -> ApiResult<()> {
    let Some(vapid) = credentials(env) else {
        return Ok(());
    };
    let db = Db(env.d1("DB")?);
    let rows=db.all("SELECT ps.subscription_id,ps.subscription_json FROM push_subscriptions ps JOIN devices d ON d.device_id=ps.device_id AND d.user_id=ps.user_id JOIN active_chat_members m ON m.user_id=ps.user_id AND m.chat_id=?1 WHERE ps.revoked_at IS NULL AND d.authorized_at IS NOT NULL AND d.revoked_at IS NULL AND ps.device_id<>?2 ORDER BY ps.subscription_id LIMIT 256",&[json!(chat),json!(sender_device)]).await?;
    let results=futures_util::future::join_all(rows.iter().map(|row|async {
        let parsed = serde_json::from_str::<Value>(row["subscription_json"].as_str().unwrap_or(""));
        let revoke = match parsed {
            Ok(value) if subscription(&value).is_ok() => {
                matches!(send(&value, &vapid).await, Ok(404 | 410))
            }
            _ => true,
        };
        if revoke {
            db.run("UPDATE push_subscriptions SET revoked_at=COALESCE(revoked_at,?2) WHERE subscription_id=?1",&[row["subscription_id"].clone(),json!(now_iso())]).await?;
        }
        Ok::<(),ApiError>(())
    })).await;
    for result in results {
        if result.is_err() {
            worker::console_warn!("Push subscription cleanup failed");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn endpoint_allowlist_blocks_local_and_credentials() {
        assert!(endpoint("https://fcm.googleapis.com/fcm/send/test").is_ok());
        for raw in [
            "https://127.0.0.1/a",
            "https://evil.test/a",
            "https://fcm.googleapis.com.evil.test/a",
            "https://user@fcm.googleapis.com/a",
            "https://fcm.googleapis.com:8443/a",
            "https://fcm.googleapis.com/a#fragment",
        ] {
            assert!(endpoint(raw).is_err(), "{raw}");
        }
    }
}
