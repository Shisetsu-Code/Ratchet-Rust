use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::{StreamExt, stream};
use std::{future::Future, time::Duration};
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

const DELIVERY_LEASE_MS: i64 = 30_000;
const DELIVERY_WORK_MS: i64 = 10_000;

#[derive(Clone, Copy)]
struct DeliveryLease {
    claimed_at: i64,
    until: i64,
}
impl DeliveryLease {
    fn new(now: i64) -> Self {
        Self {
            claimed_at: now,
            until: now + DELIVERY_LEASE_MS,
        }
    }
    fn work_deadline(self) -> i64 {
        self.claimed_at + DELIVERY_WORK_MS
    }
}

async fn dispatch_batch<'a, R, F: Future<Output = ApiResult<()>>>(
    rows: &'a [R],
    clock: impl Fn() -> i64,
    work: impl Fn(&'a R, DeliveryLease) -> F,
) -> Vec<ApiResult<()>> {
    // Sample when a concurrency slot actually starts this row, not when the
    // 32-row batch was selected. Later waves can start tens of seconds later.
    stream::iter(
        rows.iter()
            .map(|row| async { work(row, DeliveryLease::new(clock())).await }),
    )
    .buffer_unordered(4)
    .collect()
    .await
}

struct AbortOnDrop<F: FnOnce()>(Option<F>);
impl<F: FnOnce()> Drop for AbortOnDrop<F> {
    fn drop(&mut self) {
        if let Some(abort) = self.0.take() {
            abort();
        }
    }
}

async fn run_until<T>(
    deadline: i64,
    clock: impl Fn() -> i64,
    timer: impl Future<Output = ()>,
    operation: impl Future<Output = ApiResult<T>>,
    abort: impl FnOnce(),
) -> ApiResult<T> {
    let _abort = AbortOnDrop(Some(abort));
    let mut timer = std::pin::pin!(timer);
    let mut operation = std::pin::pin!(operation);
    std::future::poll_fn(|cx| {
        // Check before every continuation, even if a delayed timer callback has
        // not run yet. A suspended claim must never resume crypto or dispatch.
        if clock() >= deadline || timer.as_mut().poll(cx).is_ready() {
            return std::task::Poll::Ready(Err(ApiError::retryable("PUSH_DEADLINE_EXCEEDED", 503)));
        }
        match operation.as_mut().poll(cx) {
            std::task::Poll::Ready(_) if clock() >= deadline => {
                std::task::Poll::Ready(Err(ApiError::retryable("PUSH_DEADLINE_EXCEEDED", 503)))
            }
            result => result,
        }
    })
    .await
}

fn clock_ms() -> i64 {
    worker::Date::now().as_millis() as i64
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
            let input = json!({"endpoint":url.as_str(),"expirationTime":input.get("expirationTime").cloned().unwrap_or(Value::Null),"keys":{"p256dh":input["keys"]["p256dh"],"auth":input["keys"]["auth"]}});
            let id = crate::http::random_id()?;
            // Replacing a browser's endpoint updates its one durable slot. Unique
            // endpoint ownership and user/global cardinality are enforced by D1.
            db.run("INSERT INTO push_subscriptions(subscription_id,user_id,device_id,endpoint_hash,subscription_json,created_at) VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(device_id) DO UPDATE SET endpoint_hash=excluded.endpoint_hash,subscription_json=excluded.subscription_json,revoked_at=NULL,created_at=excluded.created_at WHERE push_subscriptions.user_id=excluded.user_id", &[json!(id),json!(auth.user_id),json!(auth.device_id),json!(hash),json!(input.to_string()),json!(now_iso())]).await.map_err(|e|storage_error_api(e,"PUSH_ENDPOINT_CONFLICT"))?;
            let row=db.first::<Value>("SELECT subscription_id,endpoint_hash FROM push_subscriptions WHERE device_id=?1 AND user_id=?2", &[json!(auth.device_id),json!(auth.user_id)]).await?.ok_or_else(||ApiError::domain("PUSH_ENDPOINT_CONFLICT",409))?;
            if row["endpoint_hash"] != hash {
                return Err(ApiError::domain("PUSH_ENDPOINT_CONFLICT", 409));
            }
            let id = text(&row, "subscription_id")?;
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
async fn send(subscription: &Value, vapid: &Vapid, lease: DeliveryLease) -> ApiResult<u16> {
    // Preparation and transport share the existing 10-second work budget. It
    // starts at claim time and ends before the unchanged 30-second lease.
    let deadline = lease.work_deadline();
    let remaining = deadline - clock_ms();
    if remaining <= 0 {
        return Err(ApiError::retryable("PUSH_DEADLINE_EXCEEDED", 503));
    }
    let controller = worker::AbortController::default();
    let signal = controller.signal();
    run_until(
        deadline,
        clock_ms,
        worker::Delay::from(Duration::from_millis(remaining as u64)),
        prepare_and_send(subscription, vapid, &signal),
        || controller.abort(),
    )
    .await
}

async fn prepare_and_send(
    subscription: &Value,
    vapid: &Vapid,
    signal: &worker::AbortSignal,
) -> ApiResult<u16> {
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
    let response = worker::Fetch::Request(request)
        .send_with_signal(signal)
        .await?;
    Ok(response.status_code())
}
/// Generic wakeup hints coalesce into one durable queue row per subscription.
pub async fn notify_push(env: &Env, chat: &str, sender_device: &str) -> ApiResult<()> {
    if credentials(env).is_none() {
        return Ok(());
    }
    let db = Db(env.d1("DB")?);
    db.run("INSERT INTO push_wakeups(subscription_id,requested_at) SELECT ps.subscription_id,?3 FROM push_subscriptions ps JOIN devices d ON d.device_id=ps.device_id AND d.user_id=ps.user_id JOIN active_chat_members m ON m.user_id=ps.user_id AND m.chat_id=?1 WHERE ps.revoked_at IS NULL AND d.authorized_at IS NOT NULL AND d.revoked_at IS NULL AND ps.device_id<>?2 ON CONFLICT(subscription_id) DO UPDATE SET generation=generation+1 WHERE push_wakeups.lease_token IS NOT NULL", &[json!(chat),json!(sender_device),json!(worker::Date::now().as_millis())]).await?;
    maintenance(env).await
}

/// Fair bounded batches prevent a failing provider or a prolific user from
/// monopolizing every dispatch. Retries survive request/Worker termination.
pub(super) async fn maintenance(env: &Env) -> ApiResult<()> {
    let Some(vapid) = credentials(env) else {
        return Ok(());
    };
    let db = Db(env.d1("DB")?);
    let now = worker::Date::now().as_millis() as i64;
    db.run("DELETE FROM push_wakeups WHERE subscription_id IN (SELECT q.subscription_id FROM push_wakeups q JOIN push_subscriptions p ON p.subscription_id=q.subscription_id JOIN devices d ON d.device_id=p.device_id WHERE p.revoked_at IS NOT NULL OR d.revoked_at IS NOT NULL OR d.authorized_at IS NULL LIMIT 100)", &[]).await?;
    let rows=db.all("SELECT * FROM (SELECT q.subscription_id,q.generation,q.attempts,q.requested_at,p.subscription_json,p.endpoint_hash,ROW_NUMBER() OVER(PARTITION BY p.user_id ORDER BY q.next_attempt_at,q.requested_at,q.subscription_id) AS user_rank FROM push_wakeups q JOIN push_subscriptions p ON p.subscription_id=q.subscription_id JOIN devices d ON d.device_id=p.device_id AND d.user_id=p.user_id JOIN users u ON u.user_id=p.user_id WHERE q.next_attempt_at<=?1 AND q.lease_until<=?1 AND p.revoked_at IS NULL AND d.revoked_at IS NULL AND d.authorized_at IS NOT NULL AND u.status='ACTIVE') ORDER BY user_rank,requested_at,subscription_id LIMIT 32", &[json!(now)]).await?;
    let results=dispatch_batch(&rows,clock_ms,|row,lease| {
      let db=&db;
      let vapid=&vapid;
      async move {
        let token=crate::http::random_id()?;
        if !changed(db,"UPDATE push_wakeups SET lease_token=?2,lease_until=?3 WHERE subscription_id=?1 AND next_attempt_at<=?4 AND lease_until<=?4 AND (SELECT COUNT(*) FROM push_wakeups WHERE lease_until>?4)<8", &[row["subscription_id"].clone(),json!(token),json!(lease.until),json!(lease.claimed_at)]).await? {return Ok(());}
        let parsed=serde_json::from_str::<Value>(row["subscription_json"].as_str().unwrap_or(""));
        let outcome=match parsed {Ok(value) if subscription(&value).is_ok()=>Some(send(&value,vapid,lease).await),_=>None};
        let permanent=matches!(outcome,None|Some(Ok(404|410)));
        let success=matches!(outcome,Some(Ok(200..=299)));
        if permanent {
            db.run("UPDATE push_subscriptions SET revoked_at=COALESCE(revoked_at,?2) WHERE subscription_id=?1 AND endpoint_hash=?3", &[row["subscription_id"].clone(),json!(now_iso()),row["endpoint_hash"].clone()]).await?;
        }
        let attempts=row["attempts"].as_u64().unwrap_or(0)+1;
        if success||permanent||attempts>=8 {
            db.0.batch(vec![db.statement("DELETE FROM push_wakeups WHERE subscription_id=?1 AND lease_token=?2 AND generation=?3", &[row["subscription_id"].clone(),json!(token),row["generation"].clone()])?,db.statement("UPDATE push_wakeups SET lease_token=NULL,lease_until=0,attempts=0,next_attempt_at=0,requested_at=?3 WHERE subscription_id=?1 AND lease_token=?2", &[row["subscription_id"].clone(),json!(token),json!(worker::Date::now().as_millis())])?]).await?;
        } else {
            let next=worker::Date::now().as_millis()+retry_delay(attempts);
            db.run("UPDATE push_wakeups SET lease_token=NULL,lease_until=0,attempts=?3,next_attempt_at=?4 WHERE subscription_id=?1 AND lease_token=?2", &[row["subscription_id"].clone(),json!(token),json!(attempts),json!(next)]).await?;
        }
        Ok::<(),ApiError>(())
      }
    }).await;
    for result in results {
        if result.is_err() {
            worker::console_warn!("Push dispatch deferred");
        }
    }
    Ok(())
}
fn retry_delay(attempts: u64) -> u64 {
    60_000u64
        .saturating_mul(1 << attempts.saturating_sub(1).min(6))
        .min(3_600_000)
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::FutureExt;
    use std::{
        cell::{Cell, RefCell},
        future::poll_fn,
        task::Poll,
    };

    #[test]
    fn slow_push_waves_receive_fresh_leases_at_each_effective_claim() {
        let now = Cell::new(0_i64);
        let claims = RefCell::new(Vec::new());
        let rows: Vec<_> = (0..32).collect();
        let mut dispatch = Box::pin(dispatch_batch(
            &rows,
            || now.get(),
            |_, lease| {
                let claimed = now.get();
                claims.borrow_mut().push((claimed, lease.until));
                let now = &now;
                poll_fn(move |cx| {
                    if now.get() >= claimed + 9_000 {
                        Poll::Ready(Ok(()))
                    } else {
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                })
            },
        ));
        for tick in [0, 9_000, 18_000, 27_000] {
            now.set(tick);
            // Drive the cooperative executor's queued wakeups at the same fake
            // instant before advancing to the next provider completion.
            for _ in 0..16 {
                assert!(dispatch.as_mut().now_or_never().is_none());
            }
            for &(claimed, until) in claims.borrow().iter() {
                assert!(
                    claimed + 9_000 < until,
                    "provider work beginning at {claimed} must finish before lease {until}"
                );
                assert_eq!(until - claimed, DELIVERY_LEASE_MS);
            }
        }
        assert_eq!(claims.borrow().len(), 16);
    }

    #[test]
    fn resumed_expired_push_claim_never_polls_crypto_or_transport() {
        let lease = DeliveryLease::new(0);
        let polled = Cell::new(0);
        let aborted = Cell::new(0);
        let result = run_until(
            lease.work_deadline(),
            || 31_000,
            async {},
            async {
                polled.set(polled.get() + 1);
                Ok::<_, ApiError>(200_u16)
            },
            || aborted.set(aborted.get() + 1),
        )
        .now_or_never();
        assert!(matches!(result, Some(Err(_))));
        assert_eq!(polled.get(), 0);
        assert_eq!(aborted.get(), 1);
    }

    #[test]
    fn cryptographic_preparation_and_fetch_share_one_absolute_push_deadline() {
        let now = Cell::new(0_i64);
        let crypto_done = Cell::new(false);
        let fetch_polls = Cell::new(0);
        let aborted = Cell::new(0);
        let lease = DeliveryLease::new(0);
        let operation = async {
            poll_fn(|_| {
                if now.get() >= 8_000 {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
            crypto_done.set(true);
            poll_fn(|_| {
                fetch_polls.set(fetch_polls.get() + 1);
                if now.get() >= 17_000 {
                    Poll::Ready(Ok::<_, ApiError>(200_u16))
                } else {
                    Poll::Pending
                }
            })
            .await
        };
        let timer = poll_fn(|_| {
            if now.get() >= lease.work_deadline() {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        });
        let mut attempt = Box::pin(run_until(
            lease.work_deadline(),
            || now.get(),
            timer,
            operation,
            || aborted.set(aborted.get() + 1),
        ));
        assert!(attempt.as_mut().now_or_never().is_none());
        now.set(8_000);
        assert!(attempt.as_mut().now_or_never().is_none());
        assert!(crypto_done.get());
        assert_eq!(fetch_polls.get(), 1);
        now.set(10_000);
        assert!(matches!(attempt.as_mut().now_or_never(), Some(Err(_))));
        assert_eq!(
            fetch_polls.get(),
            1,
            "a late callback cannot resume provider work after the shared deadline"
        );
        assert_eq!(aborted.get(), 1);
        assert!(now.get() < lease.until);
    }

    #[test]
    fn dropping_pending_push_attempt_aborts_before_its_lease_is_released() {
        let aborted = Cell::new(0);
        let mut attempt = Box::pin(run_until(
            10_000,
            || 0,
            std::future::pending(),
            std::future::pending::<ApiResult<u16>>(),
            || aborted.set(aborted.get() + 1),
        ));
        assert!(attempt.as_mut().now_or_never().is_none());
        drop(attempt);
        assert_eq!(aborted.get(), 1);
    }
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
