use super::*;
use crate::{auth::sha256_hex, http::iso_at};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use worker::{
    Date,
    js_sys::{self, Array, Function, Promise, Reflect, Uint8Array},
    wasm_bindgen::{JsCast, JsValue},
    wasm_bindgen_futures::JsFuture,
};

fn invalid() -> ApiError {
    ApiError::domain("WEBAUTHN_VERIFICATION_FAILED", 400)
}
fn decode(v: &Value) -> ApiResult<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(v.as_str().ok_or_else(invalid)?)
        .map_err(|_| invalid())
}
fn property(v: &JsValue, k: &str) -> ApiResult<JsValue> {
    Reflect::get(v, &JsValue::from_str(k)).map_err(|_| invalid())
}
async fn invoke(v: &JsValue, k: &str, args: &Array) -> ApiResult<JsValue> {
    let f = property(v, k)?
        .dyn_into::<Function>()
        .map_err(|_| invalid())?;
    let promise = f
        .apply(v, args)
        .map_err(|_| invalid())?
        .dyn_into::<Promise>()
        .map_err(|_| invalid())?;
    JsFuture::from(promise).await.map_err(|_| invalid())
}
fn js(v: &Value) -> ApiResult<JsValue> {
    js_sys::JSON::parse(&v.to_string()).map_err(|_| invalid())
}

// COSE public keys are a bounded CBOR map of integer labels to integers or bytes.
// Reject indefinite encodings, duplicate labels, trailing data and unsupported types.
enum Item {
    Int(i64),
    Bytes(Vec<u8>),
}
struct Cbor<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl Cbor<'_> {
    fn head(&mut self) -> ApiResult<(u8, u64)> {
        let b = *self.bytes.get(self.at).ok_or_else(invalid)?;
        self.at += 1;
        let a = b & 31;
        let n = match a {
            0..=23 => a as u64,
            24..=27 => {
                let count = 1usize << (a - 24);
                let end = self.at.checked_add(count).ok_or_else(invalid)?;
                let bytes = self.bytes.get(self.at..end).ok_or_else(invalid)?;
                self.at = end;
                bytes.iter().fold(0u64, |n, b| (n << 8) | u64::from(*b))
            }
            _ => return Err(invalid()),
        };
        Ok((b >> 5, n))
    }
    fn item(&mut self) -> ApiResult<Item> {
        let (t, n) = self.head()?;
        match t {
            0 if n <= i64::MAX as u64 => Ok(Item::Int(n as i64)),
            1 if n <= i64::MAX as u64 => Ok(Item::Int(-1 - n as i64)),
            2 if n <= 8192 => {
                let end = self.at.checked_add(n as usize).ok_or_else(invalid)?;
                let bytes = self.bytes.get(self.at..end).ok_or_else(invalid)?.to_vec();
                self.at = end;
                Ok(Item::Bytes(bytes))
            }
            _ => Err(invalid()),
        }
    }
    fn skip(&mut self, depth: usize) -> ApiResult<()> {
        if depth > 8 {
            return Err(invalid());
        }
        let (t, n) = self.head()?;
        match t {
            0 | 1 | 7 => {}
            2 | 3 => {
                if n > 65536 {
                    return Err(invalid());
                }
                let end = self.at.checked_add(n as usize).ok_or_else(invalid)?;
                let b = self.bytes.get(self.at..end).ok_or_else(invalid)?;
                if t == 3 {
                    std::str::from_utf8(b).map_err(|_| invalid())?;
                }
                self.at = end;
            }
            4 | 5 => {
                if n > 128 {
                    return Err(invalid());
                }
                for _ in 0..n * if t == 5 { 2 } else { 1 } {
                    self.skip(depth + 1)?;
                }
            }
            6 => self.skip(depth + 1)?,
            _ => return Err(invalid()),
        }
        Ok(())
    }
}
fn cose(bytes: &[u8]) -> ApiResult<BTreeMap<i64, Item>> {
    let mut c = Cbor { bytes, at: 0 };
    let (t, n) = c.head()?;
    if t != 5 || n > 16 {
        return Err(invalid());
    }
    let mut m = BTreeMap::new();
    for _ in 0..n {
        let Item::Int(k) = c.item()? else {
            return Err(invalid());
        };
        if m.insert(k, c.item()?).is_some() {
            return Err(invalid());
        }
    }
    if c.at != bytes.len() {
        return Err(invalid());
    }
    Ok(m)
}
fn integer(m: &BTreeMap<i64, Item>, k: i64) -> ApiResult<i64> {
    match m.get(&k) {
        Some(Item::Int(v)) => Ok(*v),
        _ => Err(invalid()),
    }
}
fn bytes(m: &BTreeMap<i64, Item>, k: i64, len: Option<usize>) -> ApiResult<Vec<u8>> {
    match m.get(&k) {
        Some(Item::Bytes(v)) if len.is_none_or(|n| v.len() == n) => Ok(v.clone()),
        _ => Err(invalid()),
    }
}
fn der_signature(input: &[u8], size: usize) -> ApiResult<Vec<u8>> {
    fn length(b: &[u8], p: &mut usize) -> ApiResult<usize> {
        let n = *b.get(*p).ok_or_else(invalid)?;
        *p += 1;
        if n < 128 {
            return Ok(n as usize);
        }
        if n != 0x81 {
            return Err(invalid());
        }
        let v = *b.get(*p).ok_or_else(invalid)? as usize;
        *p += 1;
        if v < 128 {
            return Err(invalid());
        }
        Ok(v)
    }
    let mut at = 0;
    if input.get(at) != Some(&0x30) {
        return Err(invalid());
    }
    at += 1;
    let total = length(input, &mut at)?;
    if at + total != input.len() {
        return Err(invalid());
    }
    let mut out = Vec::with_capacity(size * 2);
    for _ in 0..2 {
        if input.get(at) != Some(&2) {
            return Err(invalid());
        }
        at += 1;
        let n = length(input, &mut at)?;
        let mut part = input.get(at..at + n).ok_or_else(invalid)?;
        at += n;
        if part.is_empty() || part[0] & 128 != 0 {
            return Err(invalid());
        }
        if part[0] == 0 && part.len() > 1 {
            if part[1] & 128 == 0 {
                return Err(invalid());
            }
            part = &part[1..];
        }
        if part.len() > size {
            return Err(invalid());
        }
        out.resize(out.len() + size - part.len(), 0);
        out.extend_from_slice(part);
    }
    if at != input.len() {
        return Err(invalid());
    }
    Ok(out)
}
async fn signature(public: &[u8], signature: &[u8], signed: &[u8]) -> ApiResult<()> {
    let m = cose(public)?;
    let alg = integer(&m, 3)?;
    let kty = integer(&m, 1)?;
    let (jwk, import, verify, sig) = match (kty, alg) {
        (2, -7) | (2, -35) | (2, -36) => {
            let (curve, n, hash, c) = match alg {
                -7 => ("P-256", 32, "SHA-256", 1),
                -35 => ("P-384", 48, "SHA-384", 2),
                _ => ("P-521", 66, "SHA-512", 3),
            };
            if integer(&m, -1)? != c {
                return Err(invalid());
            }
            let x = bytes(&m, -2, Some(n))?;
            let y = bytes(&m, -3, Some(n))?;
            (
                json!({"kty":"EC","crv":curve,"x":URL_SAFE_NO_PAD.encode(x),"y":URL_SAFE_NO_PAD.encode(y),"ext":true}),
                json!({"name":"ECDSA","namedCurve":curve}),
                json!({"name":"ECDSA","hash":hash}),
                der_signature(signature, n)?,
            )
        }
        (3, -257) | (3, -258) | (3, -259) => {
            let n = bytes(&m, -1, None)?;
            let e = bytes(&m, -2, None)?;
            if !(256..=1024).contains(&n.len()) || e.is_empty() || e.len() > 8 {
                return Err(invalid());
            }
            let hash = match alg {
                -257 => "SHA-256",
                -258 => "SHA-384",
                _ => "SHA-512",
            };
            (
                json!({"kty":"RSA","n":URL_SAFE_NO_PAD.encode(n),"e":URL_SAFE_NO_PAD.encode(e),"ext":true}),
                json!({"name":"RSASSA-PKCS1-v1_5","hash":hash}),
                json!({"name":"RSASSA-PKCS1-v1_5"}),
                signature.to_vec(),
            )
        }
        (1, -8) => {
            if integer(&m, -1)? != 6 {
                return Err(invalid());
            }
            let x = bytes(&m, -2, Some(32))?;
            (
                json!({"kty":"OKP","crv":"Ed25519","x":URL_SAFE_NO_PAD.encode(x),"ext":true}),
                json!({"name":"Ed25519"}),
                json!({"name":"Ed25519"}),
                signature.to_vec(),
            )
        }
        _ => return Err(invalid()),
    };
    let subtle = property(&property(&js_sys::global(), "crypto")?, "subtle")?;
    let args = Array::new();
    args.push(&"jwk".into());
    args.push(&js(&jwk)?);
    args.push(&js(&import)?);
    args.push(&JsValue::FALSE);
    let usages = Array::new();
    usages.push(&"verify".into());
    args.push(&usages);
    let key = invoke(&subtle, "importKey", &args).await?;
    let args = Array::new();
    args.push(&js(&verify)?);
    args.push(&key);
    args.push(&Uint8Array::from(sig.as_slice()));
    args.push(&Uint8Array::from(signed));
    if invoke(&subtle, "verify", &args).await?.as_bool() != Some(true) {
        return Err(invalid());
    }
    Ok(())
}
fn parse_hex(s: &str) -> ApiResult<Vec<u8>> {
    if !s.len().is_multiple_of(2) || s.len() > 16384 {
        return Err(invalid());
    }
    (0..s.len())
        .step_by(2)
        .map(|n| u8::from_str_radix(&s[n..n + 2], 16).map_err(|_| invalid()))
        .collect()
}

pub async fn handle(request: &mut Request, env: &Env) -> ApiResult<Option<Response>> {
    let path = request.path();
    if request.method() != Method::Post {
        return Ok(None);
    }
    if matches!(
        path.as_str(),
        "/api/v1/auth/passkey/register/options" | "/api/v1/auth/passkey/register/verify"
    ) {
        return Err(ApiError::domain("ACCESS_PASSKEY_ENROLLMENT_DISABLED", 410));
    }
    let reauth = path.starts_with("/api/v1/auth/passkey/reauth/");
    if !matches!(
        path.as_str(),
        "/api/v1/auth/passkey/login/options"
            | "/api/v1/auth/passkey/login/verify"
            | "/api/v1/auth/passkey/reauth/options"
            | "/api/v1/auth/passkey/reauth/verify"
    ) {
        return Ok(None);
    }
    let auth = if reauth {
        let a = require_session(request, env).await?;
        require_authorized(&a)?;
        Some(a)
    } else {
        None
    };
    let db = Db(env.d1("DB")?);
    let now = now_iso();
    if path.ends_with("/options") {
        let mut challenge = [0; 32];
        getrandom::fill(&mut challenge)
            .map_err(|_| ApiError::domain("RANDOM_SOURCE_FAILED", 503))?;
        let challenge = URL_SAFE_NO_PAD.encode(challenge);
        let challenge_id = random_id()?;
        let kind = if reauth {
            "REAUTHENTICATION"
        } else {
            "AUTHENTICATION"
        };
        let expires = iso_at(Date::now().as_millis() as f64 + 300000.0);
        db.run("INSERT INTO webauthn_challenges(challenge_id,kind,challenge,user_id,created_at,expires_at) VALUES (?1,?2,?3,?4,?5,?6)",&[json!(challenge_id),json!(kind),json!(challenge),auth.as_ref().map(|a|json!(a.user_id)).unwrap_or(Value::Null),json!(now),json!(expires)]).await?;
        let mut options = json!({"challenge":challenge,"timeout":60000,"rpId":env.var("RP_ID")?.to_string(),"userVerification":"required"});
        if let Some(a) = &auth {
            let keys = db
                .all(
                    "SELECT credential_id,transports FROM passkeys WHERE user_id=?1",
                    &[json!(a.user_id)],
                )
                .await?;
            options["allowCredentials"]=json!(keys.into_iter().map(|k|json!({"id":k["credential_id"],"type":"public-key","transports":k["transports"].as_str().and_then(|s|serde_json::from_str::<Value>(s).ok()).filter(|v|v.is_array()).unwrap_or(json!([]))})).collect::<Vec<_>>());
        }
        return Ok(Some(json(
            &json!({"challenge_id":challenge_id,"options":options}),
        )?));
    }
    let data: Value = read_json(request, 131072).await?;
    let wire = &data["response"];
    if wire["id"].as_str().is_none_or(str::is_empty)
        || wire["rawId"].as_str().is_none_or(str::is_empty)
        || wire["type"] != "public-key"
        || !wire["response"].is_object()
        || wire
            .get("clientExtensionResults")
            .is_some_and(|v| !v.is_object())
        || wire
            .get("authenticatorAttachment")
            .is_some_and(|v| !v.is_null() && !v.is_string())
    {
        return Err(ApiError::domain("VALIDATION_ERROR", 422));
    }
    if !reauth {
        let d = &data["device"];
        if d["device_id"]
            .as_str()
            .is_none_or(|s| !ratchet_core::message::is_uuid(s))
            || !matches!(d["mode"].as_str(), Some("new" | "existing"))
        {
            return Err(ApiError::domain("VALIDATION_ERROR", 422));
        }
        if d["mode"] == "new"
            && (d["display_name"]
                .as_str()
                .is_none_or(|s| !(1..=80).contains(&s.trim().encode_utf16().count()))
                || d["crypto_identity_public_key"]
                    .as_str()
                    .is_none_or(|s| !(16..=8192).contains(&s.encode_utf16().count())))
        {
            return Err(ApiError::domain("VALIDATION_ERROR", 422));
        }
    }
    let cid = data["challenge_id"]
        .as_str()
        .filter(|s| ratchet_core::message::is_uuid(s))
        .ok_or_else(|| ApiError::domain("VALIDATION_ERROR", 422))?;
    let challenge=db.first::<Value>("SELECT c.challenge,c.user_id,c.expires_at,x.challenge_id AS consumed FROM webauthn_challenges c LEFT JOIN webauthn_challenge_consumptions x ON x.challenge_id=c.challenge_id WHERE c.challenge_id=?1 AND c.kind=?2",&[json!(cid),json!(if reauth{"REAUTHENTICATION"}else{"AUTHENTICATION"})]).await?.ok_or_else(||ApiError::domain("CHALLENGE_NOT_FOUND",404))?;
    if !challenge["consumed"].is_null() {
        return Err(ApiError::domain("CHALLENGE_CONSUMED", 409));
    }
    let expiry = js_sys::Date::parse(challenge["expires_at"].as_str().unwrap_or(""));
    if !expiry.is_finite() || expiry <= Date::now().as_millis() as f64 {
        return Err(ApiError::domain("CHALLENGE_EXPIRED", 410));
    }
    if auth
        .as_ref()
        .is_some_and(|a| challenge["user_id"] != a.user_id)
    {
        return Err(ApiError::domain("CHALLENGE_OWNER_MISMATCH", 403));
    }
    let response = &data["response"];
    let credential = response["id"]
        .as_str()
        .filter(|s| !s.is_empty() && s.len() <= 8192)
        .ok_or_else(|| ApiError::domain("VALIDATION_ERROR", 422))?;
    if response["type"] != "public-key"
        || response["rawId"] != credential
        || decode(&response["rawId"])?.is_empty()
    {
        return Err(invalid());
    }
    let p=db.first::<Value>("SELECT p.credential_id,p.user_id,hex(p.public_key) AS public_key_hex,p.counter,p.webauthn_user_id,u.status FROM passkeys p JOIN users u ON u.user_id=p.user_id WHERE p.credential_id=?1",&[json!(credential)]).await?.filter(|p|p["status"]=="ACTIVE" && auth.as_ref().is_none_or(|a|p["user_id"]==a.user_id)).ok_or_else(||ApiError::domain("PASSKEY_NOT_FOUND",404))?;
    let user = p["user_id"].as_str().ok_or_else(invalid)?;
    let counter = p["counter"].as_u64().ok_or_else(invalid)?;
    let r = &response["response"];
    let client = decode(&r["clientDataJSON"])?;
    let client_data: Value = serde_json::from_slice(&client).map_err(|_| invalid())?;
    if client_data["type"] != "webauthn.get"
        || client_data["challenge"] != challenge["challenge"]
        || client_data["origin"] != env.var("RP_ORIGIN")?.to_string()
        || client_data
            .get("crossOrigin")
            .is_some_and(|v| v != &Value::Bool(false))
    {
        return Err(invalid());
    }
    let ad = decode(&r["authenticatorData"])?;
    if ad.len() < 37
        || ad[32] & 5 != 5
        || ad[32] & 0x40 != 0
        || ad[32] & 0x10 != 0 && ad[32] & 8 == 0
    {
        return Err(invalid());
    }
    if ad[32] & 0x80 != 0 {
        let mut ext = Cbor {
            bytes: &ad[37..],
            at: 0,
        };
        if ext.bytes.first().is_none_or(|b| b >> 5 != 5) {
            return Err(invalid());
        }
        ext.skip(0)?;
        if ext.at != ext.bytes.len() {
            return Err(invalid());
        }
    } else if ad.len() != 37 {
        return Err(invalid());
    }
    let rp = env.var("RP_ID")?.to_string();
    if ad[..32] != Sha256::digest(rp.as_bytes())[..] {
        return Err(invalid());
    }
    let new_counter = u32::from_be_bytes(ad[33..37].try_into().map_err(|_| invalid())?) as u64;
    if (counter > 0 || new_counter > 0) && new_counter <= counter {
        return Err(invalid());
    }
    if let Some(handle) = r["userHandle"].as_str() {
        let expected = p["webauthn_user_id"]
            .as_str()
            .map(str::to_owned)
            .unwrap_or_else(|| URL_SAFE_NO_PAD.encode(user));
        if handle != expected {
            return Err(invalid());
        }
    }
    let mut signed = ad;
    signed.extend_from_slice(&Sha256::digest(&client));
    signature(
        &parse_hex(p["public_key_hex"].as_str().ok_or_else(invalid)?)?,
        &decode(&r["signature"])?,
        &signed,
    )
    .await?;
    commit(env, &db, &data, &p, cid, new_counter, auth.as_ref())
        .await
        .map(Some)
}

async fn commit(
    _env: &Env,
    db: &Db,
    data: &Value,
    p: &Value,
    cid: &str,
    counter: u64,
    auth: Option<&AuthContext>,
) -> ApiResult<Response> {
    let now = now_iso();
    let user = p["user_id"].as_str().ok_or_else(invalid)?;
    let credential = p["credential_id"].as_str().ok_or_else(invalid)?;
    let guard = random_id()?;
    let mut writes = vec![];
    let mut device = String::new();
    let mut mode = "existing";
    let mut session = String::new();
    let mut secret = String::new();
    if auth.is_none() {
        let d = &data["device"];
        device = d["device_id"]
            .as_str()
            .filter(|s| ratchet_core::message::is_uuid(s))
            .ok_or_else(|| ApiError::domain("VALIDATION_ERROR", 422))?
            .to_owned();
        match d["mode"].as_str() {
            Some("existing") => {
                let row=db.first::<Value>("SELECT authorized_at,revoked_at FROM devices WHERE device_id=?1 AND user_id=?2",&[json!(device),json!(user)]).await?.ok_or_else(||ApiError::domain("DEVICE_NOT_FOUND",404))?;
                if !row["revoked_at"].is_null() {
                    return Err(ApiError::domain("DEVICE_REVOKED", 403));
                }
                if row["authorized_at"].is_null() {
                    writes.push(db.statement("UPDATE devices SET authorized_at=?2 WHERE device_id=?1 AND authorized_at IS NULL",&[json!(device),json!(now)])?);
                }
            }
            Some("new") => {
                mode = "new";
                let name = d["display_name"]
                    .as_str()
                    .map(str::trim)
                    .filter(|s| (1..=80).contains(&s.encode_utf16().count()))
                    .ok_or_else(|| ApiError::domain("VALIDATION_ERROR", 422))?;
                let key = d["crypto_identity_public_key"]
                    .as_str()
                    .filter(|s| (16..=8192).contains(&s.encode_utf16().count()))
                    .ok_or_else(|| ApiError::domain("VALIDATION_ERROR", 422))?;
                if db
                    .first::<Value>("SELECT 1 FROM devices WHERE device_id=?1", &[json!(device)])
                    .await?
                    .is_some()
                {
                    return Err(ApiError::domain("DEVICE_ID_CONFLICT", 409));
                }
                writes.push(db.statement("INSERT INTO devices(device_id,user_id,display_name,crypto_identity_public_key,created_at,authorized_at,last_seen_at) VALUES (?1,?2,?3,?4,?5,?5,?5)",&[json!(device),json!(user),json!(name),json!(key),json!(now)])?);
            }
            _ => return Err(ApiError::domain("VALIDATION_ERROR", 422)),
        };
        session = random_id()?;
        let mut random = [0; 32];
        getrandom::fill(&mut random).map_err(|_| ApiError::domain("RANDOM_SOURCE_FAILED", 503))?;
        secret = URL_SAFE_NO_PAD.encode(random);
    }
    let auth_session = auth.map(|a| a.session_id.as_str());
    writes.insert(0,db.statement("INSERT INTO auth_commit_guards(assertion_id,valid) SELECT ?1,CASE WHEN EXISTS(SELECT 1 FROM passkeys p JOIN users u ON u.user_id=p.user_id WHERE p.credential_id=?2 AND p.user_id=?3 AND hex(p.public_key)=?4 AND p.counter=?5 AND u.status='ACTIVE') AND (?6='new' OR (?7 IS NULL AND EXISTS(SELECT 1 FROM devices WHERE device_id=?8 AND user_id=?3 AND revoked_at IS NULL)) OR EXISTS(SELECT 1 FROM sessions s JOIN devices d ON d.device_id=s.device_id WHERE s.session_id=?7 AND s.user_id=?3 AND s.revoked_at IS NULL AND s.expires_at>?9 AND d.revoked_at IS NULL AND d.authorized_at IS NOT NULL)) AND EXISTS(SELECT 1 FROM webauthn_challenges WHERE challenge_id=?10 AND expires_at>?9) THEN 1 ELSE 0 END",&[json!(guard),json!(credential),json!(user),p["public_key_hex"].clone(),p["counter"].clone(),json!(mode),json!(auth_session),json!(device),json!(now),json!(cid)])?);
    writes.push(db.statement(
        "INSERT INTO webauthn_challenge_consumptions(challenge_id,consumed_at) VALUES (?1,?2)",
        &[json!(cid), json!(now)],
    )?);
    writes.push(db.statement(
        "UPDATE passkeys SET counter=?2,last_used_at=?3 WHERE credential_id=?1",
        &[json!(credential), json!(counter), json!(now)],
    )?);
    if let Some(a) = auth {
        writes.push(db.statement("UPDATE sessions SET webauthn_verified_at=?2,authenticator_verified_at=?2 WHERE session_id=?1 AND user_id=?3 AND revoked_at IS NULL",&[json!(a.session_id),json!(now),json!(user)])?);
    } else {
        writes.push(db.statement("INSERT INTO sessions(session_id,secret_hash,user_id,device_id,created_at,last_seen_at,expires_at,webauthn_verified_at,authenticator_verified_at) VALUES (?1,?2,?3,?4,?5,?5,?6,?5,?5)",&[json!(session),json!(sha256_hex(&secret)),json!(user),json!(device),json!(now),json!(iso_at(Date::now().as_millis() as f64+2592000000.0))])?);
    }
    writes.push(db.statement(
        "DELETE FROM auth_commit_guards WHERE assertion_id=?1",
        &[json!(guard)],
    )?);
    db.0.batch(writes).await.map_err(|_| {
        ApiError::domain(
            if auth.is_some() {
                "REAUTHENTICATION_REPLAY"
            } else {
                "AUTHENTICATION_REPLAY"
            },
            409,
        )
    })?;
    if auth.is_some() {
        return json(&json!({"verified":true,"verified_at":now}));
    }
    let mut response = json(
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
