use super::*;
use ratchet_core::message::is_uuid;
use std::collections::HashSet;

fn text<'a>(v: &'a Value, key: &str, min: usize, max: usize) -> ApiResult<&'a str> {
    v[key]
        .as_str()
        .filter(|s| (min..=max).contains(&s.encode_utf16().count()))
        .ok_or_else(|| ApiError::domain("VALIDATION_ERROR", 422))
}
fn id<'a>(v: &'a Value, key: &str) -> ApiResult<&'a str> {
    text(v, key, 1, 64).and_then(|s| {
        if is_uuid(s) {
            Ok(s)
        } else {
            Err(ApiError::domain("VALIDATION_ERROR", 422))
        }
    })
}
fn key(v: &Value, signed: bool) -> ApiResult<()> {
    id(v, "prekey_id")?;
    text(v, "public_key", 16, 16384)?;
    if signed {
        text(v, "signature", 16, 4096)?;
    }
    Ok(())
}
const BUNDLE: &str = "SELECT d.device_id,d.user_id,b.identity_public_key,b.signed_prekey_id,b.signed_prekey,b.signed_prekey_signature,b.pq_last_resort_prekey_id,b.pq_last_resort_prekey,b.pq_last_resort_signature,(SELECT dc.certificate FROM device_certificates dc WHERE dc.device_id=d.device_id AND dc.revoked_at IS NULL ORDER BY dc.created_at DESC LIMIT 1) AS device_certificate FROM devices d JOIN device_prekey_bundles b ON b.device_id=d.device_id JOIN active_chat_members m ON m.chat_id=?1 AND m.user_id=d.user_id WHERE d.user_id=?2 AND d.authorized_at IS NOT NULL AND d.revoked_at IS NULL";
fn bundle(r: &Value) -> Value {
    json!({"device_id":r["device_id"],"user_id":r["user_id"],"identity_public_key":r["identity_public_key"],"signed_prekey":{"prekey_id":r["signed_prekey_id"],"public_key":r["signed_prekey"],"signature":r["signed_prekey_signature"]},"pq_last_resort_prekey":{"prekey_id":r["pq_last_resort_prekey_id"],"public_key":r["pq_last_resort_prekey"],"signature":r["pq_last_resort_signature"]},"device_certificate":r["device_certificate"],"account_authorized":true})
}
async fn member(db: &Db, chat: &str, user: &str, target: bool) -> ApiResult<()> {
    if db
        .first::<Value>(
            "SELECT 1 FROM active_chat_members WHERE chat_id=?1 AND user_id=?2",
            &[json!(chat), json!(user)],
        )
        .await?
        .is_none()
    {
        return Err(ApiError::domain(
            if target {
                "PREKEY_TARGET_FORBIDDEN"
            } else {
                "CHAT_FORBIDDEN"
            },
            403,
        ));
    }
    Ok(())
}
pub async fn handle(request: &mut Request, env: &Env) -> ApiResult<Option<Response>> {
    let path = request.path();
    let method = request.method();
    let segments: Vec<_> = path.split('/').collect();
    let discover = segments.len() == 7
        && segments[4] == "devices"
        && segments[6] == "bundle"
        && method == Method::Get;
    if !(path == "/api/v1/crypto/prekeys" && method == Method::Post
        || path == "/api/v1/crypto/prekeys/status" && method == Method::Get
        || path == "/api/v1/crypto/prekeys/consume" && method == Method::Post
        || discover)
    {
        return Ok(None);
    }
    let auth = require_session(request, env).await?;
    let db = Db(env.d1("DB")?);
    if path == "/api/v1/crypto/prekeys/status" {
        let r=db.first::<Value>("SELECT EXISTS(SELECT 1 FROM device_prekey_bundles WHERE device_id=?1) AS bundle_present,SUM(CASE WHEN prekey_type='EC' AND consumed_at IS NULL THEN 1 ELSE 0 END) AS ec_available,SUM(CASE WHEN prekey_type='PQ' AND consumed_at IS NULL THEN 1 ELSE 0 END) AS pq_available FROM one_time_prekeys WHERE device_id=?1",&[json!(auth.device_id)]).await?.unwrap_or(json!({}));
        return Ok(Some(json(
            &json!({"device_id":auth.device_id,"bundle_present":r["bundle_present"].as_i64()==Some(1),"ec_available":r["ec_available"].as_i64().unwrap_or(0),"pq_available":r["pq_available"].as_i64().unwrap_or(0)}),
        )?));
    }
    if path == "/api/v1/crypto/prekeys" {
        let data: Value = read_json(request, 4 * 1024 * 1024).await?;
        let identity = text(&data, "identity_public_key", 16, 16384)?;
        key(&data["signed_prekey"], true)?;
        key(&data["pq_last_resort_prekey"], true)?;
        let ec = data["ec_one_time_prekeys"]
            .as_array()
            .filter(|a| a.len() <= 100)
            .ok_or_else(|| ApiError::domain("VALIDATION_ERROR", 422))?;
        let pq = data["pq_one_time_prekeys"]
            .as_array()
            .filter(|a| a.len() <= 100)
            .ok_or_else(|| ApiError::domain("VALIDATION_ERROR", 422))?;
        let mut ids = HashSet::new();
        for (k, signed) in std::iter::once((&data["signed_prekey"], true))
            .chain(std::iter::once((&data["pq_last_resort_prekey"], true)))
            .chain(ec.iter().map(|k| (k, false)))
            .chain(pq.iter().map(|k| (k, true)))
        {
            key(k, signed)?;
            if !ids.insert(id(k, "prekey_id")?) {
                return Err(ApiError::domain("PREKEY_CONFLICT", 409));
            }
        }
        let device=db.first::<Value>("SELECT crypto_identity_public_key FROM devices WHERE device_id=?1 AND user_id=?2 AND revoked_at IS NULL",&[json!(auth.device_id),json!(auth.user_id)]).await?.ok_or_else(||ApiError::domain("DEVICE_REVOKED",403))?;
        if device["crypto_identity_public_key"] != identity {
            return Err(ApiError::domain("CRYPTO_IDENTITY_MISMATCH", 409));
        }
        let now = now_iso();
        let guard = random_id()?;
        let sp = &data["signed_prekey"];
        let lp = &data["pq_last_resort_prekey"];
        let mut writes=vec![db.statement("INSERT INTO auth_commit_guards(assertion_id,valid) SELECT ?1,CASE WHEN EXISTS(SELECT 1 FROM devices d JOIN sessions s ON s.device_id=d.device_id JOIN users u ON u.user_id=d.user_id WHERE d.device_id=?2 AND d.user_id=?3 AND d.revoked_at IS NULL AND d.crypto_identity_public_key=?4 AND s.session_id=?5 AND s.revoked_at IS NULL AND s.expires_at>?6 AND u.status='ACTIVE') THEN 1 ELSE 0 END",&[json!(guard),json!(auth.device_id),json!(auth.user_id),json!(identity),json!(auth.session_id),json!(now)])?,db.statement("INSERT INTO device_prekey_bundles(device_id,identity_public_key,signed_prekey_id,signed_prekey,signed_prekey_signature,pq_last_resort_prekey_id,pq_last_resort_prekey,pq_last_resort_signature,updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9) ON CONFLICT(device_id) DO UPDATE SET identity_public_key=excluded.identity_public_key,signed_prekey_id=excluded.signed_prekey_id,signed_prekey=excluded.signed_prekey,signed_prekey_signature=excluded.signed_prekey_signature,pq_last_resort_prekey_id=excluded.pq_last_resort_prekey_id,pq_last_resort_prekey=excluded.pq_last_resort_prekey,pq_last_resort_signature=excluded.pq_last_resort_signature,updated_at=excluded.updated_at",&[json!(auth.device_id),json!(identity),sp["prekey_id"].clone(),sp["public_key"].clone(),sp["signature"].clone(),lp["prekey_id"].clone(),lp["public_key"].clone(),lp["signature"].clone(),json!(now)])?];
        for (keys, kind) in [(ec, "EC"), (pq, "PQ")] {
            for k in keys {
                writes.push(db.statement("INSERT INTO one_time_prekeys(prekey_id,device_id,prekey_type,public_key,signature,created_at,consumed_at) VALUES (?1,?2,?3,?4,?5,?6,NULL) ON CONFLICT(prekey_id) DO UPDATE SET public_key=CASE WHEN one_time_prekeys.device_id=excluded.device_id AND one_time_prekeys.prekey_type=excluded.prekey_type AND one_time_prekeys.public_key=excluded.public_key AND IFNULL(one_time_prekeys.signature,'')=IFNULL(excluded.signature,'') THEN one_time_prekeys.public_key ELSE NULL END",&[k["prekey_id"].clone(),json!(auth.device_id),json!(kind),k["public_key"].clone(),if kind=="PQ"{k["signature"].clone()}else{Value::Null},json!(now)])?);
            }
        }
        writes.push(db.statement(
            "DELETE FROM auth_commit_guards WHERE assertion_id=?1",
            &[json!(guard)],
        )?);
        db.0.batch(writes)
            .await
            .map_err(|_| ApiError::domain("PREKEY_CONFLICT", 409))?;
        return Ok(Some(Response::empty()?.with_status(204)));
    }
    require_authorized(&auth)?;
    let data = if discover {
        let chat = request
            .url()?
            .query_pairs()
            .find(|(k, _)| k == "chat_id")
            .map(|(_, v)| v.into_owned())
            .unwrap_or_default();
        json!({"chat_id":chat,"recipient_user_id":segments[5]})
    } else {
        read_json::<Value>(request, 16384).await?
    };
    let chat = id(&data, "chat_id")?;
    let user = id(&data, "recipient_user_id")?;
    member(&db, chat, &auth.user_id, false).await?;
    member(&db, chat, user, true).await?;
    if discover {
        let rows = db
            .all(
                &format!("{BUNDLE} ORDER BY d.device_id"),
                &[json!(chat), json!(user)],
            )
            .await?;
        return Ok(Some(json(
            &json!({"user_id":user,"devices":rows.iter().map(bundle).collect::<Vec<_>>()}),
        )?));
    }
    let device = id(&data, "recipient_device_id")?;
    if db
        .first::<Value>(
            &format!("{BUNDLE} AND d.device_id=?3"),
            &[json!(chat), json!(user), json!(device)],
        )
        .await?
        .is_none()
    {
        return Err(ApiError::domain("PREKEY_TARGET_FORBIDDEN", 403));
    }
    let mut stmts=vec![db.statement(&format!("{BUNDLE} AND d.device_id=?3 AND EXISTS(SELECT 1 FROM active_chat_members WHERE chat_id=?1 AND user_id=?4)"),&[json!(chat),json!(user),json!(device),json!(auth.user_id)])?];
    for kind in ["EC", "PQ"] {
        stmts.push(db.statement("UPDATE one_time_prekeys SET consumed_at=?6 WHERE prekey_id=(SELECT otp.prekey_id FROM one_time_prekeys otp JOIN devices d ON d.device_id=otp.device_id JOIN device_prekey_bundles b ON b.device_id=d.device_id JOIN active_chat_members targetm ON targetm.chat_id=?3 AND targetm.user_id=d.user_id JOIN active_chat_members requestm ON requestm.chat_id=targetm.chat_id AND requestm.user_id=?5 JOIN sessions s ON s.user_id=requestm.user_id AND s.session_id=?7 JOIN devices sender ON sender.device_id=s.device_id WHERE otp.device_id=?1 AND d.user_id=?2 AND otp.prekey_type=?4 AND otp.consumed_at IS NULL AND d.authorized_at IS NOT NULL AND d.revoked_at IS NULL AND s.revoked_at IS NULL AND s.expires_at>?6 AND sender.revoked_at IS NULL AND sender.authorized_at IS NOT NULL ORDER BY otp.created_at,otp.prekey_id LIMIT 1) AND consumed_at IS NULL RETURNING prekey_id,public_key,signature",&[json!(device),json!(user),json!(chat),json!(kind),json!(auth.user_id),json!(now_iso()),json!(auth.session_id)])?);
    }
    let results = db.0.batch(stmts).await?;
    let rows = results[0].results::<Value>()?;
    let row = rows
        .first()
        .ok_or_else(|| ApiError::domain("PREKEY_BUNDLE_NOT_FOUND", 404))?;
    Ok(Some(json(
        &json!({"bundle":bundle(row),"ec_one_time_prekey":results[1].results::<Value>()?.first().cloned(),"pq_one_time_prekey":results[2].results::<Value>()?.first().cloned()}),
    )?))
}
