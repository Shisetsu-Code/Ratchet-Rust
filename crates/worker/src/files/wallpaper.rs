use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

struct Access {
    workspace: String,
    owner: String,
    view: bool,
    manage: bool,
}
async fn access(db: &Db, auth: &AuthContext, chat: &str) -> ApiResult<Access> {
    let row=db.first::<Value>("SELECT c.workspace_id,c.owner_admin_user_id,member.participant_role,creator.staff_role AS creator_role,creator.created_by_user_id AS creator_parent,viewer.staff_role AS viewer_role,viewer.created_by_user_id AS viewer_parent,viewer.revoked_at AS viewer_revoked FROM chats c JOIN active_chat_members member ON member.chat_id=c.chat_id AND member.user_id=?2 LEFT JOIN workspace_staff creator ON creator.workspace_id=c.workspace_id AND creator.user_id=c.owner_admin_user_id LEFT JOIN workspace_staff viewer ON viewer.workspace_id=c.workspace_id AND viewer.user_id=?2 WHERE c.chat_id=?1",&[json!(chat),json!(auth.user_id)]).await?.ok_or_else(||ApiError::domain("CHAT_NOT_FOUND",404))?;
    let owner = if row["creator_role"] == "OPERATOR" && row["creator_parent"].is_string() {
        text(&row, "creator_parent")?
    } else {
        text(&row, "owner_admin_user_id")?
    }
    .to_string();
    let staff = if row["viewer_revoked"].is_null() {
        row["viewer_role"].as_str().unwrap_or("")
    } else {
        ""
    };
    let manage = owner == auth.user_id && matches!(staff, "ADMIN" | "OWNER");
    let view = row["participant_role"] == "CUSTOMER"
        || manage
        || (staff == "OPERATOR" && row["viewer_parent"] == owner);
    Ok(Access {
        workspace: text(&row, "workspace_id")?.into(),
        owner,
        view,
        manage,
    })
}
fn manager(access: &Access) -> ApiResult<()> {
    if !access.manage {
        return Err(ApiError::domain("WALLPAPER_OWNER_REQUIRED", 403));
    }
    Ok(())
}
async fn current(db: &Db, a: &Access) -> ApiResult<Option<Value>> {
    db.first(
        "SELECT * FROM account_wallpapers WHERE workspace_id=?1 AND owner_admin_user_id=?2",
        &[json!(a.workspace), json!(a.owner)],
    )
    .await
}
fn envelopes(row: &Value) -> ApiResult<Vec<Value>> {
    let raw = row["key_envelopes_json"]
        .as_str()
        .ok_or_else(|| ApiError::retryable("WALLPAPER_METADATA_CORRUPT", 503))?;
    let values: Vec<Value> = serde_json::from_str(raw)
        .map_err(|_| ApiError::retryable("WALLPAPER_METADATA_CORRUPT", 503))?;
    for v in &values {
        validate_envelope(v).map_err(|_| ApiError::retryable("WALLPAPER_METADATA_CORRUPT", 503))?;
    }
    Ok(values)
}
fn preset(value: &str) -> bool {
    matches!(value, "default" | "sand" | "sage" | "sky")
}
fn preset_response(preset: &str, manage: bool, updated: Value) -> Value {
    json!({"kind":"preset","preset":preset,"can_manage":manage,"can_distribute":manage,"updated_at":updated})
}
async fn response(db: &Db, auth: &AuthContext, chat: &str, a: &Access) -> ApiResult<Response> {
    if !a.view {
        return json(&preset_response("default", false, Value::Null));
    }
    let Some(row) = current(db, a).await? else {
        return json(&preset_response("default", a.manage, Value::Null));
    };
    if row["kind"] == "CUSTOM"
        && [
            "wallpaper_id",
            "object_key",
            "content_type",
            "image_nonce_b64url",
            "ciphertext_sha256_b64url",
            "signer_device_id",
            "signature_b64url",
            "key_envelopes_json",
        ]
        .iter()
        .all(|k| row[*k].is_string())
    {
        let envs = envelopes(&row)?;
        let envelope = envs
            .into_iter()
            .find(|v| v["recipient_device_id"] == auth.device_id);
        return json(
            &json!({"kind":"custom","can_manage":a.manage,"can_distribute":a.manage,"updated_at":row["updated_at"],"manifest":{"protocol":"ratchet-wallpaper-e2ee","version":1,"wallpaper_id":row["wallpaper_id"],"workspace_id":a.workspace,"owner_admin_user_id":a.owner,"signer_device_id":row["signer_device_id"],"content_type":row["content_type"],"image_nonce_b64url":row["image_nonce_b64url"],"ciphertext_sha256_b64url":row["ciphertext_sha256_b64url"]},"signature_b64url":row["signature_b64url"],"image_path":format!("/api/v1/chats/{chat}/wallpaper/image"),"key_envelope":envelope}),
        );
    }
    let p = row["preset"]
        .as_str()
        .filter(|p| preset(p))
        .unwrap_or("default");
    json(&preset_response(p, a.manage, row["updated_at"].clone()))
}
async fn recipients(db: &Db, a: &Access) -> ApiResult<Vec<Value>> {
    let mut values=db.all("WITH owner_chats AS (SELECT chat_id FROM chats WHERE workspace_id=?1 AND owner_admin_user_id=?2),scope_users AS (SELECT ?2 AS user_id UNION SELECT user_id FROM workspace_staff WHERE workspace_id=?1 AND staff_role='OPERATOR' AND created_by_user_id=?2 AND revoked_at IS NULL UNION SELECT member.user_id FROM owner_chats oc JOIN active_chat_members member ON member.chat_id=oc.chat_id AND member.participant_role='CUSTOMER') SELECT d.user_id,d.device_id,b.identity_public_key,(SELECT dc.certificate FROM device_certificates dc WHERE dc.device_id=d.device_id AND dc.revoked_at IS NULL ORDER BY dc.created_at DESC LIMIT 1) AS device_certificate FROM scope_users scope JOIN users u ON u.user_id=scope.user_id AND u.status='ACTIVE' JOIN devices d ON d.user_id=scope.user_id JOIN device_prekey_bundles b ON b.device_id=d.device_id WHERE d.authorized_at IS NOT NULL AND d.revoked_at IS NULL ORDER BY d.user_id,d.device_id",&[json!(a.workspace),json!(a.owner)]).await?;
    for v in &mut values {
        v["account_authorized"] = json!(true);
    }
    Ok(values)
}
fn encoded(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
fn validate_envelope(e: &Value) -> ApiResult<()> {
    uuid(text(e, "recipient_user_id")?)?;
    uuid(text(e, "recipient_device_id")?)?;
    for (k, n) in [
        ("ephemeral_public_key_b64url", 43),
        ("nonce_b64url", 32),
        ("wrapped_key_b64url", 64),
    ] {
        if !encoded(text(e, k)?, n) {
            return Err(validation());
        }
    }
    Ok(())
}
fn validate_envelopes(value: &Value) -> ApiResult<Vec<Value>> {
    let values = value
        .as_array()
        .filter(|a| !a.is_empty() && a.len() <= 10000)
        .ok_or_else(validation)?;
    for e in values {
        validate_envelope(e)?;
    }
    Ok(values.clone())
}
fn canonical(mut values: Vec<Value>) -> ApiResult<String> {
    values.sort_by(|a, b| {
        a["recipient_device_id"]
            .as_str()
            .cmp(&b["recipient_device_id"].as_str())
    });
    serde_json::to_string(&values).map_err(|_| validation())
}
fn key(a: &Access, id: &str) -> String {
    format!("wallpapers/v2/{}/{}/{id}", a.workspace, a.owner)
}
pub async fn handle(
    request: &mut Request,
    env: &Env,
    db: &Db,
    auth: &AuthContext,
    route: &[&str],
) -> ApiResult<Option<Response>> {
    let chat = *route.get(1).ok_or_else(validation)?;
    let a = access(db, auth, chat).await?;
    match (&request.method(), route) {
        (Method::Get, [_, _, _]) => Ok(Some(response(db, auth, chat, &a).await?)),
        (Method::Get, [_, _, _, "recipients"]) => {
            if !a.manage {
                return Err(ApiError::domain("WALLPAPER_DISTRIBUTOR_REQUIRED", 403));
            }
            let row = current(db, &a).await?;
            let envs = if let Some(row) = &row {
                if row["kind"] == "CUSTOM" {
                    envelopes(row)?
                } else {
                    vec![]
                }
            } else {
                vec![]
            };
            let mut ids: Vec<_> = envs
                .iter()
                .map(|e| e["recipient_device_id"].clone())
                .collect();
            ids.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
            Ok(Some(json(
                &json!({"workspace_id":a.workspace,"owner_admin_user_id":a.owner,"can_distribute":true,"current_wallpaper_id":row.as_ref().filter(|r|r["kind"]=="CUSTOM").map(|r|r["wallpaper_id"].clone()),"enveloped_device_ids":ids,"devices":recipients(db,&a).await?}),
            )?))
        }
        (Method::Get, [_, _, _, "image"]) => {
            if !a.view {
                return Err(ApiError::domain("WALLPAPER_NOT_FOUND", 404));
            }
            let row = current(db, &a)
                .await?
                .filter(|r| r["kind"] == "CUSTOM" && r["object_key"].is_string())
                .ok_or_else(|| ApiError::domain("WALLPAPER_NOT_FOUND", 404))?;
            if !envelopes(&row)?
                .iter()
                .any(|e| e["recipient_device_id"] == auth.device_id)
            {
                return Err(ApiError::retryable("WALLPAPER_KEY_UNAVAILABLE", 409));
            }
            let bucket = env.bucket("ATTACHMENTS")?;
            let object = bucket
                .get(text(&row, "object_key")?)
                .execute()
                .await?
                .ok_or_else(|| ApiError::retryable("WALLPAPER_OBJECT_MISSING", 503))?;
            let mut response = Response::from_body(
                object
                    .body()
                    .ok_or_else(|| ApiError::retryable("WALLPAPER_OBJECT_MISSING", 503))?
                    .response_body()?,
            )?;
            response
                .headers_mut()
                .set("Content-Type", "application/octet-stream")?;
            response
                .headers_mut()
                .set("Cache-Control", "private, no-store")?;
            response
                .headers_mut()
                .set("Content-Length", &object.size().to_string())?;
            Ok(Some(response))
        }
        (Method::Put, [_, _, _]) => {
            let input: Value = read_json(request, 1024).await?;
            let p = text(&input, "preset")?;
            if !preset(p) {
                return Err(validation());
            }
            manager(&a)?;
            let mut values = authority_values(auth, chat);
            values.extend([
                json!(a.workspace),
                json!(a.owner),
                json!(p),
                json!(now_iso()),
            ]);
            let sql = format!(
                "INSERT INTO account_wallpapers(workspace_id,owner_admin_user_id,wallpaper_id,kind,preset,object_key,content_type,image_nonce_b64url,ciphertext_sha256_b64url,signer_device_id,signature_b64url,key_envelopes_json,updated_by_user_id,updated_at) SELECT ?5,?6,NULL,'PRESET',?7,NULL,NULL,NULL,NULL,NULL,NULL,NULL,?2,?8 WHERE ?2=?6 AND {AUTHORITY} ON CONFLICT(workspace_id,owner_admin_user_id) DO UPDATE SET wallpaper_id=NULL,kind='PRESET',preset=excluded.preset,object_key=NULL,content_type=NULL,encryption_key_b64url=NULL,nonce_b64url=NULL,image_nonce_b64url=NULL,ciphertext_sha256_b64url=NULL,signer_device_id=NULL,signature_b64url=NULL,key_envelopes_json=NULL,updated_by_user_id=excluded.updated_by_user_id,updated_at=excluded.updated_at"
            );
            if !changed(db, &sql, &values).await? {
                return Err(ApiError::domain("WALLPAPER_OWNER_REQUIRED", 403));
            }
            Ok(Some(response(db, auth, chat, &a).await?))
        }
        (Method::Put, [_, _, _, "uploads", id, "image"]) => {
            uuid(id)?;
            manager(&a)?;
            let bytes = body(request, 3 * 1024 * 1024 + 16)
                .await
                .map_err(|_| ApiError::domain("WALLPAPER_TOO_LARGE", 422))?;
            if bytes.len() <= 16 {
                return Err(ApiError::domain("WALLPAPER_TOO_LARGE", 422));
            }
            let size = bytes.len();
            let token = crate::http::random_id()?;
            let hash = URL_SAFE_NO_PAD.encode(Sha256::digest(&bytes));
            let key = key(&a, id);
            let mut values = authority_values(auth, chat);
            values.extend([
                json!(key),
                json!(a.workspace),
                json!(a.owner),
                json!(id),
                json!(hash),
                json!(iso_at(
                    worker::Date::now().as_millis() as f64 + 86_400_000.0
                )),
                json!(size),
                json!(token),
            ]);
            if !changed(db,&format!("INSERT INTO wallpaper_uploads(object_key,workspace_id,owner_admin_user_id,wallpaper_id,device_id,ciphertext_hash,state,expires_at,size,write_token) SELECT ?5,?6,?7,?8,?4,?9,'UPLOADING',?10,?11,?12 WHERE {AUTHORITY} ON CONFLICT DO NOTHING"),&values).await.map_err(|e| storage_error_api(e, "WALLPAPER_UPLOAD_CONFLICT"))?{return Err(ApiError::domain("WALLPAPER_UPLOAD_CONFLICT",409));}
            let bucket = env.bucket("ATTACHMENTS")?;
            // Persist the multipart handle before uploading any bytes. Cleanup
            // can abort that handle, fencing every later part/complete operation.
            let stored:ApiResult<()> = async {
                let upload=bucket.create_multipart_upload(&key).execute().await?;
                let upload_id=upload.upload_id().await;
                let mut start=authority_values(auth,chat);
                start.extend([json!(key),json!(token),json!(upload_id)]);
                if !changed(db,&format!("UPDATE wallpaper_uploads SET upload_id=?7 WHERE object_key=?5 AND state='UPLOADING' AND write_token=?6 AND {AUTHORITY}"),&start).await? {
                    let _=upload.abort().await;
                    return Err(ApiError::domain("WALLPAPER_UPLOAD_CONFLICT",409));
                }
                let part=upload.upload_part(1,bytes).await?;
                upload.complete(vec![part]).await?;
                Ok(())
            }.await;
            let mut finish = authority_values(auth, chat);
            finish.extend([json!(key), json!(token)]);
            let success=match stored{Ok(())=>changed(db,&format!("UPDATE wallpaper_uploads SET state='READY',write_token=NULL WHERE object_key=?5 AND state='UPLOADING' AND write_token=?6 AND {AUTHORITY}"),&finish).await?,_=>false};
            if !success {
                db.run("UPDATE wallpaper_uploads SET state='ABORTED',write_token=NULL,cleanup_after='' WHERE object_key=?1 AND write_token=?2",&[json!(key),json!(token)]).await?;
                return Err(ApiError::domain("WALLPAPER_UPLOAD_CONFLICT", 409));
            }
            Ok(Some(Response::empty()?.with_status(204)))
        }
        (Method::Post, [_, _, _, "uploads", id, "commit"]) => {
            uuid(id)?;
            let input: Value = read_json(request, 4 * 1024 * 1024).await?;
            manager(&a)?;
            let m = &input["manifest"];
            if m["protocol"] != "ratchet-wallpaper-e2ee"
                || m["version"] != 1
                || m["wallpaper_id"] != *id
                || m["workspace_id"] != a.workspace
                || m["owner_admin_user_id"] != a.owner
                || m["signer_device_id"] != auth.device_id
                || !matches!(
                    text(m, "content_type")?,
                    "image/jpeg" | "image/png" | "image/webp" | "image/gif"
                )
                || !encoded(text(m, "image_nonce_b64url")?, 32)
                || !encoded(text(m, "ciphertext_sha256_b64url")?, 43)
                || !encoded(text(&input, "signature_b64url")?, 86)
            {
                return Err(ApiError::domain("WALLPAPER_MANIFEST_INVALID", 422));
            }
            let envs = validate_envelopes(&input["envelopes"])?;
            let expected = recipients(db, &a).await?;
            let mut seen = std::collections::HashSet::new();
            for e in &envs {
                if !seen.insert(text(e, "recipient_device_id")?) {
                    return Err(ApiError::domain("WALLPAPER_RECIPIENT_SET_INVALID", 409));
                }
                if !expected.iter().any(|d| {
                    d["device_id"] == e["recipient_device_id"]
                        && d["user_id"] == e["recipient_user_id"]
                }) {
                    return Err(ApiError::retryable("WALLPAPER_RECIPIENT_SET_STALE", 409));
                }
            }
            if seen.len() != expected.len() {
                return Err(ApiError::retryable("WALLPAPER_RECIPIENT_SET_STALE", 409));
            }
            let key = key(&a, id);
            let object = env
                .bucket("ATTACHMENTS")?
                .head(&key)
                .await?
                .ok_or_else(|| ApiError::domain("WALLPAPER_UPLOAD_MISSING", 409))?;
            if object.size() <= 16 {
                return Err(ApiError::domain("WALLPAPER_UPLOAD_INVALID", 422));
            }
            let mut values = authority_values(auth, chat);
            values.extend([
                json!(a.workspace),
                json!(a.owner),
                json!(id),
                json!(key),
                m["content_type"].clone(),
                m["image_nonce_b64url"].clone(),
                m["ciphertext_sha256_b64url"].clone(),
                input["signature_b64url"].clone(),
                json!(canonical(envs)?),
                json!(now_iso()),
            ]);
            let sql = format!(
                "INSERT INTO account_wallpapers(workspace_id,owner_admin_user_id,wallpaper_id,kind,preset,object_key,content_type,encryption_key_b64url,nonce_b64url,image_nonce_b64url,ciphertext_sha256_b64url,signer_device_id,signature_b64url,key_envelopes_json,updated_by_user_id,updated_at) SELECT ?5,?6,?7,'CUSTOM',NULL,?8,?9,'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','AAAAAAAAAAAAAAAA',?10,?11,?4,?12,?13,?2,?14 WHERE ?2=?6 AND {AUTHORITY} ON CONFLICT(workspace_id,owner_admin_user_id) DO UPDATE SET wallpaper_id=excluded.wallpaper_id,kind='CUSTOM',preset=NULL,object_key=excluded.object_key,content_type=excluded.content_type,encryption_key_b64url=excluded.encryption_key_b64url,nonce_b64url=excluded.nonce_b64url,image_nonce_b64url=excluded.image_nonce_b64url,ciphertext_sha256_b64url=excluded.ciphertext_sha256_b64url,signer_device_id=excluded.signer_device_id,signature_b64url=excluded.signature_b64url,key_envelopes_json=excluded.key_envelopes_json,updated_by_user_id=excluded.updated_by_user_id,updated_at=excluded.updated_at"
            );
            if !changed(db, &sql, &values).await? {
                return Err(ApiError::domain("WALLPAPER_OWNER_REQUIRED", 403));
            }
            Ok(Some(response(db, auth, chat, &a).await?))
        }
        (Method::Post, [_, _, _, id, "envelopes"]) => {
            uuid(id)?;
            let input: Value = read_json(request, 4 * 1024 * 1024).await?;
            if input["wallpaper_id"] != *id {
                return Err(validation());
            }
            if !a.manage {
                return Err(ApiError::domain("WALLPAPER_DISTRIBUTOR_REQUIRED", 403));
            }
            let incoming = validate_envelopes(&input["envelopes"])?;
            let row = current(db, &a)
                .await?
                .filter(|r| r["kind"] == "CUSTOM" && r["wallpaper_id"] == *id)
                .ok_or_else(|| ApiError::retryable("WALLPAPER_VERSION_STALE", 409))?;
            let expected = recipients(db, &a).await?;
            let mut merged = envelopes(&row)?;
            for e in incoming {
                if !expected.iter().any(|d| {
                    d["device_id"] == e["recipient_device_id"]
                        && d["user_id"] == e["recipient_user_id"]
                }) {
                    return Err(ApiError::domain("WALLPAPER_RECIPIENT_FORBIDDEN", 403));
                }
                if !merged
                    .iter()
                    .any(|m| m["recipient_device_id"] == e["recipient_device_id"])
                {
                    merged.push(e);
                }
            }
            let mut values = authority_values(auth, chat);
            values.extend([
                json!(a.workspace),
                json!(a.owner),
                json!(id),
                json!(canonical(merged)?),
                row["key_envelopes_json"].clone(),
            ]);
            if !changed(db,&format!("UPDATE account_wallpapers SET key_envelopes_json=?8 WHERE workspace_id=?5 AND owner_admin_user_id=?6 AND wallpaper_id=?7 AND kind='CUSTOM' AND key_envelopes_json=?9 AND ?2=?6 AND {AUTHORITY}"),&values).await?{return Err(ApiError::retryable("WALLPAPER_VERSION_STALE",409));}
            Ok(Some(Response::empty()?.with_status(204)))
        }
        _ => Ok(None),
    }
}
