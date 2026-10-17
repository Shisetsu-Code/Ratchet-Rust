use super::*;
use worker::{Bucket, Conditional, HttpMetadata, Range, UploadedPart};
const CHUNK: u64 = 5 * 1024 * 1024;
const FULL: u64 = CHUNK + 16;
const MAX: u64 = 2 * FULL;
async fn row(db: &Db, id: &str) -> ApiResult<Value> {
    db.first("SELECT u.*,a.encrypted_metadata FROM attachment_uploads u JOIN attachments a ON a.file_id=u.file_id WHERE u.file_id=?1",&[json!(id)]).await?.ok_or_else(||ApiError::domain("ATTACHMENT_NOT_FOUND",404))
}
async fn owned(db: &Db, auth: &AuthContext, id: &str, allowed: &[&str]) -> ApiResult<Value> {
    let row = row(db, id).await?;
    if row["owner_user_id"] != auth.user_id {
        return Err(ApiError::domain("ATTACHMENT_FORBIDDEN", 403));
    }
    active_chat(db, auth, text(&row, "chat_id")?).await?;
    if !allowed.contains(&text(&row, "status")?) {
        return Err(ApiError::domain("ATTACHMENT_STATE_INVALID", 409));
    }
    Ok(row)
}
async fn parts(db: &Db, id: &str) -> ApiResult<Vec<Value>> {
    db.all(
        "SELECT part_number,etag,size FROM attachment_parts WHERE file_id=?1 ORDER BY part_number",
        &[json!(id)],
    )
    .await
}
async fn status(db: &Db, auth: &AuthContext, id: &str) -> ApiResult<Response> {
    let row = row(db, id).await?;
    active_chat(db, auth, text(&row, "chat_id")?).await?;
    if row["owner_user_id"] != auth.user_id && row["status"] != "COMMITTED" {
        return Err(ApiError::domain("ATTACHMENT_NOT_COMMITTED", 403));
    }
    json(
        &json!({"file_id":id,"chat_id":row["chat_id"],"status":row["status"],"encrypted_size":row["size"],"encrypted_metadata":row["encrypted_metadata"],"expires_at":row["expires_at"],"parts":parts(db,id).await?}),
    )
}
fn not_expired(row: &Value) -> ApiResult<()> {
    if worker::js_sys::Date::parse(text(row, "expires_at")?)
        <= worker::Date::now().as_millis() as f64
    {
        return Err(ApiError::domain("ATTACHMENT_EXPIRED", 409));
    }
    Ok(())
}
fn upload_response(row: &Value) -> Value {
    json!({"file_id":row["file_id"],"upload_id":row["upload_id"],"status":"UPLOADING","expires_at":row["expires_at"],"chunk_plaintext_bytes":CHUNK})
}
async fn discard(db: &Db, bucket: &Bucket, row: &Value) -> ApiResult<()> {
    if changed(db,"UPDATE attachment_uploads SET status='ABORTED' WHERE file_id=?1 AND status IN ('RESERVED','UPLOADING')",&[row["file_id"].clone()]).await?{if let Some(upload)=row["upload_id"].as_str(){let _=bucket.resume_multipart_upload(text(row,"object_key")?,upload)?.abort().await;}let _=bucket.delete(text(row,"object_key")?).await;}
    Ok(())
}
async fn ready(db: &Db, bucket: &Bucket, auth: &AuthContext, row: &Value) -> ApiResult<()> {
    let mut values = authority_values(auth, text(row, "chat_id")?);
    values.push(row["file_id"].clone());
    let result=changed(db,&format!("UPDATE attachment_uploads SET status='READY',quota_size=NULL WHERE file_id=?5 AND owner_user_id=?2 AND status IN ('UPLOADING','READY') AND {AUTHORITY}"),&values).await;
    match result {
        Ok(true) => Ok(()),
        result => {
            let _ = discard(db, bucket, row).await;
            match result {
                Err(error) => Err(error),
                _ => Err(ApiError::domain("ATTACHMENT_STATE_INVALID", 409)),
            }
        }
    }
}

// One durable writer per object. Cleanup never releases capacity while this marker
// exists, including when a request is cancelled between R2 and D1 completion.
async fn begin_write(db: &Db, auth: &AuthContext, row: &Value, kind: &str) -> ApiResult<String> {
    let token = format!("{kind}:{}", crate::http::random_id()?);
    let mut values = authority_values(auth, text(row, "chat_id")?);
    values.extend([row["file_id"].clone(), json!(token), json!(now_iso())]);
    if !changed(db, &format!("UPDATE attachment_uploads SET write_token=?6 WHERE file_id=?5 AND status='UPLOADING' AND write_token IS NULL AND cleaned_at IS NULL AND expires_at>?7 AND {AUTHORITY}"), &values).await? {
        return Err(ApiError::retryable("ATTACHMENT_WRITE_IN_PROGRESS", 409));
    }
    Ok(token)
}
async fn finish_write(db: &Db, id: &str, token: &str) -> ApiResult<()> {
    db.run(
        "UPDATE attachment_uploads SET write_token=NULL WHERE file_id=?1 AND write_token=?2",
        &[json!(id), json!(token)],
    )
    .await?;
    Ok(())
}

pub async fn handle(
    request: &mut Request,
    env: &Env,
    db: &Db,
    auth: &AuthContext,
    route: &[&str],
) -> ApiResult<Option<Response>> {
    if let ["chats", chat, "attachments"] = route {
        if request.method() != Method::Post {
            return Ok(None);
        }
        let input: Value = read_json(request, 128 * 1024).await?;
        let id = text(&input, "file_id")?;
        uuid(id)?;
        let size = input["encrypted_size"]
            .as_u64()
            .filter(|n| (16..=MAX).contains(n))
            .ok_or_else(validation)?;
        let metadata = text(&input, "encrypted_metadata")?;
        if metadata.is_empty() || metadata.encode_utf16().count() > 16384 {
            return Err(validation());
        }
        active_chat(db, auth, chat).await?;
        if let Some(existing)=db.first::<Value>("SELECT u.*,a.encrypted_metadata FROM attachment_uploads u JOIN attachments a ON a.file_id=u.file_id WHERE u.file_id=?1",&[json!(id)]).await?{if existing["owner_user_id"]!=auth.user_id||existing["chat_id"]!=*chat||existing["size"]!=size||existing["encrypted_metadata"]!=metadata||existing["status"]!="UPLOADING"||!existing["upload_id"].is_string(){return Err(ApiError::domain("ATTACHMENT_RESERVATION_CONFLICT",409));}return Ok(Some(json(&upload_response(&existing))?.with_status(201)));}
        let now = now_iso();
        let expires = iso_at(worker::Date::now().as_millis() as f64 + 86_400_000.0);
        let key = format!("attachments/{chat}/{id}");
        let mut values = authority_values(auth, chat);
        values.extend([
            json!(id),
            json!(key),
            json!(size),
            json!(now),
            json!(expires),
        ]);
        let reservation=db.0.batch(vec![db.statement(&format!("INSERT INTO attachment_uploads(file_id,upload_id,object_key,owner_user_id,chat_id,status,size,created_at,expires_at) SELECT ?5,NULL,?6,?2,?1,'RESERVED',?7,?8,?9 WHERE {AUTHORITY}"),&values)?,db.statement("INSERT INTO attachments(file_id,message_id,encrypted_metadata,created_at) SELECT ?1,NULL,?2,?3 WHERE EXISTS(SELECT 1 FROM attachment_uploads WHERE file_id=?1)",&[json!(id),json!(metadata),json!(now)])?]).await.map_err(|e|storage_error(e,"ATTACHMENT_RESERVATION_CONFLICT"))?;
        // D1 includes writes made by the accounting triggers in this count.
        // A successful admission can therefore report more than one change.
        if !reservation[0]
            .meta()?
            .is_some_and(|m| m.changes.unwrap_or(0) > 0)
        {
            return Err(ApiError::domain("ATTACHMENT_RESERVATION_CONFLICT", 409));
        }
        let bucket = env.bucket("ATTACHMENTS")?;
        let multipart = match bucket
            .create_multipart_upload(&key)
            .http_metadata(HttpMetadata {
                content_type: Some("application/octet-stream".into()),
                cache_control: Some("private, no-store".into()),
                ..Default::default()
            })
            .execute()
            .await
        {
            Ok(m) => m,
            Err(_) => {
                db.run("UPDATE attachment_uploads SET status='ABORTED' WHERE file_id=?1 AND status='RESERVED'",&[json!(id)]).await?;
                return Err(ApiError::retryable("ATTACHMENT_STORAGE_UNAVAILABLE", 503));
            }
        };
        let upload_id = multipart.upload_id().await;
        let mut values = authority_values(auth, chat);
        values.extend([json!(id), json!(upload_id)]);
        if !changed(db,&format!("UPDATE attachment_uploads SET upload_id=?6,status='UPLOADING' WHERE file_id=?5 AND owner_user_id=?2 AND status='RESERVED' AND {AUTHORITY}"),&values).await?{let _=multipart.abort().await;db.run("UPDATE attachment_uploads SET status='ABORTED' WHERE file_id=?1 AND status='RESERVED'",&[json!(id)]).await?;return Err(ApiError::domain("ATTACHMENT_RESERVATION_CONFLICT",409));}
        return Ok(Some(json(&json!({"file_id":id,"upload_id":upload_id,"status":"UPLOADING","expires_at":expires,"chunk_plaintext_bytes":CHUNK}))?.with_status(201)));
    }
    if route.first() != Some(&"attachments") {
        return Ok(None);
    }
    let id = *route.get(1).ok_or_else(validation)?;
    uuid(id)?;
    match (&request.method(), route) {
        (Method::Get, [_, _]) => Ok(Some(status(db, auth, id).await?)),
        (Method::Delete, [_, _]) => {
            let row = owned(db, auth, id, &["RESERVED", "UPLOADING", "READY", "ABORTED"]).await?;
            if row["status"] != "ABORTED" {
                let mut values = authority_values(auth, text(&row, "chat_id")?);
                values.extend([json!(id), row["status"].clone()]);
                if !changed(db,&format!("UPDATE attachment_uploads SET status='ABORTED' WHERE file_id=?5 AND owner_user_id=?2 AND status=?6 AND {AUTHORITY}"),&values).await? {
                    if self::row(db,id).await?["status"]!="ABORTED" {return Err(ApiError::domain("ATTACHMENT_STATE_INVALID",409));}
                } else {
                    let bucket=env.bucket("ATTACHMENTS")?;
                    if let Some(upload)=row["upload_id"].as_str(){let _=bucket.resume_multipart_upload(text(&row,"object_key")?,upload)?.abort().await;}
                    if row["status"]=="READY"{let _=bucket.delete(text(&row,"object_key")?).await;}
                }
            }
            Ok(Some(Response::empty()?.with_status(204)))
        }
        (Method::Put, [_, _, "parts", number]) => {
            let number = number
                .parse::<u16>()
                .ok()
                .filter(|n| (1..=2).contains(n))
                .ok_or_else(validation)?;
            let advertised = request
                .headers()
                .get("X-Encrypted-Part-Size")?
                .or(request.headers().get("Content-Length")?)
                .and_then(|v| v.parse::<u64>().ok())
                .filter(|n| (16..=FULL).contains(n))
                .ok_or_else(validation)?;
            let row = owned(db, auth, id, &["UPLOADING"]).await?;
            not_expired(&row)?;
            if !part_size_allowed(
                row["size"].as_u64().ok_or_else(validation)?,
                number,
                advertised,
            ) {
                return Err(ApiError::domain("ATTACHMENT_PART_SIZE_INVALID", 409));
            }
            let bucket = env.bucket("ATTACHMENTS")?;
            let upload = bucket
                .resume_multipart_upload(text(&row, "object_key")?, text(&row, "upload_id")?)?;
            let bytes = match body(request, advertised as usize).await {
                Ok(bytes) if bytes.len() == advertised as usize => bytes,
                _ => {
                    discard(db, &bucket, &row).await?;
                    return Err(validation());
                }
            };
            let token = begin_write(db, auth, &row, "part").await?;
            let outcome: ApiResult<String> = async {
                let uploaded = upload.upload_part(number, bytes).await
                    .map_err(|_| ApiError::retryable("ATTACHMENT_PART_FAILED", 503))?;
                let etag = uploaded.etag();
                let mut values = authority_values(auth, text(&row, "chat_id")?);
                values.extend([json!(id), json!(number), json!(etag), json!(advertised), json!(now_iso())]);
                if !changed(db,&format!("INSERT INTO attachment_parts(file_id,part_number,etag,size,created_at) SELECT ?5,?6,?7,?8,?9 FROM attachment_uploads u WHERE u.file_id=?5 AND u.owner_user_id=?2 AND u.status='UPLOADING' AND u.expires_at>?9 AND {AUTHORITY} ON CONFLICT(file_id,part_number) DO UPDATE SET etag=excluded.etag,size=excluded.size,created_at=excluded.created_at"),&values).await? {
                    discard(db,&bucket,&row).await?;
                    return Err(ApiError::domain("ATTACHMENT_STATE_INVALID",409));
                }
                Ok(etag)
            }.await;
            finish_write(db, id, &token).await?;
            let etag = outcome?;
            Ok(Some(json(
                &json!({"part_number":number,"etag":etag,"size":advertised}),
            )?))
        }
        (Method::Post, [_, _, "complete"]) => {
            let input: Value = read_json(request, 2048).await?;
            let requested = input["parts"]
                .as_array()
                .filter(|p| !p.is_empty() && p.len() <= 2)
                .ok_or_else(validation)?;
            for part in requested {
                if part["part_number"]
                    .as_u64()
                    .is_none_or(|n| !(1..=2).contains(&n))
                    || text(part, "etag")?.is_empty()
                    || text(part, "etag")?.len() > 256
                {
                    return Err(validation());
                }
            }
            let row = owned(db, auth, id, &["UPLOADING", "READY"]).await?;
            if row["status"] == "READY" {
                return Ok(Some(status(db, auth, id).await?));
            }
            not_expired(&row)?;
            let stored = parts(db, id).await?;
            validate_parts(
                row["size"].as_u64().ok_or_else(validation)?,
                &stored,
                requested,
            )?;
            let bucket = env.bucket("ATTACHMENTS")?;
            let key = text(&row, "object_key")?;
            let token = begin_write(db, auth, &row, "complete").await?;
            let outcome: ApiResult<()> = async {
                let object = if let Some(object) = bucket.head(key).await? {
                    object
                } else {
                    bucket
                        .resume_multipart_upload(key, text(&row, "upload_id")?)?
                        .complete(requested.iter().map(|p| {
                            UploadedPart::new(
                                p["part_number"].as_u64().unwrap_or_default() as u16,
                                p["etag"].as_str().unwrap_or_default().into(),
                            )
                        }))
                        .await
                        .map_err(|_| ApiError::retryable("ATTACHMENT_COMPLETE_FAILED", 503))?
                };
                if Some(object.size()) != row["size"].as_u64() {
                    discard(db, &bucket, &row).await?;
                    return Err(ApiError::domain("ATTACHMENT_SIZE_MISMATCH", 409));
                }
                ready(db, &bucket, auth, &row).await?;
                Ok(())
            }
            .await;
            finish_write(db, id, &token).await?;
            outcome?;
            Ok(Some(status(db, auth, id).await?))
        }
        (Method::Get, [_, _, "content"]) => {
            let row = row(db, id).await?;
            active_chat(db, auth, text(&row, "chat_id")?).await?;
            if row["status"] != "COMMITTED" {
                return Err(ApiError::domain("ATTACHMENT_NOT_COMMITTED", 403));
            }
            let bucket = env.bucket("ATTACHMENTS")?;
            let mut get = bucket.get(text(&row, "object_key")?);
            let range = request.headers().get("Range")?;
            let size = row["size"].as_u64().ok_or_else(validation)?;
            let parsed_range = range.as_deref().map(|r| parse_range(r, size)).transpose()?;
            if let Some((offset, length)) = parsed_range {
                get = get.range(Range::OffsetWithLength { offset, length });
            }
            let conditional = Conditional {
                etag_matches: request.headers().get("If-Match")?,
                etag_does_not_match: request.headers().get("If-None-Match")?,
                uploaded_before: request
                    .headers()
                    .get("If-Unmodified-Since")?
                    .filter(|s| worker::js_sys::Date::parse(s).is_finite())
                    .map(|s| worker::Date::new(worker::DateInit::String(s))),
                uploaded_after: request
                    .headers()
                    .get("If-Modified-Since")?
                    .filter(|s| worker::js_sys::Date::parse(s).is_finite())
                    .map(|s| worker::Date::new(worker::DateInit::String(s))),
            };
            get = get.only_if(conditional);
            let object = get
                .execute()
                .await?
                .ok_or_else(|| ApiError::retryable("ATTACHMENT_OBJECT_MISSING", 503))?;
            let etag = object.http_etag();
            let mut response = if let Some(body) = object.body() {
                Response::from_body(body.response_body()?)?
            } else {
                Response::empty()?.with_status(412)
            };
            response.headers_mut().set("ETag", &etag)?;
            response
                .headers_mut()
                .set("Cache-Control", "private, no-store")?;
            response.headers_mut().set("Accept-Ranges", "bytes")?;
            response
                .headers_mut()
                .set("Content-Type", "application/octet-stream")?;
            if response.status_code() != 412 {
                if let Some((offset, length)) = parsed_range {
                    response = response.with_status(206);
                    response.headers_mut().set(
                        "Content-Range",
                        &format!("bytes {offset}-{}/{size}", offset + length - 1),
                    )?;
                    response
                        .headers_mut()
                        .set("Content-Length", &length.to_string())?;
                } else {
                    response
                        .headers_mut()
                        .set("Content-Length", &size.to_string())?;
                }
            }
            Ok(Some(response))
        }
        _ => Ok(None),
    }
}
fn part_size_allowed(size: u64, number: u16, advertised: u64) -> bool {
    if !(1..=2).contains(&number) {
        return false;
    }
    let remaining = size.saturating_sub(u64::from(number - 1) * FULL);
    remaining >= 16 && advertised == remaining.min(FULL)
}
fn validate_parts(size: u64, stored: &[Value], requested: &[Value]) -> ApiResult<()> {
    if stored.len() != requested.len() || stored.is_empty() || stored.len() > 2 {
        return Err(ApiError::domain("ATTACHMENT_PART_SET_STALE", 409));
    }
    let mut total = 0;
    for (i, (server, client)) in stored.iter().zip(requested).enumerate() {
        if server["part_number"] != json!(i + 1)
            || client["part_number"] != json!(i + 1)
            || server["etag"] != client["etag"]
        {
            return Err(ApiError::domain("ATTACHMENT_PART_SET_STALE", 409));
        }
        let n = server["size"].as_u64().unwrap_or_default();
        if !(16..=FULL).contains(&n) || (i + 1 < stored.len() && n != FULL) {
            return Err(ApiError::domain("ATTACHMENT_PART_SIZE_INVALID", 409));
        }
        total += n;
    }
    if total != size {
        return Err(ApiError::domain("ATTACHMENT_SIZE_MISMATCH", 409));
    }
    Ok(())
}
fn parse_range(range: &str, size: u64) -> ApiResult<(u64, u64)> {
    let fail = || ApiError::domain("RANGE_NOT_SATISFIABLE", 416);
    let (start, end) = range
        .strip_prefix("bytes=")
        .and_then(|v| v.split_once('-'))
        .ok_or_else(fail)?;
    if start.is_empty() {
        let suffix = end
            .parse::<u64>()
            .ok()
            .filter(|n| *n > 0)
            .ok_or_else(fail)?
            .min(size);
        return Ok((size - suffix, suffix));
    }
    let start = start
        .parse::<u64>()
        .ok()
        .filter(|n| *n < size)
        .ok_or_else(fail)?;
    let end = if end.is_empty() {
        size - 1
    } else {
        end.parse::<u64>()
            .ok()
            .filter(|n| *n >= start)
            .ok_or_else(fail)?
            .min(size - 1)
    };
    Ok((start, end - start + 1))
}

pub async fn claim_attachments(
    db: &Db,
    auth: &AuthContext,
    chat: &str,
    client: &str,
    fingerprint: &str,
    ids: &[String],
) -> ApiResult<()> {
    let unique: std::collections::HashSet<_> = ids.iter().collect();
    if ids.len() > 16 || unique.len() != ids.len() {
        return Err(ApiError::domain("DUPLICATE_ATTACHMENT", 422));
    }
    for id in ids {
        uuid(id)?;
        let mut values = authority_values(auth, chat);
        values.extend([
            json!(id),
            json!(client),
            json!(fingerprint),
            json!(now_iso()),
        ]);
        db.0.batch(vec![db.statement(&format!("INSERT OR IGNORE INTO chat_storage_attachment_claims(file_id,chat_id,client_message_id,sender_device_id,fingerprint,created_at) SELECT file_id,chat_id,?6,?4,?7,?8 FROM attachment_uploads WHERE file_id=?5 AND owner_user_id=?2 AND chat_id=?1 AND status='READY' AND write_token IS NULL AND expires_at>?8 AND {AUTHORITY}"),&values)?,db.statement("UPDATE attachment_uploads SET status='COMMITTED' WHERE file_id=?1 AND status='READY' AND EXISTS(SELECT 1 FROM chat_storage_attachment_claims WHERE file_id=?1 AND chat_id=?2 AND client_message_id=?3 AND sender_device_id=?4 AND fingerprint=?5)",&[json!(id),json!(chat),json!(client),json!(auth.device_id),json!(fingerprint)])?]).await?;
        if db.first::<Value>("SELECT 1 AS ok FROM chat_storage_attachment_claims c JOIN attachment_uploads a ON a.file_id=c.file_id WHERE c.file_id=?1 AND c.chat_id=?2 AND c.client_message_id=?3 AND c.sender_device_id=?4 AND c.fingerprint=?5 AND a.status='COMMITTED' AND a.owner_user_id=?6",&[json!(id),json!(chat),json!(client),json!(auth.device_id),json!(fingerprint),json!(auth.user_id)]).await?.is_none(){return Err(ApiError::domain("ATTACHMENT_NOT_READY",409));}
    }
    Ok(())
}
pub async fn release_claims(
    db: &Db,
    chat: &str,
    client: &str,
    device: &str,
    fingerprint: &str,
    ids: &[String],
) -> ApiResult<()> {
    for id in ids {
        let values = [
            json!(id),
            json!(chat),
            json!(client),
            json!(device),
            json!(fingerprint),
        ];
        db.0.batch(vec![db.statement("UPDATE attachment_uploads SET status='READY' WHERE file_id=?1 AND status='COMMITTED' AND EXISTS(SELECT 1 FROM chat_storage_attachment_claims WHERE file_id=?1 AND chat_id=?2 AND client_message_id=?3 AND sender_device_id=?4 AND fingerprint=?5)",&values)?,db.statement("DELETE FROM chat_storage_attachment_claims WHERE file_id=?1 AND chat_id=?2 AND client_message_id=?3 AND sender_device_id=?4 AND fingerprint=?5",&values)?]).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parts_cannot_store_more_than_the_reserved_encrypted_bytes() {
        assert!(part_size_allowed(32, 1, 32));
        assert!(part_size_allowed(FULL + 32, 1, FULL));
        assert!(part_size_allowed(FULL + 32, 2, 32));
        assert!(!part_size_allowed(32, 1, FULL));
        assert!(!part_size_allowed(32, 2, 32));
        assert!(!part_size_allowed(FULL + 32, 2, FULL));
        assert!(!part_size_allowed(FULL + 32, 1, 32));
    }
    #[test]
    fn completion_rejects_stale_parts_and_size() {
        let p = json!({"part_number":1,"etag":"etag","size":32});
        assert!(validate_parts(32, std::slice::from_ref(&p), std::slice::from_ref(&p)).is_ok());
        assert!(validate_parts(33, std::slice::from_ref(&p), std::slice::from_ref(&p)).is_err());
        assert!(validate_parts(32, &[p], &[json!({"part_number":1,"etag":"wrong"})]).is_err());
    }
    #[test]
    fn byte_ranges_are_bounded() {
        assert_eq!(parse_range("bytes=-4", 10).ok(), Some((6, 4)));
        assert_eq!(parse_range("bytes=2-99", 10).ok(), Some((2, 8)));
        assert!(parse_range("bytes=10-", 10).is_err());
        assert!(parse_range("bytes=0-1,4-5", 10).is_err());
    }
}
