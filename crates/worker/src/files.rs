//! Attachment uploads, account wallpaper, Web Push and bounded object maintenance.
use crate::{
    auth::{self, AuthContext},
    db::Db,
    http::{ApiError, ApiResult, iso_at, json, now_iso, read_json},
};
use serde_json::{Value, json};
use worker::{Env, Method, Request, Response};
mod attachments;
mod push;
mod wallpaper;
pub use attachments::{claim_attachments, release_claims};
pub use push::notify_push;

pub(crate) fn storage_error(error: worker::Error, fallback: &'static str) -> ApiError {
    let detail = error.to_string();
    for code in [
        "ATTACHMENT_QUOTA_EXCEEDED",
        "WALLPAPER_QUOTA_EXCEEDED",
        "PUSH_SUBSCRIPTION_QUOTA_EXCEEDED",
    ] {
        if detail.contains(code) {
            return ApiError::domain(code, 409);
        }
    }
    ApiError::domain(fallback, 409)
}
pub(crate) fn storage_error_api(error: ApiError, fallback: &'static str) -> ApiError {
    match error {
        ApiError::Runtime(error) => storage_error(error, fallback),
        other => other,
    }
}
pub(crate) fn validation() -> ApiError {
    ApiError::domain("VALIDATION_ERROR", 422)
}
pub(crate) fn uuid(value: &str) -> ApiResult<()> {
    if ratchet_core::message::is_uuid(value) {
        Ok(())
    } else {
        Err(validation())
    }
}
pub(crate) fn text<'a>(value: &'a Value, key: &str) -> ApiResult<&'a str> {
    value[key].as_str().ok_or_else(validation)
}
pub(crate) async fn active_chat(db: &Db, auth: &AuthContext, chat: &str) -> ApiResult<()> {
    if db
        .first::<Value>(
            "SELECT 1 AS ok FROM active_chat_members WHERE chat_id=?1 AND user_id=?2",
            &[json!(chat), json!(auth.user_id)],
        )
        .await?
        .is_none()
    {
        return Err(ApiError::domain("CHAT_NOT_FOUND", 404));
    }
    Ok(())
}
/// Compare-and-set writes use this predicate after every external storage await.
pub(crate) const AUTHORITY: &str = "EXISTS (SELECT 1 FROM active_chat_members m JOIN sessions s ON s.user_id=m.user_id JOIN devices d ON d.device_id=s.device_id AND d.user_id=s.user_id WHERE m.chat_id=?1 AND m.user_id=?2 AND s.session_id=?3 AND s.device_id=?4 AND s.revoked_at IS NULL AND s.expires_at>strftime('%Y-%m-%dT%H:%M:%fZ','now') AND d.authorized_at IS NOT NULL AND d.revoked_at IS NULL)";
pub(crate) fn authority_values(auth: &AuthContext, chat: &str) -> Vec<Value> {
    vec![
        json!(chat),
        json!(auth.user_id),
        json!(auth.session_id),
        json!(auth.device_id),
    ]
}
pub(crate) async fn changed(db: &Db, sql: &str, values: &[Value]) -> ApiResult<bool> {
    Ok(db
        .run(sql, values)
        .await?
        .meta()?
        .is_some_and(|m| m.changes.unwrap_or(0) > 0))
}
pub(crate) async fn body(request: &mut Request, limit: usize) -> ApiResult<Vec<u8>> {
    use futures_util::StreamExt;
    let mut out = Vec::new();
    let mut stream = request.stream()?;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if chunk.len() > limit.saturating_sub(out.len()) {
            return Err(validation());
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}
pub async fn handle(request: &mut Request, env: &Env) -> ApiResult<Option<Response>> {
    let path = request.path();
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    if parts.len() < 3 || parts[0] != "api" || parts[1] != "v1" {
        return Ok(None);
    }
    let route = &parts[2..];
    let relevant = route.first() == Some(&"attachments")
        || route.first() == Some(&"push")
        || (route.first() == Some(&"chats")
            && route
                .get(2)
                .is_some_and(|p| matches!(*p, "attachments" | "wallpaper")));
    if !relevant {
        return Ok(None);
    }
    let auth = auth::require_session(request, env).await?;
    auth::require_authorized(&auth)?;
    let db = Db(env.d1("DB")?);
    if route.first() == Some(&"push") {
        return push::handle(request, env, &db, &auth, route).await;
    }
    if route.get(2) == Some(&"wallpaper") {
        return wallpaper::handle(request, env, &db, &auth, route).await;
    }
    attachments::handle(request, env, &db, &auth, route).await
}

/// Scheduled cleanup claims durable state before touching R2. A writer marker is
/// cleared only after the operation completes or its durable multipart handle is
/// positively closed. Elapsed time or an absent object alone is not closure.
pub async fn maintenance(env: &Env) -> ApiResult<Value> {
    let db = Db(env.d1("DB")?);
    let bucket = env.bucket("ATTACHMENTS")?;
    let now_ms = worker::Date::now().as_millis() as f64;
    let now = iso_at(now_ms);
    db.run("UPDATE attachment_uploads SET status='ABORTED' WHERE status IN ('RESERVED','UPLOADING','READY') AND expires_at<=?1", &[json!(now)]).await?;
    db.run("UPDATE wallpaper_uploads SET state='ABORTED' WHERE state IN ('UPLOADING','READY') AND expires_at<=?1", &[json!(now)]).await?;
    // Fence in D1 first, then close the provider's multipart handle. An absent
    // object alone is never considered proof that a write cannot finish later.
    let stalled=db.all("SELECT object_key,upload_id,write_token,'attachment' AS kind FROM attachment_uploads WHERE status='ABORTED' AND write_token IS NOT NULL AND cleanup_after<=?1 UNION ALL SELECT object_key,upload_id,write_token,'wallpaper' AS kind FROM wallpaper_uploads WHERE state='ABORTED' AND write_token IS NOT NULL AND cleanup_after<=?1 LIMIT 32", &[json!(now)]).await?;
    for row in &stalled {
        let table = if row["kind"] == "attachment" {
            "attachment_uploads"
        } else {
            "wallpaper_uploads"
        };
        db.run(
            &format!("UPDATE {table} SET cleanup_after=?3 WHERE object_key=?1 AND write_token=?2"),
            &[
                row["object_key"].clone(),
                row["write_token"].clone(),
                json!(iso_at(now_ms + 300_000.0)),
            ],
        )
        .await?;
        // With no durable upload ID, the fenced writer cannot upload any body.
        // A cancelled create can leave only an empty provider handle, which R2's
        // incomplete-multipart lifecycle expires; it cannot publish an object.
        let closed = if let Some(upload) = row["upload_id"].as_str() {
            close_multipart(&bucket, text(row, "object_key")?, upload)
                .await
                .is_ok()
        } else {
            true
        };
        if closed {
            db.run(&format!("UPDATE {table} SET write_token=NULL,cleanup_after='' WHERE object_key=?1 AND write_token=?2"), &[row["object_key"].clone(),row["write_token"].clone()]).await?;
        }
    }
    let mut expired = 0;
    let mut failed = 0;
    let rows=db.all("SELECT file_id,object_key,upload_id,status,cleanup_attempts FROM attachment_uploads WHERE status IN ('ABORTED','EXPIRED') AND cleaned_at IS NULL AND write_token IS NULL AND cleanup_after<=?1 ORDER BY cleanup_after,expires_at,file_id LIMIT 100", &[json!(now)]).await?;
    for row in &rows {
        let attempts = row["cleanup_attempts"].as_u64().unwrap_or(0);
        let retry = iso_at(now_ms + cleanup_delay(attempts) as f64);
        if !changed(&db,"UPDATE attachment_uploads SET status='ABORTED',cleanup_after=?2,cleanup_attempts=cleanup_attempts+1 WHERE file_id=?1 AND status IN ('ABORTED','EXPIRED') AND cleaned_at IS NULL AND write_token IS NULL AND cleanup_after<=?3", &[row["file_id"].clone(),json!(retry),json!(now)]).await? {continue;}
        let result:ApiResult<()> = async {
            let key=text(row,"object_key")?;
            if let Some(upload)=row["upload_id"].as_str() {
                close_multipart(&bucket,key,upload).await?;
            }
            bucket.delete(key).await?;
            if changed(&db,"UPDATE attachment_uploads SET status='EXPIRED',cleaned_at=?2 WHERE file_id=?1 AND status='ABORTED' AND write_token IS NULL AND cleaned_at IS NULL", &[row["file_id"].clone(),json!(now)]).await? {expired+=1;}
            Ok(())
        }.await;
        if result.is_err() {
            failed += 1;
        }
    }
    let prune=db.all("SELECT file_id FROM attachment_uploads WHERE status='EXPIRED' AND cleaned_at IS NOT NULL AND cleaned_at<=?1 AND write_token IS NULL AND NOT EXISTS(SELECT 1 FROM chat_storage_attachment_claims c WHERE c.file_id=attachment_uploads.file_id) ORDER BY cleaned_at,file_id LIMIT 100", &[json!(iso_at(now_ms-604_800_000.0))]).await?;
    for row in &prune {
        db.0.batch(vec![db.statement("DELETE FROM attachments WHERE file_id=?1 AND message_id IS NULL", &[row["file_id"].clone()])?,db.statement("DELETE FROM attachment_uploads WHERE file_id=?1 AND status='EXPIRED' AND cleaned_at IS NOT NULL AND write_token IS NULL AND NOT EXISTS(SELECT 1 FROM chat_storage_attachment_claims WHERE file_id=?1)", &[row["file_id"].clone()])?]).await?;
    }
    let wallpapers=db.all("SELECT object_key,upload_id,cleanup_attempts FROM wallpaper_uploads WHERE state IN ('ABORTED','RETIRED') AND cleaned_at IS NULL AND write_token IS NULL AND cleanup_after<=?1 ORDER BY cleanup_after,expires_at,object_key LIMIT 100", &[json!(now)]).await?;
    let mut cleaned = 0;
    for row in &wallpapers {
        let retry =
            iso_at(now_ms + cleanup_delay(row["cleanup_attempts"].as_u64().unwrap_or(0)) as f64);
        if !changed(&db,"UPDATE wallpaper_uploads SET cleanup_after=?2,cleanup_attempts=cleanup_attempts+1 WHERE object_key=?1 AND state IN ('ABORTED','RETIRED') AND cleaned_at IS NULL AND write_token IS NULL AND cleanup_after<=?3", &[row["object_key"].clone(),json!(retry),json!(now)]).await? {continue;}
        let deleted: ApiResult<()> = async {
            let key = text(row, "object_key")?;
            if let Some(upload) = row["upload_id"].as_str() {
                close_multipart(&bucket, key, upload).await?;
            }
            bucket.delete(key).await?;
            Ok(())
        }
        .await;
        if deleted.is_ok() {
            if changed(&db,"UPDATE wallpaper_uploads SET cleaned_at=?2 WHERE object_key=?1 AND state IN ('ABORTED','RETIRED') AND cleaned_at IS NULL AND write_token IS NULL", &[row["object_key"].clone(),json!(now)]).await? {cleaned+=1;}
        } else {
            failed += 1;
        }
    }
    db.run("DELETE FROM wallpaper_uploads WHERE object_key IN (SELECT object_key FROM wallpaper_uploads WHERE state IN ('ABORTED','RETIRED') AND cleaned_at IS NOT NULL AND cleaned_at<=?1 AND write_token IS NULL AND NOT EXISTS(SELECT 1 FROM account_wallpapers a WHERE a.object_key=wallpaper_uploads.object_key) ORDER BY cleaned_at,object_key LIMIT 100)", &[json!(iso_at(now_ms-604_800_000.0))]).await?;
    let pending=db.first::<Value>("SELECT (SELECT COUNT(*) FROM attachment_uploads WHERE write_token IS NOT NULL)+(SELECT COUNT(*) FROM wallpaper_uploads WHERE write_token IS NOT NULL) AS writers", &[]).await?;
    push::maintenance(env).await?;
    Ok(
        json!({"attachments":{"scanned":rows.len(),"expired":expired,"failed":failed,"pruned":prune.len()},"wallpapers":{"cleaned":cleaned},"pending_writers":pending.map(|r|r["writers"].clone())}),
    )
}
fn cleanup_delay(attempts: u64) -> u64 {
    60_000u64
        .saturating_mul(1 << attempts.min(6))
        .min(3_600_000)
}

// R2's successful abort or documented NoSuchUpload (10024) closes the upload.
// Other errors retain quota and retry; a completed object is positive evidence
// that the multipart completion has already materialized.
async fn close_multipart(bucket: &worker::Bucket, key: &str, id: &str) -> ApiResult<()> {
    match bucket.resume_multipart_upload(key, id)?.abort().await {
        Ok(()) => Ok(()),
        Err(error) if error.to_string().contains("(10024)") => Ok(()),
        Err(error) => {
            if bucket.head(key).await?.is_some() {
                Ok(())
            } else {
                Err(error.into())
            }
        }
    }
}
