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

/// Scheduled cleanup claims durable state before touching R2 objects.
pub async fn maintenance(env: &Env) -> ApiResult<Value> {
    let db = Db(env.d1("DB")?);
    let bucket = env.bucket("ATTACHMENTS")?;
    let now = now_iso();
    let mut expired = 0;
    let mut failed = 0;
    let rows=db.all("SELECT file_id,chat_id,owner_user_id,object_key,upload_id,status FROM attachment_uploads WHERE status IN ('RESERVED','UPLOADING','READY','ABORTED') AND expires_at<=?1 ORDER BY expires_at,file_id LIMIT 100",&[json!(now)]).await?;
    for row in &rows {
        let result:ApiResult<()>=async {
            if row["status"]!="ABORTED"&&!changed(&db,"UPDATE attachment_uploads SET status='ABORTED' WHERE file_id=?1 AND status=?2 AND expires_at<=?3",&[row["file_id"].clone(),row["status"].clone(),json!(now)]).await? {return Ok(());}
            if let Some(upload)=row["upload_id"].as_str(){let _=bucket.resume_multipart_upload(text(row,"object_key")?,upload)?.abort().await;}
            bucket.delete(text(row,"object_key")?).await?;
            if changed(&db,"UPDATE attachment_uploads SET status='EXPIRED' WHERE file_id=?1 AND status='ABORTED' AND expires_at<=?2",&[row["file_id"].clone(),json!(now)]).await?{expired+=1;} Ok(())
        }.await;
        if result.is_err() {
            failed += 1;
        }
    }
    let prune=db.all("SELECT file_id FROM attachment_uploads WHERE status='EXPIRED' AND expires_at<=?1 AND NOT EXISTS (SELECT 1 FROM chat_storage_attachment_claims c WHERE c.file_id=attachment_uploads.file_id) ORDER BY expires_at,file_id LIMIT 100",&[json!(iso_at(worker::Date::now().as_millis() as f64-604_800_000.0))]).await?;
    for row in &prune {
        db.0.batch(vec![db.statement("DELETE FROM attachments WHERE file_id=?1 AND message_id IS NULL",&[row["file_id"].clone()])?,db.statement("DELETE FROM attachment_uploads WHERE file_id=?1 AND status='EXPIRED' AND NOT EXISTS(SELECT 1 FROM chat_storage_attachment_claims WHERE file_id=?1)",&[row["file_id"].clone()])?]).await?;
    }
    db.run("UPDATE wallpaper_uploads SET state='ABORTED' WHERE state IN ('UPLOADING','READY') AND expires_at<=?1",&[json!(now)]).await?;
    let wallpapers=db.all("SELECT object_key FROM wallpaper_uploads WHERE state IN ('ABORTED','RETIRED') AND (cleaned_at IS NULL OR cleaned_at<?1) ORDER BY cleaned_at,object_key LIMIT 100",&[json!(iso_at(worker::Date::now().as_millis() as f64-86_400_000.0))]).await?;
    let mut cleaned = 0;
    for row in wallpapers {
        if bucket.delete(text(&row, "object_key")?).await.is_ok() {
            db.run(
                "UPDATE wallpaper_uploads SET cleaned_at=?2 WHERE object_key=?1",
                &[row["object_key"].clone(), json!(now)],
            )
            .await?;
            cleaned += 1;
        }
    }
    Ok(
        json!({"attachments":{"scanned":rows.len(),"expired":expired,"failed":failed,"pruned":prune.len()},"wallpapers":{"cleaned":cleaned}}),
    )
}
