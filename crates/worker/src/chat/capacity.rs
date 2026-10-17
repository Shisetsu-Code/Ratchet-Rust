//! Atomic aggregate credits amortize D1 accounting across many local commits.
use super::storage::Usage;
use crate::{
    db::Db,
    http::{ApiError, ApiResult},
};
use serde_json::{Value, json};
use worker::Env;

pub const CHAT_BYTES: u64 = 256 * 1024 * 1024;
pub const CHAT_ROWS: u64 = 1_000_000;
const BYTE_CHUNK: u64 = 1024 * 1024;
const ROW_CHUNK: u64 = 4096;
pub const BYTE_HEADROOM: u64 = 512 * 1024;
pub const ROW_HEADROOM: u64 = 256;
fn rounded(value: u64, step: u64) -> u64 {
    value.saturating_add(step - 1) / step * step
}

pub(super) async fn reserve(
    env: &Env,
    chat: &str,
    usage: &Usage,
    required_bytes: u64,
    required_rows: u64,
) -> ApiResult<(u64, u64)> {
    let db = Db(env.d1("DB")?);
    // Historical data must be charged even when it already exceeds a limit.
    // This write cannot create headroom: its floor is the actual retained usage.
    db.run("UPDATE chat_storage_capacity SET allocated_bytes=MAX(allocated_bytes,?2),allocated_rows=MAX(allocated_rows,?3),reconciled=1 WHERE chat_id=?1", &[json!(chat),json!(usage.bytes),json!(usage.rows)]).await?;
    let bytes = rounded(usage.bytes.saturating_add(required_bytes), BYTE_CHUNK).min(CHAT_BYTES);
    let rows = rounded(usage.rows.saturating_add(required_rows), ROW_CHUNK).min(CHAT_ROWS);
    db.run("UPDATE chat_storage_capacity SET allocated_bytes=MAX(allocated_bytes,?2),allocated_rows=MAX(allocated_rows,?3) WHERE chat_id=?1 AND reconciled=1 AND NOT EXISTS(SELECT 1 FROM chat_storage_capacity WHERE reconciled=0) AND (SELECT COALESCE(SUM(allocated_bytes),0) FROM chat_storage_capacity)+MAX(0,?2-allocated_bytes)<=(SELECT bytes FROM chat_capacity_limits WHERE id=1) AND (SELECT COALESCE(SUM(allocated_rows),0) FROM chat_storage_capacity)+MAX(0,?3-allocated_rows)<=(SELECT rows FROM chat_capacity_limits WHERE id=1)", &[json!(chat),json!(bytes),json!(rows)]).await?;
    let row=db.first::<Value>("SELECT allocated_bytes,allocated_rows,(SELECT COUNT(*) FROM chat_storage_capacity WHERE reconciled=0) AS pending FROM chat_storage_capacity WHERE chat_id=?1", &[json!(chat)]).await?.ok_or_else(||ApiError::domain("CHAT_NOT_FOUND",404))?;
    if row["pending"].as_u64().unwrap_or(1) > 0 {
        return Err(ApiError::retryable("STORAGE_RECONCILIATION_PENDING", 503));
    }
    let granted_bytes = row["allocated_bytes"].as_u64().unwrap_or(0).min(CHAT_BYTES);
    let granted_rows = row["allocated_rows"].as_u64().unwrap_or(0).min(CHAT_ROWS);
    if granted_bytes < usage.bytes.saturating_add(required_bytes)
        || granted_rows < usage.rows.saturating_add(required_rows)
    {
        return Err(ApiError::domain("CHAT_STORAGE_QUOTA_EXCEEDED", 409));
    }
    Ok((granted_bytes, granted_rows))
}

/// Scan historical rooms through the authoritative namespace, never through the
/// eventually updated chat_storage_stats projection. Reconciliation records usage
/// before returning an admission error, so a bounded cron batch makes progress.
pub(crate) async fn maintenance(env: &Env) -> ApiResult<()> {
    let db = Db(env.d1("DB")?);
    let rows=db.all("SELECT chat_id FROM chat_storage_capacity WHERE reconciled=0 ORDER BY chat_id LIMIT 100",&[]).await?;
    for row in rows {
        if let Some(chat) = row["chat_id"].as_str() {
            let _ = super::routes::forward(
                env,
                super::Call {
                    op: "capacity.reconcile".into(),
                    authority: super::authority::Authority {
                        chat_id: chat.into(),
                        user_id: String::new(),
                        device_id: String::new(),
                        session_id: String::new(),
                    },
                    data: Value::Null,
                },
            )
            .await;
        }
    }
    Ok(())
}
