//! Synchronous, durable admission preserves inbound message reservation order.
//! All frames are charged before parsing, including pings and malformed sends.
use super::authority::Authority;
use crate::http::ApiResult;
use serde_json::{Value, json};
use worker::SqlStorage;

pub(super) const SOCKETS_PER_DEVICE: usize = 4;
pub(super) const SOCKETS_PER_USER: usize = 8;
pub(super) const SOCKETS_PER_ROOM: usize = 256;
pub(super) const MAX_FRAME_BYTES: usize = ratchet_core::message::MAX_REQUEST_BYTES + 1024;

pub(super) fn initialize(sql: &SqlStorage) -> ApiResult<()> {
    for statement in include_str!("realtime-limits.sql")
        .split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        sql.exec(statement, None)?;
    }
    Ok(())
}

pub(super) fn admit(sql: &SqlStorage, meta: &Authority, bytes: usize, now: i64) -> ApiResult<bool> {
    // No live budget is removed on socket close or reconnect. Expiry is indexed,
    // and the insertion statement caps retained rows even under identity churn.
    sql.exec(
        "DELETE FROM websocket_frame_budgets WHERE expires_at<=?",
        vec![now.into()],
    )?;
    let device = json!(["device", meta.user_id, meta.device_id]).to_string();
    let user = json!(["user", meta.user_id]).to_string();
    let rows = sql
        .exec(
            include_str!("admit-frame.sql"),
            vec![
                device.into(),
                user.into(),
                now.into(),
                (bytes as i64).into(),
            ],
        )?
        .to_array::<Value>()?;
    Ok(rows.len() == 3)
}
