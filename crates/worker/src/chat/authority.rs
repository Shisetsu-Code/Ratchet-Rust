use crate::{
    db::Db,
    http::{ApiError, ApiResult, iso_at, now_iso},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use worker::{Date, Env, SqlStorage, SqlStorageValue as S, js_sys};

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Authority {
    pub chat_id: String,
    pub user_id: String,
    pub device_id: String,
    pub session_id: String,
}
impl Authority {
    pub fn key(&self) -> String {
        json!([self.chat_id, self.session_id, self.user_id, self.device_id]).to_string()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Lease {
    pub user_role: String,
    pub display_name: Option<String>,
    pub until: f64,
    pub can_mutate: bool,
}

pub fn initialize(sql: &SqlStorage) -> ApiResult<()> {
    sql.exec("CREATE TABLE IF NOT EXISTS connection_grants(id TEXT PRIMARY KEY,auth TEXT NOT NULL,expires REAL NOT NULL)",None)?;
    sql.exec(
        "CREATE TABLE IF NOT EXISTS authority_fence(id TEXT PRIMARY KEY)",
        None,
    )?;
    Ok(())
}
pub fn assert_open(sql: &SqlStorage) -> ApiResult<()> {
    if !sql
        .exec("SELECT 1 AS n FROM authority_fence LIMIT 1", None)?
        .to_array::<serde_json::Value>()?
        .is_empty()
    {
        let mut error = ratchet_core::error::DomainError::new("AUTHORITY_UPDATING", 503);
        error.retryable = true;
        return Err(error.into());
    }
    Ok(())
}
pub fn cached(sql: &SqlStorage, meta: &Authority) -> ApiResult<Option<Lease>> {
    assert_open(sql)?;
    #[derive(Deserialize)]
    struct Row {
        auth: String,
    }
    let rows = sql
        .exec(
            "SELECT auth FROM connection_grants WHERE id=? AND expires>?",
            vec![meta.key().into(), (Date::now().as_millis() as f64).into()],
        )?
        .to_array::<Row>()?;
    rows.first()
        .map(|row| {
            serde_json::from_str(&row.auth).map_err(|_| ApiError::domain("AUTHORITY_INVALID", 503))
        })
        .transpose()
}
pub fn save(sql: &SqlStorage, meta: &Authority, lease: &Lease) -> ApiResult<()> {
    assert_open(sql)?;
    sql.exec(
        "DELETE FROM connection_grants WHERE expires<=?",
        vec![(Date::now().as_millis() as f64).into()],
    )?;
    sql.exec(
        "INSERT OR REPLACE INTO connection_grants VALUES(?,?,?)",
        vec![
            meta.key().into(),
            serde_json::to_string(lease)
                .map_err(|_| ApiError::domain("AUTHORITY_INVALID", 503))?
                .into(),
            S::Float(lease.until),
        ],
    )?;
    Ok(())
}

pub async fn resolve(env: &Env, meta: &Authority) -> ApiResult<Lease> {
    #[derive(Deserialize)]
    struct Row {
        role: String,
        expires_at: String,
        last_seen_at: String,
        staff_role: Option<String>,
        display_name: Option<String>,
    }
    let now = Date::now().as_millis() as f64;
    let row=Db(env.d1("DB")?).first::<Row>("SELECT u.role,s.expires_at,s.last_seen_at,ws.staff_role,CASE WHEN ws.staff_role IN ('ADMIN','OPERATOR') THEN ws.display_name WHEN ws.staff_role='OWNER' THEN 'Soporte' ELSE NULL END AS display_name FROM sessions s JOIN users u ON u.user_id=s.user_id JOIN devices d ON d.device_id=s.device_id AND d.user_id=s.user_id JOIN active_chat_members m ON m.chat_id=?4 AND m.user_id=s.user_id JOIN chats c ON c.chat_id=m.chat_id LEFT JOIN workspace_staff ws ON ws.workspace_id=c.workspace_id AND ws.user_id=s.user_id AND ws.revoked_at IS NULL WHERE s.session_id=?1 AND s.user_id=?2 AND s.device_id=?3 AND s.revoked_at IS NULL AND s.expires_at>?5 AND u.status='ACTIVE' AND d.authorized_at IS NOT NULL AND d.revoked_at IS NULL AND (u.role<>'ADMIN' OR s.last_seen_at>?6)",&[json!(meta.session_id),json!(meta.user_id),json!(meta.device_id),json!(meta.chat_id),json!(now_iso()),json!(iso_at(now-72.0*60.0*60.0*1000.0))]).await?.ok_or_else(||ApiError::domain("CHAT_NOT_AVAILABLE",403))?;
    let mut until = js_sys::Date::parse(&row.expires_at);
    if row.role == "ADMIN" {
        until = until.min(js_sys::Date::parse(&row.last_seen_at) + 72.0 * 60.0 * 60.0 * 1000.0);
    }
    if !until.is_finite() || until <= now {
        return Err(ApiError::domain("SESSION_INVALID", 401));
    }
    Ok(Lease {
        user_role: row.role,
        display_name: row.display_name,
        until,
        can_mutate: matches!(row.staff_role.as_deref(), Some("ADMIN" | "OPERATOR")),
    })
}
