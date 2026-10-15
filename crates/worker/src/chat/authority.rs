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
    sql.exec(
        "CREATE TABLE IF NOT EXISTS authority_releases(id TEXT PRIMARY KEY)",
        None,
    )?;
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

/// Per-Durable-Object cache. Control mutations must invalidate before writing and
/// refresh after completion; any failure leaves this instance closed.
pub struct LocalAuthority {
    blocked: bool,
    grants: std::collections::HashMap<String, Lease>,
    insertion_order: std::collections::VecDeque<String>,
}
impl Default for LocalAuthority {
    fn default() -> Self {
        Self {
            blocked: true,
            grants: Default::default(),
            insertion_order: Default::default(),
        }
    }
}
impl LocalAuthority {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn initialize(&mut self, sql: &SqlStorage) -> ApiResult<()> {
        self.invalidate();
        initialize(sql)?;
        self.refresh(sql)
    }

    pub fn assert_open(&self) -> ApiResult<()> {
        if self.blocked {
            let mut error = ratchet_core::error::DomainError::new("AUTHORITY_UPDATING", 503);
            error.retryable = true;
            return Err(error.into());
        }
        Ok(())
    }

    pub fn invalidate(&mut self) {
        self.blocked = true;
        self.grants.clear();
        self.insertion_order.clear();
    }

    pub fn refresh(&mut self, sql: &SqlStorage) -> ApiResult<()> {
        self.refresh_with(|| {
            Ok(!sql
                .exec("SELECT 1 AS n FROM authority_fence LIMIT 1", None)?
                .to_array::<serde_json::Value>()?
                .is_empty())
        })
    }

    fn refresh_with(&mut self, load_fence: impl FnOnce() -> ApiResult<bool>) -> ApiResult<()> {
        self.invalidate();
        self.blocked = load_fence()?;
        Ok(())
    }

    pub fn cached(&mut self, sql: &SqlStorage, meta: &Authority) -> ApiResult<Option<Lease>> {
        let now = Date::now().as_millis() as f64;
        self.cached_with(meta, now, || {
            #[derive(Deserialize)]
            struct Row {
                auth: String,
            }
            let rows = sql
                .exec(
                    "SELECT auth FROM connection_grants WHERE id=? AND expires>?",
                    vec![meta.key().into(), now.into()],
                )?
                .to_array::<Row>()?;
            rows.first()
                .map(|row| {
                    serde_json::from_str(&row.auth)
                        .map_err(|_| ApiError::domain("AUTHORITY_INVALID", 503))
                })
                .transpose()
        })
    }

    fn cached_with(
        &mut self,
        meta: &Authority,
        now: f64,
        load: impl FnOnce() -> ApiResult<Option<Lease>>,
    ) -> ApiResult<Option<Lease>> {
        self.assert_open()?;
        let key = meta.key();
        if let Some(lease) = self.grants.get(&key) {
            if lease.until.is_finite() && lease.until > now {
                return Ok(Some(lease.clone()));
            }
            self.grants.remove(&key);
            self.insertion_order.retain(|id| id != &key);
            return Ok(None);
        }
        let lease = load()?.filter(|lease| lease.until.is_finite() && lease.until > now);
        if let Some(lease) = &lease {
            self.remember(key, lease.clone());
        }
        Ok(lease)
    }

    pub fn save(&mut self, sql: &SqlStorage, meta: &Authority, lease: &Lease) -> ApiResult<()> {
        self.assert_open()?;
        // Persist first: an unsuccessful write must never create a memory grant.
        save(sql, meta, lease)?;
        self.remember(meta.key(), lease.clone());
        Ok(())
    }

    fn remember(&mut self, key: String, lease: Lease) {
        if !self.grants.contains_key(&key) {
            self.insertion_order.push_back(key.clone());
        }
        self.grants.insert(key, lease);
        if self.grants.len() > 512
            && let Some(oldest) = self.insertion_order.pop_front()
        {
            self.grants.remove(&oldest);
        }
    }
}

#[cfg(test)]
mod cache_tests {
    use super::*;
    fn open_cache() -> LocalAuthority {
        let mut cache = LocalAuthority::new();
        assert!(cache.refresh_with(|| Ok(false)).is_ok());
        cache
    }
    fn meta(id: &str) -> Authority {
        Authority {
            chat_id: "chat".into(),
            user_id: id.into(),
            device_id: "device".into(),
            session_id: "session".into(),
        }
    }
    fn lease(until: f64) -> Lease {
        Lease {
            user_role: "USER".into(),
            display_name: Some("Alice".into()),
            until,
            can_mutate: false,
        }
    }
    #[test]
    fn new_cache_denies_until_fence_state_is_loaded() {
        let mut cache = LocalAuthority::new();
        assert!(cache.assert_open().is_err());
        assert!(
            cache
                .cached_with(&meta("alice"), 10.0, || panic!("uninitialized load"))
                .is_err()
        );
    }
    #[test]
    fn refresh_reloads_grants_and_failed_refresh_stays_closed() {
        let result = (|| -> ApiResult<()> {
            let mut cache = open_cache();
            cache.cached_with(&meta("alice"), 10.0, || Ok(Some(lease(20.0))))?;
            cache.invalidate();
            cache.refresh_with(|| Ok(false))?;
            let refreshed = cache.cached_with(&meta("alice"), 11.0, || Ok(Some(lease(30.0))))?;
            assert_eq!(refreshed.map(|v| v.until), Some(30.0));
            assert!(
                cache
                    .refresh_with(|| Err(ApiError::domain("STORAGE_FAILURE", 503)))
                    .is_err()
            );
            assert!(
                cache
                    .cached_with(&meta("alice"), 12.0, || panic!("failed refresh load"))
                    .is_err()
            );
            cache.refresh_with(|| Ok(true))?;
            assert!(cache.assert_open().is_err());
            cache.refresh_with(|| Ok(false))?;
            assert!(
                cache
                    .cached_with(&meta("alice"), 13.0, || Ok(None))?
                    .is_none()
            );
            Ok(())
        })();
        assert!(result.is_ok());
    }
    #[test]
    fn cold_load_does_not_grant_expired_or_nonfinite_lease() {
        let result = (|| -> ApiResult<()> {
            let mut cache = open_cache();
            for until in [10.0, 9.0, f64::NAN, f64::INFINITY] {
                assert!(
                    cache
                        .cached_with(&meta("alice"), 10.0, || Ok(Some(lease(until))))?
                        .is_none()
                );
            }
            Ok(())
        })();
        assert!(result.is_ok());
    }
    #[test]
    fn cold_load_is_reused_without_loading_again() {
        let result = (|| -> ApiResult<()> {
            let mut cache = open_cache();
            let first = cache.cached_with(&meta("alice"), 10.0, || Ok(Some(lease(20.0))))?;
            assert_eq!(first.map(|v| v.until), Some(20.0));
            let second =
                cache.cached_with(&meta("alice"), 11.0, || panic!("warm hit must not load"))?;
            assert_eq!(second.and_then(|v| v.display_name), Some("Alice".into()));
            Ok(())
        })();
        assert!(result.is_ok());
    }
    #[test]
    fn expiry_boundary_denies_without_reloading_expired_memory() {
        let result = (|| -> ApiResult<()> {
            let mut cache = open_cache();
            cache.cached_with(&meta("alice"), 10.0, || Ok(Some(lease(20.0))))?;
            assert!(
                cache
                    .cached_with(&meta("alice"), 20.0, || panic!("expired hit must deny"))
                    .is_ok_and(|v| v.is_none())
            );
            Ok(())
        })();
        assert!(result.is_ok());
    }
    #[test]
    fn eviction_removes_oldest_grant_and_keeps_recent_grants() {
        let result = (|| -> ApiResult<()> {
            let mut cache = open_cache();
            for i in 0..513 {
                cache.cached_with(&meta(&i.to_string()), 10.0, || Ok(Some(lease(20.0))))?;
            }
            assert!(cache.cached_with(&meta("0"), 11.0, || Ok(None))?.is_none());
            assert_eq!(
                cache
                    .cached_with(&meta("512"), 11.0, || panic!("recent grant evicted"))?
                    .map(|v| v.until),
                Some(20.0)
            );
            Ok(())
        })();
        assert!(result.is_ok());
    }
    #[test]
    fn invalidation_blocks_reads_before_loader_can_run() {
        let result = (|| -> ApiResult<()> {
            let mut cache = open_cache();
            cache.cached_with(&meta("alice"), 10.0, || Ok(Some(lease(20.0))))?;
            cache.invalidate();
            assert!(
                cache
                    .cached_with(&meta("alice"), 11.0, || panic!(
                        "blocked authority must not load"
                    ))
                    .is_err()
            );
            Ok(())
        })();
        assert!(result.is_ok());
    }
    #[test]
    fn distinct_authorities_cannot_share_a_grant() {
        let result = (|| -> ApiResult<()> {
            let mut cache = open_cache();
            let mut a = meta("alice");
            a.chat_id = "x:y".into();
            a.session_id = "z".into();
            let mut b = a.clone();
            b.chat_id = "x".into();
            b.session_id = "y:z".into();
            cache.cached_with(&a, 10.0, || Ok(Some(lease(20.0))))?;
            assert!(cache.cached_with(&b, 11.0, || Ok(None))?.is_none());
            Ok(())
        })();
        assert!(result.is_ok());
    }
}
