//! Rare authority writes are serialized independently of the message lane.
//! A D1 commit marker makes recovery safe even after an ambiguous network result.
use super::{Call, ChatRealtime, authority, routes};
use crate::{
    auth,
    db::Db,
    http::{self, ApiError, ApiResult},
};
use ratchet_core::message::is_uuid;
use serde::Deserialize;
use serde_json::{Value, json};
use worker::*;

pub const NAME: &str = "ratchet-rust-control-v1";

pub struct MutationPlan {
    pub statements: Vec<D1PreparedStatement>,
    pub affected_users: Vec<String>,
    pub affected_chats: Vec<String>,
    pub response: Value,
    pub status: u16,
    pub clear_cookie: bool,
}

#[derive(Deserialize)]
struct Journal {
    id: String,
    targets: String,
}

// Downstream outages can outlast the platform's bounded alarm retries. Catch a
// recovery failure only after persisting a new wakeup; storage failures still
// propagate so the platform can retry them.
async fn retry_failed_recovery(
    outcome: ApiResult<()>,
    rearm: impl std::future::Future<Output = ApiResult<()>>,
) -> ApiResult<()> {
    if outcome.is_err() {
        rearm.await?;
    }
    Ok(())
}

pub async fn public(
    request: &mut Request,
    env: &Env,
    op: &str,
    target: &str,
) -> ApiResult<Response> {
    domain(request, env, op, target, Value::Null).await
}

pub async fn domain(
    request: &mut Request,
    env: &Env,
    op: &str,
    target: &str,
    body: Value,
) -> ApiResult<Response> {
    let actor = auth::require_session(request, env).await?;
    let cookie = request.headers().get("Cookie")?.unwrap_or_default();
    routes::forward(
        env,
        Call {
            op: "control.write".into(),
            authority: routes::authority(&actor, NAME),
            data: json!({"operation":op,"target":target,"cookie":cookie,"body":body}),
        },
    )
    .await
}

impl ChatRealtime {
    pub(super) async fn recover_control_alarm(&self) -> ApiResult<()> {
        let namespace = self.env.durable_object("CHAT_REALTIME")?;
        if self.state.id().to_string() != namespace.id_from_name(NAME)?.to_string() {
            return Ok(());
        }
        self.ensure()?;
        let _turn = self.send_lane.enter().await?;
        let outcome = self.control_recover().await;
        retry_failed_recovery(outcome, async {
            self.state.storage().set_alarm(30_000_i64).await?;
            console_error!("Control recovery deferred; durable retry scheduled");
            Ok(())
        })
        .await
    }
    async fn control_targets(&self, id: &str, targets: &[String], op: &str) -> ApiResult<()> {
        // Bounded fanout keeps large accounts within runtime subrequest limits.
        for chunk in targets.chunks(16) {
            let results = futures_util::future::join_all(chunk.iter().map(|chat| async move {
                let response = routes::forward(
                    &self.env,
                    Call {
                        op: op.into(),
                        authority: authority::Authority {
                            chat_id: chat.clone(),
                            user_id: String::new(),
                            device_id: String::new(),
                            session_id: String::new(),
                        },
                        data: json!({"id":id}),
                    },
                )
                .await?;
                if response.status_code() != 200 {
                    return Err(ApiError::retryable("AUTHORITY_RETRY", 503));
                }
                Ok(())
            }))
            .await;
            for result in results {
                result?;
            }
        }
        Ok(())
    }

    async fn control_recover(&self) -> ApiResult<()> {
        let journals = self
            .store
            .sql()
            .exec(
                "SELECT id,targets FROM control_journal ORDER BY rowid",
                None,
            )?
            .to_array::<Journal>()?;
        let db = Db(self.env.d1("DB")?);
        for journal in journals {
            let targets: Vec<String> = serde_json::from_str(&journal.targets)
                .map_err(|_| ApiError::domain("CONTROL_STATE_INVALID", 503))?;
            db.0.batch(vec![
                db.statement("INSERT OR IGNORE INTO authority_operations(operation_id,status,created_at,completed_at) VALUES(?1,'ABORTED',?2,?2)",&[json!(journal.id),json!(http::now_iso())])?,
                db.statement("UPDATE authority_operations SET status='ABORTED',completed_at=?2 WHERE operation_id=?1 AND status='PENDING'",&[json!(journal.id),json!(http::now_iso())])?,
            ]).await?;
            self.control_targets(&journal.id, &targets, "release")
                .await?;
            self.store.sql().exec(
                "DELETE FROM control_journal WHERE id=?",
                vec![journal.id.into()],
            )?;
            self.store.durable().await?;
        }
        Ok(())
    }

    pub(super) async fn control_handle(&self, call: Call) -> ApiResult<Response> {
        let namespace = self.env.durable_object("CHAT_REALTIME")?;
        if self.state.id().to_string() != namespace.id_from_name(NAME)?.to_string() {
            return Err(ApiError::domain("NOT_FOUND", 404));
        }
        let _turn = self.send_lane.enter().await?;
        self.store.sql().exec(
            "CREATE TABLE IF NOT EXISTS registered_rooms(chat_id TEXT PRIMARY KEY)",
            None,
        )?;
        self.store.sql().exec(
            "CREATE TABLE IF NOT EXISTS control_journal(id TEXT PRIMARY KEY,targets TEXT NOT NULL)",
            None,
        )?;
        self.control_recover().await?;
        if call.op == "control.register" {
            if !is_uuid(&call.authority.chat_id) {
                return Err(ApiError::domain("VALIDATION_ERROR", 422));
            }
            let lease = authority::resolve(&self.env, &call.authority).await?;
            self.store.sql().exec(
                "INSERT OR IGNORE INTO registered_rooms VALUES(?)",
                vec![call.authority.chat_id.into()],
            )?;
            self.store.durable().await?;
            return http::json(&lease);
        }
        if call.op != "control.write" {
            if call.op == "control.owner" {
                return self
                    .execute_plan(crate::owner::prepare_control(&self.env, &call.data).await?)
                    .await;
            }
            return Err(ApiError::domain("NOT_FOUND", 404));
        }
        let cookie = call.data["cookie"]
            .as_str()
            .ok_or_else(|| ApiError::domain("SESSION_REQUIRED", 401))?;
        let request = Request::new("https://control.internal/", Method::Get)?;
        let mut request = request;
        request.headers_mut()?.set("Cookie", cookie)?;
        let actor = auth::require_session(&request, &self.env).await?;
        if actor.user_id != call.authority.user_id
            || actor.session_id != call.authority.session_id
            || actor.device_id != call.authority.device_id
        {
            return Err(ApiError::domain("SESSION_INVALID", 401));
        }
        let db = Db(self.env.d1("DB")?);
        let now = http::now_iso();
        let op = call.data["operation"].as_str().unwrap_or_default();
        let target = call.data["target"].as_str().unwrap_or_default();
        if op.starts_with("admin.") {
            return self
                .execute_plan(
                    crate::admin::prepare_control(
                        &self.env,
                        &actor,
                        op,
                        target,
                        &call.data["body"],
                    )
                    .await?,
                )
                .await;
        }
        if op.starts_with("identity.") {
            return self
                .execute_plan(
                    crate::identity::prepare_control(
                        &self.env,
                        &actor,
                        op,
                        target,
                        &call.data["body"],
                    )
                    .await?,
                )
                .await;
        }
        let mut statements = vec![];
        let clear_cookie = match op {
            "logout" => {
                statements.push(db.statement(
                    "UPDATE sessions SET revoked_at=?2 WHERE session_id=?1 AND revoked_at IS NULL",
                    &[json!(actor.session_id), json!(now)],
                )?);
                true
            }
            "session.revoke" => {
                auth::require_authorized(&actor)?;
                auth::require_recent(&actor)?;
                if !is_uuid(target) {
                    return Err(ApiError::domain("VALIDATION_ERROR", 422));
                }
                if db
                    .first::<Value>(
                        "SELECT 1 AS n FROM sessions WHERE session_id=?1 AND user_id=?2",
                        &[json!(target), json!(actor.user_id)],
                    )
                    .await?
                    .is_none()
                {
                    return Err(ApiError::domain("NOT_FOUND", 404));
                }
                statements.push(db.statement(
                    "UPDATE sessions SET revoked_at=?2 WHERE session_id=?1 AND revoked_at IS NULL",
                    &[json!(target), json!(now)],
                )?);
                target == actor.session_id
            }
            "device.revoke" => {
                auth::require_authorized(&actor)?;
                auth::require_recent(&actor)?;
                if !is_uuid(target) {
                    return Err(ApiError::domain("VALIDATION_ERROR", 422));
                }
                if db
                    .first::<Value>(
                        "SELECT 1 AS n FROM devices WHERE device_id=?1 AND user_id=?2",
                        &[json!(target), json!(actor.user_id)],
                    )
                    .await?
                    .is_none()
                {
                    return Err(ApiError::domain("NOT_FOUND", 404));
                }
                for sql in [
                    "UPDATE devices SET revoked_at=?2 WHERE device_id=?1 AND revoked_at IS NULL",
                    "UPDATE sessions SET revoked_at=?2 WHERE device_id=?1 AND revoked_at IS NULL",
                    "UPDATE device_certificates SET revoked_at=?2 WHERE device_id=?1 AND revoked_at IS NULL",
                    "UPDATE one_time_prekeys SET consumed_at=?2 WHERE device_id=?1 AND consumed_at IS NULL",
                    "UPDATE push_subscriptions SET revoked_at=?2 WHERE device_id=?1 AND revoked_at IS NULL",
                ] {
                    statements.push(db.statement(sql, &[json!(target), json!(now)])?);
                }
                statements.push(db.statement(
                    "DELETE FROM device_prekey_bundles WHERE device_id=?1",
                    &[json!(target)],
                )?);
                target == actor.device_id
            }
            _ => return Err(ApiError::domain("NOT_FOUND", 404)),
        };
        self.execute_plan(MutationPlan {
            statements,
            affected_users: vec![actor.user_id],
            affected_chats: vec![],
            response: Value::Null,
            status: 204,
            clear_cookie,
        })
        .await
    }

    async fn execute_plan(&self, plan: MutationPlan) -> ApiResult<Response> {
        let db = Db(self.env.d1("DB")?);
        let now = http::now_iso();
        let mut statements = plan.statements;
        let mut active: std::collections::BTreeSet<String> =
            plan.affected_chats.into_iter().collect();
        for user in plan.affected_users {
            for row in db
                .all(
                    "SELECT DISTINCT chat_id FROM active_chat_members WHERE user_id=?1",
                    &[json!(user)],
                )
                .await?
            {
                if let Some(id) = row["chat_id"].as_str() {
                    active.insert(id.into());
                }
            }
        }
        let registered = self
            .store
            .sql()
            .exec("SELECT chat_id FROM registered_rooms", None)?
            .to_array::<Value>()?;
        let targets: Vec<String> = active
            .into_iter()
            .filter(|id| {
                registered
                    .iter()
                    .any(|v| v["chat_id"].as_str() == Some(id.as_str()))
            })
            .collect();
        let id = http::random_id()?;
        // Arm before journaling: no crash after fencing can strand the room forever.
        self.state.storage().set_alarm(30_000_i64).await?;
        self.store.sql().exec(
            "INSERT INTO control_journal VALUES(?,?)",
            vec![id.clone().into(), json!(targets).to_string().into()],
        )?;
        self.store.durable().await?;
        let result:ApiResult<()>=async {
            db.run("INSERT INTO authority_operations(operation_id,status,created_at) VALUES(?1,'PENDING',?2)",&[json!(id),json!(now)]).await?;
            self.control_targets(&id,&targets,"fence").await?;
            statements.insert(0,db.statement("INSERT INTO auth_commit_guards(assertion_id,valid) VALUES(?1,CASE WHEN EXISTS(SELECT 1 FROM authority_operations WHERE operation_id=?1 AND status='PENDING') THEN 1 ELSE 0 END)",&[json!(id)])?);
            statements.push(db.statement("UPDATE authority_operations SET status='COMMITTED',completed_at=?2 WHERE operation_id=?1 AND status='PENDING'",&[json!(id),json!(now)])?);
            statements.push(db.statement("DELETE FROM auth_commit_guards WHERE assertion_id=?1",&[json!(id)])?);
            db.0.batch(statements).await?;
            Ok(())
        }.await;
        // Recovery preserves a committed marker; otherwise it aborts before releasing.
        self.control_recover().await?;
        result?;
        let mut response = if plan.status == 204 {
            Response::empty()?.with_status(204)
        } else {
            http::json(&plan.response)?.with_status(plan.status)
        };
        if plan.clear_cookie {
            response.headers_mut().set(
                "Set-Cookie",
                "__Host-session=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0",
            )?;
        }
        Ok(response)
    }
}

#[cfg(test)]
mod recovery_tests {
    use super::*;
    use futures_util::FutureExt;
    use std::cell::Cell;

    #[test]
    fn a_long_outage_keeps_scheduling_recovery_after_the_platform_retry_budget() {
        let scheduled = Cell::new(0);
        // Each iteration represents a new alarm invocation after eviction. This
        // exceeds the platform's six automatic retries without inbound traffic.
        for _ in 0..18 {
            let outcome =
                retry_failed_recovery(Err(ApiError::retryable("AUTHORITY_RETRY", 503)), async {
                    scheduled.set(scheduled.get() + 1);
                    Ok(())
                })
                .now_or_never();
            assert!(matches!(outcome, Some(Ok(()))));
        }
        assert_eq!(scheduled.get(), 18);
        let outcome = retry_failed_recovery(Ok(()), async {
            scheduled.set(scheduled.get() + 1);
            Ok(())
        })
        .now_or_never();
        assert!(matches!(outcome, Some(Ok(()))));
        assert_eq!(scheduled.get(), 18, "a drained journal stops waking up");
    }

    #[test]
    fn a_failed_alarm_write_is_not_swallowed() {
        let outcome =
            retry_failed_recovery(Err(ApiError::retryable("AUTHORITY_RETRY", 503)), async {
                Err(ApiError::retryable("ALARM_STORAGE_UNAVAILABLE", 503))
            })
            .now_or_never();
        assert!(matches!(outcome, Some(Err(_))));
    }
}
