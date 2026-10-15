use super::{Call, ChatRealtime, control, routes};
use crate::{
    auth,
    db::Db,
    http::{self, ApiError, ApiResult},
};
use serde_json::{Value, json};
use worker::*;

async fn retry_failed_projection(
    outcome: ApiResult<()>,
    scheduled: &std::cell::Cell<bool>,
    rearm: impl std::future::Future<Output = ApiResult<()>>,
) -> ApiResult<()> {
    if outcome.is_err() {
        // A failed alarm persistence must let the next message schedule work.
        scheduled.set(false);
        rearm.await?;
        scheduled.set(true);
    }
    Ok(())
}

pub async fn list(request: &Request, env: &Env) -> ApiResult<Response> {
    let actor = auth::require_session(request, env).await?;
    auth::require_authorized(&actor)?;
    let mut rows = Db(env.d1("DB")?)
        .all(include_str!("list.sql"), &[json!(actor.user_id)])
        .await?;
    for row in &mut rows {
        row["customer_has_account"] =
            if actor.role == "ADMIN" && !row["customer_has_account"].is_null() {
                json!(row["customer_has_account"] == 1)
            } else {
                Value::Null
            };
        if actor.role != "ADMIN" {
            for key in [
                "customer_user_id",
                "referred_by_user_id",
                "referred_by_display_name",
                "referred_by_staff_role",
                "customer_display_name",
            ] {
                row[key] = Value::Null;
            }
        }
    }
    http::json(&json!({"chats":rows}))
}

pub async fn detail(env: &Env, actor: &auth::AuthContext, chat: &str) -> ApiResult<Response> {
    let db = Db(env.d1("DB")?);
    let mut row=db.first::<Value>("SELECT c.chat_id,c.workspace_id,c.created_at,r.revision,r.message_revision,r.receipt_revision,r.mutation_revision,r.device_revision FROM chats c JOIN chat_revisions r ON r.chat_id=c.chat_id JOIN active_chat_members m ON m.chat_id=c.chat_id AND m.user_id=?2 WHERE c.chat_id=?1",&[json!(chat),json!(actor.user_id)]).await?.ok_or_else(||ApiError::domain("CHAT_NOT_AVAILABLE",403))?;
    let mut response = routes::forward(
        env,
        Call {
            op: "stats".into(),
            authority: routes::authority(actor, chat),
            data: Value::Null,
        },
    )
    .await?;
    if response.status_code() != 200 {
        return Ok(response);
    }
    let stats: Value = response.json().await?;
    row["revision"] = stats["revision"].clone();
    row["participants"]=json!(db.all("SELECT user_id,participant_role,joined_at FROM active_chat_members WHERE chat_id=?1 ORDER BY CASE participant_role WHEN 'CUSTOMER' THEN 0 ELSE 1 END,joined_at,user_id",&[json!(chat)]).await?);
    http::json(&row)
}

impl ChatRealtime {
    pub(super) async fn schedule_projection(&self) -> ApiResult<()> {
        if !self.projection_scheduled.replace(true)
            && let Err(error) = self.state.storage().set_alarm(1000_i64).await
        {
            self.projection_scheduled.set(false);
            return Err(error.into());
        }
        Ok(())
    }
    pub(super) async fn project_stats(&self) -> ApiResult<()> {
        let ns = self.env.durable_object("CHAT_REALTIME")?;
        if self.state.id().to_string() == ns.id_from_name(control::NAME)?.to_string() {
            return self.recover_control_alarm().await;
        }
        let outcome = self.project_stats_once().await;
        retry_failed_projection(outcome, &self.projection_scheduled, async {
            self.state.storage().set_alarm(30_000_i64).await?;
            console_error!("Statistics projection deferred; durable retry scheduled");
            Ok(())
        })
        .await
    }
    async fn project_stats_once(&self) -> ApiResult<()> {
        self.ensure()?;
        let rows = self
            .store
            .sql()
            .exec("SELECT chat_id FROM chat_messages LIMIT 1", None)?
            .to_array::<Value>()?;
        if let Some(chat) = rows.first().and_then(|v| v["chat_id"].as_str()) {
            let stats = self.store.stats()?;
            self.store.durable().await?;
            Db(self.env.d1("DB")?).run("INSERT INTO chat_storage_stats(chat_id,revision,message_count,last_message_at,last_sender_user_id,updated_at) VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(chat_id) DO UPDATE SET revision=excluded.revision,message_count=excluded.message_count,last_message_at=excluded.last_message_at,last_sender_user_id=excluded.last_sender_user_id,updated_at=excluded.updated_at WHERE excluded.revision>=chat_storage_stats.revision",&[json!(chat),stats["revision"].clone(),stats["message_count"].clone(),stats["last_message_at"].clone(),stats["last_sender_user_id"].clone(),json!(http::now_iso())]).await?;
            self.projection_scheduled.set(false);
            if self.store.revision()? > stats["revision"].as_u64().unwrap_or(0) {
                self.schedule_projection().await?;
            }
        } else {
            self.projection_scheduled.set(false);
        }
        Ok(())
    }
}

#[cfg(test)]
mod projection_retry_tests {
    use super::*;
    use futures_util::FutureExt;
    use std::cell::Cell;

    #[test]
    fn prolonged_projection_failure_keeps_a_durable_wakeup() {
        let scheduled = Cell::new(true);
        let alarms = Cell::new(0);
        for _ in 0..18 {
            let outcome = retry_failed_projection(
                Err(ApiError::retryable("D1_UNAVAILABLE", 503)),
                &scheduled,
                async {
                    alarms.set(alarms.get() + 1);
                    Ok(())
                },
            )
            .now_or_never();
            assert!(matches!(outcome, Some(Ok(()))));
            assert!(scheduled.get());
        }
        assert_eq!(alarms.get(), 18);
        scheduled.set(false); // A completed projection clears its scheduling flag.
        let outcome = retry_failed_projection(Ok(()), &scheduled, async {
            alarms.set(alarms.get() + 1);
            Ok(())
        })
        .now_or_never();
        assert!(matches!(outcome, Some(Ok(()))));
        assert!(!scheduled.get());
        assert_eq!(alarms.get(), 18);
    }

    #[test]
    fn failed_alarm_persistence_allows_the_next_message_to_schedule_projection() {
        let scheduled = Cell::new(true);
        let outcome = retry_failed_projection(
            Err(ApiError::retryable("D1_UNAVAILABLE", 503)),
            &scheduled,
            async { Err(ApiError::retryable("ALARM_STORAGE_UNAVAILABLE", 503)) },
        )
        .now_or_never();
        assert!(matches!(outcome, Some(Err(_))));
        assert!(!scheduled.get());
    }
}
