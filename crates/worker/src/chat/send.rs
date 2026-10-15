//! Preparation overlaps, while admission order and durable publication stay FIFO.
use super::*;
use ratchet_core::ready_batch::{PreparationPermit, PreparationWindow, ReadyBatchQueue};
use std::{
    future::poll_fn,
    rc::Rc,
    task::{Poll, Waker},
};

#[derive(Default)]
struct Signals {
    epoch: Cell<u64>,
    waiters: RefCell<Vec<Waker>>,
}
impl Signals {
    fn wake(&self) {
        self.epoch.set(self.epoch.get().wrapping_add(1));
        let waiters = std::mem::take(&mut *self.waiters.borrow_mut());
        for waiter in waiters {
            waiter.wake();
        }
    }
    async fn changed(&self, epoch: u64) {
        poll_fn(|cx| {
            if self.epoch.get() != epoch {
                return Poll::Ready(());
            }
            let mut waiters = self.waiters.borrow_mut();
            if !waiters.iter().any(|w| w.will_wake(cx.waker())) {
                waiters.push(cx.waker().clone());
            }
            Poll::Pending
        })
        .await
    }
}

pub(super) struct SendQueue {
    ready: ReadyBatchQueue<Job>,
    window: PreparationWindow,
    draining: Cell<bool>,
    signals: Rc<Signals>,
}
impl SendQueue {
    pub(super) fn new() -> Self {
        let signals = Rc::new(Signals::default());
        let notify = signals.clone();
        let ready = ReadyBatchQueue::new();
        ready.set_notify(Rc::new(move || notify.wake()));
        Self {
            ready,
            window: PreparationWindow::new(64),
            draining: Cell::new(false),
            signals,
        }
    }
}
struct DrainGuard<'a>(&'a SendQueue);
impl Drop for DrainGuard<'_> {
    fn drop(&mut self) {
        self.0.draining.set(false);
        self.0.signals.wake();
    }
}
type Completion = Rc<RefCell<Option<ApiResult<Commit>>>>;
struct Prepared {
    row: Option<storage::Record>,
    fingerprint: String,
    ciphertext: String,
    lease: Lease,
    generation: u64,
    duplicate: bool,
}
struct Job {
    meta: Authority,
    input: SendRequest,
    prepared: Option<ApiResult<Prepared>>,
    completion: Completion,
    signals: Rc<Signals>,
    _permit: PreparationPermit,
}
impl Job {
    fn complete(self, result: ApiResult<Commit>) {
        *self.completion.borrow_mut() = Some(result);
        self.signals.wake();
    }
}
impl Drop for Job {
    fn drop(&mut self) {
        let mut completion = self.completion.borrow_mut();
        if completion.is_none() {
            *completion = Some(Err(ApiError::retryable("PERSIST_FAILED", 503)));
        }
        drop(completion);
        self.signals.wake();
    }
}

impl ChatRealtime {
    pub(super) async fn send_message(
        &self,
        meta: &Authority,
        input: &SendRequest,
    ) -> ApiResult<Commit> {
        // Both reservations precede the first await, including slow authorization.
        let ticket = self.sends.ready.reserve();
        let acquisition = self.sends.window.acquire();
        let permit = acquisition.await;
        let prepared = self.prepare_send(meta, input).await;
        let completion = Rc::new(RefCell::new(None));
        self.sends.ready.ready(
            ticket,
            Job {
                meta: meta.clone(),
                input: input.clone(),
                prepared: Some(prepared),
                completion: completion.clone(),
                signals: self.sends.signals.clone(),
                _permit: permit,
            },
        );
        loop {
            let epoch = self.sends.signals.epoch.get();
            self.drain_send_batch().await;
            if let Some(result) = completion.borrow_mut().take() {
                return result;
            }
            self.sends.signals.changed(epoch).await;
        }
    }

    async fn prepare_send(&self, meta: &Authority, input: &SendRequest) -> ApiResult<Prepared> {
        let lease = self.authorize(meta, false).await?;
        let generation = self.generation.get();
        let duplicate = self
            .store
            .lookup(&meta.device_id, &input.client_message_id)?
            .is_some();
        self.message_quota(meta, &lease, duplicate).await?;
        let author = Author {
            chat_id: meta.chat_id.clone(),
            user_id: meta.user_id.clone(),
            device_id: meta.device_id.clone(),
        };
        let (row, ciphertext) = self.with_crypto(&meta.chat_id, |crypto| {
            self.store
                .prepare(crypto, &author, input, lease.display_name.clone())
        })?;
        Ok(Prepared {
            fingerprint: row.fingerprint.clone(),
            row: Some(row),
            ciphertext,
            lease,
            generation,
            duplicate,
        })
    }

    async fn release_send_claims(&self, job: &Job, prepared: &Prepared) -> ApiResult<()> {
        if !prepared.duplicate && !job.input.attachment_ids.is_empty() {
            crate::files::release_claims(
                &crate::db::Db(self.env.d1("DB")?),
                &job.meta.chat_id,
                &job.input.client_message_id,
                &job.meta.device_id,
                &prepared.fingerprint,
                &job.input.attachment_ids,
            )
            .await?;
        }
        Ok(())
    }

    async fn claim_send(&self, job: &Job, prepared: &Prepared) -> ApiResult<()> {
        if prepared.duplicate || job.input.attachment_ids.is_empty() {
            return Ok(());
        }
        let auth = crate::auth::AuthContext {
            session_id: job.meta.session_id.clone(),
            user_id: job.meta.user_id.clone(),
            device_id: job.meta.device_id.clone(),
            role: prepared.lease.user_role.clone(),
            device_authorized: true,
            webauthn_verified_at: None,
            authenticator_verified_at: None,
        };
        if let Err(error) = crate::files::claim_attachments(
            &crate::db::Db(self.env.d1("DB")?),
            &auth,
            &job.meta.chat_id,
            &job.input.client_message_id,
            &prepared.fingerprint,
            &job.input.attachment_ids,
        )
        .await
        {
            if matches!(&error, ApiError::Domain(_)) {
                self.release_send_claims(job, prepared).await?;
            }
            return Err(error);
        }
        Ok(())
    }

    async fn drain_send_batch(&self) {
        if self.sends.draining.get() {
            return;
        }
        let jobs = self.sends.ready.take_ready(16);
        if jobs.is_empty() {
            return;
        }
        self.sends.draining.set(true);
        let _drain = DrainGuard(&self.sends);
        // Reconciliation cannot release an attachment between claiming and committing it.
        let _lane = match self.send_lane.enter().await {
            Ok(lane) => lane,
            Err(_) => return,
        };
        let mut staged = Vec::new();
        for mut job in jobs {
            let Some(prepared) = job.prepared.take() else {
                job.complete(Err(ApiError::retryable("PERSIST_FAILED", 503)));
                continue;
            };
            match prepared {
                Err(error) => job.complete(Err(error)),
                Ok(prepared) => match self.claim_send(&job, &prepared).await {
                    Ok(()) => staged.push((job, prepared)),
                    Err(error) => job.complete(Err(error)),
                },
            }
        }
        let mut accepted = Vec::new();
        let mut rejected = Vec::new();
        // No await from the first write through reserving the publication lane.
        // Each message retains its own transaction and idempotency validation.
        for (job, mut prepared) in staged {
            let commit = (|| {
                self.authority_cache.borrow().assert_open()?;
                if prepared.generation != self.generation.get() {
                    return Err(ApiError::retryable("AUTHORITY_RETRY", 503));
                }
                if !lease_current(prepared.lease.until, Date::now().as_millis() as f64) {
                    return Err(ApiError::domain("SESSION_INVALID", 401));
                }
                self.store.commit(
                    prepared
                        .row
                        .take()
                        .ok_or_else(|| ApiError::retryable("PERSIST_FAILED", 503))?,
                    prepared.lease.can_mutate,
                )
            })();
            match commit {
                Ok(commit) => accepted.push((job, prepared, commit)),
                Err(error) => rejected.push((job, prepared, error)),
            }
        }
        let publication = if accepted.is_empty() {
            Ok(None)
        } else {
            enter_publication(&self.publication_lane, async {
                self.schedule_projection().await?;
                self.store.durable().await
            })
            .await
            .map(Some)
        };
        for (job, prepared, error) in rejected {
            let error = if matches!(&error, ApiError::Domain(_)) {
                match self.release_send_claims(&job, &prepared).await {
                    Ok(()) => error,
                    Err(error) => error,
                }
            } else {
                error
            };
            job.complete(Err(error));
        }
        let Ok(_publication) = publication else {
            // A failed barrier is ambiguous: retain claims and let retries reconcile.
            return;
        };
        for (job, prepared, commit) in accepted {
            if !commit.duplicate
                && let Err(error) = self.publish_send(&job, &prepared, &commit)
            {
                job.complete(Err(error));
                continue;
            }
            job.complete(Ok(commit));
        }
    }

    fn publish_send(&self, job: &Job, prepared: &Prepared, commit: &Commit) -> ApiResult<()> {
        let meta = &job.meta;
        let input = &job.input;
        let env = self.env.clone();
        let chat = meta.chat_id.clone();
        let sender = meta.device_id.clone();
        self.state.wait_until(async move {
            let _ = crate::files::notify_push(&env, &chat, &sender).await;
        });
        for socket in self.state.get_websockets() {
            if let Some(peer) = socket.deserialize_attachment::<Authority>()?
                && self
                    .authority_cache
                    .borrow_mut()
                    .cached(&self.store.sql(), &peer)?
                    .is_some()
            {
                let event = json!({"type":"message.committed","chat_id":meta.chat_id,"message_id":commit.message_id,"client_message_id":commit.client_message_id,"sender_user_id":meta.user_id,"sender_device_id":meta.device_id,"sender_display_name":prepared.lease.display_name,"sender_sequence":input.sender_sequence,"revision":commit.revision,"accepted_at":commit.accepted_at,"mutation":input.mutation,"reply_to_message_id":input.reply_to_message_id,"envelope":{"recipient_user_id":peer.user_id,"recipient_device_id":peer.device_id,"protocol":"secure-messaging","protocol_version":2,"header":"server-sqlite-v1","ciphertext":prepared.ciphertext}});
                let _ = socket.send(&event);
            }
        }
        Ok(())
    }
}

fn lease_current(until: f64, now: f64) -> bool {
    until.is_finite() && until > now
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::FutureExt;

    #[test]
    fn lease_must_still_be_valid_at_commit() {
        assert!(lease_current(1001.0, 1000.0));
        assert!(!lease_current(1000.0, 1000.0));
        assert!(!lease_current(999.0, 1000.0));
        assert!(!lease_current(f64::INFINITY, 1000.0));
        assert!(!lease_current(f64::NAN, 1000.0));
    }

    #[test]
    fn notification_before_wait_is_not_lost_and_waiters_are_released() {
        let signals = Signals::default();
        let epoch = signals.epoch.get();
        signals.wake();
        assert!(signals.changed(epoch).now_or_never().is_some());
        let mut first = Box::pin(signals.changed(signals.epoch.get()));
        let mut second = Box::pin(signals.changed(signals.epoch.get()));
        assert!(first.as_mut().now_or_never().is_none());
        assert!(second.as_mut().now_or_never().is_none());
        signals.wake();
        assert!(signals.waiters.borrow().is_empty());
        assert!(first.as_mut().now_or_never().is_some());
        assert!(second.as_mut().now_or_never().is_some());
    }

    #[test]
    fn cancelled_batch_leader_releases_ownership_and_wakes_followers() {
        let queue = SendQueue::new();
        let epoch = queue.signals.epoch.get();
        let mut leader = Box::pin(async {
            queue.draining.set(true);
            let _guard = DrainGuard(&queue);
            std::future::pending::<()>().await;
        });
        assert!(leader.as_mut().now_or_never().is_none());
        assert!(queue.draining.get());
        drop(leader);
        assert!(!queue.draining.get());
        assert!(queue.signals.changed(epoch).now_or_never().is_some());
    }

    #[test]
    fn thousand_cooperative_jobs_finish_with_a_shared_barrier_per_ready_batch() {
        let queue = ReadyBatchQueue::new();
        let signals = Rc::new(Signals::default());
        let notify = signals.clone();
        queue.set_notify(Rc::new(move || notify.wake()));
        let draining = Cell::new(false);
        let durable = Cell::new(0);
        let published = RefCell::new(Vec::new());
        let jobs = (0..1000).map(|id| {
            let ticket = queue.reserve();
            let queue = &queue;
            let signals = &signals;
            let draining = &draining;
            let durable = &durable;
            let published = &published;
            async move {
                let completion = Rc::new(Cell::new(false));
                queue.ready(ticket, (id, completion.clone()));
                loop {
                    let epoch = signals.epoch.get();
                    if !draining.get() {
                        let batch = queue.take_ready(16);
                        if !batch.is_empty() {
                            draining.set(true);
                            let mut yielded = false;
                            poll_fn(|cx| {
                                if yielded {
                                    Poll::Ready(())
                                } else {
                                    yielded = true;
                                    cx.waker().wake_by_ref();
                                    Poll::Pending
                                }
                            })
                            .await;
                            durable.set(durable.get() + 1);
                            for (revision, done) in batch {
                                published.borrow_mut().push(revision);
                                done.set(true);
                            }
                            draining.set(false);
                            signals.wake();
                        }
                    }
                    if completion.get() {
                        break;
                    }
                    signals.changed(epoch).await;
                }
            }
        });
        let mut all = Box::pin(futures_util::future::join_all(jobs));
        let mut complete = false;
        for _ in 0..2000 {
            if all.as_mut().now_or_never().is_some() {
                complete = true;
                break;
            }
        }
        assert!(complete, "every queued handler must get a completion");
        assert_eq!(*published.borrow(), (0..1000).collect::<Vec<_>>());
        assert!(
            durable.get() < 100,
            "ready jobs share barriers without waiting to fill a batch"
        );
    }
}
