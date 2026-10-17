pub(crate) mod authority;
pub(crate) mod capacity;
pub mod control;
pub mod metadata;
mod realtime_limits;
pub mod routes;
mod send;
mod storage;
mod timing;
use crate::http::{self, ApiError, ApiResult};
use authority::{Authority, Lease};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ratchet_core::{
    message::{Author, SendRequest, is_uuid},
    storage_crypto::StorageCrypto,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, BTreeSet},
};
use storage::{Commit, Store};
use worker::*;

#[derive(Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum IncomingFrame {
    #[serde(rename = "ping")]
    Ping {
        #[serde(default)]
        after_revision: Option<u64>,
    },
    #[serde(rename = "message.send")]
    Send { request: SendRequest },
}

#[derive(Serialize, Deserialize)]
pub struct Call {
    pub op: String,
    pub authority: Authority,
    #[serde(default)]
    pub data: Value,
}

#[durable_object]
pub struct ChatRealtime {
    state: State,
    env: Env,
    store: Store,
    initialized: Cell<bool>,
    registered: Cell<bool>,
    projection_scheduled: Cell<bool>,
    generation: Cell<u64>,
    peer_refreshes: Cell<usize>,
    crypto: RefCell<Option<StorageCrypto>>,
    authority_cache: RefCell<authority::LocalAuthority>,
    send_lane: ratchet_core::lane::FifoLane,
    sends: send::SendQueue,
    timing_probe_enabled: bool,
    publication_lane: ratchet_core::lane::FifoLane,
    last_presence: RefCell<Option<BTreeSet<String>>>,
}

// Poll the FIFO reservation before starting storage awaits. Later commits may
// become durable concurrently, but their notifications cannot overtake this one.
async fn enter_publication(
    lane: &ratchet_core::lane::FifoLane,
    durable: impl std::future::Future<Output = ApiResult<()>>,
) -> ApiResult<ratchet_core::lane::LaneGuard> {
    let (publication, ()) =
        futures_util::try_join!(async { Ok::<_, ApiError>(lane.enter().await?) }, durable,)?;
    Ok(publication)
}

// Release revalidates peers across D1 awaits. A close event can interleave those
// awaits, so presence must stay paused until every overlapping refresh finishes.
// Cancellation fails closed only for the generation owned by this guard.
struct PeerRefresh<'a, F: FnOnce()> {
    active: &'a Cell<usize>,
    generation: &'a Cell<u64>,
    started: u64,
    abort: Option<F>,
}

impl<'a, F: FnOnce()> PeerRefresh<'a, F> {
    fn begin(active: &'a Cell<usize>, generation: &'a Cell<u64>, abort: F) -> Self {
        active.set(active.get() + 1);
        Self {
            active,
            generation,
            started: generation.get(),
            abort: Some(abort),
        }
    }

    fn finish(mut self) {
        self.abort = None;
    }
}

impl<F: FnOnce()> Drop for PeerRefresh<'_, F> {
    fn drop(&mut self) {
        self.active.set(self.active.get() - 1);
        if self.generation.get() == self.started
            && let Some(abort) = self.abort.take()
        {
            abort();
        }
    }
}

impl ChatRealtime {
    fn peer_grants_ready(&self) -> bool {
        self.peer_refreshes.get() == 0 && self.authority_cache.borrow().assert_open().is_ok()
    }

    fn ensure(&self) -> ApiResult<()> {
        if !self.initialized.get() {
            self.store.initialize()?;
            realtime_limits::initialize(&self.store.sql())?;
            self.authority_cache
                .borrow_mut()
                .initialize(&self.store.sql())?;
            self.initialized.set(true);
            self.live_peers()?;
        }
        Ok(())
    }
    fn with_crypto<T>(
        &self,
        chat_id: &str,
        f: impl FnOnce(&StorageCrypto) -> ApiResult<T>,
    ) -> ApiResult<T> {
        let mut cell = self.crypto.borrow_mut();
        if cell.is_none() {
            let encoded = self.env.secret("MESSAGE_STORAGE_KEY")?.to_string();
            let mut master: [u8; 32] = URL_SAFE_NO_PAD
                .decode(encoded)
                .ok()
                .and_then(|b| b.try_into().ok())
                .ok_or_else(|| ApiError::domain("SERVER_CONFIGURATION_ERROR", 503))?;
            let keys = StorageCrypto::new(&master, chat_id);
            master.fill(0);
            *cell = Some(keys?);
        }
        f(cell
            .as_ref()
            .ok_or_else(|| ApiError::domain("SERVER_CONFIGURATION_ERROR", 503))?)
    }
    async fn authorize(&self, meta: &Authority, fresh: bool) -> ApiResult<Lease> {
        self.ensure()?;
        let namespace = self.env.durable_object("CHAT_REALTIME")?;
        if self.state.id().to_string() != namespace.id_from_name(&meta.chat_id)?.to_string() {
            return Err(ApiError::domain("CHAT_NOT_AVAILABLE", 403));
        }
        self.authority_cache.borrow().assert_open()?;
        if !fresh
            && let Some(lease) = self
                .authority_cache
                .borrow_mut()
                .cached(&self.store.sql(), meta)?
        {
            return Ok(lease);
        }
        let generation = self.generation.get();
        let lease = if self.registered.get() {
            authority::resolve(&self.env, meta).await?
        } else {
            let mut response = routes::forward(
                &self.env,
                Call {
                    op: "control.register".into(),
                    authority: meta.clone(),
                    data: Value::Null,
                },
            )
            .await?;
            if response.status_code() != 200 {
                if response.status_code() == 403 {
                    return Err(ApiError::domain("CHAT_NOT_AVAILABLE", 403));
                }
                return Err(ApiError::retryable("AUTHORITY_RETRY", 503));
            }
            let lease: Lease = response.json().await?;
            self.registered.set(true);
            lease
        };
        if generation != self.generation.get() {
            return Err(ApiError::retryable("AUTHORITY_RETRY", 503));
        }
        self.authority_cache
            .borrow_mut()
            .save(&self.store.sql(), meta, &lease)?;
        Ok(lease)
    }
    async fn message_quota(
        &self,
        meta: &Authority,
        lease: &Lease,
        duplicate: bool,
        probe: &mut timing::Probe,
    ) -> ApiResult<()> {
        let started = probe.now();
        let allowed = self
            .env
            .rate_limiter("MESSAGE_RATE_LIMITER")?
            .limit(format!("message:{}:{}", meta.user_id, meta.device_id))
            .await?
            .success;
        probe.record("quota_device_io", started);
        if !allowed {
            return Err(ApiError::retryable("MESSAGE_RATE_LIMITED", 503));
        }
        if lease.user_role == "CUSTOMER" && !duplicate {
            for binding in [
                "CUSTOMER_MESSAGE_BURST_RATE_LIMITER",
                "CUSTOMER_MESSAGE_SUSTAINED_RATE_LIMITER",
            ] {
                let started = probe.now();
                let allowed = self
                    .env
                    .rate_limiter(binding)?
                    .limit(format!("customer:{}", meta.user_id))
                    .await?
                    .success;
                probe.record(
                    if binding == "CUSTOMER_MESSAGE_BURST_RATE_LIMITER" {
                        "quota_customer_burst_io"
                    } else {
                        "quota_customer_sustained_io"
                    },
                    started,
                );
                if !allowed {
                    return Err(ApiError::retryable("CUSTOMER_MESSAGE_RATE_LIMITED", 429));
                }
            }
        }
        Ok(())
    }
    fn live_peers(&self) -> ApiResult<Vec<(WebSocket, Authority)>> {
        let mut peers = Vec::new();
        let mut users = BTreeMap::<String, usize>::new();
        let mut devices = BTreeMap::<(String, String), usize>::new();
        // Fences and in-flight refreshes invalidate grants without expiring the
        // underlying sessions. Retain and count those sockets; presence remains
        // paused until fresh authorization has completed. This also lets a cold
        // instance recover a persisted fence instead of failing inside ensure().
        let grants_ready = self.peer_grants_ready();
        for socket in self.state.get_websockets() {
            let Some(peer) = socket.deserialize_attachment::<Authority>()? else {
                let _ = socket.close(Some(4001), Some("Session required"));
                continue;
            };
            if grants_ready
                && self
                    .authority_cache
                    .borrow_mut()
                    .cached(&self.store.sql(), &peer)?
                    .is_none()
            {
                let _ = socket.close(Some(4001), Some("Session expired"));
                continue;
            }
            let user_count = users.entry(peer.user_id.clone()).or_default();
            let device_count = devices
                .entry((peer.user_id.clone(), peer.device_id.clone()))
                .or_default();
            if peers.len() >= realtime_limits::SOCKETS_PER_ROOM
                || *user_count >= realtime_limits::SOCKETS_PER_USER
                || *device_count >= realtime_limits::SOCKETS_PER_DEVICE
            {
                let _ = socket.close(Some(1008), Some("Connection limit"));
                continue;
            }
            *user_count += 1;
            *device_count += 1;
            peers.push((socket, peer));
        }
        Ok(peers)
    }
    fn admit_connection(&self, meta: &Authority) -> ApiResult<()> {
        let peers = self.live_peers()?;
        if peers.len() >= realtime_limits::SOCKETS_PER_ROOM
            || peers
                .iter()
                .filter(|(_, p)| p.user_id == meta.user_id)
                .count()
                >= realtime_limits::SOCKETS_PER_USER
            || peers
                .iter()
                .filter(|(_, p)| p.user_id == meta.user_id && p.device_id == meta.device_id)
                .count()
                >= realtime_limits::SOCKETS_PER_DEVICE
        {
            return Err(ApiError::retryable("REALTIME_CONNECTION_LIMIT", 429));
        }
        Ok(())
    }
    fn presence(&self, chat_id: &str, newcomer: Option<&WebSocket>) -> ApiResult<()> {
        if !self.peer_grants_ready() {
            return Ok(());
        }
        let peers = self.live_peers()?;
        let users: BTreeSet<_> = peers.iter().map(|(_, peer)| peer.user_id.clone()).collect();
        let changed = self.last_presence.borrow().as_ref() != Some(&users);
        let event = json!({"type":"presence.changed","chat_id":chat_id,"online_user_ids":users,"observed_at":http::now_iso()});
        if changed {
            for (socket, _) in peers {
                let _ = socket.send(&event);
            }
            *self.last_presence.borrow_mut() = Some(users);
        } else if let Some(socket) = newcomer {
            // Another tab for an already-online user only needs its own snapshot.
            let _ = socket.send(&event);
        }
        Ok(())
    }
    async fn handle(&self, mut request: Request) -> ApiResult<Response> {
        self.ensure()?;
        let call: Call = if request.method() == Method::Get {
            let value = request
                .headers()
                .get("X-Ratchet-Call")?
                .ok_or_else(|| ApiError::domain("VALIDATION_ERROR", 422))?;
            serde_json::from_str(&value).map_err(|_| ApiError::domain("VALIDATION_ERROR", 422))?
        } else {
            http::read_json(&mut request, 2 * 1024 * 1024 + 4096).await?
        };
        if call.op.starts_with("control.") {
            return self.control_handle(call).await;
        }
        let meta = &call.authority;
        if !is_uuid(&meta.chat_id) {
            return Err(ApiError::domain("VALIDATION_ERROR", 422));
        }
        if call.op == "capacity.reconcile" {
            let namespace = self.env.durable_object("CHAT_REALTIME")?;
            if self.state.id().to_string() != namespace.id_from_name(&meta.chat_id)?.to_string() {
                return Err(ApiError::domain("CHAT_NOT_AVAILABLE", 403));
            }
            self.store.ensure_capacity(&self.env, &meta.chat_id).await?;
            self.store.durable().await?;
            return http::json(&json!({"ok":true}));
        }
        if call.op == "fence" || call.op == "release" {
            let id = call.data["id"]
                .as_str()
                .ok_or_else(|| ApiError::domain("VALIDATION_ERROR", 422))?;
            self.generation.set(self.generation.get() + 1);
            let refresh = (call.op == "release").then(|| {
                PeerRefresh::begin(&self.peer_refreshes, &self.generation, || {
                    self.authority_cache.borrow_mut().invalidate();
                })
            });
            self.authority_cache.borrow_mut().invalidate();
            // A new tab accepted during refresh still needs its first snapshot,
            // even when revalidation leaves the set of online users unchanged.
            *self.last_presence.borrow_mut() = None;
            self.registered.set(true);
            self.store
                .sql()
                .exec("DELETE FROM connection_grants", None)?;
            if call.op == "fence" {
                self.store
                    .sql()
                    .exec(include_str!("fence.sql"), vec![id.into()])?;
                self.authority_cache
                    .borrow_mut()
                    .refresh(&self.store.sql())?;
            } else {
                self.store.sql().exec(
                    "INSERT OR IGNORE INTO authority_releases VALUES(?)",
                    vec![id.into()],
                )?;
                self.store
                    .sql()
                    .exec("DELETE FROM authority_fence WHERE id=?", vec![id.into()])?;
                self.authority_cache
                    .borrow_mut()
                    .refresh(&self.store.sql())?;
                for socket in self.state.get_websockets() {
                    if let Some(peer) = socket.deserialize_attachment::<Authority>()? {
                        match self.authorize(&peer, true).await {
                            Ok(_) => {}
                            Err(ApiError::Domain(error)) if error.status < 500 => {
                                let _ = socket.close(Some(4001), Some("Session ended"));
                            }
                            Err(_) => {
                                let _ = socket.close(Some(1013), Some("Please reconnect"));
                            }
                        }
                    }
                }
            }
            self.store.durable().await?;
            if let Some(refresh) = refresh {
                refresh.finish();
                self.presence(&meta.chat_id, None)?;
            }
            return http::json(&json!({"ok":true}));
        }
        if call.op == "owner.read" {
            let ns = self.env.durable_object("CHAT_REALTIME")?;
            if self.state.id().to_string() != ns.id_from_name(&meta.chat_id)?.to_string() {
                return Err(ApiError::domain("CHAT_NOT_AVAILABLE", 403));
            }
            crate::owner::require_chat(&self.env, &call.data, &meta.chat_id).await?;
            let after = call.data["after"]
                .as_u64()
                .filter(|n| *n <= ratchet_core::message::MAX_SAFE_INTEGER)
                .ok_or_else(|| ApiError::domain("VALIDATION_ERROR", 422))?;
            let limit = call.data["limit"]
                .as_u64()
                .filter(|n| (1..=100).contains(n))
                .ok_or_else(|| ApiError::domain("VALIDATION_ERROR", 422))?;
            let data = self.with_crypto(&meta.chat_id, |crypto| {
                self.store.sync(crypto, &meta.chat_id, after, limit as u32)
            })?;
            self.store.durable().await?;
            crate::owner::require_chat(&self.env, &call.data, &meta.chat_id).await?;
            return http::json(&data);
        }
        if call.op == "attachments.reconcile" {
            let ns = self.env.durable_object("CHAT_REALTIME")?;
            if self.state.id().to_string() != ns.id_from_name(&meta.chat_id)?.to_string() {
                return Err(ApiError::domain("CHAT_NOT_AVAILABLE", 403));
            }
            let _turn = self.send_lane.enter().await?;
            let client = call.data["client_message_id"]
                .as_str()
                .ok_or_else(|| ApiError::domain("VALIDATION_ERROR", 422))?;
            let device = call.data["sender_device_id"]
                .as_str()
                .ok_or_else(|| ApiError::domain("VALIDATION_ERROR", 422))?;
            let fingerprint = call.data["fingerprint"]
                .as_str()
                .ok_or_else(|| ApiError::domain("VALIDATION_ERROR", 422))?;
            let id = call.data["file_id"]
                .as_str()
                .ok_or_else(|| ApiError::domain("VALIDATION_ERROR", 422))?;
            if self.store.lookup(device, client)?.is_none() {
                crate::files::release_claims(
                    &crate::db::Db(self.env.d1("DB")?),
                    &meta.chat_id,
                    client,
                    device,
                    fingerprint,
                    &[id.into()],
                )
                .await?;
            } else {
                self.store.durable().await?;
                crate::db::Db(self.env.d1("DB")?).run("DELETE FROM chat_storage_attachment_claims WHERE file_id=?1 AND chat_id=?2 AND client_message_id=?3 AND sender_device_id=?4 AND fingerprint=?5",&[json!(id),json!(meta.chat_id),json!(client),json!(device),json!(fingerprint)]).await?;
            }
            return http::json(&json!({"ok":true}));
        }
        let lease = self.authorize(meta, call.op != "send").await?;
        match call.op.as_str() {
            "open" => {
                self.admit_connection(meta)?;
                let pair = WebSocketPair::new()?;
                pair.server.serialize_attachment(meta)?;
                self.state.accept_web_socket(&pair.server);
                pair.server.send(&json!({"type":"realtime.ready","chat_id":meta.chat_id,"revision":self.store.revision()?}))?;
                self.presence(&meta.chat_id, Some(&pair.server))?;
                Ok(Response::from_websocket(pair.client)?)
            }
            "send" => {
                let input: SendRequest = serde_json::from_value(call.data)
                    .map_err(|_| ApiError::domain("VALIDATION_ERROR", 422))?;
                let commit = self.send_message(meta, &input).await?;
                Ok(http::json(&commit)?.with_status(if commit.duplicate { 200 } else { 201 }))
            }
            "sequence" => {
                http::json(&json!({"next_sequence":self.store.sequence(&meta.device_id)?}))
            }
            "lookup" => {
                let id = call.data["id"]
                    .as_str()
                    .filter(|id| is_uuid(id))
                    .ok_or_else(|| ApiError::domain("VALIDATION_ERROR", 422))?;
                match self.store.lookup(&meta.device_id, id)? {
                    Some(row) => http::json(
                        &json!({"accepted":true,"message_id":row.metadata.message_id,"client_message_id":id,"revision":row.revision,"accepted_at":row.created_at}),
                    ),
                    None => http::json(&json!({"accepted":false,"client_message_id":id})),
                }
            }
            "stats" => http::json(&self.store.stats()?),
            "sync" => {
                let after = call.data["after"]
                    .as_u64()
                    .filter(|n| *n <= ratchet_core::message::MAX_SAFE_INTEGER)
                    .ok_or_else(|| ApiError::domain("VALIDATION_ERROR", 422))?;
                let limit = call.data["limit"]
                    .as_u64()
                    .filter(|n| (1..=200).contains(n))
                    .ok_or_else(|| ApiError::domain("VALIDATION_ERROR", 422))?;
                self.with_crypto(&meta.chat_id, |crypto| {
                    http::json(
                        &self
                            .store
                            .sync(crypto, &meta.chat_id, after, limit as u32)?,
                    )
                })
            }
            "receipts" => {
                let entries = call.data["receipts"]
                    .as_array()
                    .ok_or_else(|| ApiError::domain("VALIDATION_ERROR", 422))?;
                let id = call.data["request_id"]
                    .as_str()
                    .filter(|id| is_uuid(id))
                    .ok_or_else(|| ApiError::domain("VALIDATION_ERROR", 422))?;
                storage::receipt_entries(entries.clone())?;
                let generation = self.generation.get();
                // Known request IDs still undergo exact fingerprint validation in
                // Store::receipts, but a replay needs no new storage credit.
                if !self.store.receipt_request_known(&meta.user_id, id)? {
                    self.store
                        .ensure_capacity_for(
                            &self.env,
                            &meta.chat_id,
                            entries.len() as u64 * 2048 + 1024,
                            entries.len() as u64 * 2 + 1,
                        )
                        .await?;
                }
                self.authority_cache.borrow().assert_open()?;
                if generation != self.generation.get() {
                    return Err(ApiError::retryable("AUTHORITY_RETRY", 503));
                }
                if lease.until <= Date::now().as_millis() as f64
                    || self
                        .authority_cache
                        .borrow_mut()
                        .cached(&self.store.sql(), meta)?
                        .is_none()
                {
                    return Err(ApiError::domain("SESSION_INVALID", 401));
                }
                let receipts =
                    self.store
                        .receipts(meta.user_id.clone(), entries.clone(), id.into())?;
                let _publication = enter_publication(&self.publication_lane, async {
                    self.schedule_projection().await?;
                    self.store.durable().await
                })
                .await?;
                for row in receipts.iter().filter(|r| r["duplicate"] == false) {
                    let event = json!({"type":"receipt.committed","chat_id":meta.chat_id,"revision":row["revision"],"message_id":row["message_id"],"user_id":meta.user_id,"state":row["state"]});
                    for socket in self.state.get_websockets() {
                        if let Some(peer) = socket.deserialize_attachment::<Authority>()?
                            && self
                                .authority_cache
                                .borrow_mut()
                                .cached(&self.store.sql(), &peer)?
                                .is_some()
                        {
                            let _ = socket.send(&event);
                        }
                    }
                }
                http::json(&json!({"receipts":receipts}))
            }
            _ => Err(ApiError::domain("NOT_FOUND", 404)),
        }
    }
}

impl DurableObject for ChatRealtime {
    fn new(state: State, env: Env) -> Self {
        let store = Store::new(state.storage());
        let timing_probe_enabled = env
            .var("RATCHET_TIMING_PROBE")
            .is_ok_and(|v| v.to_string() == "sample10");
        Self {
            state,
            env,
            store,
            initialized: Cell::new(false),
            registered: Cell::new(false),
            projection_scheduled: Cell::new(false),
            generation: Cell::new(0),
            peer_refreshes: Cell::new(0),
            crypto: RefCell::new(None),
            authority_cache: RefCell::new(authority::LocalAuthority::new()),
            send_lane: ratchet_core::lane::FifoLane::new(),
            sends: send::SendQueue::new(),
            timing_probe_enabled,
            publication_lane: ratchet_core::lane::FifoLane::new(),
            last_presence: RefCell::new(None),
        }
    }
    async fn fetch(&self, request: Request) -> Result<Response> {
        match self.handle(request).await {
            Ok(r) => Ok(r),
            Err(error) => error.response("chat-runtime"),
        }
    }
    async fn alarm(&self) -> Result<Response> {
        self.project_stats()
            .await
            .map_err(|_| Error::RustError("Authority recovery must retry".into()))?;
        Response::empty()
    }
    async fn websocket_message(
        &self,
        socket: WebSocket,
        message: WebSocketIncomingMessage,
    ) -> Result<()> {
        let entry_started = timing::snapshot(self.timing_probe_enabled);
        let Some(meta) = socket.deserialize_attachment::<Authority>()? else {
            return socket.close(Some(4001), Some("Session required"));
        };
        if self.ensure().is_err() {
            return socket.close(Some(1013), Some("Please reconnect"));
        }
        let size = match &message {
            WebSocketIncomingMessage::String(value) => value.len(),
            WebSocketIncomingMessage::Binary(value) => value.len(),
        };
        match realtime_limits::admit(
            &self.store.sql(),
            &meta,
            size,
            Date::now().as_millis() as i64,
        ) {
            Ok(true) => {}
            Ok(false) => return socket.close(Some(1008), Some("Frame budget exceeded")),
            Err(_) => return socket.close(Some(1013), Some("Please reconnect")),
        }
        let raw = match message {
            WebSocketIncomingMessage::String(s) if s.len() <= realtime_limits::MAX_FRAME_BYTES => s,
            _ => return socket.close(Some(1009), Some("Invalid frame")),
        };
        let value: IncomingFrame = match serde_json::from_str(&raw) {
            Ok(v) => v,
            Err(_) => return socket.close(Some(1003), Some("Invalid JSON")),
        };
        match value {
            IncomingFrame::Ping { after_revision } => {
                if after_revision
                    .is_some_and(|revision| revision > ratchet_core::message::MAX_SAFE_INTEGER)
                {
                    return socket.close(Some(1003), Some("Invalid revision"));
                }
                match self.authorize(&meta, false).await {
                    Ok(_) => {}
                    Err(ApiError::Domain(error)) if error.retryable || error.status >= 500 => {
                        return Ok(());
                    }
                    Err(ApiError::Domain(_)) => {
                        return socket.close(Some(4001), Some("Session expired"));
                    }
                    Err(_) => return Ok(()),
                }
                socket.send(&json!({"type":"pong","chat_id":meta.chat_id,"revision":self.store.revision().unwrap_or_default()}))?;
            }
            IncomingFrame::Send { request: input } => {
                let id = &input.client_message_id;
                let decoded_at = timing::snapshot(self.timing_probe_enabled);
                let result = self
                    .send_message_timed(&meta, &input, Some((entry_started, decoded_at)))
                    .await;
                match result{Ok(commit)=>socket.send(&json!({"type":"message.ack","chat_id":meta.chat_id,"message_id":commit.message_id,"client_message_id":commit.client_message_id,"revision":commit.revision,"accepted_at":commit.accepted_at,"duplicate":commit.duplicate}))?,Err(error)=>{let(error_type,retryable)=match error{ApiError::Domain(e)=>(e.code,e.retryable),ApiError::Runtime(_)=>("PERSIST_FAILED",true)};socket.send(&json!({"type":"message.nack","chat_id":meta.chat_id,"client_message_id":id,"error_type":error_type,"retryable":retryable}))?;}}
            }
        }
        Ok(())
    }
    async fn websocket_close(
        &self,
        socket: WebSocket,
        _code: usize,
        _reason: String,
        _clean: bool,
    ) -> Result<()> {
        if let Some(meta) = socket.deserialize_attachment::<Authority>()? {
            let _ = self.presence(&meta.chat_id, None);
        }
        Ok(())
    }
    async fn websocket_error(&self, socket: WebSocket, _error: Error) -> Result<()> {
        socket.close(Some(1011), Some("Socket error"))
    }
}

#[cfg(test)]
mod publication_tests {
    use super::*;
    use futures_util::FutureExt;
    use std::future::poll_fn;
    use std::task::Poll;

    #[test]
    fn peer_refresh_stays_paused_until_all_overlapping_refreshes_complete() {
        let active = Cell::new(0);
        let generation = Cell::new(1);
        let invalidated = Cell::new(0);
        let first = PeerRefresh::begin(&active, &generation, || {
            invalidated.set(invalidated.get() + 1)
        });
        assert_eq!(active.get(), 1);
        generation.set(2);
        let second = PeerRefresh::begin(&active, &generation, || {
            invalidated.set(invalidated.get() + 1)
        });
        first.finish();
        assert_eq!(
            active.get(),
            1,
            "an older refresh cannot enable presence during the newer refresh"
        );
        second.finish();
        assert_eq!(active.get(), 0);
        assert_eq!(invalidated.get(), 0);
    }

    #[test]
    fn cancelled_peer_refresh_fails_closed_without_invalidating_a_newer_generation() {
        let active = Cell::new(0);
        let generation = Cell::new(1);
        let invalidated = Cell::new(0);
        let interrupted = PeerRefresh::begin(&active, &generation, || {
            invalidated.set(invalidated.get() + 1)
        });
        drop(interrupted);
        assert_eq!(invalidated.get(), 1);
        assert_eq!(active.get(), 0);

        let old = PeerRefresh::begin(&active, &generation, || {
            invalidated.set(invalidated.get() + 1)
        });
        generation.set(2);
        let current = PeerRefresh::begin(&active, &generation, || {
            invalidated.set(invalidated.get() + 1)
        });
        current.finish();
        assert_eq!(
            active.get(),
            1,
            "presence remains paused while an older refresh is still pending"
        );
        drop(old);
        assert_eq!(active.get(), 0);
        assert_eq!(
            invalidated.get(),
            1,
            "a cancelled stale guard must not invalidate the newly refreshed generation"
        );
    }

    #[test]
    fn inbound_frames_reject_unknown_variants_and_extension_fields() {
        assert!(serde_json::from_str::<IncomingFrame>(r#"{"type":"ping"}"#).is_ok());
        assert!(
            serde_json::from_str::<IncomingFrame>(r#"{"type":"ping","after_revision":42}"#).is_ok()
        );
        for raw in [
            r#"{"type":"ping","padding":"untrusted"}"#,
            r#"{"type":"unknown"}"#,
            r#"{"type":"message.send","request":null}"#,
            r#"{"type":"ping","after_revision":-1}"#,
        ] {
            assert!(serde_json::from_str::<IncomingFrame>(raw).is_err(), "{raw}");
        }
    }

    #[test]
    fn slow_first_durability_preserves_message_and_receipt_publication_order() {
        let lane = ratchet_core::lane::FifoLane::new();
        let first_durable = Cell::new(false);
        let later_durability_polled = Cell::new(0);
        let committed = RefCell::new(Vec::new());
        let published = RefCell::new(Vec::new());
        let mut first = Box::pin(async {
            committed.borrow_mut().push(1);
            let _publication = enter_publication(
                &lane,
                poll_fn(|_| {
                    if first_durable.get() {
                        Poll::Ready(Ok(()))
                    } else {
                        Poll::Pending
                    }
                }),
            )
            .await?;
            published.borrow_mut().push(1);
            Ok::<_, ApiError>(())
        });
        assert!(first.as_mut().now_or_never().is_none());
        let mut second_message = Box::pin(async {
            committed.borrow_mut().push(2);
            let _publication = enter_publication(&lane, async {
                later_durability_polled.set(later_durability_polled.get() + 1);
                Ok(())
            })
            .await?;
            published.borrow_mut().push(2);
            Ok::<_, ApiError>(())
        });
        let mut receipt = Box::pin(async {
            committed.borrow_mut().push(3);
            let _publication = enter_publication(&lane, async {
                later_durability_polled.set(later_durability_polled.get() + 1);
                Ok(())
            })
            .await?;
            published.borrow_mut().push(3);
            Ok::<_, ApiError>(())
        });
        assert!(second_message.as_mut().now_or_never().is_none());
        assert!(receipt.as_mut().now_or_never().is_none());
        assert_eq!(*committed.borrow(), vec![1, 2, 3]);
        assert_eq!(
            later_durability_polled.get(),
            2,
            "later durability is not serialized behind publication"
        );
        assert!(published.borrow().is_empty());
        first_durable.set(true);
        assert!(matches!(first.as_mut().now_or_never(), Some(Ok(()))));
        assert!(matches!(
            second_message.as_mut().now_or_never(),
            Some(Ok(()))
        ));
        assert!(matches!(receipt.as_mut().now_or_never(), Some(Ok(()))));
        assert_eq!(*published.borrow(), vec![1, 2, 3]);
    }

    #[test]
    fn failed_durability_releases_publication_for_following_commits() {
        let lane = ratchet_core::lane::FifoLane::new();
        let first_failed = Cell::new(false);
        let mut first = Box::pin(enter_publication(
            &lane,
            poll_fn(|_| {
                if first_failed.get() {
                    Poll::Ready(Err(ApiError::retryable("PERSIST_FAILED", 503)))
                } else {
                    Poll::Pending
                }
            }),
        ));
        assert!(first.as_mut().now_or_never().is_none());
        let mut next = Box::pin(enter_publication(&lane, async { Ok(()) }));
        assert!(next.as_mut().now_or_never().is_none());
        first_failed.set(true);
        assert!(matches!(first.as_mut().now_or_never(), Some(Err(_))));
        assert!(matches!(next.as_mut().now_or_never(), Some(Ok(_))));
    }

    #[test]
    fn publication_fifo_drains_twenty_sequential_writers_through_one_thousand_commits() {
        let lane = ratchet_core::lane::FifoLane::new();
        let committed = Cell::new(0);
        let published = RefCell::new(Vec::new());
        let writers = (0..20).map(|_| async {
            for _ in 0..50 {
                committed.set(committed.get() + 1);
                let revision = committed.get();
                let mut yielded = false;
                let _publication = enter_publication(
                    &lane,
                    poll_fn(|cx| {
                        if yielded {
                            Poll::Ready(Ok(()))
                        } else {
                            yielded = true;
                            cx.waker().wake_by_ref();
                            Poll::Pending
                        }
                    }),
                )
                .await?;
                published.borrow_mut().push(revision);
            }
            Ok::<_, ApiError>(())
        });
        let mut all = Box::pin(futures_util::future::join_all(writers));
        let mut completed = false;
        for _ in 0..2000 {
            if let Some(results) = all.as_mut().now_or_never() {
                assert!(results.iter().all(Result::is_ok));
                completed = true;
                break;
            }
        }
        assert!(
            completed,
            "bounded native polling drains the publication queue"
        );
        assert_eq!(committed.get(), 1000);
        assert_eq!(*published.borrow(), (1..=1000).collect::<Vec<_>>());
    }
}
