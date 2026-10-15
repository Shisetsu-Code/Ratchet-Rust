mod authority;
pub mod control;
pub mod routes;
mod storage;
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
    collections::BTreeSet,
};
use storage::{Commit, Store};
use worker::*;

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
    generation: Cell<u64>,
    crypto: RefCell<Option<StorageCrypto>>,
    send_lane: ratchet_core::lane::FifoLane,
}

impl ChatRealtime {
    fn ensure(&self) -> ApiResult<()> {
        if !self.initialized.get() {
            self.store.initialize()?;
            authority::initialize(&self.store.sql())?;
            self.initialized.set(true);
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
        authority::assert_open(&self.store.sql())?;
        if !fresh && let Some(lease) = authority::cached(&self.store.sql(), meta)? {
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
        authority::save(&self.store.sql(), meta, &lease)?;
        Ok(lease)
    }
    async fn message_quota(
        &self,
        meta: &Authority,
        lease: &Lease,
        duplicate: bool,
    ) -> ApiResult<()> {
        if !self
            .env
            .rate_limiter("MESSAGE_RATE_LIMITER")?
            .limit(format!("message:{}:{}", meta.user_id, meta.device_id))
            .await?
            .success
        {
            return Err(ApiError::retryable("MESSAGE_RATE_LIMITED", 503));
        }
        if lease.user_role == "CUSTOMER" && !duplicate {
            for binding in [
                "CUSTOMER_MESSAGE_BURST_RATE_LIMITER",
                "CUSTOMER_MESSAGE_SUSTAINED_RATE_LIMITER",
            ] {
                if !self
                    .env
                    .rate_limiter(binding)?
                    .limit(format!("customer:{}", meta.user_id))
                    .await?
                    .success
                {
                    return Err(ApiError::domain("CUSTOMER_MESSAGE_RATE_LIMITED", 429));
                }
            }
        }
        Ok(())
    }
    async fn send_message(&self, meta: &Authority, input: &SendRequest) -> ApiResult<Commit> {
        // Serialize preparation/commit order, then release before the durability wait.
        let lane = self.send_lane.enter().await?;
        let lease = self.authorize(meta, false).await?;
        let generation = self.generation.get();
        if !input.attachment_ids.is_empty() {
            return Err(ApiError::domain("ATTACHMENT_NOT_READY", 503));
        }
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
        authority::assert_open(&self.store.sql())?;
        if generation != self.generation.get() {
            return Err(ApiError::retryable("AUTHORITY_RETRY", 503));
        }
        let commit = self.store.commit(row, lease.can_mutate)?;
        drop(lane);
        self.store.durable().await?;
        if !commit.duplicate {
            for socket in self.state.get_websockets() {
                if let Some(peer) = socket.deserialize_attachment::<Authority>()?
                    && authority::cached(&self.store.sql(), &peer)?.is_some()
                {
                    let event = json!({"type":"message.committed","chat_id":meta.chat_id,"message_id":commit.message_id,"client_message_id":commit.client_message_id,"sender_user_id":meta.user_id,"sender_device_id":meta.device_id,"sender_display_name":lease.display_name,"sender_sequence":input.sender_sequence,"revision":commit.revision,"accepted_at":commit.accepted_at,"mutation":input.mutation,"reply_to_message_id":input.reply_to_message_id,"envelope":{"recipient_user_id":peer.user_id,"recipient_device_id":peer.device_id,"protocol":"secure-messaging","protocol_version":2,"header":"server-sqlite-v1","ciphertext":ciphertext}});
                    let _ = socket.send(&event);
                }
            }
        }
        Ok(commit)
    }
    fn presence(&self, chat_id: &str) -> ApiResult<()> {
        let mut users = BTreeSet::new();
        for socket in self.state.get_websockets() {
            if let Some(peer) = socket.deserialize_attachment::<Authority>()?
                && authority::cached(&self.store.sql(), &peer)?.is_some()
            {
                users.insert(peer.user_id);
            }
        }
        let event = json!({"type":"presence.changed","chat_id":chat_id,"online_user_ids":users.into_iter().take(256).collect::<Vec<_>>(),"observed_at":http::now_iso()});
        for socket in self.state.get_websockets() {
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
        if call.op == "fence" || call.op == "release" {
            let id = call.data["id"]
                .as_str()
                .ok_or_else(|| ApiError::domain("VALIDATION_ERROR", 422))?;
            self.generation.set(self.generation.get() + 1);
            self.registered.set(true);
            self.store
                .sql()
                .exec("DELETE FROM connection_grants", None)?;
            if call.op == "fence" {
                self.store
                    .sql()
                    .exec(include_str!("fence.sql"), vec![id.into()])?;
            } else {
                self.store.sql().exec(
                    "INSERT OR IGNORE INTO authority_releases VALUES(?)",
                    vec![id.into()],
                )?;
                self.store
                    .sql()
                    .exec("DELETE FROM authority_fence WHERE id=?", vec![id.into()])?;
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
            return http::json(&json!({"ok":true}));
        }
        let lease = self.authorize(meta, call.op != "send").await?;
        match call.op.as_str() {
            "open" => {
                let pair = WebSocketPair::new()?;
                pair.server.serialize_attachment(meta)?;
                self.state.accept_web_socket(&pair.server);
                pair.server.send(&json!({"type":"realtime.ready","chat_id":meta.chat_id,"revision":self.store.revision()?}))?;
                self.presence(&meta.chat_id)?;
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
                let _ = lease;
                let entries = call.data["receipts"]
                    .as_array()
                    .ok_or_else(|| ApiError::domain("VALIDATION_ERROR", 422))?;
                let id = call.data["request_id"]
                    .as_str()
                    .filter(|id| is_uuid(id))
                    .ok_or_else(|| ApiError::domain("VALIDATION_ERROR", 422))?;
                let mut ids = BTreeSet::new();
                if entries.is_empty() || entries.len() > 100 {
                    return Err(ApiError::domain("VALIDATION_ERROR", 422));
                }
                for row in entries {
                    let message = row["message_id"]
                        .as_str()
                        .filter(|id| is_uuid(id))
                        .ok_or_else(|| ApiError::domain("VALIDATION_ERROR", 422))?;
                    if !ids.insert(message)
                        || !matches!(row["state"].as_str(), Some("READ" | "DELIVERED"))
                    {
                        return Err(ApiError::domain("VALIDATION_ERROR", 422));
                    }
                }
                let receipts =
                    self.store
                        .receipts(meta.user_id.clone(), entries.clone(), id.into())?;
                self.store.durable().await?;
                for row in receipts.iter().filter(|r| r["duplicate"] == false) {
                    let event = json!({"type":"receipt.committed","chat_id":meta.chat_id,"revision":row["revision"],"message_id":row["message_id"],"user_id":meta.user_id,"state":row["state"]});
                    for socket in self.state.get_websockets() {
                        if let Some(peer) = socket.deserialize_attachment::<Authority>()?
                            && authority::cached(&self.store.sql(), &peer)?.is_some()
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
        Self {
            state,
            env,
            store,
            initialized: Cell::new(false),
            registered: Cell::new(false),
            generation: Cell::new(0),
            crypto: RefCell::new(None),
            send_lane: ratchet_core::lane::FifoLane::new(),
        }
    }
    async fn fetch(&self, request: Request) -> Result<Response> {
        match self.handle(request).await {
            Ok(r) => Ok(r),
            Err(error) => error.response("chat-runtime"),
        }
    }
    async fn alarm(&self) -> Result<Response> {
        self.recover_control_alarm()
            .await
            .map_err(|_| Error::RustError("Authority recovery must retry".into()))?;
        Response::empty()
    }
    async fn websocket_message(
        &self,
        socket: WebSocket,
        message: WebSocketIncomingMessage,
    ) -> Result<()> {
        let Some(meta) = socket.deserialize_attachment::<Authority>()? else {
            return socket.close(Some(4001), Some("Session required"));
        };
        let raw = match message {
            WebSocketIncomingMessage::String(s) if s.len() <= 2 * 1024 * 1024 + 1024 => s,
            _ => return socket.close(Some(1009), Some("Invalid frame")),
        };
        let value: Value = match serde_json::from_str(&raw) {
            Ok(v) => v,
            Err(_) => return socket.close(Some(1003), Some("Invalid JSON")),
        };
        match value["type"].as_str() {
            Some("ping") => {
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
            Some("message.send") => {
                let id = value["request"]["client_message_id"]
                    .as_str()
                    .unwrap_or_default();
                let input = serde_json::from_value::<SendRequest>(value["request"].clone())
                    .map_err(|_| ApiError::domain("VALIDATION_ERROR", 422));
                let result = match input {
                    Ok(input) => self.send_message(&meta, &input).await,
                    Err(error) => Err(error),
                };
                match result{Ok(commit)=>socket.send(&json!({"type":"message.ack","chat_id":meta.chat_id,"message_id":commit.message_id,"client_message_id":commit.client_message_id,"revision":commit.revision,"accepted_at":commit.accepted_at,"duplicate":commit.duplicate}))?,Err(error)=>{let(error_type,retryable)=match error{ApiError::Domain(e)=>(e.code,e.retryable),ApiError::Runtime(_)=>("PERSIST_FAILED",true)};socket.send(&json!({"type":"message.nack","chat_id":meta.chat_id,"client_message_id":id,"error_type":error_type,"retryable":retryable}))?;}}
            }
            _ => {
                socket.close(Some(1003), Some("Unknown frame"))?;
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
            let _ = self.presence(&meta.chat_id);
        }
        Ok(())
    }
    async fn websocket_error(&self, socket: WebSocket, _error: Error) -> Result<()> {
        socket.close(Some(1011), Some("Socket error"))
    }
}
