use crate::http::{ApiError, ApiResult, now_iso, random_id};
use ratchet_core::{
    error::DomainError,
    message::{Author, SendRequest, validate_message},
    storage_crypto::{StorageCrypto, StorageMetadata},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::{cell::RefCell, collections::HashMap, rc::Rc};
use worker::{
    Date, SqlStorage, SqlStorageValue as S, Storage, js_sys,
    wasm_bindgen::{JsCast, JsValue, closure::Closure},
};

#[derive(Clone, Serialize, Deserialize)]
pub struct Record {
    #[serde(flatten)]
    pub metadata: StorageMetadata,
    pub created_at: String,
    pub sender_display_name: Option<String>,
    pub fingerprint: String,
    #[serde(deserialize_with = "blob")]
    pub nonce: Vec<u8>,
    #[serde(deserialize_with = "blob")]
    pub ciphertext: Vec<u8>,
    #[serde(default)]
    pub revision: u64,
}
#[derive(Serialize, Deserialize)]
struct Event {
    revision: u64,
    kind: String,
    payload: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Commit {
    pub message_id: String,
    pub client_message_id: String,
    pub revision: u64,
    pub accepted_at: String,
    pub duplicate: bool,
}
pub struct Store {
    storage: Storage,
    sql: SqlStorage,
}

// Durable SQLite returns ArrayBuffer for BLOB columns, not a JavaScript array.
fn blob<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    struct Bytes;
    impl<'de> serde::de::Visitor<'de> for Bytes {
        type Value = Vec<u8>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("SQLite binary column")
        }
        fn visit_bytes<E: serde::de::Error>(self, value: &[u8]) -> Result<Vec<u8>, E> {
            Ok(value.to_vec())
        }
        fn visit_byte_buf<E: serde::de::Error>(self, value: Vec<u8>) -> Result<Vec<u8>, E> {
            Ok(value)
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut sequence: A,
        ) -> Result<Vec<u8>, A::Error> {
            let mut output = vec![];
            while let Some(byte) = sequence.next_element()? {
                output.push(byte);
            }
            Ok(output)
        }
    }
    deserializer.deserialize_byte_buf(Bytes)
}

fn all<T: DeserializeOwned>(sql: &SqlStorage, query: &str, params: Vec<S>) -> ApiResult<Vec<T>> {
    Ok(sql.exec(query, params)?.to_array()?)
}
fn one<T: DeserializeOwned>(sql: &SqlStorage, query: &str, params: Vec<S>) -> ApiResult<T> {
    Ok(sql.exec(query, params)?.one()?)
}
fn number(sql: &SqlStorage, query: &str, params: Vec<S>) -> ApiResult<u64> {
    #[derive(Deserialize)]
    struct N {
        n: u64,
    }
    Ok(one::<N>(sql, query, params)?.n)
}
fn nullable(value: &Option<String>) -> S {
    value
        .as_ref()
        .map(|v| S::String(v.clone()))
        .unwrap_or(S::Null)
}
fn commit_result(row: &Record, duplicate: bool) -> Commit {
    Commit {
        message_id: row.metadata.message_id.clone(),
        client_message_id: row.metadata.client_message_id.clone(),
        revision: row.revision,
        accepted_at: row.created_at.clone(),
        duplicate,
    }
}

impl Store {
    pub fn new(storage: Storage) -> Self {
        let sql = storage.sql();
        Self { storage, sql }
    }
    pub fn initialize(&self) -> ApiResult<()> {
        for query in [
            "CREATE TABLE IF NOT EXISTS events(revision INTEGER PRIMARY KEY AUTOINCREMENT,kind TEXT NOT NULL,payload TEXT)",
            "CREATE TABLE IF NOT EXISTS chat_messages(revision INTEGER PRIMARY KEY,chat_id TEXT NOT NULL,message_id TEXT UNIQUE NOT NULL,client_message_id TEXT NOT NULL,sender_user_id TEXT NOT NULL,sender_device_id TEXT NOT NULL,sender_display_name TEXT,sender_sequence INTEGER NOT NULL,created_at TEXT NOT NULL,mutation TEXT,reply_to_message_id TEXT,attachment_ids TEXT NOT NULL,fingerprint TEXT NOT NULL,nonce BLOB NOT NULL,ciphertext BLOB NOT NULL,UNIQUE(sender_device_id,client_message_id),UNIQUE(sender_device_id,sender_sequence))",
            "CREATE TABLE IF NOT EXISTS receipts(message_id TEXT NOT NULL,user_id TEXT NOT NULL,state TEXT NOT NULL,revision INTEGER NOT NULL,PRIMARY KEY(message_id,user_id))",
            "CREATE TABLE IF NOT EXISTS receipt_requests(user_id TEXT NOT NULL,request_id TEXT NOT NULL,payload TEXT NOT NULL,response TEXT NOT NULL,PRIMARY KEY(user_id,request_id))",
            "CREATE TABLE IF NOT EXISTS send_quota(user_id TEXT NOT NULL,at INTEGER NOT NULL)",
            "CREATE INDEX IF NOT EXISTS quota_user_time ON send_quota(user_id,at)",
        ] {
            self.sql.exec(query, None)?;
        }
        Ok(())
    }
    pub fn sql(&self) -> SqlStorage {
        self.sql.clone()
    }
    pub async fn durable(&self) -> ApiResult<()> {
        Ok(self.storage.sync().await?)
    }
    pub fn revision(&self) -> ApiResult<u64> {
        number(
            &self.sql,
            "SELECT COALESCE(MAX(revision),0) AS n FROM events",
            vec![],
        )
    }
    pub fn sequence(&self, device: &str) -> ApiResult<u64> {
        number(
            &self.sql,
            "SELECT COALESCE(MAX(sender_sequence),0)+1 AS n FROM chat_messages WHERE sender_device_id=?",
            vec![device.into()],
        )
    }
    pub fn lookup(&self, device: &str, id: &str) -> ApiResult<Option<Record>> {
        Ok(all(
            &self.sql,
            "SELECT * FROM chat_messages WHERE sender_device_id=? AND client_message_id=?",
            vec![device.into(), id.into()],
        )?
        .into_iter()
        .next())
    }
    pub fn stats(&self) -> ApiResult<Value> {
        #[derive(Deserialize)]
        struct Last {
            created_at: String,
            sender_user_id: String,
        }
        let last = all::<Last>(
            &self.sql,
            "SELECT created_at,sender_user_id FROM chat_messages ORDER BY revision DESC LIMIT 1",
            vec![],
        )?
        .into_iter()
        .next();
        Ok(
            json!({"revision":self.revision()?,"message_count":number(&self.sql,"SELECT COUNT(*) AS n FROM chat_messages",vec![])?,"last_message_at":last.as_ref().map(|r|&r.created_at),"last_sender_user_id":last.as_ref().map(|r|&r.sender_user_id)}),
        )
    }
    // A Rust callback returning Err throws through wasm-bindgen, causing SQLite rollback.
    fn transaction<T: 'static>(
        &self,
        operation: impl FnOnce(SqlStorage) -> ApiResult<T> + 'static,
    ) -> ApiResult<T> {
        let outcome = Rc::new(RefCell::new(None));
        let slot = outcome.clone();
        let sql = self.sql.clone();
        let callback = Closure::once(move || -> Result<(), JsValue> {
            let result = operation(sql);
            let failed = result.is_err();
            *slot.borrow_mut() = Some(result);
            if failed {
                Err(JsValue::from_str("Transaction rejected"))
            } else {
                Ok(())
            }
        });
        let raw = self.storage.as_raw().as_ref();
        let function = js_sys::Reflect::get(raw, &"transactionSync".into())
            .map_err(worker::Error::from)?
            .dyn_into::<js_sys::Function>()
            .map_err(worker::Error::from)?;
        let called = function.call1(raw, callback.as_ref());
        let result = outcome.borrow_mut().take();
        match result {
            Some(value) => {
                if let Err(error) = called
                    && value.is_ok()
                {
                    return Err(worker::Error::from(error).into());
                }
                value
            }
            None => Err(called
                .err()
                .map(worker::Error::from)
                .unwrap_or_else(|| {
                    worker::Error::RustError("Transaction callback not invoked".into())
                })
                .into()),
        }
    }
    pub fn prepare(
        &self,
        crypto: &StorageCrypto,
        author: &Author,
        request: &SendRequest,
        display: Option<String>,
    ) -> ApiResult<(Record, String)> {
        let content = validate_message(author, request)?;
        let metadata = StorageMetadata {
            chat_id: author.chat_id.clone(),
            message_id: random_id()?,
            client_message_id: request.client_message_id.clone(),
            sender_user_id: author.user_id.clone(),
            sender_device_id: author.device_id.clone(),
            sender_sequence: request
                .sender_sequence
                .ok_or_else(|| ApiError::domain("SQLITE_MESSAGE_REQUIRED", 422))?,
            mutation: request
                .mutation
                .as_ref()
                .map(serde_json::to_string)
                .transpose()
                .map_err(|_| ApiError::domain("VALIDATION_ERROR", 422))?,
            reply_to_message_id: request.reply_to_message_id.clone(),
            attachment_ids: serde_json::to_string(&request.attachment_ids)
                .map_err(|_| ApiError::domain("VALIDATION_ERROR", 422))?,
        };
        let mut nonce = [0; 12];
        getrandom::fill(&mut nonce).map_err(|_| ApiError::domain("RANDOM_SOURCE_FAILED", 503))?;
        let fingerprint = crypto.fingerprint(&metadata, &content.ciphertext)?;
        let ciphertext = crypto.seal(&metadata, &nonce, &content.ciphertext)?;
        Ok((
            Record {
                metadata,
                created_at: now_iso(),
                sender_display_name: display,
                fingerprint,
                nonce: nonce.to_vec(),
                ciphertext,
                revision: 0,
            },
            content.ciphertext,
        ))
    }
    pub fn commit(&self, mut row: Record, can_mutate: bool) -> ApiResult<Commit> {
        self.transaction(move|sql|{
            if let Some(previous)=all::<Record>(&sql,"SELECT * FROM chat_messages WHERE sender_device_id=? AND client_message_id=?",vec![row.metadata.sender_device_id.clone().into(),row.metadata.client_message_id.clone().into()])?.into_iter().next(){
                if previous.fingerprint!=row.fingerprint{return Err(ApiError::domain("IDEMPOTENCY_CONFLICT",409));}return Ok(commit_result(&previous,true));
            }
            let expected=number(&sql,"SELECT COALESCE(MAX(sender_sequence),0)+1 AS n FROM chat_messages WHERE sender_device_id=?",vec![row.metadata.sender_device_id.clone().into()])?;
            if row.metadata.sender_sequence!=expected{return Err(DomainError::sequence(expected).into());}
            let now=Date::now().as_millis() as i64;
            sql.exec("DELETE FROM send_quota WHERE at<=?",vec![(now-10_000).into()])?;
            if number(&sql,"SELECT COUNT(*) AS n FROM send_quota WHERE user_id=?",vec![row.metadata.sender_user_id.clone().into()])?>=100{return Err(ApiError::retryable("MESSAGE_RATE_LIMITED",503));}
            sql.exec("INSERT INTO send_quota VALUES(?,?)",vec![row.metadata.sender_user_id.clone().into(),now.into()])?;
            let mutation=row.metadata.mutation.as_ref().map(|s|serde_json::from_str::<Value>(s)).transpose().map_err(|_|ApiError::domain("VALIDATION_ERROR",422))?;
            if mutation.is_some()&&!can_mutate{return Err(ApiError::domain("MESSAGE_MUTATION_FORBIDDEN",403));}
            for target in [mutation.as_ref().and_then(|m|m["target_message_id"].as_str()),row.metadata.reply_to_message_id.as_deref()].into_iter().flatten(){
                if number(&sql,"SELECT COUNT(*) AS n FROM chat_messages WHERE message_id=? AND mutation IS NULL",vec![target.into()])?==0{return Err(ApiError::domain("MESSAGE_NOT_FOUND",404));}
            }
            sql.exec("INSERT INTO events(kind) VALUES('message')",None)?;
            row.revision=number(&sql,"SELECT last_insert_rowid() AS n",vec![])?;
            let m=&row.metadata;
            sql.exec("INSERT INTO chat_messages(revision,chat_id,message_id,client_message_id,sender_user_id,sender_device_id,sender_display_name,sender_sequence,created_at,mutation,reply_to_message_id,attachment_ids,fingerprint,nonce,ciphertext) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",vec![(row.revision as i64).into(),m.chat_id.clone().into(),m.message_id.clone().into(),m.client_message_id.clone().into(),m.sender_user_id.clone().into(),m.sender_device_id.clone().into(),nullable(&row.sender_display_name),(m.sender_sequence as i64).into(),row.created_at.clone().into(),nullable(&m.mutation),nullable(&m.reply_to_message_id),m.attachment_ids.clone().into(),row.fingerprint.clone().into(),S::Blob(row.nonce.clone()),S::Blob(row.ciphertext.clone())])?;
            Ok(commit_result(&row,false))
        })
    }
    pub fn sync(
        &self,
        crypto: &StorageCrypto,
        chat_id: &str,
        after: u64,
        limit: u32,
    ) -> ApiResult<Value> {
        let events = all::<Event>(
            &self.sql,
            "SELECT revision,kind,payload FROM events WHERE revision>? ORDER BY revision LIMIT ?",
            vec![(after as i64).into(), (limit as i64 + 1).into()],
        )?;
        let last = events
            .iter()
            .take(limit as usize)
            .next_back()
            .map(|e| e.revision)
            .unwrap_or(after);
        let mut rows: HashMap<_, _> = all::<Record>(
            &self.sql,
            "SELECT * FROM chat_messages WHERE revision>? AND revision<=? ORDER BY revision",
            vec![(after as i64).into(), (last as i64).into()],
        )?
        .into_iter()
        .map(|r| (r.revision, r))
        .collect();
        let mut changes = vec![];
        for event in events.iter().take(limit as usize) {
            if event.kind == "receipt" {
                let mut payload: Value =
                    serde_json::from_str(event.payload.as_deref().unwrap_or("{}"))
                        .map_err(|_| ApiError::domain("CORRUPT_SYNC_ROW", 503))?;
                payload["type"] = json!("receipt");
                payload["revision"] = json!(event.revision);
                changes.push(payload);
                continue;
            }
            let row = rows
                .remove(&event.revision)
                .ok_or_else(|| ApiError::domain("CORRUPT_SYNC_ROW", 503))?;
            let nonce: [u8; 12] = row
                .nonce
                .as_slice()
                .try_into()
                .map_err(|_| ApiError::domain("STORAGE_CRYPTO_FAILED", 503))?;
            let ciphertext = crypto.open(&row.metadata, &nonce, &row.ciphertext)?;
            let m = row.metadata;
            changes.push(json!({"type":"message","revision":row.revision,"message_id":m.message_id,"client_message_id":m.client_message_id,"sender_user_id":m.sender_user_id,"sender_device_id":m.sender_device_id,"sender_display_name":row.sender_display_name,"protocol":"secure-messaging","protocol_version":2,"created_at":row.created_at,"mutation":m.mutation.and_then(|v|serde_json::from_str::<Value>(&v).ok()),"reply_to_message_id":m.reply_to_message_id,"envelope":{"header":"server-sqlite-v1","ciphertext":ciphertext}}));
        }
        Ok(
            json!({"chat_id":chat_id,"revision":self.revision()?,"sender_profiles":[],"changes":changes,"next_revision":last,"has_more":events.len()>limit as usize}),
        )
    }
    pub fn receipts(
        &self,
        user: String,
        entries: Vec<Value>,
        request_id: String,
    ) -> ApiResult<Vec<Value>> {
        self.transaction(move|sql|{
            #[derive(Deserialize)]struct Previous{payload:String,response:String}
            let payload=serde_json::to_string(&entries).map_err(|_|ApiError::domain("VALIDATION_ERROR",422))?;
            if let Some(old)=all::<Previous>(&sql,"SELECT payload,response FROM receipt_requests WHERE user_id=? AND request_id=?",vec![user.clone().into(),request_id.clone().into()])?.into_iter().next(){
                if old.payload!=payload{return Err(ApiError::domain("IDEMPOTENCY_CONFLICT",409));}
                let mut response:Vec<Value>=serde_json::from_str(&old.response).map_err(|_|ApiError::domain("CORRUPT_SYNC_ROW",503))?;for row in &mut response{row["duplicate"]=json!(true);}return Ok(response);
            }
            #[derive(Deserialize)]struct Receipt{state:String,revision:u64}
            let mut response=vec![];
            for entry in &entries{
                let id=entry["message_id"].as_str().ok_or_else(||ApiError::domain("VALIDATION_ERROR",422))?;
                let incoming=entry["state"].as_str().ok_or_else(||ApiError::domain("VALIDATION_ERROR",422))?;
                if number(&sql,"SELECT COUNT(*) AS n FROM chat_messages WHERE message_id=?",vec![id.into()])?==0{return Err(ApiError::domain("MESSAGE_NOT_FOUND",404));}
                if let Some(old)=all::<Receipt>(&sql,"SELECT state,revision FROM receipts WHERE message_id=? AND user_id=?",vec![id.into(),user.clone().into()])?.into_iter().next()&& (old.state=="READ"||old.state==incoming){response.push(json!({"message_id":id,"state":old.state,"revision":old.revision,"duplicate":true}));continue;}
                let event=json!({"message_id":id,"state":incoming,"user_id":user,"updated_at":now_iso()});
                sql.exec("INSERT INTO events(kind,payload) VALUES('receipt',?)",vec![event.to_string().into()])?;
                let revision=number(&sql,"SELECT last_insert_rowid() AS n",vec![])?;
                sql.exec("INSERT INTO receipts VALUES(?,?,?,?) ON CONFLICT(message_id,user_id) DO UPDATE SET state=excluded.state,revision=excluded.revision",vec![id.into(),user.clone().into(),incoming.into(),(revision as i64).into()])?;
                response.push(json!({"message_id":id,"state":incoming,"revision":revision,"duplicate":false}));
            }
            sql.exec("INSERT INTO receipt_requests VALUES(?,?,?,?)",vec![user.into(),request_id.into(),payload.into(),serde_json::to_string(&response).map_err(|_|ApiError::domain("VALIDATION_ERROR",422))?.into()])?;
            Ok(response)
        })
    }
}
