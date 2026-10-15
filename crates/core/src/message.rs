use crate::error::DomainError;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;

pub const SERVER_WIRE: &str = "server-sqlite-v1";
pub const MAX_REQUEST_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_CIPHERTEXT_CHARS: usize = 256 * 1024;
pub const MAX_ATTACHMENTS: usize = 16;
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Author {
    pub chat_id: String,
    pub user_id: String,
    pub device_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub recipient_user_id: String,
    pub recipient_device_id: String,
    pub protocol: String,
    pub protocol_version: u32,
    pub header: String,
    pub ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MutationType {
    #[serde(rename = "EDIT")]
    Edit,
    #[serde(rename = "TOMBSTONE")]
    Tombstone,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mutation {
    pub target_message_id: String,
    pub r#type: MutationType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SendRequest {
    pub client_message_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_sequence: Option<u64>,
    pub envelopes: Vec<Envelope>,
    #[serde(default)]
    pub recovery_envelopes: Vec<Value>,
    #[serde(default)]
    pub attachment_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mutation: Option<Mutation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to_message_id: Option<String>,
}

#[derive(Debug)]
pub struct PreparedContent {
    pub ciphertext: String,
    pub content: Value,
}

pub fn is_uuid(input: &str) -> bool {
    input.len() == 36
        && [8, 13, 18, 23].iter().all(|&i| input.as_bytes()[i] == b'-')
        && uuid::Uuid::parse_str(input).is_ok()
}

fn validation() -> DomainError {
    DomainError::new("VALIDATION_ERROR", 422)
}
fn content_error() -> DomainError {
    DomainError::new("INVALID_MESSAGE_CONTENT", 422)
}

pub fn validate_message(
    author: &Author,
    request: &SendRequest,
) -> Result<PreparedContent, DomainError> {
    if !is_uuid(&request.client_message_id)
        || request.attachment_ids.len() > MAX_ATTACHMENTS
        || request.attachment_ids.iter().any(|id| !is_uuid(id))
        || request
            .sender_sequence
            .is_some_and(|n| n == 0 || n > MAX_SAFE_INTEGER)
        || request
            .reply_to_message_id
            .as_ref()
            .is_some_and(|id| !is_uuid(id))
        || request
            .mutation
            .as_ref()
            .is_some_and(|m| !is_uuid(&m.target_message_id))
    {
        return Err(validation());
    }
    for envelope in &request.envelopes {
        if !is_uuid(&envelope.recipient_user_id)
            || !is_uuid(&envelope.recipient_device_id)
            || envelope.protocol != "secure-messaging"
            || envelope.protocol_version != 2
            || envelope.header.is_empty()
            || envelope.header.len() > 32 * 1024
            || envelope.ciphertext.is_empty()
            || envelope.ciphertext.len() > MAX_CIPHERTEXT_CHARS
        {
            return Err(validation());
        }
    }
    if serde_json::to_vec(request).map_err(|_| validation())?.len() > MAX_REQUEST_BYTES {
        return Err(validation());
    }
    let envelope = match request.envelopes.as_slice() {
        [envelope]
            if envelope.header == SERVER_WIRE
                && request.recovery_envelopes.is_empty()
                && request.sender_sequence.is_some() =>
        {
            envelope
        }
        _ => return Err(DomainError::new("SQLITE_MESSAGE_REQUIRED", 422)),
    };
    let decoded = URL_SAFE_NO_PAD
        .decode(envelope.ciphertext.trim_end_matches('='))
        .map_err(|_| content_error())?;
    let content: Value = serde_json::from_slice(&decoded).map_err(|_| content_error())?;
    let text = content["text"].as_str().ok_or_else(content_error)?;
    let attachments = content["attachments"]
        .as_array()
        .ok_or_else(content_error)?;
    if content["protocol"] != "secure-message-content"
        || content["v"] != 2
        || text.encode_utf16().count() > 200_000
    {
        return Err(content_error());
    }
    let expected_type = match &request.mutation {
        Some(m) => match m.r#type {
            MutationType::Edit => "EDIT",
            MutationType::Tombstone => "TOMBSTONE",
        },
        None => "MESSAGE",
    };
    let mutation_matches = match &request.mutation {
        Some(m) => {
            content["mutation"]["type"] == expected_type
                && content["mutation"]["target_message_id"] == m.target_message_id
        }
        None => {
            content["mutation"]["type"].is_null()
                && content["mutation"]["target_message_id"].is_null()
        }
    };
    let reply_matches = match &request.reply_to_message_id {
        Some(id) => content["reply_to_message_id"] == *id,
        None => content
            .get("reply_to_message_id")
            .is_some_and(Value::is_null),
    };
    if content["chat_id"] != author.chat_id
        || content["client_message_id"] != request.client_message_id
        || content["sender_user_id"] != author.user_id
        || content["sender_device_id"] != author.device_id
        || content["message_type"] != expected_type
        || !mutation_matches
        || !reply_matches
    {
        return Err(DomainError::new("MESSAGE_IDENTITY_MISMATCH", 422));
    }
    let payload_ids: Option<HashSet<&str>> =
        attachments.iter().map(|a| a["file_id"].as_str()).collect();
    let expected_ids: HashSet<&str> = request.attachment_ids.iter().map(String::as_str).collect();
    if payload_ids
        .as_ref()
        .is_none_or(|ids| ids.len() != attachments.len() || *ids != expected_ids)
        || attachments.len() != request.attachment_ids.len()
    {
        return Err(DomainError::new("ATTACHMENT_MISMATCH", 422));
    }
    Ok(PreparedContent {
        ciphertext: envelope.ciphertext.clone(),
        content,
    })
}
