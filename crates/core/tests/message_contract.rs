use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ratchet_core::{
    message::{Author, SendRequest, validate_message},
    receipt::{ReceiptState, advance_receipt},
};
use serde_json::{Value, json};

const CHAT: &str = "11111111-1111-4111-8111-111111111111";
const USER: &str = "22222222-2222-4222-8222-222222222222";
const DEVICE: &str = "33333333-3333-4333-8333-333333333333";
const CLIENT: &str = "44444444-4444-4444-8444-444444444444";
const FILE: &str = "55555555-5555-4555-8555-555555555555";

fn payload() -> Value {
    json!({"protocol":"secure-message-content","v":2,"chat_id":CHAT,
        "client_message_id":CLIENT,"sender_user_id":USER,"sender_device_id":DEVICE,
        "message_type":"MESSAGE","text":"Hola","attachments":[],"mutation":null,"reply_to_message_id":null})
}

fn request(content: &Value) -> SendRequest {
    serde_json::from_value(json!({"client_message_id":CLIENT,"sender_sequence":1,
        "envelopes":[{"recipient_user_id":USER,"recipient_device_id":DEVICE,
        "protocol":"secure-messaging","protocol_version":2,"header":"server-sqlite-v1",
        "ciphertext":URL_SAFE_NO_PAD.encode(content.to_string())}],"attachment_ids":[]}))
    .unwrap_or_else(|error| panic!("valid fixture: {error}"))
}

fn author() -> Author {
    Author {
        chat_id: CHAT.into(),
        user_id: USER.into(),
        device_id: DEVICE.into(),
    }
}

#[test]
fn accepts_existing_client_format_and_keeps_original_ciphertext() {
    let input = request(&payload());
    let parsed = validate_message(&author(), &input).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(parsed.ciphertext, input.envelopes[0].ciphertext);
    assert_eq!(parsed.content["text"], "Hola");
}

#[test]
fn rejects_identity_spoofing_for_every_bound_field() {
    for field in [
        "chat_id",
        "client_message_id",
        "sender_user_id",
        "sender_device_id",
    ] {
        let mut content = payload();
        content[field] = json!(FILE);
        assert_eq!(
            validate_message(&author(), &request(&content))
                .err()
                .map(|e| e.code),
            Some("MESSAGE_IDENTITY_MISMATCH")
        );
    }
}

#[test]
fn counts_utf16_units_like_the_existing_client() {
    let mut content = payload();
    content["text"] = json!("😀".repeat(100_001));
    assert_eq!(
        validate_message(&author(), &request(&content))
            .err()
            .map(|e| e.code),
        Some("VALIDATION_ERROR")
    );
    // A smaller plain-text value remains within the envelope byte limit.
    content["text"] = json!("a".repeat(10_000));
    assert!(validate_message(&author(), &request(&content)).is_ok());
}

#[test]
fn rejects_duplicate_or_unbound_attachment_ids() {
    let mut content = payload();
    content["attachments"] = json!([{"file_id":FILE}]);
    assert_eq!(
        validate_message(&author(), &request(&content))
            .err()
            .map(|e| e.code),
        Some("ATTACHMENT_MISMATCH")
    );
    let mut input = request(&content);
    input.attachment_ids = vec![FILE.into()];
    assert!(validate_message(&author(), &input).is_ok());
    content["attachments"] = json!([{"file_id":FILE},{"file_id":FILE}]);
    assert_eq!(
        validate_message(&author(), &request(&content))
            .err()
            .map(|e| e.code),
        Some("ATTACHMENT_MISMATCH")
    );
}

#[test]
fn rejects_mutation_and_reply_metadata_mismatches() {
    let mut content = payload();
    content["reply_to_message_id"] = json!(FILE);
    assert_eq!(
        validate_message(&author(), &request(&content))
            .err()
            .map(|e| e.code),
        Some("MESSAGE_IDENTITY_MISMATCH")
    );
    content = payload();
    content["mutation"] = json!({"type":"EDIT","target_message_id":FILE});
    assert_eq!(
        validate_message(&author(), &request(&content))
            .err()
            .map(|e| e.code),
        Some("MESSAGE_IDENTITY_MISMATCH")
    );
}

#[test]
fn sequence_must_be_positive_and_javascript_safe() {
    for sequence in [0, 9_007_199_254_740_992] {
        let mut input = request(&payload());
        input.sender_sequence = Some(sequence);
        assert!(validate_message(&author(), &input).is_err());
    }
}

#[test]
fn malformed_content_and_unknown_request_fields_are_rejected() {
    let mut input = request(&payload());
    input.envelopes[0].ciphertext = "not~base64".into();
    assert_eq!(
        validate_message(&author(), &input).err().map(|e| e.code),
        Some("INVALID_MESSAGE_CONTENT")
    );
    let mut raw = serde_json::to_value(request(&payload())).unwrap_or_default();
    raw["user_id"] = json!(USER);
    assert!(serde_json::from_value::<SendRequest>(raw).is_err());
}

#[test]
fn read_receipts_never_regress_and_duplicates_are_noops() {
    assert_eq!(
        advance_receipt(None, ReceiptState::Delivered),
        ReceiptState::Delivered
    );
    assert_eq!(
        advance_receipt(Some(ReceiptState::Delivered), ReceiptState::Read),
        ReceiptState::Read
    );
    assert_eq!(
        advance_receipt(Some(ReceiptState::Read), ReceiptState::Delivered),
        ReceiptState::Read
    );
    assert_eq!(
        advance_receipt(Some(ReceiptState::Read), ReceiptState::Read),
        ReceiptState::Read
    );
}
