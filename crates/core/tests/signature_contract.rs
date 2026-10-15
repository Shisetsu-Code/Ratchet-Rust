use ratchet_core::signatures::{canonical_owner_json, portable_signature_message, verify_ed25519};
use serde_json::json;

fn bytes<const N: usize>(hex: &str) -> [u8; N] {
    let mut output = [0; N];
    for (i, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap_or_default();
    }
    output
}

#[test]
fn accepts_rfc8032_vector_and_rejects_altered_message_or_signature() {
    let public = bytes::<32>("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let mut signature = bytes::<64>(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    );
    assert!(verify_ed25519(&public, b"", &signature).is_ok());
    assert!(verify_ed25519(&public, b"altered", &signature).is_err());
    signature[63] ^= 1;
    assert!(verify_ed25519(&public, b"", &signature).is_err());
    assert!(verify_ed25519(&[0; 32], b"", &[0; 64]).is_err());
}

#[test]
fn portable_key_message_is_bound_to_purpose_origin_and_key() {
    let body = portable_signature_message(
        "BOOTSTRAP",
        "id",
        "challenge",
        "https://ratchet.test",
        "key",
    );
    assert_eq!(
        body,
        b"ratchet-portable-key-v1\nBOOTSTRAP\nid\nchallenge\nhttps://ratchet.test\nkey"
    );
    assert_ne!(
        body,
        portable_signature_message(
            "AUTHENTICATION",
            "id",
            "challenge",
            "https://ratchet.test",
            "key"
        )
    );
}

#[test]
fn canonical_owner_json_sorts_recursively_and_rejects_unsafe_numbers() {
    assert_eq!(
        canonical_owner_json(&json!({"z":[{"b":2,"a":1}],"a":"hola"})).unwrap_or_default(),
        "{\"a\":\"hola\",\"z\":[{\"a\":1,\"b\":2}]}"
    );
    assert!(canonical_owner_json(&json!(9_007_199_254_740_992_u64)).is_err());
    assert!(canonical_owner_json(&json!(1.5)).is_err());
}
