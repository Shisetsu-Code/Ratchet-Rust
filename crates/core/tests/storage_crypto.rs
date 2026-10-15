use base64::{Engine, engine::general_purpose::STANDARD};
use ratchet_core::storage_crypto::{StorageCrypto, StorageMetadata};
use serde::Deserialize;

#[derive(Deserialize)]
struct Vector {
    master: String,
    nonce: String,
    metadata: StorageMetadata,
    plaintext: String,
    ciphertext: String,
    fingerprint: String,
}
fn vector() -> Vector {
    serde_json::from_str(include_str!("../../../baseline/storage-crypto-vector.json"))
        .unwrap_or_else(|e| panic!("fixture {e}"))
}
fn decode(value: &str) -> Vec<u8> {
    STANDARD
        .decode(value)
        .unwrap_or_else(|e| panic!("fixture {e}"))
}

#[test]
fn matches_web_crypto_ciphertext_fingerprint_and_decryption() {
    let v = vector();
    let master: [u8; 32] = decode(&v.master).try_into().unwrap_or_default();
    let nonce: [u8; 12] = decode(&v.nonce).try_into().unwrap_or_default();
    let crypto = StorageCrypto::new(&master, &v.metadata.chat_id).unwrap_or_else(|e| panic!("{e}"));
    let ciphertext = crypto
        .seal(&v.metadata, &nonce, &v.plaintext)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(STANDARD.encode(&ciphertext), v.ciphertext);
    assert_eq!(
        crypto
            .fingerprint(&v.metadata, &v.plaintext)
            .unwrap_or_default(),
        v.fingerprint
    );
    assert_eq!(
        crypto
            .open(&v.metadata, &nonce, &ciphertext)
            .unwrap_or_default(),
        v.plaintext
    );
}

#[test]
fn rejects_tampering_wrong_chat_and_wrong_key() {
    let v = vector();
    let master: [u8; 32] = decode(&v.master).try_into().unwrap_or_default();
    let nonce: [u8; 12] = decode(&v.nonce).try_into().unwrap_or_default();
    let crypto = StorageCrypto::new(&master, &v.metadata.chat_id).unwrap_or_else(|e| panic!("{e}"));
    let original = decode(&v.ciphertext);
    let mut corrupted = original.clone();
    corrupted[0] ^= 1;
    assert!(crypto.open(&v.metadata, &nonce, &corrupted).is_err());
    let mut changed = v.metadata.clone();
    changed.sender_sequence += 1;
    assert!(crypto.open(&changed, &nonce, &original).is_err());
    let wrong_chat = StorageCrypto::new(&master, "another-chat").unwrap_or_else(|e| panic!("{e}"));
    assert!(wrong_chat.open(&v.metadata, &nonce, &original).is_err());
    let wrong_key =
        StorageCrypto::new(&[99; 32], &v.metadata.chat_id).unwrap_or_else(|e| panic!("{e}"));
    assert!(wrong_key.open(&v.metadata, &nonce, &original).is_err());
}
