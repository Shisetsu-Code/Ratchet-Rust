use crate::error::DomainError;
use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageMetadata {
    pub chat_id: String,
    pub message_id: String,
    pub client_message_id: String,
    pub sender_user_id: String,
    pub sender_device_id: String,
    pub sender_sequence: u64,
    pub mutation: Option<String>,
    pub reply_to_message_id: Option<String>,
    /// JSON string, intentionally matching the existing SQLite column and AAD.
    pub attachment_ids: String,
}

pub struct StorageCrypto {
    aes: Zeroizing<[u8; 32]>,
    mac: Zeroizing<[u8; 64]>,
}

fn crypto_error() -> DomainError {
    DomainError::new("STORAGE_CRYPTO_FAILED", 503)
}

impl StorageCrypto {
    pub fn new(master: &[u8; 32], chat_id: &str) -> Result<Self, DomainError> {
        let hkdf = Hkdf::<Sha256>::new(Some(chat_id.as_bytes()), master);
        let mut aes = Zeroizing::new([0; 32]);
        // Web Crypto defaults HMAC-SHA256 deriveKey to its 512-bit block size.
        let mut mac = Zeroizing::new([0; 64]);
        hkdf.expand(b"ratchet-sqlite-storage-v1", aes.as_mut())
            .map_err(|_| crypto_error())?;
        hkdf.expand(b"ratchet-sqlite-idempotency-v1", mac.as_mut())
            .map_err(|_| crypto_error())?;
        Ok(Self { aes, mac })
    }

    fn aad(row: &StorageMetadata) -> Result<Vec<u8>, DomainError> {
        serde_json::to_vec(&(
            &row.chat_id,
            &row.message_id,
            &row.client_message_id,
            &row.sender_user_id,
            &row.sender_device_id,
            row.sender_sequence,
            &row.mutation,
            &row.reply_to_message_id,
            &row.attachment_ids,
        ))
        .map_err(|_| crypto_error())
    }

    /// Caller supplies a fresh cryptographically random 96-bit nonce per write.
    pub fn seal(
        &self,
        row: &StorageMetadata,
        nonce: &[u8; 12],
        plaintext: &str,
    ) -> Result<Vec<u8>, DomainError> {
        let cipher = Aes256Gcm::new_from_slice(self.aes.as_ref()).map_err(|_| crypto_error())?;
        cipher
            .encrypt(
                &(*nonce).into(),
                Payload {
                    msg: plaintext.as_bytes(),
                    aad: &Self::aad(row)?,
                },
            )
            .map_err(|_| crypto_error())
    }

    pub fn open(
        &self,
        row: &StorageMetadata,
        nonce: &[u8; 12],
        ciphertext: &[u8],
    ) -> Result<String, DomainError> {
        let cipher = Aes256Gcm::new_from_slice(self.aes.as_ref()).map_err(|_| crypto_error())?;
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    &(*nonce).into(),
                    Payload {
                        msg: ciphertext,
                        aad: &Self::aad(row)?,
                    },
                )
                .map_err(|_| crypto_error())?,
        );
        String::from_utf8(plaintext.to_vec()).map_err(|_| crypto_error())
    }

    pub fn fingerprint(
        &self,
        row: &StorageMetadata,
        ciphertext: &str,
    ) -> Result<String, DomainError> {
        let payload = serde_json::to_vec(&(
            &row.chat_id,
            &row.sender_user_id,
            &row.sender_device_id,
            row.sender_sequence,
            &row.client_message_id,
            ciphertext,
            &row.mutation,
            &row.reply_to_message_id,
            &row.attachment_ids,
        ))
        .map_err(|_| crypto_error())?;
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(self.mac.as_ref())
            .map_err(|_| crypto_error())?;
        mac.update(&payload);
        Ok(STANDARD.encode(mac.finalize().into_bytes()))
    }
}
