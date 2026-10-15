use crate::{error::DomainError, message::MAX_SAFE_INTEGER};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::Value;

pub fn verify_ed25519(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> Result<(), DomainError> {
    let failure = || DomainError::new("PORTABLE_KEY_VERIFICATION_FAILED", 403);
    VerifyingKey::from_bytes(public_key)
        .map_err(|_| failure())?
        .verify_strict(message, &Signature::from_bytes(signature))
        .map_err(|_| failure())
}

pub fn portable_signature_message(
    purpose: &str,
    challenge_id: &str,
    challenge: &str,
    origin: &str,
    key_id: &str,
) -> Vec<u8> {
    [
        "ratchet-portable-key-v1",
        purpose,
        challenge_id,
        challenge,
        origin,
        key_id,
    ]
    .join("\n")
    .into_bytes()
}

pub fn canonical_owner_json(value: &Value) -> Result<String, DomainError> {
    let invalid = || DomainError::new("VALIDATION_ERROR", 422);
    match value {
        Value::Array(values) => Ok(format!(
            "[{}]",
            values
                .iter()
                .map(canonical_owner_json)
                .collect::<Result<Vec<_>, _>>()?
                .join(",")
        )),
        Value::Object(values) => {
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            let mut fields = Vec::with_capacity(keys.len());
            for key in keys {
                fields.push(format!(
                    "{}:{}",
                    serde_json::to_string(key).map_err(|_| invalid())?,
                    canonical_owner_json(&values[key])?
                ));
            }
            Ok(format!("{{{}}}", fields.join(",")))
        }
        Value::Number(number) => {
            let safe = number.as_u64().is_some_and(|n| n <= MAX_SAFE_INTEGER)
                || number
                    .as_i64()
                    .is_some_and(|n| n.unsigned_abs() <= MAX_SAFE_INTEGER);
            if !safe {
                return Err(invalid());
            }
            Ok(number.to_string())
        }
        _ => serde_json::to_string(value).map_err(|_| invalid()),
    }
}
