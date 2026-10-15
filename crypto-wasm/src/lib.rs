use core::convert::Infallible;
use core::fmt;
use std::cell::Cell;
use std::rc::Rc;

use rand::{TryCryptoRng, TryRng};
use wasm_bindgen::prelude::*;
use xeddsa::xed25519::{PrivateKey, PublicKey};
use xeddsa::{Sign, Verify};
use zeroize::{Zeroize, Zeroizing};

const PRIVATE_KEY_LEN: usize = 32;
const PUBLIC_KEY_LEN: usize = 32;
const SIGNATURE_LEN: usize = 64;
const SIGN_RANDOMNESS_LEN: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CryptoWasmError {
    PrivateKeyLength,
    RandomnessLength,
    UnexpectedRandomnessConsumption,
}

impl fmt::Display for CryptoWasmError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::PrivateKeyLength => "XEd25519 private key must be 32 bytes",
            Self::RandomnessLength => "XEd25519 randomness must be 64 bytes",
            Self::UnexpectedRandomnessConsumption => {
                "XEd25519 signer consumed an unexpected amount of randomness"
            }
        };
        formatter.write_str(message)
    }
}

/// Signs `message` with an `X25519`-format private key using `XEd25519`.
///
/// # Errors
///
/// Returns a JavaScript error when the private key is not 32 bytes, randomness
/// is not exactly 64 bytes, or the pinned signer consumes an unexpected amount
/// of randomness.
#[wasm_bindgen]
pub fn xed25519_sign(
    private_key: Vec<u8>,
    message: &[u8],
    randomness: Vec<u8>,
) -> Result<Vec<u8>, JsError> {
    sign_internal(private_key, message, randomness)
        .map(|signature| signature.to_vec())
        .map_err(|error| JsError::new(&error.to_string()))
}

/// Verifies an `XEd25519` signature against an `X25519`-format public key.
#[must_use]
#[wasm_bindgen]
pub fn xed25519_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    verify_internal(public_key, message, signature)
}

/// Returns the explicit cryptographic profile implemented by this WASM module.
#[must_use]
#[wasm_bindgen]
pub fn crypto_wasm_profile() -> String {
    "ratchet-crypto-wasm/xed25519/v1".to_owned()
}

fn sign_internal(
    private_key: Vec<u8>,
    message: &[u8],
    randomness: Vec<u8>,
) -> Result<[u8; SIGNATURE_LEN], CryptoWasmError> {
    let private_key = Zeroizing::new(private_key);
    let randomness = Zeroizing::new(randomness);

    let private: [u8; PRIVATE_KEY_LEN] = private_key
        .as_slice()
        .try_into()
        .map_err(|_| CryptoWasmError::PrivateKeyLength)?;
    let random: [u8; SIGN_RANDOMNESS_LEN] = randomness
        .as_slice()
        .try_into()
        .map_err(|_| CryptoWasmError::RandomnessLength)?;

    let private = Zeroizing::new(private);
    let random = Zeroizing::new(random);
    let signing_key = PrivateKey::from(&*private);

    let consumed = Rc::new(Cell::new(0usize));
    let rng = FixedRandom::new(*random, Rc::clone(&consumed));
    let signature: [u8; SIGNATURE_LEN] = signing_key.sign(message, rng);

    if consumed.get() != SIGN_RANDOMNESS_LEN {
        return Err(CryptoWasmError::UnexpectedRandomnessConsumption);
    }
    Ok(signature)
}

fn verify_internal(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let Ok(public): Result<[u8; PUBLIC_KEY_LEN], _> = public_key.try_into() else {
        return false;
    };
    let Ok(signature): Result<[u8; SIGNATURE_LEN], _> = signature.try_into() else {
        return false;
    };
    PublicKey(public).verify(message, &signature).is_ok()
}

struct FixedRandom {
    bytes: [u8; SIGN_RANDOMNESS_LEN],
    offset: usize,
    consumed: Rc<Cell<usize>>,
}

impl FixedRandom {
    fn new(bytes: [u8; SIGN_RANDOMNESS_LEN], consumed: Rc<Cell<usize>>) -> Self {
        Self {
            bytes,
            offset: 0,
            consumed,
        }
    }

    fn fill_exact(&mut self, destination: &mut [u8]) {
        let end = self.offset.saturating_add(destination.len());
        assert!(
            end <= self.bytes.len(),
            "pinned XEd25519 implementation requested more than 64 random bytes"
        );
        destination.copy_from_slice(&self.bytes[self.offset..end]);
        self.offset = end;
        self.consumed.set(end);
    }
}

impl TryRng for FixedRandom {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0u8; 4];
        self.fill_exact(&mut bytes);
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0u8; 8];
        self.fill_exact(&mut bytes);
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
        self.fill_exact(destination);
        Ok(())
    }
}

impl TryCryptoRng for FixedRandom {}

impl Drop for FixedRandom {
    fn drop(&mut self) {
        self.bytes.zeroize();
        self.offset = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC7748_ALICE_PRIVATE: [u8; 32] = [
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66,
        0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9,
        0x2c, 0x2a,
    ];
    const RFC7748_ALICE_PUBLIC: [u8; 32] = [
        0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7,
        0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b,
        0x4e, 0x6a,
    ];

    #[test]
    fn signs_and_verifies_with_x25519_key_format() -> Result<(), CryptoWasmError> {
        let message = b"signed prekey material";
        let randomness: Vec<u8> = (0u8..64).collect();
        let signature = sign_internal(RFC7748_ALICE_PRIVATE.to_vec(), message, randomness)?;

        assert!(verify_internal(&RFC7748_ALICE_PUBLIC, message, &signature));
        assert!(!verify_internal(
            &RFC7748_ALICE_PUBLIC,
            b"different message",
            &signature
        ));
        Ok(())
    }

    #[test]
    fn rejects_modified_signature() -> Result<(), CryptoWasmError> {
        let message = b"pq prekey";
        let randomness = vec![0xa5; SIGN_RANDOMNESS_LEN];
        let mut signature = sign_internal(RFC7748_ALICE_PRIVATE.to_vec(), message, randomness)?;
        signature[0] ^= 0x01;
        assert!(!verify_internal(&RFC7748_ALICE_PUBLIC, message, &signature));
        Ok(())
    }

    #[test]
    fn rejects_wrong_lengths_without_js_runtime() {
        assert_eq!(
            sign_internal(vec![0u8; 31], b"m", vec![0u8; 64]),
            Err(CryptoWasmError::PrivateKeyLength)
        );
        assert_eq!(
            sign_internal(vec![0u8; 32], b"m", vec![0u8; 63]),
            Err(CryptoWasmError::RandomnessLength)
        );
        assert!(!verify_internal(&[0u8; 31], b"m", &[0u8; 64]));
        assert!(!verify_internal(&[0u8; 32], b"m", &[0u8; 63]));
    }
}
