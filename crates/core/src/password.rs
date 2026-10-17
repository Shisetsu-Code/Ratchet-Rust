use crate::error::DomainError;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub const PASSWORD_ITERATIONS: u32 = 600_000;

pub fn token_matches(expected: &str, provided: &str) -> bool {
    bool::from(
        Sha256::digest(expected.as_bytes())
            .as_slice()
            .ct_eq(Sha256::digest(provided.as_bytes()).as_slice()),
    )
}

#[derive(Deserialize, Serialize)]
pub struct Credential {
    pub algorithm: String,
    pub iterations: u32,
    pub salt: String,
    pub verifier: String,
}

pub fn derive_verifier(
    password: &str,
    salt: &[u8],
    iterations: u32,
) -> Result<Zeroizing<[u8; 32]>, DomainError> {
    if iterations == 0
        || iterations > PASSWORD_ITERATIONS
        || password.encode_utf16().count() > 256
        || salt.is_empty()
        || salt.len() > 64
    {
        return Err(DomainError::new("INVALID_PASSWORD_CREDENTIAL", 422));
    }
    let mut output = Zeroizing::new([0; 32]);
    pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, iterations, output.as_mut());
    Ok(output)
}

pub fn verify_password(password: &str, credential: &Credential) -> bool {
    if credential.algorithm != "PBKDF2-SHA256" {
        return false;
    }
    let Ok(salt) = URL_SAFE_NO_PAD.decode(&credential.salt) else {
        return false;
    };
    let Ok(expected) = URL_SAFE_NO_PAD.decode(&credential.verifier) else {
        return false;
    };
    let expected = Zeroizing::new(expected);
    if expected.len() != 32 {
        return false;
    }
    let Ok(actual) = derive_verifier(password, &salt, credential.iterations) else {
        return false;
    };
    bool::from(actual.as_slice().ct_eq(expected.as_slice()))
}

/// Use only after admission: real, legacy, missing and malformed credentials
/// spend the same PBKDF2 iteration budget. A rate-rejected request must never
/// call this function merely to equalize its response timing.
pub fn verify_password_uniform(password: &str, credential: Option<&Credential>) -> bool {
    let supported = credential.filter(|credential| {
        credential.algorithm == "PBKDF2-SHA256"
            && (1..=PASSWORD_ITERATIONS).contains(&credential.iterations)
            && URL_SAFE_NO_PAD
                .decode(&credential.salt)
                .is_ok_and(|salt| !salt.is_empty() && salt.len() <= 64)
            && URL_SAFE_NO_PAD
                .decode(&credential.verifier)
                .is_ok_and(|verifier| verifier.len() == 32)
    });
    let spent = supported.map_or(0, |credential| credential.iterations);
    let valid = supported.is_some_and(|credential| verify_password(password, credential));
    if spent < PASSWORD_ITERATIONS {
        // A fixed-size dummy salt and zeroized output keep legacy padding and
        // unknown-account work independent of the supplied account name.
        let padding = derive_verifier(password, &[0; 16], PASSWORD_ITERATIONS - spent);
        let _ = std::hint::black_box(padding);
    }
    valid
}
