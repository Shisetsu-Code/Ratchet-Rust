use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ratchet_core::password::{Credential, PASSWORD_ITERATIONS, derive_verifier, verify_password};

#[test]
fn password_derivation_matches_pbkdf2_sha256_reference_vector() {
    let result = derive_verifier("password", b"salt", 1).unwrap_or_else(|e| panic!("{e}"));
    let hex: String = result.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        hex,
        "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
    );
    assert_eq!(PASSWORD_ITERATIONS, 600_000);
}

#[test]
fn password_verification_rejects_wrong_password_and_corrupt_credential() {
    let verifier = derive_verifier("correct password", b"sixteen byte salt", 2).unwrap_or_default();
    let mut credential = Credential {
        algorithm: "PBKDF2-SHA256".into(),
        iterations: 2,
        salt: URL_SAFE_NO_PAD.encode(b"sixteen byte salt"),
        verifier: URL_SAFE_NO_PAD.encode(verifier),
    };
    assert!(verify_password("correct password", &credential));
    assert!(!verify_password("wrong password", &credential));
    credential.verifier = "invalid~encoding".into();
    assert!(!verify_password("correct password", &credential));
    credential.algorithm = "legacy".into();
    assert!(!verify_password("correct password", &credential));
    assert!(derive_verifier("password", b"salt", 0).is_err());
    assert!(derive_verifier("password", b"salt", u32::MAX).is_err());
}
