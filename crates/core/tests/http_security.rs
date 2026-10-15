use ratchet_core::http_security::{BodyBudget, check_origin, session_cookie};

#[test]
fn writes_require_exact_origin_and_host_even_with_a_session() {
    assert!(
        check_origin(
            "POST",
            Some("https://ratchet.test"),
            "ratchet.test",
            "https://ratchet.test",
            "ratchet.test"
        )
        .is_ok()
    );
    for origin in [
        None,
        Some("https://evil.test"),
        Some("null"),
        Some("https://ratchet.test.evil.test"),
    ] {
        assert!(
            check_origin(
                "POST",
                origin,
                "ratchet.test",
                "https://ratchet.test",
                "ratchet.test"
            )
            .is_err()
        );
    }
    assert!(
        check_origin(
            "POST",
            Some("https://ratchet.test"),
            "other.test",
            "https://ratchet.test",
            "ratchet.test"
        )
        .is_err()
    );
    assert!(
        check_origin(
            "GET",
            None,
            "ratchet.test",
            "https://ratchet.test",
            "ratchet.test"
        )
        .is_ok()
    );
}

#[test]
fn cookies_do_not_allow_ambiguous_duplicate_session_values() {
    assert_eq!(
        session_cookie(Some("other=x; __Host-session=abc_123; another=y")),
        Some("abc_123")
    );
    assert_eq!(
        session_cookie(Some("__Host-session=x; __Host-session=y")),
        None
    );
    assert_eq!(session_cookie(Some("__Host-session=")), None);
    assert_eq!(session_cookie(None), None);
}

#[test]
fn actual_stream_bytes_cannot_exceed_limit_even_with_false_content_length() {
    let mut budget = BodyBudget::new(64 * 1024);
    assert!(budget.consume(32 * 1024).is_ok());
    assert!(budget.consume(32 * 1024).is_ok());
    assert!(budget.consume(1).is_err());
    assert!(BodyBudget::new(10).consume(usize::MAX).is_err());
}
