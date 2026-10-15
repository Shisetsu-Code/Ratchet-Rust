use serde::Serialize;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DomainError {
    #[serde(rename = "type")]
    pub code: &'static str,
    pub title: &'static str,
    pub status: u16,
    pub retryable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_sender_sequence: Option<u64>,
}

impl DomainError {
    pub const fn new(code: &'static str, status: u16) -> Self {
        Self {
            code,
            title: code,
            status,
            retryable: false,
            expected_sender_sequence: None,
        }
    }
    pub const fn sequence(expected: u64) -> Self {
        Self {
            code: "SENDER_SEQUENCE_GAP",
            title: "Sender sequence gap",
            status: 409,
            retryable: true,
            expected_sender_sequence: Some(expected),
        }
    }
}
impl fmt::Display for DomainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.code, self.status)
    }
}
impl std::error::Error for DomainError {}
