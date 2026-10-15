use crate::error::DomainError;

pub fn check_origin(
    method: &str,
    origin: Option<&str>,
    request_host: &str,
    expected_origin: &str,
    expected_host: &str,
) -> Result<(), DomainError> {
    if matches!(method, "GET" | "HEAD" | "OPTIONS")
        || (origin == Some(expected_origin) && request_host == expected_host)
    {
        Ok(())
    } else {
        Err(DomainError::new("ORIGIN_MISMATCH", 403))
    }
}

pub fn session_cookie(header: Option<&str>) -> Option<&str> {
    let mut found = None;
    for item in header?.split(';') {
        let Some((name, value)) = item.trim().split_once('=') else {
            continue;
        };
        if name == "__Host-session" {
            if found.is_some()
                || value.is_empty()
                || value.len() > 512
                || !value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            {
                return None;
            }
            found = Some(value);
        }
    }
    found
}

pub struct BodyBudget {
    maximum: usize,
    consumed: usize,
}
impl BodyBudget {
    pub const fn new(maximum: usize) -> Self {
        Self {
            maximum,
            consumed: 0,
        }
    }
    pub fn consume(&mut self, bytes: usize) -> Result<(), DomainError> {
        self.consumed = self
            .consumed
            .checked_add(bytes)
            .filter(|&n| n <= self.maximum)
            .ok_or_else(|| DomainError::new("REQUEST_TOO_LARGE", 413))?;
        Ok(())
    }
}
