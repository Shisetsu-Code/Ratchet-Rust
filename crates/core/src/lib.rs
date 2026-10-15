//! Runtime-independent contracts and invariants shared by HTTP and WebSocket handlers.
pub mod error;
pub mod http_security;
pub mod lane;
pub mod message;
pub mod password;
pub mod policy;
pub mod ready_batch;
pub mod receipt;
pub mod signatures;
pub mod storage_crypto;
