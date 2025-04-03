use core::time::Duration;

use chrono::{DateTime, Utc};
use http::Uri;

use crate::protocol::config::Configuration;

use super::time::MsSinceEpoch;

pub trait ProtocolCtx {
    type Protocol;
    type TokenType;
    
    /// Compares the current time against another time.
    fn current_time(&self) -> MsSinceEpoch;
    fn config(&self) -> &Configuration;
    fn connection(&self) -> &Connection;
    fn protocol(&self) -> Self::Protocol;
    fn retry_cooldown(&self) -> Duration;
    fn get_token_type(&self) -> Self::TokenType;
    fn issue_expiry(&self) -> Duration;
}



pub struct Connection {
    uri: Uri,
}

impl Connection {
    pub fn from_uri(uri: Uri) -> Self {
        Self { uri }
    }
    pub fn uri(&self) -> &Uri {
        &self.uri
    }
}

impl Connection {
    pub fn new(uri: Uri) -> Self {
        Self { uri }
    }
}



pub trait FixedByteRepr<const N: usize> {
    fn to_fixed_repr(&self) -> [u8; N];
    fn from_fixed_repr(val: [u8; N]) -> Self;
}

impl FixedByteRepr<8> for DateTime<Utc> {
    fn to_fixed_repr(&self) -> [u8; 8] {
        self.timestamp_millis().to_le_bytes()
    }
    fn from_fixed_repr(val: [u8; 8]) -> Self {
        DateTime::from_timestamp_millis(i64::from_le_bytes(val)).unwrap()
    }
}