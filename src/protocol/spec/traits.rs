use core::{cmp::Ordering, time::Duration};

use chrono::{DateTime, Utc};
use http::Uri;

use crate::protocol::config::Configuration;

pub trait ProtocolCtx {
    type Protocol;
    type TokenType;
    
    /// Compares the current time against another time.
    fn current_time(&self) -> DateTime<Utc>;
    fn config(&self) -> &Configuration;
    fn connection(&self) -> &Connection;
    fn protocol(&self) -> Self::Protocol;
    fn retry_cooldown(&self) -> Duration;
    fn get_token_type(&self) -> Self::TokenType;
    fn issue_expiry(&self) -> DateTime<Utc>;
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

pub trait TimeObj {
    fn cmp_within(&self, other: &Self, bound: i64) -> Ordering {
        (self.seconds_since_epoch() + bound).cmp(&(other.seconds_since_epoch()))
    }
    fn from_millis_since_epoch(seconds: i64) -> Self;
    fn seconds_since_epoch(&self) -> i64;
}

impl TimeObj for DateTime<Utc> {
    fn from_millis_since_epoch(seconds: i64) -> Self {
        Self::from_timestamp_millis(seconds).unwrap()
    }
    fn seconds_since_epoch(&self) -> i64 {
        self.timestamp()
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