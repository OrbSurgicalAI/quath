use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::token::{token::GenericToken, tolerance::TokenTolerance};





pub trait ServerContext {
    fn current_time(&self) -> DateTime<Utc>;
    fn key_renewal_period(&self) -> Duration;
    fn token_tolerance(&self) -> &TokenTolerance;
    fn issue_expiry(&self) -> DateTime<Utc>;
    fn modify_token(&self, token: GenericToken) -> GenericToken;
}