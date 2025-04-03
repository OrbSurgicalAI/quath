use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::{protocol::spec::{details::Protocol, time::MsSinceEpoch}, token::{token::GenericToken, tolerance::TokenTolerance}};





pub trait ServerContext {
    fn current_time(&self) -> MsSinceEpoch;
    fn key_renewal_period(&self) -> Duration;
    fn token_tolerance(&self) -> &TokenTolerance;
    fn issue_expiry(&self) -> Duration;
    fn modify_token(&self, token: GenericToken) -> GenericToken;
    fn protocol(&self) -> Protocol;
}