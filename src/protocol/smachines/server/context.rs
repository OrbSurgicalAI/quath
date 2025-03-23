use std::time::Duration;

use crate::protocol::spec::registry::TokenTolerance;



pub trait ServerContext {
    type Time;
    fn current_time(&self) -> Self::Time;
    fn key_renewal_period(&self) -> Duration;
    fn token_tolerance(&self) -> &TokenTolerance;
}