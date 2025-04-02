use core::time::Duration;
use core::ops::Range;

use chrono::{DateTime, Utc};


use crate::protocol::spec::traits::FixedByteRepr;

use super::token::GenericToken;

/// The tolerance range for approving a token.
/// 
/// This range is inclusive.
pub struct TokenTolerance {
    
    forwards: Duration,
    backwards: Duration
}




impl TokenTolerance {
    pub const ZERO: Self = Self {
        backwards: Duration::ZERO,
        forwards: Duration::ZERO
    };
    pub fn new(backwards: Duration, forwards: Duration) -> Self {
        Self {
            forwards, backwards
        }
    }
    pub fn check(&self, token: &GenericToken, current: DateTime<Utc>) -> bool
    {
        let current_ms = current.timestamp_millis();
        let token_ms = DateTime::<Utc>::from_fixed_repr(token.get_time_field()).timestamp_millis();

        let difference = token_ms - current_ms;

        println!("Current: {current_ms}, Token: {token_ms}, Difference: {difference}, Range: {:?}", self.range_ms());


        
        self.range_ms().contains(&difference)
    }
    fn range_ms(&self) -> Range<i64> {
        -(self.backwards.as_millis() as i64)..(self.forwards.as_millis() as i64 + 1)
    }
}



#[cfg(test)]
mod tests {
    use std::time::Duration;

    use chrono::{DateTime, Utc};

    use crate::{protocol::spec::traits::TimeObj, token::token::{GenericToken, TimestampToken}};

    use super::TokenTolerance;


    fn qts(time: i64) -> DateTime<Utc> {
        DateTime::from_millis_since_epoch(time)
    }

    #[test]
    pub fn verify_tolerance_calculation_forwards() {
        let tolerance = TokenTolerance::new(Duration::ZERO, Duration::from_millis(20));


        let faux_time = qts(45);


        assert!(tolerance.check(&TimestampToken::random_with_ts(qts(45)).generic(), faux_time), "Did not approve token that was right on the mark.");

        assert!(tolerance.check(&TimestampToken::random_with_ts(qts(55)).generic(), faux_time), "Did not approve token that was in between 0 and max.");
        assert!(tolerance.check(&TimestampToken::random_with_ts(qts(65)).generic(), faux_time), "Did not approve token at the maximum.");
        assert!(!tolerance.check(&TimestampToken::random_with_ts(qts(66)).generic(), faux_time), "Approved token past the maximum.");

    
    }

    #[test]
    pub fn verify_tolerance_calculation_backwards() {
        let tolerance = TokenTolerance::new(Duration::from_millis(20), Duration::ZERO);


        let faux_time = qts(45);

        assert!(tolerance.check(&TimestampToken::random_with_ts(qts(45)).generic(), faux_time), "Did not approve token that was right on the mark.");

        assert!(tolerance.check(&TimestampToken::random_with_ts(qts(35)).generic(), faux_time), "Did not approve token that was in between 0 and max.");
        assert!(tolerance.check(&TimestampToken::random_with_ts(qts(25)).generic(), faux_time), "Did not approve token at the maximum.");
        assert!(!tolerance.check(&TimestampToken::random_with_ts(qts(10)).generic(), faux_time), "Approved token past the maximum.");
    }

    #[test]
    pub fn verify_tolerance_calculation_bidirectional() {
        let tolerance = TokenTolerance::new(Duration::from_millis(20), Duration::from_millis(20));


        let faux_time = qts(45);


        // Check backwards.
        assert!(tolerance.check(&TimestampToken::random_with_ts(qts(45)).generic(), faux_time), "Did not approve token that was right on the mark.");
        assert!(tolerance.check(&TimestampToken::random_with_ts(qts(35)).generic(), faux_time), "Did not approve token that was in between 0 and max.");
        assert!(tolerance.check(&TimestampToken::random_with_ts(qts(25)).generic(), faux_time), "Did not approve token at the maximum.");
        assert!(!tolerance.check(&TimestampToken::random_with_ts(qts(10)).generic(), faux_time), "Approved token past the maximum.");

        // Check forwards
        assert!(tolerance.check(&TimestampToken::random_with_ts(qts(45)).generic(), faux_time), "Did not approve token that was right on the mark.");

        assert!(tolerance.check(&TimestampToken::random_with_ts(qts(55)).generic(), faux_time), "Did not approve token that was in between 0 and max.");
        assert!(tolerance.check(&TimestampToken::random_with_ts(qts(65)).generic(), faux_time), "Did not approve token at the maximum.");
        assert!(!tolerance.check(&TimestampToken::random_with_ts(qts(66)).generic(), faux_time), "Approved token past the maximum.");
    }
}