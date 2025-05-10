use std::{
    ops::{Add, AddAssign, Sub, SubAssign},
    time::Duration,
};

#[derive(Clone, Copy, PartialEq, PartialOrd, Debug, Eq, Ord)]
pub struct MsSinceEpoch(pub i64);

#[derive(Debug, Clone)]
pub struct TokenValidityInterval {
    backwards: Duration,
    forwards: Duration,
}

impl TokenValidityInterval {
    pub fn new(backwards: Duration, forwards: Duration) -> Self {
        Self {
            backwards,
            forwards,
        }
    }
    pub fn from_seconds(backwards: u64, forwards: u64) -> Self {
        Self::new(Duration::from_secs(backwards), Duration::from_secs(forwards))
    }
    pub fn from_milliseconds(backwards: u64, forwards: u64) -> Self {
        Self::new(Duration::from_millis(backwards), Duration::from_millis(forwards))
    }
    pub fn check_time_validity(&self, current: MsSinceEpoch, to_check: MsSinceEpoch) -> bool {
        (-(self.backwards.as_millis() as i128)..(self.forwards.as_millis() as i128 + 1))
            .contains(&((to_check - current).0 as i128))
    }
}

impl Sub<Self> for MsSinceEpoch {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl SubAssign<Self> for MsSinceEpoch {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 -= rhs.0;
    }
}

impl Add<Self> for MsSinceEpoch {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl AddAssign<Self> for MsSinceEpoch {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
    }
}


#[cfg(test)]
mod tests {
    use crate::core::crypto::MsSinceEpoch;

    use super::TokenValidityInterval;


    #[test]
    pub fn test_check_time_validity() {
        let interval = TokenValidityInterval::from_milliseconds(20, 30);
        assert!(interval.check_time_validity(MsSinceEpoch(50), MsSinceEpoch(50)));
        assert!(!interval.check_time_validity(MsSinceEpoch(50), MsSinceEpoch(20)));
        assert!(interval.check_time_validity(MsSinceEpoch(50), MsSinceEpoch(30)));
        assert!(interval.check_time_validity(MsSinceEpoch(50), MsSinceEpoch(55)));
        assert!(interval.check_time_validity(MsSinceEpoch(50), MsSinceEpoch(80)));
        assert!(!interval.check_time_validity(MsSinceEpoch(50), MsSinceEpoch(81)));
    }
}