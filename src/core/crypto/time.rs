use std::{
    ops::{Add, AddAssign, Sub, SubAssign},
    time::Duration,
};
 
#[derive(Clone, Copy, PartialEq, PartialOrd, Eq, Debug, Ord)]
pub struct ProtocolTime(pub i64);

#[derive(Clone, Copy, PartialEq, PartialOrd, Debug, Eq, Ord)]
pub struct MsSinceEpoch(pub i64);


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
