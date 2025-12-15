use std::{
    ops::{Add, AddAssign, Sub, SubAssign}
};
 
#[derive(Clone, Copy, PartialEq, PartialOrd, Eq, Debug, Ord)]
pub struct ProtocolTime(pub u64);

#[derive(Clone, Copy, PartialEq, PartialOrd, Debug, Eq, Ord)]
pub struct MsSinceEpoch(pub i64);

impl ProtocolTime {
    pub const ZERO: ProtocolTime = ProtocolTime(0);

    pub fn is_maxed(&self) -> bool {
        self.0 == u64::MAX
    }
}

/// This is a helper function that instructs how to update
/// the time.
pub enum ProtocolTimeMutator {
    Registration,
    Cycle,
    Operation
}

impl ProtocolTimeMutator {
    /// Takes in a [ProtocolTime] and an action in the form of [ProtocolTimeMutator] and
    /// outputs a new [ProtocolTime].
    pub fn mutate(action: ProtocolTimeMutator, protocol_time: ProtocolTime) -> ProtocolTime {
        match action {
            ProtocolTimeMutator::Cycle | ProtocolTimeMutator::Registration => ProtocolTime::ZERO,
            ProtocolTimeMutator::Operation => ProtocolTime(protocol_time.0 + 1)
        }
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
