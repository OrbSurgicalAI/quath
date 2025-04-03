use core::{ops::Add, time::Duration};
use core::ops::AddAssign;


use super::traits::FixedByteRepr;


#[derive(Clone, Copy, PartialEq, Debug)]
pub struct MsSinceEpoch(pub i64);

impl MsSinceEpoch {

    pub const ZERO: MsSinceEpoch = MsSinceEpoch(0);


    pub fn from_timestamp_millis(millis: i64) -> Self {
        Self(millis)
    }
   

    pub fn milliseconds_since_epoch(&self) -> i64 {
        self.0
    }

    pub fn seconds_since_epoch(&self) -> u64 {
        (self.0 / 1000) as u64
    }
}

impl Add<Duration> for MsSinceEpoch {
    type Output = MsSinceEpoch;
    fn add(self, rhs: Duration) -> Self::Output {
        Self(self.0 + rhs.as_millis() as i64)
    }
}

impl AddAssign<Duration> for MsSinceEpoch {
    fn add_assign(&mut self, rhs: Duration) {
        self.0 += rhs.as_millis() as i64;
    }
}

impl FixedByteRepr<8> for MsSinceEpoch {
    fn to_fixed_repr(&self) -> [u8; 8] {
        (self.0 as i64).to_le_bytes()
    }
    fn from_fixed_repr(val: [u8; 8]) -> Self {
        Self(i64::from_le_bytes(val))
    }
}




#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::MsSinceEpoch;


    use arbitrary::Arbitrary;

    impl Arbitrary<'_> for MsSinceEpoch {
        fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
            let millis_random: i64 = i64::arbitrary(u)?;
            Ok(Self(millis_random))
        }
    }


    #[test]
    pub fn test_correct_ms_since_epoch_addition() {
        let time = MsSinceEpoch::ZERO;
        assert_eq!(time.milliseconds_since_epoch(), 0);

        let time = time + Duration::from_millis(200);
        assert_eq!(time.milliseconds_since_epoch(), 200);
    }

}