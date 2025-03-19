use std::cmp::Ordering;

use super::config::Configuration;



pub trait ProtocolExecutor<D>
where 
    D: TimeObj
{
    /// Compares the current time against another time.
    fn current_time(&self) -> D;

    fn config(&self) -> &Configuration;
}

pub trait TimeObj {
    fn cmp_within(&self, other: &Self, bound: u64) -> Ordering {
        (self.seconds() + bound).cmp(&(other.seconds()))
    }
    fn from_seconds(seconds: u64) -> Self;
    fn seconds(&self) -> u64;
}


pub trait FixedByteRepr<const N: usize> {
    fn to_fixed_repr(&self) -> [u8; N];
    fn from_fixed_repr(val: [u8; N]) -> Self;
}