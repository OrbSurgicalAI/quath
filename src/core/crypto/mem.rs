use std::ops::Deref;

use zeroize::{Zeroize, Zeroizing};



#[derive(PartialEq, Eq, Clone, Debug)]
#[repr(transparent)]
pub struct Hash<const N: usize>(pub [u8; N]);

impl<const N: usize> Deref for Hash<N> {
    type Target = [u8; N];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}