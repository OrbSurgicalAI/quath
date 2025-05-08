use std::ops::Deref;

use zeroize::{Zeroize, Zeroizing};

use super::{Signature, ViewBytes};






#[derive(Debug, PartialEq, Eq)]
pub struct B64<T>(pub T);

impl<T> Deref for B64<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
