use std::{fmt::Debug, ops::Deref};

use base64::{Engine, prelude::BASE64_STANDARD};

use super::ViewBytes;

#[derive(PartialEq, Eq, Clone)]
pub struct B64<T>(pub T);

impl<T> Deref for B64<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: ViewBytes> Debug for B64<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        BASE64_STANDARD.encode(self.view()).fmt(f)
    }
}
