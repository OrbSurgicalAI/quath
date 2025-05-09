use std::ops::Deref;







#[derive(Debug, PartialEq, Eq, Clone)]
pub struct B64<T>(pub T);

impl<T> Deref for B64<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
