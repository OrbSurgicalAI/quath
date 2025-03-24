use std::ops::{Deref, DerefMut};


/// This is a state container object, allows us to deal with state in a cleaner way and prevents
/// accidentally leaving us in a null state and then invalidating the state machine.
pub(crate) struct State<D> {
    inner: Option<D>,
    is_extracted: bool
}


impl<D> State<D> {
    pub fn new(inner: D) -> Self {
        Self {
            inner: Some(inner),
            is_extracted: false
        }
    }
}
pub struct StateHandle<'a, D> {
    inner: &'a mut Option<D>
}


impl<'a, D> Deref for StateHandle<'a, D> {
    type Target = D;
    fn deref(&self) -> &Self::Target {
        self.inner.as_ref().unwrap()
    }
}


impl<D> State<D> {
    pub fn handle(&mut self) -> StateHandle<D> {
        StateHandle { inner: &mut self.inner }
    }
    pub fn take(&mut self) -> D {
        if self.is_extracted {
            panic!("Cannot pull out the state twice!");
        }
        self.is_extracted = true;
        self.inner.take().unwrap()
    }

}

impl<'a, D> DerefMut for StateHandle<'a, D> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.inner.as_mut().unwrap()
    }
}

impl<'a, D> StateHandle<'a, D> {
    pub fn set(&mut self, state: D) {
        *self.inner = Some(state);
    }
}