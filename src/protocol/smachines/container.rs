
/// This is a state container object, allows us to deal with state in a cleaner way.
/// 
pub(crate) struct State<D> {
    inner: D
}

impl<D> State<D> {
    pub fn new(inner: D) -> Self {
        Self { inner }
    }
    pub fn get(&mut self) -> &mut D {
        &mut self.inner
    }
    pub fn set(&mut self, value: D) {
        self.inner = value;
    }

}