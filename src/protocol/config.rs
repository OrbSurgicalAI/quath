

pub struct Configuration {
    /// How long a token is valind
    pub stamping_timeout_secs: u64
}

impl Configuration {
    pub fn timeout(&self) -> u64 {
        self.stamping_timeout_secs
    }
}