use uuid::Uuid;

use crate::core::crypto::{Identifier, ToBytes};
impl ToBytes for Uuid {
    fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes_le().to_vec()
    }
}


impl Identifier for Uuid {
    fn gen_id() -> Self {
        Self::new_v4()
    }
    fn to_u128(&self) -> u128 {
        self.to_u128_le()
    }
}