use sha3::{Digest, Sha3_256};

use crate::core::crypto::{HashingAlgorithm, ToBytes};



impl HashingAlgorithm for Sha3_256 {
    type HashResult = [u8; 32];

    fn hash<T: ToBytes>(buffer: &T) -> Self::HashResult {
        let mut hasher = Self::default();
        hasher.update(&buffer.to_bytes());
        hasher.finalize().into()
    }

}

