use sha3::{digest::core_api::CoreWrapper, Digest, Sha3_224, Sha3_256, Sha3_384, Sha3_512, Shake128, Shake256, TurboShake128, TurboShake256};

use crate::core::crypto::{HashingAlgorithm};


macro_rules! impl_hashing_fn {
    ( $($name:ident, $size:expr),* ) => {

        $(
            impl HashingAlgorithm<$size> for $name {
                fn hash_sequence(buffer: &[&[u8]]) -> [u8; $size] {
                    let mut hasher = Self::default();
                    for item in buffer {
                        hasher.update(*item);
                    }
                    hasher.finalize().into()
                }
            }

        )*
        
    }
}


impl_hashing_fn!(
    Sha3_224, 28,
    Sha3_256, 32,
    Sha3_384, 48,
    Sha3_512, 64
);






// impl HashingAlgorithm for Sha3_384 {
//     type HashResult = [u8; 48];

//     fn hash<T: ToBytes>(buffer: &T) -> Self::HashResult {
//         let mut hasher = Self::default();
//         hasher.update(&buffer.to_bytes());
//         hasher.finalize().into()
//     }

// }

// impl HashingAlgorithm for sha3::Keccak384 {
//     type HashResult = [u8; 48];

//     fn hash<T: ToBytes>(buffer: &T) -> Self::HashResult {
//         let mut hasher = Self::default();
//         hasher.update(&buffer.to_bytes());
//         hasher.finalize().into()
//     }

// }

// impl HashingAlgorithm for Sha3_224 {
//     type HashResult = [u8; 28];

//     fn hash<T: ToBytes>(buffer: &T) -> Self::HashResult {
//         let mut hasher = Self::default();
//         hasher.update(&buffer.to_bytes());
//         hasher.finalize().into()
//     }

// }

// impl HashingAlgorithm for Sha3_256 {
//     type HashResult = [u8; 32];

//     fn hash<T: ToBytes>(buffer: &T) -> Self::HashResult {
//         let mut hasher = Self::default();
//         hasher.update(&buffer.to_bytes());
//         hasher.finalize().into()
//     }

// }





// impl HashingAlgorithm for Sha3_512 {
//     type HashResult = [u8; 64];

//     fn hash<T: ToBytes>(buffer: &T) -> Self::HashResult {
//         let mut hasher = Self::default();
//         hasher.update(&buffer.to_bytes());
//         hasher.finalize().into()
//     }

// }

