use sha3::Sha3_256;

use crate::algos::{fips203::MlKem512, fips204::MlDsa44};

use super::protocol::ProtocolKit;

pub type QuantumKitL1 = ProtocolKit<MlDsa44, MlKem512, Sha3_256, 32>;
