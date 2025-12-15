pub mod crypto;

pub use crypto::*;
use sha3::Sha3_256;

use crate::{algos::{fips203::MlKem512, fips204::MlDsa44}, protocol::ProtocolKit};


pub type Sec1Kit = ProtocolKit<MlDsa44, MlKem512, Sha3_256, 32>;