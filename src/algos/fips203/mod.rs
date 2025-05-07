use fips203::{traits::{Decaps, Encaps, KeyGen, SerDes}, *};
use crate::core::crypto::*;

impl ToBytes for ml_kem_512::EncapsKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.clone().into_bytes().to_vec()
    }
}

impl ToBytes for ml_kem_512::DecapsKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.clone().into_bytes().to_vec()
    }
}


impl ToBytes for ml_kem_512::CipherText {
    fn to_bytes(&self) -> Vec<u8> {
        self.clone().into_bytes().to_vec()
    }
}


impl FixedByteRepr<32> for fips203::SharedSecretKey {
    fn to_fixed_repr(self) -> [u8; 32] {
        self.into_bytes()
    }
}
impl KEMAlgorithm for ml_kem_512::KG {
    type EncapsulationKey = ml_kem_512::EncapsKey;
    type DecapsulationKey = ml_kem_512::DecapsKey;
    type CipherText = ml_kem_512::CipherText;
    type SharedSecret = fips203::SharedSecretKey;
    type Context = ();
    type Error = &'static str;

    fn generate(_: &Self::Context) -> Result<(Self::DecapsulationKey, Self::EncapsulationKey), Self::Error> {
        let (encap, decap) = ml_kem_512::KG::try_keygen()?;

        Ok((decap, encap))
    }

    fn encapsulate(encap_key: &Self::EncapsulationKey, _: &Self::Context) -> Result<(Self::CipherText, Self::SharedSecret), Self::Error> {
        let (ss, ct) = encap_key.try_encaps()?;
        Ok((ct, ss))
    }

    fn decapsulate(decap_key: &Self::DecapsulationKey, cipher: &Self::CipherText, _: &Self::Context) -> Result<Self::SharedSecret, Self::Error> {
       let ss =  decap_key.try_decaps(cipher)?;
       
       Ok(ss)
    }
}   


