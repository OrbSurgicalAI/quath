use fips204::{ml_dsa_44, traits::{KeyGen, SerDes, Signer, Verifier}};

use crate::core::crypto::{SigningAlgorithm, ToBytes};


impl ToBytes for ml_dsa_44::PublicKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.clone().into_bytes().to_vec()
    }
}

impl ToBytes for ml_dsa_44::PrivateKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.clone().into_bytes().to_vec()
    }
}



impl SigningAlgorithm for ml_dsa_44::KG {
    type Error = &'static str;
    type PrivateKey = ml_dsa_44::PrivateKey;
    type PublicKey = ml_dsa_44::PublicKey;
    type Signature = [u8; 2420];
  

    fn generate() -> Result<(Self::PublicKey, Self::PrivateKey), Self::Error> {
        ml_dsa_44::try_keygen()
    }

    fn sign<T: ToBytes>(sequence: &T, private: &Self::PrivateKey) -> Result<Self::Signature, Self::Error> {
        private.try_sign(sequence.to_bytes().as_ref(), &[])
    }

    fn verify<T: ToBytes>(sequence: &T, signature: &Self::Signature, key: &Self::PublicKey) -> bool {
        key.verify(sequence.to_bytes().as_ref(), signature, &[])
    }
}