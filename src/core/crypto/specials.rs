use super::{SigningAlgorithm, ToBytes};


pub struct PermissiveSign;

impl ToBytes for () {
    fn to_bytes(&self) -> Vec<u8> {
        vec![]
    }
}

impl SigningAlgorithm for PermissiveSign {
    type Error = ();
    type PrivateKey = ();
    type PublicKey = ();
    type Signature = ();


    fn generate() -> Result<(Self::PublicKey, Self::PrivateKey), Self::Error> {
        Ok(((), ()))
    }
    fn sign_bytes(_: &[u8], _: &Self::PrivateKey) -> Result<Self::Signature, Self::Error> {
        Ok(())
    }
    fn verify_bytes(_: &[u8], _: &Self::Signature, _: &Self::PublicKey) -> bool {
        true
    }
}