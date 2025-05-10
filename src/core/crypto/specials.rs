use std::borrow::Cow;

use rand::Rng;

use super::{DsaSystem, FixedByteRepr, KemAlgorithm, Parse, PrivateKey, PublicKey, Signature, ViewBytes};



#[derive(Clone)]
pub struct FauxPrivate {
    random: u64
}

#[derive(Clone)]
pub struct FauxPublic {
    private: u64,
    id: u64
}
#[derive(Clone)]
pub struct FauxSignature {
    message: Vec<u8>,
    private: u64
}

impl<'a> Parse<'a> for FauxSignature {
    type Error = &'static str;
    fn parse_bytes(seq: &'a [u8]) -> Result<Self, Self::Error> {
        let id = u64::from_le_bytes(seq[0..8].try_into().unwrap());
        Ok(Self {
            message: seq[8..].to_vec(),
            private: id
        })
    }
}

impl ViewBytes for FauxSignature {
    fn view(&self) -> std::borrow::Cow<'_, [u8]> {
        Cow::Owned(self.private.to_le_bytes().iter().chain(self.message.iter()).copied().collect())
    }
}

impl Signature for FauxSignature {}


impl ViewBytes for FauxPublic {
    fn view(&self) -> Cow<'_, [u8]> {
        Cow::Owned(self.id.to_le_bytes().iter().chain(self.private.to_le_bytes().iter()).copied().collect())
    }
}

impl<'a> Parse<'a> for FauxPublic {
    type Error = &'static str;
    fn parse_bytes(array: &'a [u8]) -> Result<Self, Self::Error> {
        let first = u64::from_le_bytes(array[0..8].try_into().unwrap());
        let second = u64::from_le_bytes(array[8..16].try_into().unwrap());
        Ok(Self {
            id: first,
            private: second
        })
    }
}

impl PublicKey for FauxPublic {
    type Signature = FauxSignature;
    fn verify(&self, message: &[u8], signature: &Self::Signature) -> bool {
        self.private == signature.private && signature.message == message
    }
}

pub struct FauxChain;

impl PrivateKey for FauxPrivate {
    type Error = &'static str;
    type Signature = FauxSignature;
    fn sign_bytes(&self, sequence: &[u8]) -> Result<Self::Signature, Self::Error> {
        Ok(FauxSignature {
            message: sequence.to_vec(),
            private: self.random
        })
    }
}



impl DsaSystem for FauxChain {
    type GenError = &'static str;
    type Private = FauxPrivate;
    type Public = FauxPublic;
    type Signature = FauxSignature;
    fn generate() -> Result<(Self::Public, Self::Private), Self::GenError> {

        let public_id = rand::rng().random();
        let private_id = rand::rng().random();



        Ok((FauxPublic {
            id: public_id,
            private: private_id
        }, FauxPrivate {
            random: private_id
        }))
    }
}

#[derive(Clone)]
pub struct FauxDecapKey {

    secret: [u8; 32],
}

#[derive(Clone)]
pub struct FauxEncapKey {
    secret: [u8; 32],
}

#[derive(Clone)]
pub struct FauxCipherText {
    encrypted: [u8; 32],
}

#[derive(Clone)]
pub struct FauxSharedSecret(pub [u8; 32]);

impl ViewBytes for FauxCipherText {
    fn view(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(&self.encrypted)
    }
}

impl<'a> Parse<'a> for FauxCipherText {
    type Error = &'static str;
    fn parse_bytes(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        Ok(Self {
            encrypted: bytes[0..64].try_into().unwrap()
        })
    }
}

impl ViewBytes for FauxEncapKey {
    fn view(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(&self.secret)
    }
}

impl<'a> Parse<'a> for FauxEncapKey {
    type Error = &'static str;
    fn parse_bytes(bytes: &'a [u8]) -> Result<Self, Self::Error> {

        Ok(Self {
            secret: bytes[0..64].try_into().unwrap()
        })
    }
}

impl ViewBytes for FauxSharedSecret {
    fn view(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(&self.0)
    }
}

impl<'a> Parse<'a> for FauxSharedSecret {
    type Error = &'static str;
    fn parse_bytes(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        Ok(FauxSharedSecret(bytes[0..32].try_into().unwrap()))
    }
}

impl FixedByteRepr<32> for FauxSharedSecret {
    fn to_fixed_repr(&self) -> [u8; 32] {
        self.0
    }
}

pub struct FauxKem;

impl KemAlgorithm for FauxKem {
    type DecapsulationKey = FauxDecapKey;
    type EncapsulationKey = FauxEncapKey;
    type CipherText = FauxCipherText;
    type SharedSecret = FauxSharedSecret;
    type Error = &'static str;

    fn generate() -> Result<(Self::DecapsulationKey, Self::EncapsulationKey), Self::Error> {
        let secret = rand::rng().random();
        Ok((
            FauxDecapKey { secret },
            FauxEncapKey { secret },
        ))
    }

    fn encapsulate(encap_key: &Self::EncapsulationKey) -> Result<(Self::CipherText, Self::SharedSecret), Self::Error> {
        let shared = encap_key.secret[0..32].try_into().unwrap();
        Ok((
            FauxCipherText { encrypted: encap_key.secret.clone() },
            FauxSharedSecret(shared ),
        ))
    }

    fn decapsulate(decap_key: &Self::DecapsulationKey, _: &Self::CipherText) -> Result<Self::SharedSecret, Self::Error> {

        Ok(FauxSharedSecret(decap_key.secret[0..32].try_into().unwrap()))
    }
}

