use std::{borrow::Cow, fmt::Display};

pub mod protocol;
pub mod token;
pub mod specials;
pub mod mem;
pub mod opcode;
mod error;
mod simple;

pub mod data;


use crate::algos::parse_into_fixed_length;
pub use crate::core::crypto::data::*;
pub use error::*;
pub use simple::*;



pub trait Signature: ViewBytes + for<'a> Parse<'a> {
    fn from_byte(seq: &[u8]) -> Self;
}






/// The [PrivateKey] trait specifies how a [PrivateKey] compatible with this protocol
/// should be implemented. This alows for the protocol to operate over a wide range
/// of Signing/KEM algorithms.
pub trait PrivateKey {
    type Signature: Signature;
    type Error;
    /// Signs a byte sequence with the private key.
    fn sign_bytes(&self, sequence: &[u8]) -> Result<Self::Signature, Self::Error>;
}

pub trait PublicKey: ViewBytes + for<'a> Parse<'a>
{
    type Signature;

    /// Verifies a message was signed by the corresponding key.
    fn verify(&self, message: &[u8], signature: &Self::Signature) -> bool;
}

pub trait DsaSystem {
    type Public: PublicKey<Signature = Self::Signature>;
    type Private: PrivateKey<Signature = Self::Signature>;
    type Signature: Signature;
    type GenError;

    fn generate() -> Result<(Self::Public, Self::Private), Self::GenError>;
}



pub trait HashingAlgorithm<const N: usize> {
    fn hash(buffer: &[u8]) -> [u8; N] {
        Self::hash_sequence(&[buffer])
    }
    fn hash_sequence(buffer: &[&[u8]]) -> [u8; N];
}

pub trait KEMAlgorithm {
    type Context;
    type DecapsulationKey;
    type EncapsulationKey: ViewBytes + for<'a> Parse<'a>;
    type CipherText: ViewBytes + for<'a> Parse<'a>;
    type SharedSecret: FixedByteRepr<32> + ViewBytes + for<'a> Parse<'a>;
    type Error;

    fn generate(context: &Self::Context) -> Result<(Self::DecapsulationKey, Self::EncapsulationKey), Self::Error>;
    fn encapsulate(encap_key: &Self::EncapsulationKey, context: &Self::Context) -> Result<(Self::CipherText, Self::SharedSecret), Self::Error>;
    fn decapsulate(decap_key: &Self::DecapsulationKey, cipher: &Self::CipherText, context: &Self::Context) -> Result<Self::SharedSecret, Self::Error>;
}



pub trait Parse<'a>: Sized {
    type Error: Display;
    fn parse_bytes(array: &'a [u8]) -> Result<Self, Self::Error>;
}

impl<'a, const N: usize> Parse<'a> for [u8; N] {
    type Error = &'static str;
    fn parse_bytes(array: &'a [u8]) -> Result<Self, Self::Error> {
        parse_into_fixed_length(array)
    }
}

/// Returns a view into the underlying bytes of the
/// object. Some cryptographic implementations may
/// not allow peering into the bytes by reference
/// and thus we allow returning a [Cow] in order to
/// return owned values.
pub trait ViewBytes {
    
    fn view<'a>(&'a self) -> Cow<'a, [u8]>;
}



impl<const N: usize> ViewBytes for [u8; N] {
    fn view<'a>(&'a self) -> Cow<'a, [u8]> {
        Cow::Borrowed(self)
    }
}

impl<const N: usize> Signature for [u8; N] {
    fn from_byte(seq: &[u8]) -> Self {
        seq.try_into().unwrap()
    }
}

pub trait FixedByteRepr<const N: usize> {
    fn to_fixed_repr(&self) -> [u8; N];
}



