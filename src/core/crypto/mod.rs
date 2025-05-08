use std::ops::Deref;

pub mod protocol;
pub mod token;
pub mod specials;
pub mod mem;
pub mod opcode;

pub trait Identifier: Copy {
    fn gen_id() -> Self;
    fn to_u128(&self) -> u128;
    fn to_bytes(&self) -> [u8; 16] {
        self.to_u128().to_le().to_le_bytes()
    }
}

pub trait Signature {
    fn view(&self) -> &[u8];
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

pub trait PublicKey
{
    type Signature;

    /// Verifies a message was signed by the corresponding key.
    fn verify(&self, message: &[u8], signature: &Self::Signature) -> bool;

    /// Converts the public key into a fixed representation.
    fn view(&self) -> &[u8];
}

pub trait DsaSystem {
    type Public: PublicKey<Signature = Self::Signature>;
    type Private: PrivateKey<Signature = Self::Signature>;
    type Signature: Signature;
    type GenError;

    fn generate() -> Result<(Self::Public, Self::Private), Self::GenError>;
}

pub trait SigningAlgorithm {

    type Signature: ToBytes;
    type PublicKey: ToBytes;
    type PrivateKey;
    type Error;
    
    fn generate() -> Result<(Self::PublicKey, Self::PrivateKey), Self::Error>;
    fn sign<T: ToBytes>(sequence: &T, private: &Self::PrivateKey) -> Result<Self::Signature, Self::Error> {
        Self::sign_bytes(&sequence.to_bytes(), private)
    }
    fn sign_bytes(sequence: &[u8], private: &Self::PrivateKey) -> Result<Self::Signature, Self::Error>;
    fn verify<T: ToBytes>(sequence: &T, signature: &Self::Signature, key: &Self::PublicKey) -> bool {
        Self::verify_bytes(sequence.to_bytes().as_ref(), signature, key)
    }

    fn verify_bytes(sequenc: &[u8], signature: &Self::Signature, key: &Self::PublicKey) -> bool;
}

pub trait HashingAlgorithm<const N: usize> {
    fn hash(buffer: &[u8]) -> [u8; N] {
        Self::hash_sequence(&[buffer])
    }
    fn hash_sequence(buffer: &[&[u8]]) -> [u8; N];
}

pub trait KEMAlgorithm {
    type Context;
    type DecapsulationKey: ToBytes;
    type EncapsulationKey: ToBytes;
    type CipherText: ToBytes;
    type SharedSecret: FixedByteRepr<32>;
    type Error;

    fn generate(context: &Self::Context) -> Result<(Self::DecapsulationKey, Self::EncapsulationKey), Self::Error>;
    fn encapsulate(encap_key: &Self::EncapsulationKey, context: &Self::Context) -> Result<(Self::CipherText, Self::SharedSecret), Self::Error>;
    fn decapsulate(decap_key: &Self::DecapsulationKey, cipher: &Self::CipherText, context: &Self::Context) -> Result<Self::SharedSecret, Self::Error>;
}

pub trait ToBytes {
    fn to_bytes(&self) -> Vec<u8>;
}

pub trait FixedByteRepr<const N: usize> {
    fn to_fixed_repr(&self) -> [u8; N];
}

impl<const N: usize> ToBytes for [u8; N] {
    fn to_bytes(&self) -> Vec<u8> {
        self.to_vec()
    }
}

#[derive(Debug)]
pub struct Signable<T> {
    inner: T
}

impl<T> Signable<T>
where 
    T: ToBytes
{
    pub fn new(inner: T) -> Self {
        Self {
            inner
        }
    }
    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T: ToBytes> ToBytes for Signable<T> {
    fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes()
    }
}

impl<T> Deref for Signable<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T1, T2, T3, T4> ToBytes for (T1, T2, T3, T4)
where 
    T1: ToBytes,
    T2: ToBytes,
    T3: ToBytes,
    T4: ToBytes
{

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = self.0.to_bytes();
        buffer.append(self.1.to_bytes().as_mut());
        buffer.append(self.2.to_bytes().as_mut());
        buffer.append(self.3.to_bytes().as_mut());
        buffer
    }
}

impl<T1, T2, T3> ToBytes for (T1, T2, T3)
where 
    T1: ToBytes,
    T2: ToBytes,
    T3: ToBytes,
{

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = self.0.to_bytes();
        buffer.append(self.1.to_bytes().as_mut());
        buffer.append(self.2.to_bytes().as_mut());

        buffer
    }
}

impl<T: ToBytes> ToBytes for &T {
    fn to_bytes(&self) -> Vec<u8> {
        <T as ToBytes>::to_bytes(self)
    }
}

impl<T1, T2> ToBytes for (T1, T2)
where 
    T1: ToBytes,
    T2: ToBytes,
{

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = self.0.to_bytes();
        buffer.append(self.1.to_bytes().as_mut());
        buffer
    }
}