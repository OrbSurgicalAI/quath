use std::ops::Deref;

pub mod protocol;
pub mod token;

pub trait Identifier: Copy + ToBytes {
    fn gen_id() -> Self;
    fn to_u128(&self) -> u128;
}

pub trait SigningAlgorithm {
    type Signature: ToBytes;
    type PublicKey: ToBytes;
    type PrivateKey: ToBytes;
    type Error;
    
    fn generate() -> Result<(Self::PublicKey, Self::PrivateKey), Self::Error>;
    fn sign<T: ToBytes>(sequence: &T, private: &Self::PrivateKey) -> Result<Self::Signature, Self::Error>;
    fn verify<T: ToBytes>(sequence: &T, signature: &Self::Signature, key: &Self::PublicKey) -> bool;
}

pub trait HashingAlgorithm {
    type HashResult: ToBytes;

    fn hash<T: ToBytes>(buffer: &T) -> Self::HashResult;
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
    fn to_fixed_repr(self) -> [u8; N];
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