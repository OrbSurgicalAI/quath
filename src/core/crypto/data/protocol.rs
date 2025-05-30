use uuid::Uuid;

use crate::{
    ServerProtocolError,
    core::crypto::{
        KemAlgorithm, MsSinceEpoch, PublicKey, Signature, ViewBytes,
        mem::B64,
        opcode::OpCode,
        token::{Pending, Token},
    },
};

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ServerToken<const H: usize, K, S>
where
    K: KemAlgorithm,
    S: Signature,
{
    pub body: ServerTokenBody<H, K>,
    pub signature: B64<S>,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ServerTokenBody<const H: usize, K>
where
    K: KemAlgorithm,
{
    pub code: OpCode,
    pub hash: B64<[u8; H]>,
    pub cipher_text: B64<K::CipherText>,
    pub expiry: MsSinceEpoch,
}

impl<const H: usize, K> ServerTokenBody<H, K>
where
    K: KemAlgorithm,
{
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(const { 1 + H });
        buffer.push(self.code.to_code());
        buffer.extend_from_slice(&*self.hash);
        buffer.extend_from_slice(&self.cipher_text.view());
        buffer
    }
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ClientToken<S, K>
where
    S: Signature,
    K: KemAlgorithm,
{
    pub body: ClientTokenBody<K>,
    pub signature: B64<S>,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ClientTokenBody<K: KemAlgorithm> {
    pub code: OpCode,
    pub token: B64<Token<Pending>>,
    pub ek: B64<K::EncapsulationKey>,
}

impl<K> ClientTokenBody<K>
where
    K: KemAlgorithm,
{
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(75);
        buffer.push(self.code.to_code());
        buffer.extend_from_slice(&self.token.to_fixed_bytes());
        buffer.extend_from_slice(&self.ek.view());
        buffer
    }
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug)]
pub struct ClientRegisterPost<PK>
where
    PK: PublicKey,
{
    pub code: OpCode,
    pub identifier: Uuid,
    pub public_key: B64<PK>,
    pub admin_approval_id: Uuid,
}

impl<PK> ClientRegisterPost<PK>
where
    PK: PublicKey,
{
    pub fn bytes(&self) -> Vec<u8> {
        let mut buffer = vec![];
        buffer.push(self.code.to_code());
        buffer.extend_from_slice(&self.identifier.to_bytes_le());
        buffer.extend_from_slice(&self.public_key.view());
        buffer.extend_from_slice(&self.admin_approval_id.to_bytes_le());

        buffer
    }
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug)]
pub struct ClientRegisterInit<PK, S>
where
    PK: PublicKey,
    S: Signature,
{
    pub body: ClientRegisterPost<PK>,
    pub k_proof: B64<S>,
    pub a_proof: B64<S>,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ServerRegister<S, const HASH_SIZE: usize>
where
    S: Signature,
{
    pub body: ServerRegisterBody<HASH_SIZE>,
    pub signature: B64<S>,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug)]
pub struct ServerRegisterBody<const H: usize> {
    pub code: OpCode,
    pub identity_hash: B64<[u8; H]>,
}

impl<const H: usize> ServerRegisterBody<H> {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = vec![0u8; 1 + H];
        buffer.push(self.code.to_code());
        buffer[1..const { 1 + H }].copy_from_slice(&*self.identity_hash);

        buffer
    }
}

#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ClientDeregister<S, const N: usize>
where
    S: Signature,
{
    pub target: Uuid,
    pub claimant: Uuid,
    pub proof: B64<S>,
}

#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ServerDeregister<S, const N: usize>
where
    S: Signature,
{
    pub approval: B64<[u8; N]>,
    pub proof: B64<S>,
}

#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ClientRevoke<S, const N: usize>
where
    S: Signature,
{
    pub token_hash: B64<[u8; N]>,
    pub target: Uuid,
    pub claimant: Uuid,
    pub proof: B64<S>,
}

#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ServerRevoke<S, const N: usize>
where
    S: Signature,
{
    pub revoke_hash: B64<[u8; N]>,
    pub proof: B64<S>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ServerErrorResponse {
    pub name: &'static str,
    pub error: String,
}

impl From<ServerProtocolError> for ServerErrorResponse {
    fn from(value: ServerProtocolError) -> Self {
        Self {
            name: value.error_name(),
            error: value.to_string(),
        }
    }
}

#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CycleInit<PK, S>
where
    S: Signature,
    PK: PublicKey,
{
    pub body: CycleInitBody<PK>,
    pub new_proof: B64<S>,
    pub original_proof: B64<S>,
}

#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CycleInitBody<PK>
where
    PK: PublicKey,
{
    pub code: OpCode,
    pub identifier: Uuid,
    pub new_public_key: B64<PK>,
}

impl<PK> CycleInitBody<PK>
where
    PK: PublicKey,
{
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = vec![];
        buffer.push(self.code.to_code());
        buffer.extend_from_slice(&self.identifier.to_bytes_le());
        buffer.extend_from_slice(&self.new_public_key.view());
        buffer
    }
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ServerCycle<const H: usize, S>
where
    S: Signature,
{
    pub body: ServerCycleBody<H>,
    pub signature: B64<S>,
}

#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ServerCycleBody<const H: usize> {
    pub code: OpCode,
    pub hash: B64<[u8; H]>,
}

impl<const H: usize> ServerCycleBody<H> {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(const { 1 + H });
        buffer.push(self.code.to_code());
        buffer.extend_from_slice(self.hash.as_ref());
        buffer
    }
}
