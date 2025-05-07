use std::marker::PhantomData;

use fips203::ml_kem_512;
use fips204::ml_dsa_44;
use rand::Rng;
use uuid::Uuid;

use super::{token::{MsSinceEpoch, Token}, HashingAlgorithm, Identifier, KEMAlgorithm, Signable, SigningAlgorithm, ToBytes};

#[derive(Debug)]
pub enum OpCode {
    Register,
    RegSuccess,
    Cycle,
    CycleOk,
    Stamp,
    Stamped
}

impl ToBytes for OpCode {
    fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Register => vec![0],
            Self::RegSuccess => vec![1],
            Self::Cycle => vec![2],
            Self::CycleOk => vec![ 3],
            Self::Stamp => vec![ 4 ],
            Self::Stamped => vec![ 5 ]
        }
    }
}

pub type MlDSA44 = ml_dsa_44::KG;
pub type MlStandardLight = ProtocolKit<MlDSA44, ml_kem_512::KG, sha3::Sha3_256, Uuid, MlDSA44>;

pub struct ProtocolKit<S, K, H, I, A> {
    _s: PhantomData<S>,
    _k: PhantomData<K>,
    _h: PhantomData<H>,
    _i: PhantomData<I>,
    _a: PhantomData<A>,
}

impl<S, K, H, I, A> ProtocolKit<S, K, H, I, A>
where
    S: SigningAlgorithm,
    K: KEMAlgorithm,
    H: HashingAlgorithm,
    I: Identifier,
    A: SigningAlgorithm,
{
    pub fn client_register_init(
        admin_id: I,
        admin_priv: &A::PrivateKey,
    ) -> Result<(ClientRegisterInit<S, A, I>, S::PrivateKey), ClientRegisterError<S, A>> {
        let (public, private) = S::generate().map_err(|e| ClientRegisterError::KeyGenError(e))?;

        let sigable = Signable::new((OpCode::Register, I::gen_id(), public, admin_id.clone()));

        let k_proof = S::sign(&sigable, &private).map_err(|e| ClientRegisterError::KProofSignError(e))?;

        let a_proof = A::sign(&k_proof, admin_priv).map_err(|e| ClientRegisterError::AProofSignError(e))?;

        Ok((
            ClientRegisterInit {
                body: sigable,
                k_proof,
                a_proof,
            },
            private,
        ))
    }
    pub fn server_register(
        client: &ClientRegisterInit<S, A, I>,
        admin_public_key: &A::PublicKey,
        server_key: &S::PrivateKey,
    ) -> Result<ServerRegister<H, S>, RegisterError<S::Error>> {
        if !S::verify(&client.body, &client.k_proof, &client.body.2) {
            return Err(RegisterError::KProofFail);
        }
        if !A::verify(&client.k_proof, &client.a_proof, &admin_public_key) {
            return Err(RegisterError::AProofFail);
        }

        let packet = Signable::new((OpCode::RegSuccess, H::hash(&client.body.inner.1)));

        let signature = S::sign(&packet, server_key).map_err(|e| RegisterError::Error(e))?;

        Ok(ServerRegister {
            body: packet,
            sig: signature,
        })
    }
    pub fn client_register_finish(
        in_resp: ServerRegister<H, S>,
        server_public: &S::PublicKey,
    ) -> bool {
        S::verify(&in_resp.body, &in_resp.sig, &server_public)
    }
    pub fn client_cycle_init(
        client_id: I,
        old_private: &S::PrivateKey,
    ) -> Result<(CycleInit<I, S>, S::PrivateKey), S::Error> {
        let (new_public, new_private) = S::generate()?;

        let body = Signable::new((OpCode::Cycle, client_id.clone(), new_public));

        let signature = S::sign(&body, old_private)?;

        Ok((CycleInit { body, signature }, new_private))
    }
    pub fn server_cycle(
        in_msg: CycleInit<I, S>,
        client_public: &S::PublicKey,
        server_private: &S::PrivateKey
    ) -> Result<ServerCycle<H, S>, ServerCycleError<S::Error>>
    {

        if !S::verify(&in_msg.body, &in_msg.signature, client_public) {
            return Err(ServerCycleError::ServerVerifyFail);
        }

        let sig = Signable::new((OpCode::CycleOk, H::hash(&(&in_msg.body.1, &in_msg.body.2))));


        let signature = S::sign(&sig, &server_private).map_err(|e| ServerCycleError::Other(e))?;

        Ok(ServerCycle {
            body: sig,
            signature
        })

    }
    pub fn client_cycle_finish(
        in_msg: ServerCycle<H, S>,
        server_public: &S::PublicKey
    ) -> Result<(), CycleFinishError<S::Error>>
    {

        if !S::verify(&in_msg.body, &in_msg.signature, server_public) {
            return Err(CycleFinishError::ServerVerifyFail);
        }

        Ok(())

    }
   
    pub fn client_token_init(
        current_time: MsSinceEpoch,
        client_pk: &S::PrivateKey,
        client_id: I,
        context: &K::Context
    ) -> Result<(ClientToken<S, K>, K::DecapsulationKey), ClientTokenError<K, S>> 
    {
        let token = Token {
            protocol: 0,
            sub_protocol: 0,
            id: client_id.to_u128(),
            permissions: 0,
            timestamp: current_time,
            body: rand::rng().random()
        };


        let (dk, ek) = K::generate(context).map_err(|e| ClientTokenError::KemSetupError(e))?;

        let body = (OpCode::Stamp, token, ek);

        let signature = S::sign(&body, &client_pk).map_err(|e| ClientTokenError::SigningError(e))?;

        Ok((ClientToken {
            body,
            signature
        }, dk))
    }
    pub fn server_token(
        ClientToken { body, signature }: ClientToken<S, K>,
        client_pk: &S::PublicKey,
        ctx: &K::Context,
        server_key: &S::PrivateKey
    ) -> Result<(ServerToken<K, H, S>, Token), ServerTokenError<K, S>>
    {
        if !S::verify(&body, &signature, client_pk) {
            return Err(ServerTokenError::FailedToVerifyClientKey);
        }

        let (_, mut token, ek) = body;

        let (ct, ss) = K::encapsulate(&ek, ctx).map_err(|e| ServerTokenError::EncapError(e.into()))?;


        
        let modified = token.update_with_shared_secret::<K>(ss);


        let approval_hash = H::hash(&(&modified, &token));


        /* Create the token */
        let body = (OpCode::Stamped, approval_hash, ct);
        let signature = S::sign(&body, server_key).map_err(|e| ServerTokenError::ServerSignError(e.into()))?;


        Ok((ServerToken {
            body,
            signature
        }, modified))
    }
    pub fn client_token_finish(
        token: &Token,
        decap_key: &K::DecapsulationKey,
        ServerToken { body, signature }: ServerToken<K, H, S>,
        server_pk: &S::PublicKey,
        ctx: &K::Context
    ) -> Result<Token, ServerVerificationError<K>> {
        let (code, approval, ct) = body;
        if !S::verify(&(&code, &approval, &ct), &signature, server_pk) {
            return Err(ServerVerificationError::ServerSignatureFailure);
        }

        let ss = K::decapsulate(decap_key, &ct, ctx).map_err(|e| ServerVerificationError::DecapsulationError(e))?;

        Ok(token.update_with_shared_secret::<K>(ss))

        
    }
}

#[derive(Debug)]
pub enum ClientRegisterError<S, A>
where 
    S: SigningAlgorithm,
    A: SigningAlgorithm
{
    KeyGenError(S::Error),
    KProofSignError(S::Error),
    AProofSignError(A::Error)
}

#[derive(Debug)]
pub enum ClientTokenError<K, S>
where 
    K: KEMAlgorithm,
    S: SigningAlgorithm
{
    KemSetupError(K::Error),
    SigningError(S::Error)
}


#[derive(Debug)]
pub enum ServerVerificationError<K>
where 
    K: KEMAlgorithm
{
    ServerSignatureFailure,
    DecapsulationError(K::Error)
}


#[derive(Debug)]
pub struct ServerToken<K, H, S>
where 
    K: KEMAlgorithm,
    H: HashingAlgorithm,
    S: SigningAlgorithm
{
    pub body: (OpCode, H::HashResult, K::CipherText),
    pub signature: S::Signature
}


#[derive(Debug)]
pub enum ServerTokenError<K, S>
where 
    K: KEMAlgorithm,
    S: SigningAlgorithm
{
    FailedToVerifyClientKey,
    EncapError(K::Error),
    ServerSignError(S::Error)
}


#[derive(Debug)]
pub struct ClientToken<S, K>
where 
    S: SigningAlgorithm,
    K: KEMAlgorithm
{
    pub body: (OpCode, Token, K::EncapsulationKey),
    pub signature: S::Signature
}

impl<S: SigningAlgorithm, K: KEMAlgorithm> ClientToken<S, K>
{
    pub fn token(&self) -> &Token {
        &self.body.1
    }
    
}

#[derive(Debug)]
pub enum RegisterError<E> {
    KProofFail,
    AProofFail,
    Error(E),
}

#[derive(Debug)]
pub enum ServerCycleError<E> {
    ServerVerifyFail,
    Other(E)
}


#[derive(Debug)]
pub enum CycleFinishError<E> {
    ServerVerifyFail,
    Other(E)
}

#[derive(Debug)]
pub enum ClientRegisterFinish<E> {
    SignatureFailure,
    Error(E),
}

#[derive(Debug)]
pub struct ClientRegisterInit<S, A, I>
where
    I: Identifier,
    S: SigningAlgorithm,
    A: SigningAlgorithm,
{
    pub body: Signable<(OpCode, I, S::PublicKey, I)>,
    pub k_proof: S::Signature,
    pub a_proof: A::Signature,
}

#[derive(Debug)]
pub struct ServerRegister<H, S>
where
    H: HashingAlgorithm,
    S: SigningAlgorithm,
{
    pub body: Signable<(OpCode, H::HashResult)>,
    pub sig: S::Signature,
}

#[derive(Debug)]
pub struct CycleInit<I, S>
where
    I: Identifier,
    S: SigningAlgorithm,
{
    pub body: Signable<(OpCode, I, S::PublicKey)>,
    pub signature: S::Signature,
}

#[derive(Debug)]
pub struct ServerCycle<H, S>
where 
    H: HashingAlgorithm,
    S: SigningAlgorithm
{
    pub body: Signable<(OpCode, H::HashResult)>,
    pub signature: S::Signature
}

