use std::{marker::PhantomData, ops::Deref};

use bitvec::array::BitArray;
use rand::Rng;
use sha3::Sha3_256;
use uuid::Uuid;



use super::{
    opcode::OpCode, token::{Final, MsSinceEpoch, Pending, Token}, DsaSystem, FixedByteRepr, HashingAlgorithm, Identifier, KEMAlgorithm, PrivateKey, PublicKey, Signable, Signature, SigningAlgorithm, ToBytes
};




pub type UniformSignedProtocol<S, K, H, I, const H_SIZE: usize> = ProtocolKit<S, K, H, I, S, H_SIZE>;

pub struct ProtocolKit<S, K, H, I, A, const HASH_SIZE: usize> {
    _s: PhantomData<S>,
    _k: PhantomData<K>,
    _h: PhantomData<H>,
    _i: PhantomData<I>,
    _a: PhantomData<A>,
    _hashsize: PhantomData<[u8; HASH_SIZE]>,
}

impl<S, K, H, I, A, const HASH_SIZE: usize> ProtocolKit<S, K, H, I, A, HASH_SIZE>
where
    S: DsaSystem,
    K: KEMAlgorithm,
    H: HashingAlgorithm<HASH_SIZE>,
    I: Identifier,
    A: DsaSystem,
{
    pub fn client_register_init(
        admin_id: I,
        admin_priv: &A::Private,
    ) -> Result<(ClientRegisterInit<S, A, I>, S::Private), ClientRegisterError<S>> {
        let (public, private) = S::generate().map_err(|e| ClientRegisterError::KeyGenError(e))?;

        let body = ClientRegisterPost {
            code: OpCode::Register,
            identifier: I::gen_id(),
            public_key: public,
            admin_approval_id: admin_id.clone(),
        };

        // Create the client signature to prove key ownership.
        let k_proof = private
            .sign_bytes(&body.bytes())
            .map_err(|_| ClientRegisterError::KProofSignFailure)?;

        // Create the administrator signature.
        let a_proof = admin_priv
            .sign_bytes(k_proof.view())
            .map_err(|_| ClientRegisterError::AProofSignFailure)?;

        Ok((
            ClientRegisterInit {
                body,
                k_proof,
                a_proof,
            },
            private,
        ))
    }
    pub fn server_register(
        client: &ClientRegisterInit<S, A, I>,
        admin_public_key: &A::Public,
        server_key: &S::Private,
    ) -> Result<ServerRegister<S::Signature, HASH_SIZE>, ServerProtocolError> {
        if !client
            .body
            .public_key
            .verify(&client.body.bytes(), &client.k_proof)
        {
            return Err(ServerProtocolError::FailedToVerifyKProof);
        }

        println!("FLAG A.2");

        if !admin_public_key.verify(client.k_proof.view(), &client.a_proof) {
            return Err(ServerProtocolError::FailedToVeifyAProof);
        }

        println!("FLAG A.3");

        // Create the response.
        let body = ServerRegisterBody {
            code: OpCode::RegSuccess,
            identity_hash: H::hash(&client.body.identifier.to_bytes()),
        };

        println!("FLAG A.4");

        // We now need to sign the response with the key.
        let signature = server_key
            .sign_bytes(&body.to_bytes())
            .map_err(|_| ServerProtocolError::FailedToSignResponse)?;

        println!("FLAG A.5");

        Ok(ServerRegister { body, signature })
    }
    pub fn client_register_finish(
        in_resp: ServerRegister<S::Signature, HASH_SIZE>,
        server_public: &S::Public,
    ) -> bool {
        server_public.verify(&in_resp.body.to_bytes(), &in_resp.signature)
    }
    pub fn client_cycle_init(
        client_id: I,
        old_private: &S::Private,
    ) -> Result<(CycleInit<I, S::Public, S::Signature>, S::Private), ClientProtocolError> {

        // Generate the new key pair.
        let (new_public, new_private) = S::generate()
            .map_err(|_| ClientProtocolError::FailedToGenerateDsaPair)?;


        // The actual body of the cycle request.
        let body = CycleInitBody {
            code: OpCode::Cycle,
            identifier: client_id,
            new_public_key: new_public
        };

        // The actual signature of the cycle request.
        let signature = old_private.sign_bytes(&body.to_bytes())
            .map_err(|_| ClientProtocolError::FailedToSignRequest)?;



        Ok((CycleInit { body, signature }, new_private))
    }
    pub fn server_cycle(
        in_msg: CycleInit<I, S::Public, S::Signature>,
        client_public: &S::Public,
        server_private: &S::Private,
    ) -> Result<ServerCycle<HASH_SIZE, S::Signature>, ServerProtocolError> {

        if !client_public.verify(&in_msg.body.to_bytes(), &in_msg.signature) {
            return Err(ServerProtocolError::FailedToVerifyCycleReq);
        }

       


        let body = ServerCycleBody {
            code: OpCode::CycleOk,
            hash: H::hash(&in_msg.body.identifier.to_bytes().into_iter().chain(in_msg.body.new_public_key.view().into_iter().copied()).collect::<Vec<_>>())
        };

        let signature = server_private.sign_bytes(&body.to_bytes())
            .map_err(|_| ServerProtocolError::FailedToSignResponse)?;
       
       
        Ok(ServerCycle {
            body,
            signature,
        })
    }
    pub fn client_cycle_finish(
        in_msg: ServerCycle<HASH_SIZE, S::Signature>,
        server_public: &S::Public,
    ) -> Result<(), ClientProtocolError> {

        if !server_public.verify(&in_msg.body.to_bytes(), &in_msg.signature) {
            return Err(ClientProtocolError::InauthenticCycleResponse);
        }

   

        Ok(())
    }

    pub fn client_token_init(
        current_time: MsSinceEpoch,
        client_pk: &S::Private,
        client_id: I,
        context: &K::Context,
    ) -> Result<(ClientToken<S::Signature, K>, K::DecapsulationKey), ClientProtocolError> {
        let token = Token {
            protocol: 0,
            sub_protocol: 0,
            id: client_id.to_u128(),
            permissions: BitArray::new([0u8; 16]),
            timestamp: current_time,
            body: rand::rng().random(),
            _state: PhantomData
        };

        // Generate the decapsulation & encapsulation keypair.
        let (dk, ek) = K::generate(context)
            .map_err(|_| ClientProtocolError::FailedToGenerateKemPair)?;

        // Build the request body.
        let body = ClientTokenBody {
            code: OpCode::Stamp,
            token,
            ek
        };

        // Sign the request body.
        let signature = client_pk.sign_bytes(&body.to_bytes())
            .map_err(|_| ClientProtocolError::FailedToSignRequest)?;

       
        Ok((ClientToken { body, signature }, dk))
    }
    pub fn server_token(
        ClientToken { body, signature }: ClientToken<S::Signature, K>,
        client_pk: &S::Public,
        ctx: &K::Context,
        server_key: &S::Private,
    ) -> Result<(ServerToken<HASH_SIZE, K, S::Signature>, Token<Final>), ServerProtocolError> {

        if !client_pk.verify(&body.to_bytes(), &signature) {
            return Err(ServerProtocolError::FailedToVerifyTokenSignature)?;
        }



        // Perform encapsulation using the KEM.
        let (cipher_text, shared_secret) = K::encapsulate(&body.ek, ctx)
            .map_err(|_| ServerProtocolError::EncapsulationFailed)?;


        // Create the 'new_token' object.
        let new_token = body.token.update_with_shared_secret::<K>(shared_secret);

        // Generate the approval hash.
        let approval = H::hash_sequence(&[ &new_token.to_bytes(), &body.token.to_bytes() ]);

        // Create the response body.
        let body = ServerTokenBody {
            code: OpCode::Stamped,
            cipher_text,
            hash: approval
        };

        // Sign the response body with the server private key.
        let signature = server_key.sign_bytes(&body.to_bytes())
            .map_err(|_| ServerProtocolError::FailedToSignResponse)?;
       
     
        Ok((ServerToken { body, signature }, new_token))
    }
    pub fn client_token_finish(
        token: &Token<Pending>,
        decap_key: &K::DecapsulationKey,
        ServerToken { body, signature }: ServerToken<HASH_SIZE, K, S::Signature>,
        server_pk: &S::Public,
        ctx: &K::Context,
    ) -> Result<Token<Final>, ClientProtocolError> {


        // Verify the body hash.
        if !server_pk.verify(&body.to_bytes(), &signature) {
            return Err(ClientProtocolError::InauthenticTokenResponse);
        }

        // Get the shared secret.
        let shared_secret = K::decapsulate(decap_key, &body.cipher_text, ctx)
            .map_err(|_| ClientProtocolError::DecapsulationError)?;


        // Compute the final token.
        Ok(token.update_with_shared_secret::<K>(shared_secret))
    }
}

#[derive(Debug)]
pub enum ClientRegisterError<S>
where
    S: DsaSystem,
{
    KeyGenError(S::GenError),
    KProofSignFailure,
    AProofSignFailure,
}

#[derive(Debug)]
pub enum ClientTokenError<K, S>
where
    K: KEMAlgorithm,
    S: SigningAlgorithm,
{
    KemSetupError(K::Error),
    SigningError(S::Error),
}

#[derive(Debug)]
pub enum ServerVerificationError<K>
where
    K: KEMAlgorithm,
{
    ServerSignatureFailure,
    DecapsulationError(K::Error),
}

pub struct ServerToken<const H: usize, K, S>
where
    K: KEMAlgorithm,
    S: Signature
{
    pub body: ServerTokenBody<H, K>,
    pub signature: S,
}


pub struct ServerTokenBody<const H: usize, K>
where 
    K: KEMAlgorithm
{
    code: OpCode,
    hash: [u8; H],
    cipher_text: K::CipherText
}

impl<const H: usize, K> ServerTokenBody<H, K>
where 
    K: KEMAlgorithm
{
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(const { 1 + H });
        buffer.push(self.code.to_code());
        buffer.extend_from_slice(&self.hash);
        buffer.extend_from_slice(&self.cipher_text.to_bytes());
        buffer
    }
}

#[derive(Debug)]
pub enum ServerTokenError<K, S>
where
    K: KEMAlgorithm,
    S: SigningAlgorithm,
{
    FailedToVerifyClientKey,
    EncapError(K::Error),
    ServerSignError(S::Error),
}


pub struct ClientToken<S, K>
where
    S: Signature,
    K: KEMAlgorithm,
{
    pub body: ClientTokenBody<K>,
    pub signature: S,
}

pub struct ClientTokenBody<K: KEMAlgorithm> {
    pub code: OpCode,
    pub token: Token<Pending>,
    pub ek: K::EncapsulationKey
}

impl<K> ClientTokenBody<K>
where 
    K: KEMAlgorithm
{
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(75);
        buffer.push(self.code.to_code());
        buffer.extend_from_slice(&self.token.to_bytes());
        buffer.extend_from_slice(&self.ek.to_bytes());
        buffer
    }
}



#[derive(Debug)]
pub struct ClientRegisterPost<I, PK> {
    pub code: OpCode,
    pub identifier: I,
    pub public_key: PK,
    pub admin_approval_id: I,
}

impl<I, PK> ClientRegisterPost<I, PK>
where
    I: Identifier,
    PK: PublicKey,
{
    fn bytes(&self) -> Vec<u8> {
        let mut buffer = vec![];
        buffer.push(self.code.to_code());
        buffer.extend_from_slice(&self.identifier.to_bytes());
        buffer.extend_from_slice(self.public_key.view());
        buffer.extend_from_slice(&self.admin_approval_id.to_bytes());

        buffer
    }
}


#[derive(Debug)]
pub struct ClientRegisterInit<S, A, I>
where
    I: Identifier,
    S: DsaSystem,
    A: DsaSystem,
{
    pub body: ClientRegisterPost<I, S::Public>,
    pub k_proof: S::Signature,
    pub a_proof: A::Signature,
}

pub struct ServerRegister<S, const HASH_SIZE: usize>
where
    S: Signature,
{
    pub body: ServerRegisterBody<HASH_SIZE>,
    pub signature: S,
}

#[derive(Debug)]
pub struct ServerRegisterBody<const H: usize> {
    pub code: OpCode,
    pub identity_hash: [u8; H],
}

impl<const H: usize> ServerRegisterBody<H> {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = vec![ 0u8;  1 + H  ];
        buffer.push(self.code.to_code());
        buffer[1..const { 1 + H }].copy_from_slice(&self.identity_hash);

        buffer
    }
}


pub struct CycleInit<I, PK, S>
{
    pub body: CycleInitBody<I, PK>,
    pub signature: S
}

pub struct CycleInitBody<I, PK> {
    code: OpCode,
    identifier: I,
    new_public_key: PK
}

#[derive(PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct SigWrapper<S: Signature>(pub S);

impl<S> Deref for SigWrapper<S>
where 
    S: Signature
{
    type Target = S;
    fn deref(&self) -> &Self::Target {
        &self.0
    }

}

impl<I, PK> CycleInitBody<I, PK>
where   
    I: Identifier,
    PK: PublicKey
{
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = vec![];
        buffer.push(self.code.to_code());
        buffer.extend_from_slice(&self.identifier.to_bytes());
        buffer.extend_from_slice(self.new_public_key.view());
        buffer
    }
}




#[derive(Debug)]
pub enum ServerProtocolError {
    FailedToVerifyTokenSignature,
    EncapsulationFailed,
    FailedToSignResponse,
    FailedToVerifyCycleReq,
    FailedToVerifyKProof,
    FailedToVeifyAProof
}

#[derive(Debug)]
pub enum ClientProtocolError {
    FailedToGenerateDsaPair,
    FailedToGenerateKemPair,
    InauthenticCycleResponse,
    InauthenticTokenResponse,
    DecapsulationError,
    FailedToSignRequest
}

pub struct ServerCycle<const H: usize, S>
where
    S: Signature,
{
    pub body: ServerCycleBody<H>,
    pub signature: S,
}

pub struct ServerCycleBody<const H: usize> {
    pub code: OpCode,
    pub hash: [u8; H]
}

impl<const H: usize> ServerCycleBody<H> {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(const { 1 + H });
        buffer.push(self.code.to_code());
        buffer.extend_from_slice(self.hash.as_ref());
        buffer
    }
}