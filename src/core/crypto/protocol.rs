use std::{marker::PhantomData, time::Duration};

use bitvec::array::BitArray;
use rand::Rng;
use uuid::Uuid;



use super::{
    mem::B64, opcode::OpCode, token::{Final, Pending, Token}, ClientProtocolError, ClientRegisterInit, DsaSystem, HashingAlgorithm, KEMAlgorithm, MsSinceEpoch, PrivateKey, PublicKey, ServerProtocolError, TokenValidityInterval, ViewBytes
};


use super::data::*;


pub type UniformSignedProtocol<S, K, H, const H_SIZE: usize> = ProtocolKit<S, K, H, H_SIZE>;

pub type ClientProtocolResult<T> = Result<T, ClientProtocolError>;
pub type ServerProtocolResult<T> = Result<T, ServerProtocolError>;


pub type ServerTokenResult<const H: usize, K, S> = ServerProtocolResult<(ServerToken<H, K, S>, Token<Final>)>;
pub type ClientTokenResult<S, K, D> = ClientProtocolResult<(ClientToken<S, K>, D)>; 
pub type ClientCycleResult<PUB, S, PRIV> = ClientProtocolResult<(CycleInit<PUB, S>, PRIV)>;
pub type ClientRegisterResult<PUB, SIG, PRIV> = ClientProtocolResult<(ClientRegisterInit<PUB, SIG>, PRIV)>;



pub struct ProtocolKit<S, K, H, const HS: usize> {
    _s: PhantomData<S>,
    _k: PhantomData<K>,
    _h: PhantomData<H>,
    _hashsize: PhantomData<[u8; HS]>,
}

impl<S, K, H, const HS: usize> ProtocolKit<S, K, H, HS>
where
    S: DsaSystem,
    K: KEMAlgorithm,
    H: HashingAlgorithm<HS>,
{
    /// Initiates client registration. We start by proposing a new [Uuid], which the server will only approve if it is unique. We then provide two proofs:
    /// 
    /// 1. The first proof states that we do actually own the key. Although this is not strictly a necessary security condition, it prevents clients from registering null entities.
    /// 
    /// 2. The second proof states that the administrator actually approves of this rquest.
    /// 
    /// The output in terms of state is the private key. The client only needs to store
    /// the [Uuid] and the [PrivateKey].
    pub fn client_register_init(
        client_id: Uuid,
        admin_id: Uuid,
        admin_priv: &S::Private,
    ) -> ClientRegisterResult<S::Public, S::Signature, S::Private> {
        let (public, private) = S::generate().map_err(|_| ClientProtocolError::FailedToGenerateDsaPair)?;


        
        // Form the request body.
        let body = ClientRegisterPost {
            code: OpCode::Register,
            identifier: client_id,
            public_key: B64(public),
            admin_approval_id: admin_id
        };

        // Create the client signature to prove key ownership.
        let k_proof = private
            .sign_bytes(&body.bytes())
            .map_err(|_| ClientProtocolError::KProofSignError)?;

        // Create the administrator signature.
        let a_proof = admin_priv
            .sign_bytes(&k_proof.view())
            .map_err(|_| ClientProtocolError::AProofSignError)?;

        Ok((
            ClientRegisterInit {
                body,
                k_proof: B64(k_proof),
                a_proof: B64(a_proof),
            },
            private,
        ))
    }
    /// The server register method takes in the client request and performs several checks. The primary
    /// purpose of this method is to verify that the client is legitimate. The checks are as follows:
    /// 
    /// 1. The client's k-proof, which is the proof used to show they own the key they want to submit is verifiable with the public key that was submitted. Hence implying they do actually own this private key.
    /// 
    /// 2. The client's ID is unique. This is actually a precondition of this function call, this function call makes no assumptions about the backend and thus cannot verify that.
    /// 
    /// 3. The client's public key is unique. 
    /// 
    /// The parameters of this method include the actual request, the correspondng admin public key, and the server key that will be used to sign this request.
    /// 
    /// # Preconditions
    /// The client ID is unique.
    /// The client PK is unique.
    pub fn server_register(
        client: &ClientRegisterInit<S::Public, S::Signature>,
        admin_public_key: &S::Public,
        server_key: &S::Private,
    ) -> ServerProtocolResult<ServerRegister<S::Signature, HS>> {
        if !client
            .body
            .public_key
            .verify(&client.body.bytes(), &*client.k_proof)
        {
            return Err(ServerProtocolError::FailedToVerifyKProof);
        }



        // Verify that the administrator actually made this request.
        if !admin_public_key.verify(&client.k_proof.view(), &client.a_proof) {
            return Err(ServerProtocolError::FailedToVerifyAProof);
        }

     

        // Create the response.
        let body = ServerRegisterBody {
            code: OpCode::RegSuccess,
            identity_hash: B64(H::hash(&client.body.identifier.to_bytes_le())),
        };



        // We now need to sign the response with the key.
        let signature = server_key
            .sign_bytes(&body.to_bytes())
            .map_err(|_| ServerProtocolError::FailedToSignResponse)?;

        Ok(ServerRegister { body, signature:B64(signature ) })
    }
    /// This method is the termination of the client 
    pub fn client_register_finish(
        in_resp: &ServerRegister<S::Signature, HS>,
        client_id: Uuid,
        server_public: &S::Public,
    ) -> ClientProtocolResult<()> {

        // Verify the hash is actually correct by calculating it against
        // our stored client ID.
        if H::hash(&client_id.to_bytes_le()) != *in_resp.body.identity_hash {
            return Err(ClientProtocolError::FailedToVerifyIdentityHash);
        }

        // Verify the server actually signe this message.
        if !server_public.verify(&in_resp.body.to_bytes(), &in_resp.signature) {
            return Err(ClientProtocolError::InauthenticRegisterResponse);
        }


        Ok(())
    }

    /// Initializes a cycle on the client's end. To do so, we need the client [Uuid] and the current
    /// private key. This will perform the following steps.
    /// 
    /// 1. Generate a new key pair.
    /// 2. Generate a response.
    /// 3. Sign the response with the new key.
    /// 4. Sign the previous signature with the old key.
    /// 
    /// This format of proof is identical to the registration step, except that the client authorizes
    /// on it's own behalf.
    pub fn client_cycle_init(
        client_id: Uuid,
        old_private: &S::Private,
    ) -> ClientCycleResult<S::Public, S::Signature, S::Private> {

        // Generate the new key pair.
        let (new_public, new_private) = S::generate()
            .map_err(|_| ClientProtocolError::FailedToGenerateDsaPair)?;


        // The actual body of the cycle request.
        let body = CycleInitBody {
            code: OpCode::Cycle,
            identifier: client_id,
            new_public_key: B64(new_public)
        };

        // The proof from the new key.
        let new_proof = new_private.sign_bytes(&body.to_bytes())
            .map_err(|_| ClientProtocolError::FailedToSignRequest)?;

        // The proof from the old key.
        let original_proof = old_private.sign_bytes(&new_proof.view())
            .map_err(|_| ClientProtocolError::FailedToSignRequest)?;



        Ok((CycleInit { 
            body,
            new_proof: B64(new_proof),
            original_proof: B64(original_proof)
         }, new_private))
    }
    /// This function represents the Server's response to the client's initiation of a cycle.
    /// 
    /// This will verify that the signatures are legitimate (the message is proven) and additionally
    /// generate a response that includes a hash of the identity and the new public key to differentiate
    /// it from previous requests, sign this, and then send it back to the client.
    /// 
    /// # Preconditions
    /// The new key must be unique.
    pub fn server_cycle(
        in_msg: &CycleInit<S::Public, S::Signature>,
        client_public: &S::Public,
        server_private: &S::Private,
    ) -> ServerProtocolResult<ServerCycle<HS, S::Signature>> {

        // We need to check that the client actually owns the new
        // key being proposed.
        if !in_msg.body.new_public_key.verify(&in_msg.body.to_bytes(), &in_msg.new_proof) {
            return Err(ServerProtocolError::FailedToVerifyNewCycleKey)?;

        }

        // We need to check the old key approves.
        if !client_public.verify(&in_msg.new_proof.view(), &in_msg.original_proof) {
            return Err(ServerProtocolError::FailedToVerifyOldKeyDuringCycle);
        }

       
        // Produce the response.
        let body = ServerCycleBody {
            code: OpCode::CycleOk,
            hash: B64(H::hash_sequence(&[ (&in_msg.body.identifier.to_bytes_le()) as &[u8], &in_msg.body.new_public_key.view() ]))
        };

        // Sign the body.
        let signature = server_private.sign_bytes(&body.to_bytes())
            .map_err(|_| ServerProtocolError::FailedToSignResponse)?;
       
       
        Ok(ServerCycle {
            body,
            signature: B64(signature),
        })
    }
    /// This method is how the client terminates the cycling process. The client will perform the following steps.
    /// 1. Verify that the hash provided by the server corresponds to the actual request that was made.
    /// 2. 
    pub fn client_cycle_finish(
        in_msg: &ServerCycle<HS, S::Signature>,
        client_id: Uuid,
        proposed_public_key: &S::Public,
        server_public: &S::Public,
    ) -> ClientProtocolResult<()> {

        // Calculate the hash to verify that it actually corresponds to that of the server.
        let calculated = H::hash_sequence(&[ &client_id.to_bytes_le(), &proposed_public_key.view() ]);


        // Verify the hashes coincide.
        if *in_msg.body.hash != calculated {
            return Err(ClientProtocolError::FailedToVerifyCycleHash);
        }

        // Verify the key signing.
        if !server_public.verify(&in_msg.body.to_bytes(), &in_msg.signature) {
            return Err(ClientProtocolError::InauthenticCycleResponse);
        }

        Ok(())
    }
    /// Initiaizes a client token request. This requires several pieces of informaton such as the current
    /// time, the client private key, and additionally the [KEMAlgorithm] context, which may be empty for
    /// many KEMs.
    /// 
    /// This will perform the following operations:
    /// 1. Generate the KEM (dk, ek). The encapsulation key is packaged and will be sent to the server.
    /// 2. Formulate the token according to the parameters given.
    /// 3. Sign the token with the current client private key.
    pub fn client_token_init<F>(
        protocol: u8,
        sub_protocol: u8,
        current_time: MsSinceEpoch,
        client_pk: &S::Private,
        client_id: Uuid,
        mut modifier: F
    ) -> ClientTokenResult<S::Signature, K, K::DecapsulationKey>
    where   
        F: FnMut(&mut Token<Pending>)
    {
        // Create the pending token, this involves generating a random body.
        let mut token = Token {
            protocol,
            sub_protocol,
            id: client_id,
            permissions: BitArray::new([0u8; 16]),
            timestamp: current_time,
            body: rand::rng().random(),
            _state: PhantomData
        };

        modifier(&mut token);

        // Generate the decapsulation & encapsulation keypair.
        let (dk, ek) = K::generate()
            .map_err(|_| ClientProtocolError::FailedToGenerateKemPair)?;

        // Build the request body.
        let body = ClientTokenBody {
            code: OpCode::Stamp,
            token: B64(token),
            ek: B64(ek)
        };

        // Sign the request body.
        let signature = client_pk.sign_bytes(&body.to_bytes())
            .map_err(|_| ClientProtocolError::FailedToSignRequest)?;

       
        Ok((ClientToken { body, signature: B64(signature) }, dk))
    }

    /// The server response to the client token request. This will perform the following steps:
    /// 1. Verify the client sent this request.
    /// 2. Produce the shared secret, and thus, finalize the token. 
    /// 3. Produce and sign a response to the client.
    /// 
    /// NOTE: The server should _not_ store the final token as is, it must
    /// be hashed first!
    pub fn server_token(
        ClientToken { body, signature }: &ClientToken<S::Signature, K>,
        client_pk: &S::Public,
        server_key: &S::Private,
        interval: &TokenValidityInterval,
        current_time: MsSinceEpoch,
        expiry: Duration
    ) -> ServerTokenResult<HS, K, S::Signature> {

        // The token is out of the interval here.
        if !interval.check_time_validity(current_time, body.token.timestamp) {
            return Err(ServerProtocolError::TokenOutOfInterval);
        }


        // Verify the client actually sent this request.
        if !client_pk.verify(&body.to_bytes(), signature) {
            return Err(ServerProtocolError::FailedToVerifyTokenSignature)?;
        }



        // Perform encapsulation using the KEM.
        let (cipher_text, shared_secret) = K::encapsulate(&body.ek)
            .map_err(|_| ServerProtocolError::EncapsulationFailed)?;


        // Create the 'new_token' object.
        let new_token = body.token.update_with_shared_secret::<K>(shared_secret);

        // Generate the approval hash.
        let approval = H::hash_sequence(&[ &new_token.view(), &body.token.view() ]);

        // Create the response body.
        let body = ServerTokenBody {
            code: OpCode::Stamped,
            cipher_text: B64(cipher_text),
            hash: B64(approval),
            expiry: MsSinceEpoch(current_time.0 + expiry.as_millis() as i64)
        };

        // Sign the response body with the server private key.
        let signature = server_key.sign_bytes(&body.to_bytes())
            .map_err(|_| ServerProtocolError::FailedToSignResponse)?;
       
     
        Ok((ServerToken { body, signature: B64(signature) }, new_token))
    }

    /// Terminates the token request on the client's side. This will perform a few
    /// veriifcations to verify the correctness and authenticity of the request,
    /// and then will create the final token.
    pub fn client_token_finish(
        ServerToken { body, signature }: &ServerToken<HS, K, S::Signature>,
        token: &Token<Pending>,
        decap_key: &K::DecapsulationKey,
        
        server_pk: &S::Public,
    ) -> ClientProtocolResult<Token<Final>> {


      
        // Verify the body hash.
        if !server_pk.verify(&body.to_bytes(), signature) {
            return Err(ClientProtocolError::InauthenticTokenResponse);
        }

        // Get the shared secret.
        let shared_secret = K::decapsulate(decap_key, &body.cipher_text)
            .map_err(|_| ClientProtocolError::DecapsulationError)?;

        // Calculate the approval hash.
        let new_token = token.update_with_shared_secret::<K>(shared_secret);


        // Calculate the approval hash
        let c_approval_hash = H::hash_sequence(&[ &new_token.view(), &token.view() ]);
        if c_approval_hash != *body.hash {
            return Err(ClientProtocolError::FailedToReconstructApprovalHash);
        }

        // Compute the final token.
        Ok(new_token)
    }
}








#[cfg(test)]
mod tests {
    use std::time::Duration;

    use sha3::Sha3_256;
    use uuid::Uuid;

    use crate::{algos::{fips203::MlKem512, fips204::MlDsa44}, core::crypto::{token::{Pending, Token}, DsaSystem, MsSinceEpoch, QuantumKitL1, TokenValidityInterval}};

    use super::ProtocolKit;



    fn execute_protocol_run() -> anyhow::Result<(), String> {
        let (server_public, server_private) = MlDsa44::generate()?;
        let (admin_public, admin_private) = MlDsa44::generate()?;


        let admin_id = Uuid::new_v4();
        let client_id = Uuid::new_v4();

        

        // Send the original client request.
        let (req, client_private) = ProtocolKit::<MlDsa44, MlKem512, Sha3_256, 32>::client_register_init(client_id, admin_id, &admin_private).unwrap();


        // Perform the server side of registry.
        let server_registry = QuantumKitL1::server_register(&req, &admin_public, &server_private).unwrap();



        // Client finishes registry
        QuantumKitL1::client_register_finish(&server_registry, client_id, &server_public).unwrap();

        // client response
        let (cycle_init, client_private) = QuantumKitL1::client_cycle_init(client_id, &client_private).unwrap();


        let new_public = cycle_init.body.new_public_key.clone();

        // server answers cycle.
        let serv = ProtocolKit::<MlDsa44, MlKem512, Sha3_256, 32>::server_cycle(&cycle_init, &req.body.public_key, &server_private).unwrap();

        // client sees the server answer.
        QuantumKitL1::client_cycle_finish(&serv, client_id, &*new_public, &server_public).unwrap();

        // client proposes toen.
        let (req, decapskey) = QuantumKitL1::client_token_init(0, 0, MsSinceEpoch(0), &client_private, client_id, |_: &mut Token<Pending>| {
            
        }).unwrap();


        // Server will responsee.
        let (res, server_final_token) = QuantumKitL1::server_token(&req, &new_public, &server_private, &TokenValidityInterval::from_seconds(0, 0), MsSinceEpoch(0), Duration::from_secs(3)).unwrap();

        // Client will see the server response.
        let client_final_token = QuantumKitL1::client_token_finish(&res, &req.body.token, &decapskey, &server_public).unwrap();



        assert_eq!(server_final_token, client_final_token);


        Ok(())
    }

    #[test]
    pub fn test_protocol_run() -> anyhow::Result<(), &'static str> {
        execute_protocol_run().unwrap();
        Ok(())
    }

    #[test]
    pub fn test_protocol_run_arbtest() -> anyhow::Result<(), &'static str> {
        arbtest::arbtest(|_| {
            execute_protocol_run().unwrap();
            Ok(())
        });
        Ok(())
    }
}