use k256::{ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey}, elliptic_curve::{rand_core::OsRng, sec1::EncodedPoint}, Secp256k1};
use rand::seq;

use k256::ecdsa::signature::Verifier;

pub struct K256ECDSA;



// impl crate::core::crypto::Signature<64> for k256::ecdsa::Signature {
//     fn view(&self) -> &[u8] {
//         self.to_bytes().into()
//     }
// }

// impl crate::core::crypto::PrivateKey for SigningKey {
//     type Signature = k256::ecdsa::Signature;
//     type Error = k256::ecdsa::Error;

//     fn sign_bytes(&self, sequence: &[u8]) -> Result<Self::Signature, Self::Error> {
//         self.try_sign(sequence)
//     }
// }


#[repr(transparent)]
pub struct K256Public(EncodedPoint<Secp256k1>);


impl crate::core::crypto::PublicKey for K256Public {
    type Signature = Signature;
    fn verify(&self, message: &[u8], signature: &Self::Signature) -> bool {
        VerifyingKey::from_encoded_point(&self.0).is_ok_and(|f| {
            f.verify(message, signature).is_ok()
        })
    }
    fn view(&self) -> &[u8] {
        self.0.as_bytes()
    }
}
