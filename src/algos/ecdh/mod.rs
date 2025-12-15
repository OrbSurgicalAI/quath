// use k256::{
//     EncodedPoint, PublicKey, Secp256k1, elliptic_curve::{
//         self,
//         ecdh::{EphemeralSecret, SharedSecret},
//         rand_core::OsRng,
//         sec1::FromEncodedPoint,
//     },
// };

// use crate::{algos::k256common::K256EncodedPoint, KemAlgorithm, Parse, ViewBytes};


// pub struct K256ECDH;

// impl<'a> Parse<'a> for SharedSecret<Secp256k1> {
//     type Error = elliptic_curve::Error;
//     fn parse_bytes(array: &'a [u8]) -> Result<Self, Self::Error> {
//         Ok(SharedSecret::try_from(array))
//     }
// }



// impl KemAlgorithm for K256ECDH {
//     type CipherText = K256EncodedPoint;
//     type SharedSecret = SharedSecret<Secp256k1>;
//     type DecapsulationKey = EphemeralSecret<Secp256k1>;
//     type EncapsulationKey = EncodedPoint;
//     type Error = ();

//     fn generate(
//         _: &Self::Context,
//     ) -> Result<(Self::DecapsulationKey, Self::EncapsulationKey), Self::Error> {
//         let alice_secret = EphemeralSecret::random(&mut OsRng);
//         let alice_pk_bytes: EncodedPoint = EncodedPoint::from(alice_secret.public_key());
//         Ok((alice_secret, alice_pk_bytes))
//     }

//     fn encapsulate(
//         encap_key: &Self::EncapsulationKey,
//         _: &Self::Context,
//     ) -> Result<(Self::CipherText, Self::SharedSecret), Self::Error> {
//         let bob_secret: EphemeralSecret<Secp256k1> = EphemeralSecret::random(&mut OsRng);
//         let bob_pk_bytes: EncodedPoint = EncodedPoint::from(bob_secret.public_key());

//         let shared_secret =
//             bob_secret.diffie_hellman(&PublicKey::from_encoded_point(encap_key).unwrap());

//         Ok((bob_pk_bytes, shared_secret))
//     }

//     fn decapsulate(
//         decap_key: &Self::DecapsulationKey,
//         cipher: &Self::CipherText,
//         context: &Self::Context,
//     ) -> Result<Self::SharedSecret, Self::Error> {
//         let shared_secret =
//             decap_key.diffie_hellman(&PublicKey::from_encoded_point(cipher).unwrap());
//         Ok(shared_secret)
//     }
// }

// #[cfg(test)]
// mod tests {
//     use crate::core::crypto::KEMAlgorithm;

//     use super::K256ECDH;

//     #[test]
//     pub fn test_ecdh_kem() {
//         let (dk, ek) = K256ECDH::generate(&()).unwrap();
//         let (ct, server_ss) = K256ECDH::encapsulate(&ek, &()).unwrap();
//         let client_ss = K256ECDH::decapsulate(&dk, &ct, &()).unwrap();

//         assert_eq!(server_ss.raw_secret_bytes(), client_ss.raw_secret_bytes());
//     }
// }
