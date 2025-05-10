use k256::{
    EncodedPoint, PublicKey, Secp256k1, ecdh,
    elliptic_curve::{
        self,
        ecdh::{EphemeralSecret, SharedSecret},
        rand_core::OsRng,
        sec1::FromEncodedPoint,
    },
};

use crate::core::crypto::{FixedByteRepr, KEMAlgorithm, ToBytes};

pub struct K256ECDH;

impl ToBytes for EncodedPoint {
    fn to_bytes(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

impl ToBytes for SharedSecret<Secp256k1> {
    fn to_bytes(&self) -> Vec<u8> {
        self.raw_secret_bytes().to_vec()
    }
}

impl ToBytes for EphemeralSecret<Secp256k1> {
    fn to_bytes(&self) -> Vec<u8> {
        self.public_key().to_sec1_bytes().to_vec()
    }
}

impl KEMAlgorithm for K256ECDH {
    type Context = ();
    type CipherText = elliptic_curve::sec1::EncodedPoint<Secp256k1>;
    type SharedSecret = SharedSecret<Secp256k1>;
    type DecapsulationKey = EphemeralSecret<Secp256k1>;
    type EncapsulationKey = EncodedPoint;
    type Error = ();

    fn generate(
        _: &Self::Context,
    ) -> Result<(Self::DecapsulationKey, Self::EncapsulationKey), Self::Error> {
        let alice_secret = EphemeralSecret::random(&mut OsRng);
        let alice_pk_bytes: EncodedPoint = EncodedPoint::from(alice_secret.public_key());
        Ok((alice_secret, alice_pk_bytes))
    }

    fn encapsulate(
        encap_key: &Self::EncapsulationKey,
        _: &Self::Context,
    ) -> Result<(Self::CipherText, Self::SharedSecret), Self::Error> {
        let bob_secret: EphemeralSecret<Secp256k1> = EphemeralSecret::random(&mut OsRng);
        let bob_pk_bytes: EncodedPoint = EncodedPoint::from(bob_secret.public_key());

        let shared_secret =
            bob_secret.diffie_hellman(&PublicKey::from_encoded_point(encap_key).unwrap());

        Ok((bob_pk_bytes, shared_secret))
    }

    fn decapsulate(
        decap_key: &Self::DecapsulationKey,
        cipher: &Self::CipherText,
        context: &Self::Context,
    ) -> Result<Self::SharedSecret, Self::Error> {
        let shared_secret =
            decap_key.diffie_hellman(&PublicKey::from_encoded_point(cipher).unwrap());
        Ok(shared_secret)
    }
}

#[cfg(test)]
mod tests {
    use crate::core::crypto::KEMAlgorithm;

    use super::K256ECDH;

    #[test]
    pub fn test_ecdh_kem() {
        let (dk, ek) = K256ECDH::generate(&()).unwrap();
        let (ct, server_ss) = K256ECDH::encapsulate(&ek, &()).unwrap();
        let client_ss = K256ECDH::decapsulate(&dk, &ct, &()).unwrap();

        assert_eq!(server_ss.raw_secret_bytes(), client_ss.raw_secret_bytes());
    }
}
