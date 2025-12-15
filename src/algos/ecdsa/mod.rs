use std::{default, ops::Add};

use ecdsa::{hazmat::{DigestPrimitive, VerifyPrimitive}, signature::Verifier, EncodedPoint, PrimeCurve, VerifyingKey};
use elliptic_curve::{ecdh::EphemeralSecret, generic_array::ArrayLength, rand_core::OsRng, sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint}, Curve, CurveArithmetic};
use k256::Secp256k1;

use crate::{algos::curves::QuathCurvePoint, DsaSystem, Parse, PrivateKey, PublicKey, ViewBytes};


#[derive(Clone)]
pub struct QuathEcdsaPublic<K>
where 
    K: PrimeCurve + CurveArithmetic,
    K: Curve,
    <K as Curve>::FieldBytesSize: ModulusSize
{
    key: QuathCurvePoint<K>
}

impl<'a, C> QuathEcdsaPublic<C>
where 
    C: PrimeCurve + CurveArithmetic,
    C: Curve,
    <C as Curve>::FieldBytesSize: ModulusSize
{
    pub fn from_encoded_point(point: EncodedPoint<C>) -> Self {
        Self {
            key: QuathCurvePoint::from_raw_point(point)
        }
    }

}

impl<'a, C> Parse<'a> for QuathEcdsaPublic<C>
where 
    C: PrimeCurve + CurveArithmetic,
    C: Curve,
    <C as Curve>::FieldBytesSize: ModulusSize
{
    type Error = elliptic_curve::Error;
    fn parse_bytes(array: &'a [u8]) -> Result<Self, Self::Error> {
        let point = QuathCurvePoint::<C>::parse_bytes(array)?;
        Ok(Self {
            key: point
        })
    }
}

impl<'a, C> ViewBytes for QuathEcdsaPublic<C>
where 
    C: PrimeCurve + CurveArithmetic,
    C: Curve,
    <C as Curve>::FieldBytesSize: ModulusSize
{
    fn view(&self) -> std::borrow::Cow<'_, [u8]> {
        self.key.view()
    }
}

impl<K> PublicKey for QuathEcdsaPublic<K>
where 
    K: PrimeCurve + CurveArithmetic,
    K: Curve + DigestPrimitive,
    <K as Curve>::FieldBytesSize: ModulusSize,
    <K as CurveArithmetic>::AffinePoint: FromEncodedPoint<K>,
    <K as CurveArithmetic>::AffinePoint: ToEncodedPoint<K>,
    <K as CurveArithmetic>::AffinePoint: VerifyPrimitive<K>,
    <<K as elliptic_curve::Curve>::FieldBytesSize as Add>::Output: ArrayLength<u8>
{
    type Signature = ecdsa::Signature<K>;

    fn verify(&self, message: &[u8], signature: &Self::Signature) -> bool {
        VerifyingKey::from_encoded_point(self.key.encoded_point())
            .is_ok_and(|f| f.verify(message, signature).is_ok())
    }
}

impl PrivateKey for EphemeralSecret<Secp256k1> {
    fn sign_bytes(&self, sequence: &[u8]) -> Result<Self::Signature, Self::Error> {
        self.
    }
}


impl DsaSystem for Secp256k1 {
    type Private = EphemeralSecret<Secp256k1>;
    type Public = QuathEcdsaPublic<Secp256k1>;
    fn generate() -> Result<(Self::Public, Self::Private), Self::GenError> {
        let alice_secret = EphemeralSecret::<Secp256k1>::random(&mut OsRng);
         let alice_pk_bytes = EncodedPoint::<Secp256k1>::from(alice_secret.public_key());
         Ok((alice_secret, alice_pk_bytes))
    }
}



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






// impl crate::core::crypto::PublicKey for K256EncodedPoint {
//     type Signature = Signature;
//     fn verify(&self, message: &[u8], signature: &Self::Signature) -> bool {
//         VerifyingKey::from_encoded_point(self.encoded_point())
//             .is_ok_and(|f| f.verify(message, signature).is_ok())
//     }
// }
