use std::borrow::Cow;

use elliptic_curve::{sec1::{EncodedPoint, ModulusSize}, Curve};
use k256::Secp256k1;

use crate::{Parse, PublicKey, ViewBytes};


#[derive(Clone)]
#[repr(transparent)]
pub struct QuathCurvePoint<C>
where 
    C: Curve,
    <C as elliptic_curve::Curve>::FieldBytesSize: ModulusSize
{
    point: EncodedPoint<C>
}

impl<C> QuathCurvePoint<C>
where 
    C: Curve,
    <C as elliptic_curve::Curve>::FieldBytesSize: ModulusSize
{

    pub fn from_raw_point(point: EncodedPoint<C>) -> Self {
        Self {
            point
        }
    }

}

impl<C> QuathCurvePoint<C>
where 
    C: Curve,
    <C as Curve>::FieldBytesSize: ModulusSize
{
    pub fn encoded_point(&self) -> &EncodedPoint<C> {
        &self.point
    }
}

impl<'a, C> Parse<'a> for QuathCurvePoint<C>
where 
    C: Curve,
    <C as Curve>::FieldBytesSize: ModulusSize
{
    type Error = elliptic_curve::Error;
    fn parse_bytes(array: &'a [u8]) -> Result<Self, Self::Error> {
        let value: EncodedPoint<C> = EncodedPoint::<C>::from_bytes(array)?;
        Ok(Self {
            point: value
        })
    }
}

impl<C> ViewBytes for QuathCurvePoint<C>
where 
    C: Curve,
    <C as Curve>::FieldBytesSize: ModulusSize
{
    fn view(&self) -> std::borrow::Cow<'_, [u8]> {
        let secret = self.point.as_bytes();
        Cow::Borrowed(secret)
    }
}

