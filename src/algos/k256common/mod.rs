use k256::{elliptic_curve::{self, sec1}, EncodedPoint, Secp256k1};

use crate::{Parse, ViewBytes};

#[derive(Clone)]
#[repr(transparent)]
pub struct K256EncodedPoint(EncodedPoint);

impl K256EncodedPoint {
    pub fn encoded_point(&self) -> &EncodedPoint {
        &self.0
    }
}

impl<'a> Parse<'a> for K256EncodedPoint {
    type Error = elliptic_curve::Error;
    fn parse_bytes(array: &'a [u8]) -> Result<Self, Self::Error> {
        Ok(EncodedPoint::from_bytes(array).map(|i| Self(i))?)
    }
}

impl ViewBytes for K256EncodedPoint {
     fn view(&self) -> std::borrow::Cow<'_, [u8]> {
         self.0.as_bytes().into()
     }
}