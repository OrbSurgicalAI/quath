use std::{borrow::Borrow, marker::PhantomData, ops::Deref};

use base64::{prelude::BASE64_URL_SAFE, DecodeError, Engine};
use serde::{Deserialize, Serialize, de::Visitor};



pub trait Signature: AsRef<[u8]> {
    fn as_bytes(&self) -> &[u8];
}



pub trait KeyChain {
    type Private: PrivateKey<Self::Signature, Self::Error>;
    type Public: PublicKey<Self::Signature>;
    type Signature: Signature;
    type Error;

    fn generate() -> (Self::Public, Self::Private);
}

// pub trait AsBytes {
//     fn as_bytes(&self) -> &[u8];
// }

pub trait PrivateKey<S, E>: AsRef<[u8]> {
    fn sign(&self, bytes: &[u8]) -> Result<S, E>;
    fn as_bytes(&self) -> &[u8] {
        self.as_ref()
    }
}

pub trait PublicKey<S>: AsRef<[u8]> {
    fn verify(&self, bytes: &[u8], signature: &S) -> bool;
    fn as_bytes(&self) -> &[u8] {
        self.as_ref()
    }
}


#[cfg(test)]
mod tests {
    use arbitrary::Arbitrary;

    use crate::protocol::web::container::b64::{B64Owned, B64Ref};





    #[test]
    pub fn test_b64_container_owned() {
        arbtest::arbtest(|u| {
            let wow: Vec<u8> = Vec::arbitrary(u)?;

            let obj = serde_json::to_string(&B64Owned(wow.clone())).unwrap();

            let decoded: B64Owned<Vec<u8>> = serde_json::from_str(&obj).unwrap();
            assert_eq!(wow, decoded.inner());


            Ok(())
        });
    }

    #[test]
    pub fn test_b64_container_reference() {
        arbtest::arbtest(|u| {
            let wow: Vec<u8> = Vec::arbitrary(u)?;

            let obj = serde_json::to_string(&B64Ref(&wow)).unwrap();

            let decoded: B64Owned<Vec<u8>> = serde_json::from_str(&obj).unwrap();
            assert_eq!(wow, decoded.inner());


            Ok(())
        });
    }
}