use serde::{ser::SerializeStruct, Deserialize, Serialize};
use uuid::Uuid;

use crate::token::{signature::KeyChain, token::GenericToken};

use super::container::{b64::{B64Owned, B64Ref}, rfc3339::{Rfc3339, Rfc3339Container, Rfc3339Str}};
use crate::protocol::executor::FixedByteRepr;

pub struct CycleRequest<'a, P, M, KC>
where
    P: Serialize,
    M: Serialize,
    KC: KeyChain,
{
    pub id: Uuid,
    pub protocol: &'a P,
    pub key: B64Ref<'a, KC::Public>,
    pub signature: B64Owned<KC::Signature>,
    pub metadata: &'a Option<M>,
}

#[derive(Serialize)]
pub struct CreateServiceEntityRequest<'a, P, M, KC>
where
    P: Serialize,
    M: Serialize,
    KC: KeyChain,
{
    pub id: Uuid,
    pub protocol: &'a P,
    pub key: B64Ref<'a, KC::Public>,
    pub metadata: &'a Option<M>,
}

#[derive(Serialize)]
pub struct DeleteSvcEntityRequest
{
    pub id: Uuid
}


impl<'a, P, M, KC> Serialize for CycleRequest<'a, P, M, KC>
where 
    P: Serialize,
    M: Serialize,
    KC: KeyChain
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer {
        let mut stru = serializer.serialize_struct("Request", 2)?;
        stru.serialize_field("id", &self.id)?;
        stru.serialize_field("protocol", &self.protocol)?;
        stru.serialize_field("key", &self.key)?;
        stru.serialize_field("signature", &self.signature)?;
        stru.serialize_field("metadata", &self.metadata)?;
        stru.end()
    }
}


pub struct TokenStampRequest<'a, D, KC>
where 
    KC: KeyChain
{
    pub token: B64Ref<'a, GenericToken<D>>,
    pub signature: B64Ref<'a, KC::Signature>
}

impl<'a, D, KC> Serialize for TokenStampRequest<'a, D, KC>
where 
    KC: KeyChain
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer {
        let mut stru = serializer.serialize_struct("Request", 2)?;
        stru.serialize_field("token", &self.token)?;
        stru.serialize_field("signature", &self.signature)?;
        stru.end()
        
    }
}



#[derive(Deserialize, Serialize)]
pub struct PostTokenResponse<D>
{
    #[serde(bound(serialize = ""))]
    #[serde(bound(deserialize = "D: FixedByteRepr<8>"))]
    pub token: B64Owned<GenericToken<D>>,
    #[serde(bound(deserialize = "D: Rfc3339"))]
    #[serde(bound(serialize = "D: Rfc3339"))]
    pub expiry: Rfc3339Container<D>
}



#[cfg(test)]
mod tests {
    use serde::Serialize;
    use uuid::Uuid;

    use crate::{protocol::web::{container::b64::{B64Owned, B64Ref}, payload::CycleRequest}, testing::{DummyKeyChain, DummySignature, ExampleProtocol}, token::{signature::{KeyChain, Signature}, token::GenericToken}};

    use super::TokenStampRequest;


    #[test]
    pub fn serialize_token_stamp_integrity() {

        let token = GenericToken::random();
        let dummy_sig = DummySignature::random();

        let wow: TokenStampRequest<'_, (), DummyKeyChain> = TokenStampRequest {
            token: B64Ref(&token),
            signature: B64Ref(&dummy_sig)
        };


        let object = serde_json::to_value(&wow).unwrap();
        assert!(object.is_object());
        assert!(object.get("token").is_some_and(|f| f.is_string()));
        assert!(object.get("signature").is_some_and(|f| f.is_string()));
        
        // panic!("Hello: {}", serde_json::to_string(&wow).unwrap());
    }

    #[test]
    pub fn serialize_cycle_request_integrity() {

        #[derive(Serialize)]
        struct TestStub {
            a: u8
        }

        let token = GenericToken::random();
        let dummy_sig = DummySignature::random();
        let (pubk, privk) = DummyKeyChain::generate();
        let protocol = "hello";
        let metadata = Some(TestStub {
            a: 4
        });

        let wow: CycleRequest<'_, &str, TestStub, DummyKeyChain> = CycleRequest {
            id: Uuid::nil(),
            key: B64Ref(&pubk),
            protocol: &protocol,
            metadata: &metadata,
            signature: B64Owned(dummy_sig)
        };


        let object = serde_json::to_value(&wow).unwrap();
        assert!(object.is_object());
        assert!(object.get("id").is_some_and(|f| f.is_string()));
        assert!(object.get("key").is_some_and(|f| f.is_string()));
        assert!(object.get("protocol").is_some_and(|f| f.is_string()));
        assert!(object.get("metadata").is_some_and(|f| f.is_object()));
        assert!(object.get("signature").is_some_and(|f| f.is_string()));
        
        // panic!("Hello: {}", serde_json::to_string(&wow).unwrap());
    }
}