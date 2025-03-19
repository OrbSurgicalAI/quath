use std::{cell::RefCell, collections::HashMap};

use arbitrary::Arbitrary;
use rand::Rng;
use uuid::Uuid;

use crate::{
    protocol::{
        config::Configuration, error::FluidError, executor::{AsyncClient, FixedByteRepr, ProtocolCtx, Response, SyncClient, TimeObj}
    },
    token::{signature::{KeyChain, PrivateKey, PublicKey, Signature}, token::{AliveToken, FluidToken, GenericToken}},
};



type DummyToken = AliveToken<TestTimeStub>;


pub struct FauxDummyServer {
    keys: RefCell<HashMap<Uuid, DummyPublic>>
}

pub struct DummyClientSyncStruct {
    context: TestExecutor,
    id: Option<Uuid>,
    private_key: Option<DummyPrivate>,
    current_token: Option<DummyToken>,

    faux_server: FauxDummyServer


}



impl AsyncClient<TestTimeStub, TestExecutor, DummyKeyChain, ExampleType, ExampleProtocol> for DummyClientSyncStruct {
    type Err = FluidError;

    async fn ctx<'a>(&'a self) -> &'a TestExecutor where TestExecutor: 'a {
        &self.context
    }
    async fn register_request(&self, id: Uuid, public: &<DummyKeyChain as KeyChain>::Public) -> Result<Uuid, Self::Err> {
        self.faux_server.keys.borrow_mut().insert(id, public.clone());
        Ok(id)
    }
    async fn cycle_request(&self, id: Uuid, public: &<DummyKeyChain as KeyChain>::Public, new_sig: &<DummyKeyChain as KeyChain>::Signature, old_sig: &<DummyKeyChain as KeyChain>::Signature) -> Result<bool, Self::Err> {
        let hook = self.faux_server.keys.borrow();
        let current = hook.get(&id).unwrap();
        if current.verify(public.as_bytes(), old_sig) && public.verify(public.as_bytes(), new_sig) {
            Ok(true)
        } else {
            Ok(false)
        }

    }
    async fn stamp_request(&self, id: Uuid, token: &GenericToken<TestTimeStub>, signature: &<DummyKeyChain as KeyChain>::Signature) -> Result<crate::protocol::executor::Response<TestTimeStub>, Self::Err> {
        let hook = self.faux_server.keys.borrow();
        let wow = hook.get(&id).unwrap();
        if wow.verify(token.get_bytes(), signature) {
            Ok(Response::Return { token: token.clone(), life: TestTimeStub::from_seconds(60) })
        } else {
            Ok(Response::Invalid)
        }
    }
    async fn get_current_token<'a>(&'a self) -> Result<&'a Option<AliveToken<TestTimeStub>>, Self::Err> where TestTimeStub: 'a {
        Ok(&self.current_token)
    }
    async fn set_current_token(&mut self, token: Option<crate::token::token::AliveToken<TestTimeStub>>) -> Result<(), Self::Err> {
        self.current_token = token;
        Ok(())
    }
    async fn private_key<'a>(&'a self) -> Result<&'a Option<<DummyKeyChain as KeyChain>::Private>, Self::Err> where <DummyKeyChain as KeyChain>::Private: 'a {
        Ok(&self.private_key)
    }
    async fn set_private_key(&mut self, privkey: Option<<DummyKeyChain as KeyChain>::Private>) -> Result<(), Self::Err> {
        self.private_key = privkey;
        Ok(())
    }
    async fn get_id<'a>(&self) -> Result<Option<Uuid>, Self::Err> where TestExecutor: 'a {
       Ok(self.id)
    }
    async fn set_id(&mut self, id: Option<Uuid>) -> Result<Option<Uuid>, Self::Err> {
        self.id = id;
        Ok(id)
    }

}

pub struct DummyKeyChain;


impl Signature for DummySignature {
    fn as_bytes(&self) -> &[u8] {
        &self.underlying
    }
}

impl AsRef<[u8]> for DummyPrivate {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl AsRef<[u8]> for DummyPublic {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for DummySignature {
    fn as_ref(&self) -> &[u8] {
        &self.actual
    }
}

impl PrivateKey<DummySignature, FluidError> for DummyPrivate {
    fn sign(&self, bytes: &[u8]) -> Result<DummySignature, FluidError> {
        Ok(DummySignature {
            actual: bytes.to_vec(),
            underlying: self.0.clone()
        })
    }
}


impl PublicKey<DummySignature> for DummyPublic {
    fn verify(&self, bytes: &[u8], signature: &DummySignature) -> bool {
        signature.actual == bytes && self.0 == signature.underlying
    }
    fn as_bytes(&self) -> &[u8] {
        &self.1
    }
}

impl KeyChain for DummyKeyChain {
    type Private = DummyPrivate;
    type Public = DummyPublic;
    type Signature = DummySignature;
    type Error = FluidError;
    fn generate() -> (Self::Public, Self::Private) {
        let stem: [u8; 8] = rand::rng().random();
        (DummyPublic(stem.clone(), rand::rng().random()), DummyPrivate(stem))
    }
}

pub struct DummyPrivate([u8; 8]);

#[derive(Clone)]
pub struct DummyPublic([u8; 8], [u8; 4]);

pub struct DummySignature {
    actual: Vec<u8>,
    underlying: [u8; 8]
}

#[derive(Arbitrary, PartialEq, Debug, Clone)]
pub struct TestTimeStub {
    pub seconds: u64,
}

impl TimeObj for TestTimeStub {
    fn from_seconds(seconds: u64) -> Self {
        Self { seconds }
    }
    fn seconds(&self) -> u64 {
        self.seconds
    }
}

#[derive(Arbitrary, PartialEq, Debug, Clone)]
pub struct ExampleProtocol(u8);

impl FixedByteRepr<1> for ExampleProtocol {
    fn to_fixed_repr(&self) -> [u8; 1] {
        [self.0]
    }
    fn from_fixed_repr(val: [u8; 1]) -> Self {
        ExampleProtocol(val[0])
    }
}

#[derive(Arbitrary, PartialEq, Debug, Clone)]
pub struct ExampleType(u8);

impl FixedByteRepr<1> for ExampleType {
    fn to_fixed_repr(&self) -> [u8; 1] {
        [self.0]
    }
    fn from_fixed_repr([val]: [u8; 1]) -> Self {
        ExampleType(val)
    }
}

impl FixedByteRepr<8> for TestTimeStub {
    fn from_fixed_repr(val: [u8; 8]) -> Self {
        Self {
            seconds: u64::from_le_bytes(val),
        }
    }
    fn to_fixed_repr(&self) -> [u8; 8] {
        self.seconds.to_le_bytes()
    }
}

impl<'a, D, T, P> Arbitrary<'a> for FluidToken<D, T, P>
where
    D: Arbitrary<'a> + FixedByteRepr<8> + TimeObj,
    T: Arbitrary<'a> + FixedByteRepr<1>,
    P: Arbitrary<'a> + FixedByteRepr<1>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(FluidToken::from_raw(
            P::arbitrary(u)?,
            T::arbitrary(u)?,
            Uuid::from_bytes_le(<[u8; 16]>::arbitrary(u)?),
            D::arbitrary(u)?,
            <[u8; 32]>::arbitrary(u)?,
            <[u8; 16]>::arbitrary(u)?,
        ))
    }
}

pub(crate) fn make_testing_token(
    time: u64,
) -> FluidToken<TestTimeStub, ExampleType, ExampleProtocol> {
    let token = FluidToken::from_raw(
        ExampleProtocol(0),
        ExampleType(0),
        Uuid::new_v4(),
        TestTimeStub { seconds: time },
        [0u8; 32],
        [0u8; 16],
    );
    token
}

pub struct TestExecutor {
    pub internal_clock: u64,
    pub configuration: Configuration,
}

impl ProtocolCtx<TestTimeStub> for TestExecutor {
    fn current_time(&self) -> TestTimeStub {
        TestTimeStub {
            seconds: self.internal_clock,
        }
    }
    fn config(&self) -> &crate::protocol::config::Configuration {
        &self.configuration
    }
}


#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::{protocol::{config::Configuration, executor::{AsyncClient, SyncClient}}, token::signature::{KeyChain, PrivateKey, PublicKey}};

    use super::{DummyClientSyncStruct, DummyKeyChain, TestExecutor};


    #[test]
    pub fn test_dummy_sign() {
        let (public, private) = DummyKeyChain::generate();

        let sig = private.sign(&[1, 2, 3]).unwrap();
        assert!(public.verify(&[1, 2, 3], &sig));
        assert!(!public.verify(&[1, 3], &sig));
    }

    

    #[tokio::test]
    pub async fn test_dummy_client_protocol_execution() {
        let mut executor = DummyClientSyncStruct {
            context: TestExecutor {
                configuration: Configuration {
                    stamping_timeout_secs: 10
                },
                internal_clock: 0
            },
            current_token: None,
            faux_server: super::FauxDummyServer { keys: HashMap::new().into() },
            id: None,
            private_key: None
        };

        assert!(!executor.is_registered().await.unwrap());
        let token = executor.get_token(super::ExampleType(0), super::ExampleProtocol(0)).await.unwrap();
        assert!(executor.is_registered().await.unwrap());

    }
}