use std::{cell::RefCell, collections::HashMap, time::Duration};

use arbitrary::Arbitrary;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use http::Uri;
use rand::{Rng, RngCore};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    protocol::{
        config::Configuration, error::FluidError, executor::{Connection, ExecResponse, FixedByteRepr, ProtocolCtx, TimeObj}, web::container::rfc3339::{Rfc3339, Rfc3339Str}
    },
    token::{signature::{KeyChain, PrivateKey, PublicKey, Signature}, token::{AliveToken, FluidToken, TimestampToken}},
};





pub struct FauxDummyServer {
    keys: RefCell<HashMap<Uuid, DummyPublic>>
}

pub struct DummyClientSyncStruct {
    context: TestExecutor,
    id: Option<Uuid>,
    private_key: Option<DummyPrivate>,
    current_token: Option<AliveToken>,

    faux_server: FauxDummyServer


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

#[derive(Clone)]
pub struct DummyPrivate([u8; 8]);

#[derive(Clone)]
pub struct DummyPublic([u8; 8], [u8; 4]);

pub struct DummySignature {
    actual: Vec<u8>,
    underlying: [u8; 8]
}

impl DummySignature {
    pub fn random() -> Self {
        let mut exam = vec![0u8; 256];
        rand::rng().fill_bytes(&mut exam);
        Self {
            actual: exam,
        underlying: rand::rng().random()
        }
    }
}

#[derive(Arbitrary, PartialEq, Debug, Clone, Deserialize)]
pub struct TestTimeStub {
    pub seconds: i64,
}

impl Rfc3339 for TestTimeStub {
    type Error = chrono::ParseError;
    fn parse_rfc3339(candidate: &str) -> Result<Self, Self::Error> {
        Ok(Self { seconds: DateTime::parse_from_rfc3339(candidate)?.timestamp_millis() })
    }
    fn to_rfc3339(&self) -> crate::protocol::web::container::rfc3339::Rfc3339Str {
        Rfc3339Str::from_str(&DateTime::from_timestamp_millis(self.seconds).unwrap().to_rfc3339()).unwrap()
    }
}

impl TimeObj for TestTimeStub {
    fn from_millis_since_epoch(seconds: i64) -> Self {
        Self { seconds }
    }
    fn seconds_since_epoch(&self) -> i64 {
        self.seconds
    }
}

#[derive(Arbitrary, PartialEq, Debug, Clone, Serialize)]
pub struct ExampleProtocol(pub u8);

impl FixedByteRepr<1> for ExampleProtocol {
    fn to_fixed_repr(&self) -> [u8; 1] {
        [self.0]
    }
    fn from_fixed_repr(val: [u8; 1]) -> Self {
        ExampleProtocol(val[0])
    }
}

#[derive(Arbitrary, PartialEq, Debug, Clone)]
pub struct ExampleType(pub u8);

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
            seconds: i64::from_le_bytes(val),
        }
    }
    fn to_fixed_repr(&self) -> [u8; 8] {
        self.seconds.to_le_bytes()
    }
}

impl<'a, T, P> Arbitrary<'a> for FluidToken<T, P>
where
    T: Arbitrary<'a> + FixedByteRepr<1>,
    P: Arbitrary<'a> + FixedByteRepr<1>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(FluidToken::from_raw(
            P::arbitrary(u)?,
            T::arbitrary(u)?,
            Uuid::from_bytes_le(<[u8; 16]>::arbitrary(u)?),
            DateTime::arbitrary(u)?,
            <[u8; 32]>::arbitrary(u)?,
            <[u8; 16]>::arbitrary(u)?,
        ))
    }
}

pub(crate) fn make_testing_token(
    time: i64,
) -> FluidToken<ExampleType, ExampleProtocol> {
    let token = FluidToken::from_raw(
        ExampleProtocol(0),
        ExampleType(0),
        Uuid::new_v4(),
        DateTime::from_millis_since_epoch(time),
        [0u8; 32],
        [0u8; 16],
    );
    token
}

pub struct TestExecutor {
    pub internal_clock: i64,
    pub configuration: Configuration,
    pub connection: Connection,
    pub protocol: ExampleProtocol,
    pub retry_cooldown: Duration
}
impl TestExecutor {
    pub fn generic() -> Self {
        Self {
            internal_clock: 0,
            configuration: Configuration { stamping_timeout_secs: 30 },
            connection: Connection::from_uri(Uri::from_static("https://www.google.com")),
            protocol: ExampleProtocol(0),
            retry_cooldown: Duration::from_secs(0)
        }
    }
}

impl ProtocolCtx for TestExecutor {
    type Protocol = ExampleProtocol;
    type TokenType = ExampleType;
    fn current_time(&self) -> DateTime<Utc> {
        DateTime::from_timestamp_millis(self.internal_clock).unwrap()
    }
    fn config(&self) -> &crate::protocol::config::Configuration {
        &self.configuration
    }
    fn connection(&self) -> &crate::protocol::executor::Connection {
        &self.connection
    }
    fn protocol(&self) -> ExampleProtocol {
        self.protocol.clone()
    }
    fn retry_cooldown(&self) -> std::time::Duration {
        self.retry_cooldown
    }
    fn get_token_type(&self) -> Self::TokenType {
        ExampleType(0)
    }
    fn issue_expiry(&self) -> DateTime<Utc> {
        self.current_time() + Duration::from_secs(50)
    }
}


#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::{protocol::config::Configuration, token::signature::{KeyChain, PrivateKey, PublicKey}};

    use super::{DummyClientSyncStruct, DummyKeyChain, TestExecutor};


    #[test]
    pub fn test_dummy_sign() {
        let (public, private) = DummyKeyChain::generate();

        let sig = private.sign(&[1, 2, 3]).unwrap();
        assert!(public.verify(&[1, 2, 3], &sig));
        assert!(!public.verify(&[1, 3], &sig));
    }

    

   
}