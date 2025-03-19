use arbitrary::Arbitrary;
use uuid::Uuid;

use crate::{
    protocol::{
        config::Configuration,
        executor::{FixedByteRepr, ProtocolExecutor, TimeObj},
    },
    token::token::FluidToken,
};

#[derive(Arbitrary, PartialEq, Debug)]
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

#[derive(Arbitrary, PartialEq, Debug)]
pub struct ExampleProtocol(u8);

impl FixedByteRepr<1> for ExampleProtocol {
    fn to_fixed_repr(&self) -> [u8; 1] {
        [self.0]
    }
    fn from_fixed_repr(val: [u8; 1]) -> Self {
        ExampleProtocol(val[0])
    }
}

#[derive(Arbitrary, PartialEq, Debug)]
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

impl ProtocolExecutor<TestTimeStub> for TestExecutor {
    fn current_time(&self) -> TestTimeStub {
        TestTimeStub {
            seconds: self.internal_clock,
        }
    }
    fn config(&self) -> &crate::protocol::config::Configuration {
        &self.configuration
    }
}
