use std::{cmp::Ordering, fmt::Debug};

use rand::Rng;
use sha3::{Digest, Sha3_256};
use uuid::Uuid;

use crate::protocol::{error::FluidError, executor::{FixedByteRepr, ProtocolCtx, TimeObj}};


pub struct AliveToken<D> {
    token: GenericToken<D>,
    life: D
}


impl<D> AliveToken<D> {
    pub fn from_raw(token: GenericToken<D>, life: D) -> AliveToken<D> {
        AliveToken { token, life }
    }
    pub fn token(&self) -> &GenericToken<D> {
        &self.token
    }
    pub fn life(&self) -> &D {
        &self.life
    }
    
}

impl<D> AliveToken<D>
where
    D: TimeObj
{
    pub fn is_alive<C: ProtocolCtx<D>>(&self, ctx: &C) -> bool{
        self.token.timestamp.seconds() + self.life.seconds() > ctx.current_time().seconds()
    }
}

pub struct FluidToken<D, T, P> {
    protocol: P,
    token_type: T,
    id: Uuid,
    permissions: [u8; 16],
    timestamp: D,
    body: [u8; 32]
}

pub struct GenericToken<D> {
    timestamp: D,
    data: [u8; 74]
}

impl<D> GenericToken<D> {
    pub fn get_bytes(&self) -> &[u8; 74] {
        &self.data
    }
}

impl<D: Clone> Clone for GenericToken<D> {
    fn clone(&self) -> Self {
        Self {
            timestamp: self.timestamp.clone(),
            data: self.data.clone()
        }
    }
}


impl<D, T, P> PartialEq for FluidToken<D, T, P>
where 
    D: PartialEq,
    T: PartialEq,
    P: PartialEq
{
    fn eq(&self, other: &Self) -> bool {
        self.protocol == other.protocol
        && self.token_type == other.token_type
        && self.id == other.id
        && self.permissions == other.permissions
        && self.timestamp == other.timestamp
        && self.body == other.body
    }
}

impl<D, T, P> Debug for FluidToken<D, T, P>
where 
    D: Debug,
    T: Debug,
    P: Debug
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.body.fmt(f)
    }
}

impl<D, T, P> FluidToken<D, T, P>
where 
    D: TimeObj + FixedByteRepr<8>,
    T: FixedByteRepr<1>,
    P: FixedByteRepr<1>
{
    /// Checks if a token can be stamped.
    pub fn is_stampable<E>(&self, executor: &E) -> bool
    where 
        E: ProtocolCtx<D>
    {
        let ts = self.timestamp.seconds();
        let es = executor.current_time().seconds();
        let pad = executor.config().timeout();

        if ts > es {
            // The timestamp is in the future.
            false
        } else if ts < es && ts.abs_diff(es) > pad {
            // The timestamp is in the past more than the threshold.
            false
        } else {
            true
        }
    }
}

impl<D, T, P> FluidToken<D, T, P>
{
    pub fn from_raw(protocol: P, token_type: T, id: Uuid, timestamp: D, body: [u8; 32], permissions: [u8; 16]) -> Self {
        Self {
            protocol,
            token_type,
            id,
            timestamp,
            body,
            permissions

        }
    }
    pub fn generate<C: ProtocolCtx<D>>(context: &C, id: Uuid, token_type: T, protocol: P) -> FluidToken<D, T, P> {
        Self::from_raw(protocol, token_type, id, context.current_time(), rand::rng().random(), [0u8; 16])
    }
    pub fn get_id(&self) -> Uuid {
        self.id
    }
    
}

impl<D, T, P> FluidToken<D, T, P>
where 
    D: FixedByteRepr<8>,
    T: FixedByteRepr<1>,
    P: FixedByteRepr<1>
{
    pub fn generic(self) -> GenericToken<D> {
        let data = self.to_bytes();
        GenericToken { timestamp: self.timestamp, data }
    }
    pub fn to_bytes(&self) -> [u8; 74] {
        let mut buffer = [0u8; 74];
        buffer[0] = self.protocol.to_fixed_repr()[0];
        buffer[1] = self.token_type.to_fixed_repr()[0];
        buffer[2..18].copy_from_slice(&self.id.to_bytes_le());
        buffer[18..34].copy_from_slice(&self.permissions);
        buffer[34..42].copy_from_slice(&self.timestamp.to_fixed_repr());
        buffer[42..].copy_from_slice(&self.body);
        buffer
    }
    pub fn from_bytes(buffer: [u8; 74]) -> Result<Self, FluidError> {
        let protocol = P::from_fixed_repr([ buffer[0] ]);
        let token_type = T::from_fixed_repr([ buffer[1] ]);
        let id = Uuid::from_bytes_le(buffer[2..18].try_into().or(Err(FluidError::FailedDeserializingId))?);
        let permissions = buffer[18..34].try_into().or(Err(FluidError::FailedDeserializingPermissions))?;
        let timestamp = D::from_fixed_repr(buffer[34..42].try_into().or(Err(FluidError::FailedDeserTimestamp))?);
        let body = buffer[42..].try_into().or(Err(FluidError::FailedDeserBody))?;
        

        Ok(Self {
            protocol,
            token_type,
            id,
            permissions,
            timestamp,
            body
        })

    }
    pub fn cmp_bytes<D2, T2, P2>(&self, other: &FluidToken<D2, T2, P2>) -> Ordering
    where 
        D2: TimeObj + FixedByteRepr<8>,
        T2: FixedByteRepr<1>,
        P2: FixedByteRepr<1>
    {
        self.to_bytes().cmp(&other.to_bytes())
    }
    pub fn hash(&self) -> [u8; 32] {
        let mut digest = Sha3_256::new();
        digest.update(&self.to_bytes());
        digest.finalize().into()
    }
}


#[cfg(test)]
mod tests {
    use arbitrary::Arbitrary;
    use sha3::{Digest, Sha3_256};

    use crate::{protocol::config::Configuration, testing::{make_testing_token, ExampleProtocol, ExampleType, TestExecutor, TestTimeStub}};

    use super::FluidToken;


    #[test]
    pub fn test_token_serde_bytes() {
        arbtest::arbtest(|u| {
            let token: FluidToken<TestTimeStub, ExampleType, ExampleProtocol> = FluidToken::arbitrary(u)?;

            let reserialized: FluidToken<TestTimeStub, ExampleType, ExampleProtocol> = FluidToken::from_bytes(token.to_bytes()).unwrap();
            
            assert_eq!(token, reserialized);

            Ok(())
        });
    }

    #[test]
    pub fn test_token_hash_consistency() {
        arbtest::arbtest(|u| {
            let token: FluidToken<TestTimeStub, ExampleType, ExampleProtocol> = FluidToken::arbitrary(u)?;

            let mut bytes = Sha3_256::new();
            bytes.update(&token.to_bytes());
            let final_bytes: [u8; 32] = bytes.finalize().into();
            
          

            assert_eq!(token.hash(), final_bytes);

            Ok(())
        });
    }
    


    /// This tests that the protocol functions when there is zero padding.
    #[test]
    pub fn test_basic_is_stampable_zero_timeout() {
        let token = make_testing_token(0);

        let mut executor = TestExecutor {
            configuration: Configuration {
                stamping_timeout_secs: 0
            },
            internal_clock: 0
        };

        // This is stampable since the time is the same.
        assert!(token.is_stampable(&executor));


        // Future tokens should not be stampable.
        let token = make_testing_token(10);
        assert!(!token.is_stampable(&executor));

        // Check that past tokens are not stampable since the timeout is zero (zero tolerance policy)
        executor.internal_clock += 10;
        let token = make_testing_token(0);
        assert!(!token.is_stampable(&executor));
    }

    /// This tests that the protocol functions when there is some tolerance.
    #[test]
    pub fn test_basic_is_stampable_with_tolerance() {
        let token = make_testing_token(0);

        let mut executor = TestExecutor {
            configuration: Configuration {
                stamping_timeout_secs: 5
            },
            internal_clock: 0
        };

        // This is stampable since the time is the same.
        assert!(token.is_stampable(&executor));


        // Future tokens should not be stampable.
        let token = make_testing_token(10);
        assert!(!token.is_stampable(&executor));

        // Check that past tokens are not stampable since the timeout is zero (zero tolerance policy)
        executor.internal_clock += 10;
        let token = make_testing_token(0);
        assert!(!token.is_stampable(&executor));
        assert!(make_testing_token(5).is_stampable(&executor));
    }
    
}