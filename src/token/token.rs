use std::{cmp::Ordering, fmt::Debug, ops::Range};

use chrono::{DateTime, Utc};
use rand::{Rng, RngCore};
use sha3::{Digest, Sha3_256};
use uuid::Uuid;

use crate::protocol::{error::FluidError, spec::traits::{FixedByteRepr, ProtocolCtx, TimeObj}};




const UUID_RANGE: Range<usize> = 2..18;
const TIMESTAMP_RANGE: Range<usize> = 34..42;

pub struct AliveToken {
    token: TimestampToken,
    life: DateTime<Utc>
}


impl AliveToken {
    pub fn from_raw(token: TimestampToken, life: DateTime<Utc>) -> AliveToken {
        AliveToken { token, life }
    }
    pub fn token(&self) -> &TimestampToken {
        &self.token
    }
    pub fn life(&self) -> &DateTime<Utc> {
        &self.life
    }
    
}

impl AliveToken
{
    pub fn is_alive<C: ProtocolCtx>(&self, ctx: &C) -> bool{
        self.token.timestamp.seconds_since_epoch() + self.life.seconds_since_epoch() > ctx.current_time().seconds_since_epoch()
    }
}

pub struct FluidToken<T, P> {
    protocol: P,
    token_type: T,
    id: Uuid,
    permissions: [u8; 16],
    timestamp: DateTime<Utc>,
    body: [u8; 32]
}

pub struct TimestampToken {
    timestamp: DateTime<Utc>,
    data: [u8; 74]
}

#[derive(Debug, PartialEq)]
pub struct GenericToken([u8; 74]);

impl GenericToken {
    pub fn get_uuid_field(&self) -> [u8; 16] {
        self.0[UUID_RANGE].try_into().unwrap()
    }
    pub fn get_time_field(&self) -> [u8; 8] {
        self.0[TIMESTAMP_RANGE].try_into().unwrap()
    }
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(self.as_bytes());
        hasher.finalize().into()
    }
}

impl GenericToken {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl TimestampToken {
    pub fn generic(self) -> GenericToken {
        GenericToken(self.data)
    }
}

impl AsRef<[u8]> for TimestampToken {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}


impl TimestampToken {
    pub fn random() -> Self {
        Self {
            timestamp: DateTime::from_timestamp_nanos(0),
            data: rand::rng().random()
        }
    }
    
}

impl TimestampToken
{
    pub fn random_with_ts(stamp: DateTime<Utc>) -> Self{
        let mut body: [u8; 74] = rand::rng().random();
        body[TIMESTAMP_RANGE].copy_from_slice(&stamp.to_fixed_repr());
        Self {
            timestamp: stamp,
            data: body
        }
    }
    
}

impl TimestampToken {
    pub fn timestamp(&self) -> &DateTime<Utc> {
        &self.timestamp
    }
    pub fn get_bytes(&self) -> &[u8; 74] {
        &self.data
    }
    pub fn randomize_body(mut self) -> Self {
        rand::rng().fill_bytes(&mut self.data[42..]);
        self
    }
}

impl Clone for TimestampToken {
    fn clone(&self) -> Self {
        Self {
            timestamp: self.timestamp.clone(),
            data: self.data.clone()
        }
    }
}

impl TryFrom<Vec<u8>> for TimestampToken
{
    type Error = FluidError;
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        assert_eq!(value.len(), 74);

        let timestamp: [u8; 8] = value[34..42].try_into().or(Err(FluidError::FailedDeserTimestamp))?;
        let time = DateTime::<Utc>::from_fixed_repr(timestamp);
        Ok(Self {
            data: value.try_into().or(Err(FluidError::FailedDeserBody))?,
            timestamp: time
        })

    }
}

// impl<D> AsRef<[u8]> for GenericToken<D> {
//     fn as_ref(&self) -> &[u8] {
//         &self.data
//     }
// }


impl<T, P> PartialEq for FluidToken<T, P>
where
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

impl<T, P> Debug for FluidToken<T, P>
where
    T: Debug,
    P: Debug
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.body.fmt(f)
    }
}

// impl<T, P> FluidToken<T, P>
// where
//     T: FixedByteRepr<1>,
//     P: FixedByteRepr<1>
// {
//     /// Checks if a token can be stamped.
//     pub fn is_stampable<E>(&self, executor: &E) -> bool
//     where 
//         E: ProtocolCtx
//     {
//         let ts = self.timestamp.seconds_since_epoch();
//         let es = executor.current_time().seconds_since_epoch();
//         let pad = executor.config().timeout();

//         if ts > es {
//             // The timestamp is in the future.
//             false
//         } else if ts < es && ts.abs_diff(es) > pad {
//             // The timestamp is in the past more than the threshold.
//             false
//         } else {
//             true
//         }
//     }
// }

impl<T, P> FluidToken<T, P>
{
    pub fn from_raw(protocol: P, token_type: T, id: Uuid, timestamp: DateTime<Utc>, body: [u8; 32], permissions: [u8; 16]) -> Self {
        Self {
            protocol,
            token_type,
            id,
            timestamp,
            body,
            permissions

        }
    }
    pub fn generate<C: ProtocolCtx>(context: &C, id: Uuid, token_type: T, protocol: P) -> FluidToken<T, P> {
        Self::from_raw(protocol, token_type, id, context.current_time(), rand::rng().random(), [0u8; 16])
    }
    pub fn get_id(&self) -> Uuid {
        self.id
    }
    
}

impl<T, P> FluidToken<T, P>
where
    T: FixedByteRepr<1>,
    P: FixedByteRepr<1>
{
    pub fn generic(&self) -> TimestampToken {
        let data = self.to_bytes();
        TimestampToken { timestamp: self.timestamp, data }
    }
    pub fn to_bytes(&self) -> [u8; 74] {
        let mut buffer = [0u8; 74];
        buffer[0] = self.protocol.to_fixed_repr()[0];
        buffer[1] = self.token_type.to_fixed_repr()[0];
        buffer[2..18].copy_from_slice(&self.id.to_bytes_le());
        buffer[18..34].copy_from_slice(&self.permissions);
        buffer[TIMESTAMP_RANGE].copy_from_slice(&self.timestamp.to_fixed_repr());
        buffer[42..].copy_from_slice(&self.body);
        buffer
    }
    pub fn from_bytes(buffer: [u8; 74]) -> Result<Self, FluidError> {
        let protocol = P::from_fixed_repr([ buffer[0] ]);
        let token_type = T::from_fixed_repr([ buffer[1] ]);
        let id = Uuid::from_bytes_le(buffer[2..18].try_into().or(Err(FluidError::FailedDeserializingId))?);
        let permissions = buffer[18..34].try_into().or(Err(FluidError::FailedDeserializingPermissions))?;
        let timestamp = DateTime::<Utc>::from_fixed_repr(buffer[34..42].try_into().or(Err(FluidError::FailedDeserTimestamp))?);
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
    pub fn cmp_bytes<T2, P2>(&self, other: &FluidToken<T2, P2>) -> Ordering
    where 
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
    use std::time::Duration;

    use arbitrary::Arbitrary;
    use chrono::{Date, DateTime};
    use http::Uri;
    use sha3::{Digest, Sha3_256};

    use crate::{testing::{make_testing_token, ExampleProtocol, ExampleType}, token::tolerance::TokenTolerance};

    use super::FluidToken;


    #[test]
    pub fn test_token_serde_bytes() {
        arbtest::arbtest(|u| {
            let token: FluidToken<ExampleType, ExampleProtocol> = FluidToken::arbitrary(u)?;

            let wow = token.to_bytes();

            let reserialized: FluidToken<ExampleType, ExampleProtocol> = FluidToken::from_bytes(token.to_bytes()).unwrap();
            
            assert_eq!(token.to_bytes(), reserialized.to_bytes());

            Ok(())
        });
    }

    #[test]
    pub fn test_token_hash_consistency() {
        arbtest::arbtest(|u| {
            let token: FluidToken<ExampleType, ExampleProtocol> = FluidToken::arbitrary(u)?;

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

        let tolerance = TokenTolerance::new(Duration::ZERO, Duration::ZERO);

        let mut current_time = DateTime::from_timestamp_millis(0).unwrap();

        let token = make_testing_token(0).generic().generic();

        // This is stampable since the time is the same.
        assert!(tolerance.check(&token, current_time));


        // Future tokens should not be stampable.
        let token = make_testing_token(10).generic().generic();
        assert!(!tolerance.check(&token, current_time));

        // Check that past tokens are not stampable since the timeout is zero (zero tolerance policy)
        current_time += Duration::from_millis(10);
        let token = make_testing_token(0).generic().generic();
        assert!(!tolerance.check(&token, current_time));
    }

    /// This tests that the protocol functions when there is some tolerance.
    #[test]
    pub fn test_basic_is_stampable_with_tolerance() {
        let token = make_testing_token(0);


        let mut clock = DateTime::from_timestamp_millis(0).unwrap();

        let tolerance = TokenTolerance::new(Duration::from_millis(5), Duration::ZERO);

        // This is stampable since the time is the same.
        assert!(tolerance.check(&token.generic().generic(), clock));


        // Future tokens should not be stampable.
        let token = make_testing_token(10);
        assert!(!tolerance.check(&token.generic().generic(), clock));


        // Check that past tokens are not stampable since the timeout is zero (zero tolerance policy)
        clock += Duration::from_millis(10);
        let token = make_testing_token(0);
        assert!(!tolerance.check(&token.generic().generic(), clock));
        assert!(tolerance.check(&make_testing_token(5).generic().generic(), clock));
    }
    
}