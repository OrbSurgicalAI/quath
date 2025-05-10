use std::{marker::PhantomData, task::Poll};

use bitvec::array::BitArray;
use fips204::Ph;
use ringbuffer::{GrowableAllocRingBuffer, RingBuffer};
use uuid::Uuid;

use crate::{
    token::{Final, Token}, CheckTokenQuery, DsaSystem, HashingAlgorithm, KemAlgorithm, MsSinceEpoch, ServerProtocolError, TokenValidityInterval, ViewBytes
};

use super::{ServerPollResult, ServerTokenDriverInner, ServerTokenInput};

pub struct ServerVerifyDriver<H, const N: usize>
where
    H: HashingAlgorithm<N>,
{
    inner: ServerVerifyDriverInner<H, N>,
    state: DriverState,
}

struct ServerVerifyDriverInner<H, const N: usize>
where
    H: HashingAlgorithm<N>,
{
    buffer: GrowableAllocRingBuffer<ServerVerifyOutput<N>>,
    validity_interval: TokenValidityInterval,
    terminated: bool,
    _h: PhantomData<H>,
}

enum DriverState {
    Init,
    WaitingForRequestVerification(Option<Token<Final>>),
    Finished(Option<Token<Final>>),
    Errored(Option<ServerProtocolError>),
    Vacant,
}

pub enum ServerVerifyOutput<const N: usize> {
    /// We need to do the following checks:
    /// 1. the client ID does in fact exist.
    /// 2. the token is not in a revocation list.
    /// 3. the token is in the database.
    /// 4. The permissions are good
    CheckToken(CheckTokenQuery<N>),
}

pub enum CheckTokenStatus {
    Valid,
    InvalidClientUuid,
    Expired,
    Revoked,
    Forbidden,
    NonExistent,
    Failure(String)
}

pub enum ServerVerifyInput {
    Request(Token<Final>),
    TokenResponse(CheckTokenStatus)
}

impl<H, const N: usize> ServerVerifyDriver<H, N>
where
    H: HashingAlgorithm<N>,
{
    pub fn new(interval: TokenValidityInterval) -> Self {
        Self {
            inner: ServerVerifyDriverInner {
                buffer: GrowableAllocRingBuffer::default(),
                validity_interval: interval,
                terminated: false,
                _h: PhantomData,
            },
            state: DriverState::Init,
        }
    }
    pub fn recv(&mut self, time: MsSinceEpoch, packet: Option<ServerVerifyInput>) {
        if self.inner.terminated {
            return;
        }

        match recv_internal(self, packet, time) {
            Ok(_) => { /* Nothing to do */ }
            Err(e) => {
                self.inner.terminated = true;
                self.state = DriverState::Errored(Some(e))
            }
        }
    }
    pub fn poll_transmit(&mut self) -> Option<ServerVerifyOutput<N>> {
        self.inner.buffer.dequeue()
    }
    pub fn poll_result(&mut self) -> ServerPollResult<Token<Final>> {
        match &mut self.state {
            DriverState::Errored(e) => {
                let value = e.take().unwrap();
                self.state = DriverState::Vacant;
                Poll::Ready(Err(value))
            }
            DriverState::Finished(inner) => {
                let value = inner.take().unwrap();
                self.state = DriverState::Vacant;
                Poll::Ready(Ok(value))
            }
            _ => Poll::Pending,
        }
    }
}

fn recv_internal<H, const N: usize>(
    obj: &mut ServerVerifyDriver<H, N>,
    packet: Option<ServerVerifyInput>,
    current_time: MsSinceEpoch,
) -> Result<(), ServerProtocolError>
where
    H: HashingAlgorithm<N>,
{
    let state = match &mut obj.state {
        DriverState::Init => handle_registry_init(&mut obj.inner, packet, current_time)?,
        DriverState::WaitingForRequestVerification(request) => {
            handle_verification(&mut obj.inner, packet, request)?
        }
        _ => None, // The other states do not have any active behaviour.
    };

    if let Some(inner) = state {
        // If we output a new state, use said state.
        obj.state = inner;
    }

    Ok(())
}

fn handle_registry_init<H, const N: usize>(
    inner: &mut ServerVerifyDriverInner<H, N>,
    packet: Option<ServerVerifyInput>,
    current_time: MsSinceEpoch,
) -> Result<Option<DriverState>, ServerProtocolError>
where
    H: HashingAlgorithm<N>,
{
    let Some(packet) = packet else {
        return Ok(None);
    };

    match packet {
        ServerVerifyInput::Request(token) => {
            // First we will check it is in the time interval.
            if !inner
                .validity_interval
                .check_time_validity(current_time, token.timestamp)
            {
                return Err(ServerProtocolError::TokenOutOfInterval);
            }

            // We have received a request, we now broadcast a request to the server.
            inner.buffer.enqueue(ServerVerifyOutput::CheckToken(CheckTokenQuery {
                client_id: token.id,
                array: token.permissions.clone(),
                token_hash: H::hash(&token.view()),
            }));

            // Wait for the request to verify now.
            Ok(Some(DriverState::WaitingForRequestVerification(Some(
                token,
            ))))
        }
        _ => Ok(None), // do nothing.
    }
}

fn handle_verification<H, const N: usize>(
    inner: &mut ServerVerifyDriverInner<H, N>,
    packet: Option<ServerVerifyInput>,
    token_wrapper: &mut Option<Token<Final>>,
) -> Result<Option<DriverState>, ServerProtocolError>
where
    H: HashingAlgorithm<N>,
{
    let Some(packet) = packet else {
        return Ok(None);
    };

    match packet {

        ServerVerifyInput::TokenResponse(token_res) => match token_res {
            CheckTokenStatus::Valid => {
                // The token is good, we are done.
            inner.terminated = true;
            Ok(Some(DriverState::Finished(token_wrapper.take())))
            },
            CheckTokenStatus::Revoked => Err(ServerProtocolError::TokenInRevocationList),
            CheckTokenStatus::InvalidClientUuid => Err(ServerProtocolError::InvalidClientUuid),
            CheckTokenStatus::Expired => Err(ServerProtocolError::TokenExpired),
            CheckTokenStatus::NonExistent => Err(ServerProtocolError::TokenDoesNotExist),
            CheckTokenStatus::Forbidden => Err(ServerProtocolError::TokenPermissionError),
            CheckTokenStatus::Failure(reason) => Err(ServerProtocolError::Misc(reason))
        }
        _ => Ok(None), // do nothing.
    }
}

#[cfg(test)]
mod tests {
    use std::{task::Poll, time::Duration};

 
    use sha3::Sha3_256;
    use uuid::Uuid;

    use crate::{
        token::{Final, Pending, Token}, CheckTokenQuery, HashingAlgorithm, MsSinceEpoch, ServerProtocolError, ServerVerifyDriver, ServerVerifyInput, ServerVerifyOutput, TokenValidityInterval, ViewBytes
    };

    #[test]
    fn test_verify_driver_success() {
    

        let now = 1_000_000;
        let token = Token::<Pending>::new(0, 0, Uuid::new_v4(), MsSinceEpoch(now)).finalize();
        let mut driver = ServerVerifyDriver::<Sha3_256, 32>::new(TokenValidityInterval::from_seconds(60, 60));

        driver.recv(MsSinceEpoch(now), Some(ServerVerifyInput::Request(token.clone())));
        let output = driver.poll_transmit();

        match output {
            Some(ServerVerifyOutput::CheckToken(CheckTokenQuery {
                client_id,
                token_hash,
                ..
            })) => {
                assert_eq!(client_id, token.id);
                assert_eq!(token_hash, Sha3_256::hash(&token.view()));
            }
            _ => panic!("Expected CheckToken output"),
        }

        driver.recv(MsSinceEpoch(now), Some(ServerVerifyInput::TokenResponse(super::CheckTokenStatus::Valid)));

        match driver.poll_result() {
            Poll::Ready(Ok(t)) => assert_eq!(t.view(), token.view()),
            _ => panic!("Expected successful result"),
        }
    }

    #[test]
fn test_verify_driver_token_in_revocation_list() {
    let now = 1_000_000;
    let token = Token::<Pending>::new(0, 0, Uuid::new_v4(), MsSinceEpoch(now)).finalize();
    let mut driver = ServerVerifyDriver::<Sha3_256, 32>::new(TokenValidityInterval::from_seconds(60, 60));

    driver.recv(MsSinceEpoch(now), Some(ServerVerifyInput::Request(token.clone())));
    driver.poll_transmit(); // consume CheckToken

    driver.recv(MsSinceEpoch(now), Some(ServerVerifyInput::TokenResponse(super::CheckTokenStatus::Revoked)));

    match driver.poll_result() {
        Poll::Ready(Err(e)) => assert!(matches!(e, ServerProtocolError::TokenInRevocationList)),
        _ => panic!("Expected revocation list error"),
    }
}

#[test]
fn test_verify_driver_invalid_uuid() {
    let now = 1_000_000;
    let token = Token::<Pending>::new(0, 0, Uuid::new_v4(), MsSinceEpoch(now)).finalize();
    let mut driver = ServerVerifyDriver::<Sha3_256, 32>::new(TokenValidityInterval::from_seconds(60, 60));

    driver.recv(MsSinceEpoch(now), Some(ServerVerifyInput::Request(token)));
    driver.poll_transmit();

    driver.recv(MsSinceEpoch(now), Some(ServerVerifyInput::TokenResponse(super::CheckTokenStatus::InvalidClientUuid)));

    match driver.poll_result() {
        Poll::Ready(Err(e)) => match e {
            ServerProtocolError::InvalidClientUuid => {}
            _ => panic!("Expected InvalidClientUuid error"),
        },
        _ => panic!("Expected error result"),
    }
}

#[test]
fn test_verify_driver_token_expired() {
    let now = 1_000_000;
    let token = Token::<Pending>::new(0, 0, Uuid::new_v4(), MsSinceEpoch(now)).finalize();
    let mut driver = ServerVerifyDriver::<Sha3_256, 32>::new(TokenValidityInterval::from_seconds(60, 60));

    driver.recv(MsSinceEpoch(now), Some(ServerVerifyInput::Request(token)));
    driver.poll_transmit();

    driver.recv(MsSinceEpoch(now), Some(ServerVerifyInput::TokenResponse(super::CheckTokenStatus::Expired)));

    match driver.poll_result() {
        Poll::Ready(Err(e)) => match e {
            ServerProtocolError::TokenExpired => {}
            _ => panic!("Expected TokenExpired error"),
        },
        _ => panic!("Expected error result"),
    }
}


#[test]
fn test_verify_driver_token_not_in_db() {
    let now = 1_000_000;
    let token = Token::<Pending>::new(0, 0, Uuid::new_v4(), MsSinceEpoch(now)).finalize();
    let mut driver = ServerVerifyDriver::<Sha3_256, 32>::new(TokenValidityInterval::from_seconds(60, 60));

    driver.recv(MsSinceEpoch(now), Some(ServerVerifyInput::Request(token)));
    driver.poll_transmit();

    driver.recv(MsSinceEpoch(now), Some(ServerVerifyInput::TokenResponse(super::CheckTokenStatus::NonExistent)));

    match driver.poll_result() {
        Poll::Ready(Err(e)) => match e {
            ServerProtocolError::TokenDoesNotExist => {}
            _ => panic!("Expected TokenDoesNotExist error"),
        },
        _ => panic!("Expected error result"),
    }
}
#[test]
fn test_verify_driver_permission_failure() {
    let now = 1_000_000;
    let token = Token::<Pending>::new(0, 0, Uuid::new_v4(), MsSinceEpoch(now)).finalize();
    let mut driver = ServerVerifyDriver::<Sha3_256, 32>::new(TokenValidityInterval::from_seconds(60, 60));

    driver.recv(MsSinceEpoch(now), Some(ServerVerifyInput::Request(token)));
    driver.poll_transmit();

    driver.recv(MsSinceEpoch(now), Some(ServerVerifyInput::TokenResponse(super::CheckTokenStatus::Forbidden)));

    match driver.poll_result() {
        Poll::Ready(Err(e)) => match e {
            ServerProtocolError::TokenPermissionError => {},
            _ => panic!("Expected TokenPermissionError"),
        },
        _ => panic!("Expected error result"),
    }
}

#[test]
fn test_verify_driver_other_failure() {
    let now = 1_000_000;
    let token = Token::<Pending>::new(0, 0, Uuid::new_v4(), MsSinceEpoch(now)).finalize();
    let mut driver = ServerVerifyDriver::<Sha3_256, 32>::new(TokenValidityInterval::from_seconds(60, 60));

    driver.recv(MsSinceEpoch(now), Some(ServerVerifyInput::Request(token)));
    driver.poll_transmit();

    driver.recv(MsSinceEpoch(now), Some(ServerVerifyInput::TokenResponse(super::CheckTokenStatus::Failure("unexpected".into()))));

    match driver.poll_result() {
        Poll::Ready(Err(e)) => match e {
            ServerProtocolError::Misc(reason) => assert_eq!(reason, "unexpected"),
            _ => panic!("Expected Misc error"),
        },
        _ => panic!("Expected error result"),
    }
}

#[test]
fn test_verify_driver_token_out_of_validity_interval() {
    // Token issued far outside the validity window
    let token_timestamp = 1_000_000;
    let current_time = 2_000_000;

    // Validity interval is centered around `current_time`
    let interval = TokenValidityInterval::from_seconds(60, 60);
    let token = Token::<Pending>::new(0, 0, Uuid::new_v4(), MsSinceEpoch(token_timestamp)).finalize();
    let mut driver = ServerVerifyDriver::<Sha3_256, 32>::new(interval);

    // Feed the token with a timestamp that's way out of bounds
    driver.recv(MsSinceEpoch(current_time), Some(ServerVerifyInput::Request(token)));

    // It should fail immediately with TokenOutOfInterval error
    match driver.poll_result() {
        Poll::Ready(Err(e)) => match e {
            ServerProtocolError::TokenOutOfInterval => {}
            _ => panic!("Expected TokenOutOfInterval error"),
        },
        _ => panic!("Expected immediate error due to time validity"),
    }

    // Ensure that no transmission message was queued
    assert!(driver.poll_transmit().is_none());
}

#[test]
fn test_verify_driver_token_too_far_in_future() {
    // Token timestamp is far in the future
    let current_time = 1_000_000;
    let token_timestamp = current_time + 10_000_000;

    let interval = TokenValidityInterval::from_seconds(60, 60);
    let token = Token::<Pending>::new(0, 0, Uuid::new_v4(), MsSinceEpoch(token_timestamp)).finalize();
    let mut driver = ServerVerifyDriver::<Sha3_256, 32>::new(interval);

    // Feed the future token
    driver.recv(MsSinceEpoch(current_time), Some(ServerVerifyInput::Request(token)));

    // It should fail with TokenOutOfInterval
    match driver.poll_result() {
        Poll::Ready(Err(e)) => match e {
            ServerProtocolError::TokenOutOfInterval => {}
            _ => panic!("Expected TokenOutOfInterval error"),
        },
        _ => panic!("Expected error due to token being too far in the future"),
    }

    // Ensure no output was queued
    assert!(driver.poll_transmit().is_none());
}


}
