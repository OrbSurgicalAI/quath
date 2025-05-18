use std::{marker::PhantomData, task::Poll, time::Duration};

use ringbuffer::{GrowableAllocRingBuffer, RingBuffer};
use uuid::Uuid;

use crate::{
    protocol::ProtocolKit, ClientToken, DsaSystem, HashingAlgorithm, KemAlgorithm, MsSinceEpoch, ProtocolTime, RevokeTokenQuery, ServerProtocolError, ServerToken, StorageStatus, StoreTokenQuery, TokenRevocationStatus, VerifyTokenQuery, ViewBytes
};

use super::ServerPollResult;

pub struct ServerTokenDriver<S, K, H, const N: usize>
where
    S: DsaSystem,
    K: KemAlgorithm,
    H: HashingAlgorithm<N>,
{
    inner: ServerTokenDriverInner<S, K, H, N>,
    state: DriverState<S, K, N>,
}

pub struct ServerTokenDriverInner<S, K, H, const N: usize>
where
    S: DsaSystem,
    K: KemAlgorithm,
    H: HashingAlgorithm<N>,
{
    server_sk: S::Private,
    buffer: GrowableAllocRingBuffer<ServerTokenOutput<N>>,
    token_lifetime: Duration,
    terminated: bool,
    _h: PhantomData<H>,
    _k: PhantomData<K>,
}

pub enum ServerTokenOutput<const N: usize> {
    /// We must check that the hash does not exist in the database
    /// and also fetch the existing public key associated with this [Uuid].
    ///
    /// Also check if this is in some revocation list.
    VerificationRequest(VerifyTokenQuery<N>),
    Revoke(RevokeTokenQuery<N>),
    StorageRequest(StoreTokenQuery<N>),
}

pub enum ServerTokenInput<S, K>
where
    S: DsaSystem,
    K: KemAlgorithm,
{
    ReceiveRequest(ClientToken<S::Signature, K>),
    VerifyResponse(TokenVerifyStatus<S>),
    RevokeResponse(TokenRevocationStatus),
    StorageResponse(StorageStatus),
}

pub enum TokenVerifyStatus<S>
where
    S: DsaSystem,
{
    Success {
        client_id: Uuid,
        current_public: S::Public,
        protocol_time: ProtocolTime
    },
    CycleNeeded,
    Duplicate,
    InRevocationList,
    Other(String),
}

enum DriverState<S, K, const N: usize>
where
    S: DsaSystem,
    K: KemAlgorithm,
{
    Init,
    WaitingForRequestVerification {
        request: ClientToken<S::Signature, K>,
        token_hash: [u8; N],
    },
    WaitingForRevocation,
    WaitingForStore(Option<ServerToken<N, K, S::Signature>>),
    Errored(Option<ServerProtocolError>),
    Finished(Option<ServerToken<N, K, S::Signature>>),
    Vacant,
}

impl<S, K, H, const N: usize> ServerTokenDriver<S, K, H, N>
where
    S: DsaSystem,
    K: KemAlgorithm,
    H: HashingAlgorithm<N>,
{
    pub fn new(
        server_sk: S::Private,
        token_lifetime: Duration,
    ) -> Self {
        Self {
            inner: ServerTokenDriverInner {
                server_sk,
                buffer: GrowableAllocRingBuffer::default(),
                token_lifetime,
                terminated: false,
                _h: PhantomData,
                _k: PhantomData,
            },
            state: DriverState::Init,
        }
    }
    pub fn recv(&mut self, time: MsSinceEpoch, packet: Option<ServerTokenInput<S, K>>) {
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
    pub fn poll_transmit(&mut self) -> Option<ServerTokenOutput<N>> {
        self.inner.buffer.dequeue()
    }
    pub fn poll_result(&mut self) -> ServerPollResult<ServerToken<N, K, S::Signature>> {
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

fn recv_internal<S, K, H, const N: usize>(
    obj: &mut ServerTokenDriver<S, K, H, N>,
    packet: Option<ServerTokenInput<S, K>>,
    current_time: MsSinceEpoch,
) -> Result<(), ServerProtocolError>
where
    S: DsaSystem,
    K: KemAlgorithm,
    H: HashingAlgorithm<N>,
{
    let state = match &mut obj.state {
        DriverState::Init => handle_registry_init(&mut obj.inner, packet)?,
        DriverState::WaitingForRequestVerification {
            request,
            token_hash,
        } => handle_verification(&mut obj.inner, packet, request, current_time, token_hash)?,
        DriverState::WaitingForStore(resp) => handle_storage_wait(&mut obj.inner, packet, resp)?,
        DriverState::WaitingForRevocation => handle_revocation_wait(&mut obj.inner, packet)?,
        _ => None, // The other states do not have any active behaviour.
    };

    if let Some(inner) = state {
        // If we output a new state, use said state.
        obj.state = inner;
    }

    Ok(())
}

fn handle_registry_init<S, K, H, const HS: usize>(
    inner: &mut ServerTokenDriverInner<S, K, H, HS>,
    packet: Option<ServerTokenInput<S, K>>,
) -> Result<Option<DriverState<S, K, HS>>, ServerProtocolError>
where
    S: DsaSystem,
    K: KemAlgorithm,
    H: HashingAlgorithm<HS>,
{
    // We only want to proceed if the packet is not none.
    let Some(packet) = packet else {
        return Ok(None);
    };

    match packet {
        ServerTokenInput::ReceiveRequest(request) => {
            // Send out a verification request, this will also fetch the new key from the database with
            // which we can actually validate the request.

            let tok_hash = H::hash(&request.body.token.view());

            inner
                .buffer
                .enqueue(ServerTokenOutput::VerificationRequest(VerifyTokenQuery {
                    client_id: request.body.token.id,
                    token_hash: tok_hash,
                }));
            Ok(Some(DriverState::WaitingForRequestVerification {
                request,
                token_hash: tok_hash,
            }))
        }
        _ => {
            /* Nothig */
            Ok(None)
        }
    }
}

fn handle_verification<S, K, H, const HS: usize>(
    inner: &mut ServerTokenDriverInner<S, K, H, HS>,
    packet: Option<ServerTokenInput<S, K>>,
    init_msg: &ClientToken<S::Signature, K>,
    current_time: MsSinceEpoch,
    token_hash: &[u8; HS],
) -> Result<Option<DriverState<S, K, HS>>, ServerProtocolError>
where
    S: DsaSystem,
    K: KemAlgorithm,
    H: HashingAlgorithm<HS>,
{
    // We only want to proceed if the packet is not none.
    let Some(packet) = packet else {
        return Ok(None);
    };

    match packet {
        ServerTokenInput::VerifyResponse(resp) => match resp {
            TokenVerifyStatus::CycleNeeded => Err(ServerProtocolError::CycleRequired),
            TokenVerifyStatus::InRevocationList => Err(ServerProtocolError::TokenInRevocationList),
            TokenVerifyStatus::Other(reason) => Err(ServerProtocolError::Misc(reason)),
            TokenVerifyStatus::Duplicate => {
                // Enqueues a token revocation request and puts the state machine in a waiting mode.
                inner
                    .buffer
                    .enqueue(ServerTokenOutput::Revoke(RevokeTokenQuery {
                        client_id: init_msg.body.token.id,
                        token_hash: *token_hash,
                    }));
                Ok(Some(DriverState::WaitingForRevocation))
            }
            TokenVerifyStatus::Success {
                client_id,
                current_public,
                protocol_time
            } => {
                // Perform the actual token verification.
                let (response, server_token) = ProtocolKit::<S, K, H, HS>::server_token(
                    init_msg,
                    &current_public,
                    &inner.server_sk,
                    protocol_time,
                    inner.token_lifetime,
                )?;

                // Get the expiry.
                let expiry = response.body.expiry;

                // Submit a storage request.
                inner
                    .buffer
                    .enqueue(ServerTokenOutput::StorageRequest(StoreTokenQuery {
                        client_id,
                        token_hash: H::hash(&server_token.view()),
                        token_stamp_time: current_time,
                        token_expiry_time: expiry,
                    }));

                // Make the state machine wait.
                Ok(Some(DriverState::WaitingForStore(Some(response))))
            }
        },
        _ => {
            /* Nothig */
            Ok(None)
        }
    }
}

fn handle_storage_wait<S, K, H, const HS: usize>(
    inner: &mut ServerTokenDriverInner<S, K, H, HS>,
    packet: Option<ServerTokenInput<S, K>>,
    resp: &mut Option<ServerToken<HS, K, S::Signature>>,
) -> Result<Option<DriverState<S, K, HS>>, ServerProtocolError>
where
    S: DsaSystem,
    K: KemAlgorithm,
    H: HashingAlgorithm<HS>,
{
    // We only want to proceed if the packet is not none.
    let Some(packet) = packet else {
        return Ok(None);
    };

    match packet {
        ServerTokenInput::StorageResponse(storage_res) => match storage_res {
            StorageStatus::Success => {
                // The storage was succesful, so the server has the token.
                inner.terminated = true;
                Ok(Some(DriverState::Finished(resp.take())))
            }
            StorageStatus::Failure(reason) => Err(ServerProtocolError::StoreFailure(reason)),
        },
        _ => {
            /* Nothig */
            Ok(None)
        }
    }
}

fn handle_revocation_wait<S, K, H, const HS: usize>(
    _inner: &mut ServerTokenDriverInner<S, K, H, HS>,
    packet: Option<ServerTokenInput<S, K>>,
) -> Result<Option<DriverState<S, K, HS>>, ServerProtocolError>
where
    S: DsaSystem,
    K: KemAlgorithm,
    H: HashingAlgorithm<HS>,
{
    // We only want to proceed if the packet is not none.
    let Some(packet) = packet else {
        return Ok(None);
    };

    match packet {
        // Although revocaton occured, we still need to notify the client of this failure.
        ServerTokenInput::RevokeResponse(_) => Err(ServerProtocolError::TokenDuplicate),
        _ => {
            /* Nothig */
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use core::panic;
    use std::{ops::Deref, task::Poll, time::Duration};

    use sha3::Sha3_256;

    use crate::{
        protocol::ProtocolKit, specials::{FauxChain, FauxKem}, testutil::BasicSetupDetails, DsaSystem, HashingAlgorithm, ProtocolTime, StoreTokenQuery, VerifyTokenQuery, ViewBytes
    };

    use super::{ServerTokenDriver, ServerTokenOutput};

    #[test]
    pub fn test_server_token_happy() {
        let setup = BasicSetupDetails::<FauxChain>::new();

        let mut driver = ServerTokenDriver::<FauxChain, FauxKem, Sha3_256, 32>::new(
            setup.server_sk.clone(),
            Duration::from_secs(60),
        );

        let (client_pk, client_sk) = FauxChain::generate().unwrap();

        // Form the initial client request.
        let (req, dk) = ProtocolKit::<FauxChain, FauxKem, Sha3_256, 32>::client_token_init(
            0,
            0,
            crate::ProtocolTime(0),
            &client_sk,
            setup.client_id,
            |_| {},
        )
        .unwrap();

        let client_pending_token = req.body.token.deref().clone();

        // Make a requst.
        driver.recv(
            crate::MsSinceEpoch(0),
            Some(super::ServerTokenInput::ReceiveRequest(req)),
        );

        // Check the verification request.
        let ServerTokenOutput::VerificationRequest(VerifyTokenQuery { .. }) =
            driver.poll_transmit().unwrap()
        else {
            panic!("Expected verification request, got something else.");
        };

        // driver receive
        driver.recv(
            crate::MsSinceEpoch(0),
            Some(super::ServerTokenInput::VerifyResponse(
                super::TokenVerifyStatus::Success {
                    client_id: setup.client_id,
                    current_public: client_pk.clone(),
                    protocol_time: ProtocolTime(0)
                },
            )),
        );

        let ServerTokenOutput::StorageRequest(StoreTokenQuery {
            token_hash: server_token_hash,
            ..
        }) = driver.poll_transmit().unwrap()
        else {
            panic!("Expected a storage request, found somehing else!");
        };

        driver.recv(
            crate::MsSinceEpoch(0),
            Some(super::ServerTokenInput::StorageResponse(
                crate::StorageStatus::Success,
            )),
        );

        let Poll::Ready(Ok(response)) = driver.poll_result() else {
            panic!("Did not pull to a final result");
        };

        let client_token_final =
            ProtocolKit::<FauxChain, FauxKem, Sha3_256, 32>::client_token_finish(
                &response,
                &client_pending_token,
                &dk,
                &setup.server_pk,
            )
            .unwrap();

        assert_eq!(
            Sha3_256::hash(&client_token_final.view()),
            server_token_hash
        );
    }

    #[test]
    fn test_server_token_duplicate_triggers_revocation_flow() {
        use crate::specials::{FauxChain, FauxKem};
        use crate::testutil::BasicSetupDetails;
        use crate::{MsSinceEpoch, ServerTokenDriver, ServerTokenInput, TokenVerifyStatus};
        use sha3::Sha3_256;
        use std::time::Duration;

        let setup = BasicSetupDetails::<FauxChain>::new();

        let mut driver = ServerTokenDriver::<FauxChain, FauxKem, Sha3_256, 32>::new(
            setup.server_sk.clone(),
            Duration::from_secs(60),
        );

        let (_client_pk, client_sk) = FauxChain::generate().unwrap();
        let (req, _) = ProtocolKit::<FauxChain, FauxKem, Sha3_256, 32>::client_token_init(
            0,
            0,
            ProtocolTime(0),
            &client_sk,
            setup.client_id,
            |_| {},
        )
        .unwrap();

        driver.recv(MsSinceEpoch(0), Some(ServerTokenInput::ReceiveRequest(req)));

        let _ = driver.poll_transmit().unwrap(); // discard VerificationRequest

        driver.recv(
            MsSinceEpoch(0),
            Some(ServerTokenInput::VerifyResponse(
                TokenVerifyStatus::Duplicate,
            )),
        );

        let Some(crate::ServerTokenOutput::Revoke { .. }) = driver.poll_transmit() else {
            panic!("Expected revocation to be enqueued");
        };

        // Still waiting for revocation confirmation
        assert!(matches!(driver.poll_result(), std::task::Poll::Pending));
    }

    #[test]
    fn test_server_token_revocation_fails() {
        use crate::specials::{FauxChain, FauxKem};
        use crate::testutil::BasicSetupDetails;
        use crate::{
            MsSinceEpoch, ServerProtocolError, ServerTokenDriver, ServerTokenInput,
            TokenVerifyStatus,
        };
        use sha3::Sha3_256;
        use std::task::Poll;
        use std::time::Duration;

        let setup = BasicSetupDetails::<FauxChain>::new();

        let mut driver = ServerTokenDriver::<FauxChain, FauxKem, Sha3_256, 32>::new(
            setup.server_sk.clone(),
            Duration::from_secs(60),
        );

        let (_client_pk, client_sk) = FauxChain::generate().unwrap();
        let (req, _) = ProtocolKit::<FauxChain, FauxKem, Sha3_256, 32>::client_token_init(
            0,
            0,
            ProtocolTime(0),
            &client_sk,
            setup.client_id,
            |_| {},
        )
        .unwrap();

        driver.recv(MsSinceEpoch(0), Some(ServerTokenInput::ReceiveRequest(req)));
        let _ = driver.poll_transmit(); // VerificationRequest

        driver.recv(
            MsSinceEpoch(0),
            Some(ServerTokenInput::VerifyResponse(
                TokenVerifyStatus::Duplicate,
            )),
        );
        let _ = driver.poll_transmit(); // Revoke

        driver.recv(
            MsSinceEpoch(0),
            Some(ServerTokenInput::RevokeResponse(
                crate::TokenRevocationStatus::Confirmed,
            )),
        );
        let Poll::Ready(Err(ServerProtocolError::TokenDuplicate)) = driver.poll_result() else {
            panic!("Expected a duplicate token protocol error");
        };
    }

    #[test]
    fn test_server_token_cycle_needed_fails_immediately() {
        use crate::specials::{FauxChain, FauxKem};
        use crate::testutil::BasicSetupDetails;
        use crate::{
            MsSinceEpoch, ServerProtocolError, ServerTokenDriver, ServerTokenInput,
            TokenVerifyStatus,
        };
        use sha3::Sha3_256;
        use std::{task::Poll, time::Duration};

        let setup = BasicSetupDetails::<FauxChain>::new();

        let mut driver = ServerTokenDriver::<FauxChain, FauxKem, Sha3_256, 32>::new(
            setup.server_sk.clone(),
            Duration::from_secs(60),
        );

        let (_pk, sk) = FauxChain::generate().unwrap();

        let (req, _) = ProtocolKit::<FauxChain, FauxKem, Sha3_256, 32>::client_token_init(
            0,
            0,
            ProtocolTime(0),
            &sk,
            setup.client_id,
            |_| {},
        )
        .unwrap();

        driver.recv(MsSinceEpoch(0), Some(ServerTokenInput::ReceiveRequest(req)));
        let _ = driver.poll_transmit(); // VerificationRequest

        driver.recv(
            MsSinceEpoch(0),
            Some(ServerTokenInput::VerifyResponse(
                TokenVerifyStatus::CycleNeeded,
            )),
        );

        let Poll::Ready(Err(ServerProtocolError::CycleRequired)) = driver.poll_result() else {
            panic!("Expected CycleRequired error");
        };
    }
    #[test]
    fn test_server_token_storage_failure() {
        use crate::specials::{FauxChain, FauxKem};
        use crate::testutil::BasicSetupDetails;
        use crate::{
            MsSinceEpoch, ServerProtocolError, ServerTokenDriver, ServerTokenInput,
            TokenVerifyStatus,
        };
        use sha3::Sha3_256;
        use std::{task::Poll, time::Duration};

        let setup = BasicSetupDetails::<FauxChain>::new();

        let mut driver = ServerTokenDriver::<FauxChain, FauxKem, Sha3_256, 32>::new(
            setup.server_sk.clone(),
            Duration::from_secs(60),
        );

        let (pk, sk) = FauxChain::generate().unwrap();
        let (req, _) = ProtocolKit::<FauxChain, FauxKem, Sha3_256, 32>::client_token_init(
            0,
            0,
            ProtocolTime(0),
            &sk,
            setup.client_id,
            |_| {},
        )
        .unwrap();

        driver.recv(MsSinceEpoch(0), Some(ServerTokenInput::ReceiveRequest(req)));
        let _ = driver.poll_transmit(); // VerificationRequest

        driver.recv(
            MsSinceEpoch(0),
            Some(ServerTokenInput::VerifyResponse(
                TokenVerifyStatus::Success {
                    client_id: setup.client_id,
                    current_public: pk,
                    protocol_time: ProtocolTime(0)
                },
            )),
        );
        let _ = driver.poll_transmit(); // StorageRequest

        driver.recv(
            MsSinceEpoch(0),
            Some(ServerTokenInput::StorageResponse(
                crate::StorageStatus::Failure("db down".into()),
            )),
        );

        let Poll::Ready(Err(ServerProtocolError::StoreFailure(reason))) = driver.poll_result()
        else {
            panic!("Expected StoreFailure error");
        };

        assert_eq!(reason, "db down");
    }

    #[test]
    fn test_server_token_duplicate_token_revocation_and_confirmation() {
        use crate::specials::{FauxChain, FauxKem};
        use crate::testutil::BasicSetupDetails;
        use crate::{
            MsSinceEpoch, ServerProtocolError, ServerTokenDriver, ServerTokenInput,
            ServerTokenOutput, TokenVerifyStatus,
        };
        use sha3::Sha3_256;
        use std::{task::Poll, time::Duration};

        let setup = BasicSetupDetails::<FauxChain>::new();

        let mut driver = ServerTokenDriver::<FauxChain, FauxKem, Sha3_256, 32>::new(
            setup.server_sk.clone(),
            Duration::from_secs(60),
        );

        let (_pk, sk) = FauxChain::generate().unwrap();

        // Client creates and sends token
        let (req, _) = ProtocolKit::<FauxChain, FauxKem, Sha3_256, 32>::client_token_init(
            0,
            0,
            ProtocolTime(0),
            &sk,
            setup.client_id,
            |_| {},
        )
        .unwrap();

        // Step 1: Receive the token request
        driver.recv(MsSinceEpoch(0), Some(ServerTokenInput::ReceiveRequest(req)));

        // Step 2: Expect verification request to be emitted
        let Some(ServerTokenOutput::VerificationRequest { .. }) = driver.poll_transmit() else {
            panic!("Expected VerificationRequest");
        };

        // Step 3: Receive duplicate status
        driver.recv(
            MsSinceEpoch(0),
            Some(ServerTokenInput::VerifyResponse(
                TokenVerifyStatus::Duplicate,
            )),
        );

        // Step 4: Revocation should be emitted
        let Some(ServerTokenOutput::Revoke { .. }) = driver.poll_transmit() else {
            panic!("Expected Revoke output after duplicate detection");
        };

        // Step 5: Simulate receiving confirmation
        driver.recv(
            MsSinceEpoch(0),
            Some(ServerTokenInput::RevokeResponse(
                crate::TokenRevocationStatus::Confirmed,
            )),
        );

        // Step 6: The result should now be a final protocol error
        let Poll::Ready(Err(ServerProtocolError::TokenDuplicate)) = driver.poll_result() else {
            panic!("Expected TokenDuplicate protocol error");
        };
    }

    #[test]
    fn test_server_token_duplicate_token_revocation_never_confirmed_times_out() {
        use crate::specials::{FauxChain, FauxKem};
        use crate::testutil::BasicSetupDetails;
        use crate::{
            MsSinceEpoch, ServerTokenDriver, ServerTokenInput, ServerTokenOutput, TokenVerifyStatus,
        };
        use sha3::Sha3_256;
        use std::time::Duration;

        let setup = BasicSetupDetails::<FauxChain>::new();

        let mut driver = ServerTokenDriver::<FauxChain, FauxKem, Sha3_256, 32>::new(
            setup.server_sk.clone(),
            Duration::from_secs(60),
        );

        let (_pk, sk) = FauxChain::generate().unwrap();

        let (req, _) = ProtocolKit::<FauxChain, FauxKem, Sha3_256, 32>::client_token_init(
            0,
            0,
            ProtocolTime(0),
            &sk,
            setup.client_id,
            |_| {},
        )
        .unwrap();

        driver.recv(MsSinceEpoch(0), Some(ServerTokenInput::ReceiveRequest(req)));

        let Some(ServerTokenOutput::VerificationRequest { .. }) = driver.poll_transmit() else {
            panic!("Expected VerificationRequest");
        };

        driver.recv(
            MsSinceEpoch(0),
            Some(ServerTokenInput::VerifyResponse(
                TokenVerifyStatus::Duplicate,
            )),
        );

        let Some(ServerTokenOutput::Revoke { .. }) = driver.poll_transmit() else {
            panic!("Expected Revoke output");
        };

        // No confirmation is sent. The state machine should not yield a result yet.
        assert!(matches!(driver.poll_result(), std::task::Poll::Pending));
    }
}
