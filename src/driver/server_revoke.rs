use std::{marker::PhantomData, task::Poll};

use ringbuffer::{GrowableAllocRingBuffer, RingBuffer};
use uuid::Uuid;

use crate::{
    protocol::ProtocolKit, ClientRevoke, DsaSystem, GetPublicKeyQuery, HashingAlgorithm, KemAlgorithm, KeyFetchResponse, KeyFetchResult, RevokeTokenQuery, ServerProtocolError, ServerRevoke, TokenRevocationStatus
};

use super::ServerPollResult;

pub struct ServerRevokeDriver<S, K, H, const N: usize>
where
    S: DsaSystem,
    K: KemAlgorithm,
    H: HashingAlgorithm<N>,
{
    inner: ServerRevokeDriverInner<S, K, H, N>,
    state: DriverState<S, N>,
}

struct ServerRevokeDriverInner<S, K, H, const N: usize>
where
    S: DsaSystem,
    K: KemAlgorithm,
    H: HashingAlgorithm<N>,
{
    buffer: GrowableAllocRingBuffer<ServerRevokeOutput<N>>,
    server_sk: S::Private,
    terminated: bool,
    _h: PhantomData<H>,
    _k: PhantomData<K>,
    _s: PhantomData<S>,
}

enum DriverState<S, const N: usize>
where
    S: DsaSystem,
{
    Init,
    WaitingForPublicKeyFetch(Option<ClientRevoke<S::Signature, N>>),
    WaitingForRevocation {
        public_key: S::Public,
        request: Option<ServerRevoke<S::Signature, N>>,
    },

    Errored(Option<ServerProtocolError>),
    Finished(Option<ServerRevoke<S::Signature, N>>),
    Vacant,
}

pub enum ServerRevokeInput<S, const N: usize>
where
    S: DsaSystem,
{
    Request(ClientRevoke<S::Signature, N>),

    KeyFetchResponse(KeyFetchResult<S>),
    RevokeResponse(TokenRevocationStatus)
}



pub enum ServerRevokeOutput<const N: usize> {
    /// Fetch the public key. We also must report back if this user is an admin
    /// as admins can revoke tokens along with the clients themselves.
    GetPublicKey(GetPublicKeyQuery),
    Revoke(RevokeTokenQuery<N>),
}

impl<S, K, H, const N: usize> ServerRevokeDriver<S, K, H, N>
where
    S: DsaSystem,
    K: KemAlgorithm,
    H: HashingAlgorithm<N>,
{
    pub fn new(server_sk: S::Private) -> Self {
        Self {
            inner: ServerRevokeDriverInner {
                buffer: GrowableAllocRingBuffer::default(),
                server_sk,
                terminated: false,
                _h: PhantomData,
                _k: PhantomData,
                _s: PhantomData,
            },
            state: DriverState::Init,
        }
    }
    pub fn recv(&mut self, packet: Option<ServerRevokeInput<S, N>>) {
        if self.inner.terminated {
            return;
        }

        match recv_internal(self, packet) {
            Ok(_) => { /* Nothing to do */ }
            Err(e) => {
                self.inner.terminated = true;
                self.state = DriverState::Errored(Some(e))
            }
        }
    }
    pub fn poll_transmit(&mut self) -> Option<ServerRevokeOutput<N>> {
        self.inner.buffer.dequeue()
    }
    pub fn poll_result(&mut self) -> ServerPollResult<ServerRevoke<S::Signature, N>> {
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
    obj: &mut ServerRevokeDriver<S, K, H, N>,
    packet: Option<ServerRevokeInput<S, N>>,
) -> Result<(), ServerProtocolError>
where
    S: DsaSystem,
    K: KemAlgorithm,
    H: HashingAlgorithm<N>,
{
    let state = match &mut obj.state {
        DriverState::Init => handle_registry_init(&mut obj.inner, packet)?,
        DriverState::WaitingForPublicKeyFetch(req) => {
            handle_public_key_fetch(&mut obj.inner, packet, req)?
        }
        DriverState::WaitingForRevocation {
            request,
            public_key,
        } => handle_revocation_wait(&mut obj.inner, packet, request, public_key)?,
        _ => None, // The other states do not have any active behaviour.
    };

    if let Some(inner) = state {
        // If we output a new state, use said state.
        obj.state = inner;
    }

    Ok(())
}

fn handle_registry_init<S, K, H, const N: usize>(
    inner: &mut ServerRevokeDriverInner<S, K, H, N>,
    packet: Option<ServerRevokeInput<S, N>>,
) -> Result<Option<DriverState<S, N>>, ServerProtocolError>
where
    S: DsaSystem,
    K: KemAlgorithm,
    H: HashingAlgorithm<N>,
{
    let Some(packet) = packet else {
        return Ok(None);
    };

    match packet {
        ServerRevokeInput::Request(req) => {
            // Send out a request for the public key.
            inner.buffer.enqueue(ServerRevokeOutput::GetPublicKey(GetPublicKeyQuery {
                target: req.claimant,
                claimant: req.claimant,
            }));
            // Switch into waiting state.
            return Ok(Some(DriverState::WaitingForPublicKeyFetch(Some(req))));
        }
        _ => Ok(None), // ignore all other requests.
    }
}

fn handle_public_key_fetch<S, K, H, const N: usize>(
    inner: &mut ServerRevokeDriverInner<S, K, H, N>,
    packet: Option<ServerRevokeInput<S, N>>,
    request: &mut Option<ClientRevoke<S::Signature, N>>,
) -> Result<Option<DriverState<S, N>>, ServerProtocolError>
where
    S: DsaSystem,
    K: KemAlgorithm,
    H: HashingAlgorithm<N>,
{
    let Some(packet) = packet else {
        return Ok(None);
    };

    match packet {
        ServerRevokeInput::KeyFetchResponse(keyres) => match keyres {
            KeyFetchResult::Success(KeyFetchResponse { claimant, key, is_admin, has_permissions }) => {
                if !is_admin && !has_permissions {
                // the admin and has permissions.
                return Err(ServerProtocolError::UnauthorizedTokenRequest);
            }

            let request = request.take().unwrap();

            if claimant != request.claimant {
                return Err(ServerProtocolError::MalformedPkFetch);
            }

            // send out the revocation request
            inner.buffer.enqueue(ServerRevokeOutput::Revoke(RevokeTokenQuery {
                client_id: request.target,
                token_hash: (*request.token_hash).clone(),
            }));

            let request = ProtocolKit::<S, K, H, N>::server_revoke(
                &request,
                &key,
                &inner.server_sk,
            )?;

            Ok(Some(DriverState::WaitingForRevocation {
                request: Some(request),
                public_key: key,
            }))
            },
            KeyFetchResult::InvalidClaimant => Err(ServerProtocolError::InvalidClientUuid),
            KeyFetchResult::Failure(reason) =>  Err(ServerProtocolError::Misc(reason))
        }
        
        _ => Ok(None), // ignore all other requests.
    }
}

fn handle_revocation_wait<S, K, H, const N: usize>(
    inner: &mut ServerRevokeDriverInner<S, K, H, N>,
    packet: Option<ServerRevokeInput<S, N>>,
    request: &mut Option<ServerRevoke<S::Signature, N>>,
    public_key: &mut S::Public,
) -> Result<Option<DriverState<S, N>>, ServerProtocolError>
where
    S: DsaSystem,
    K: KemAlgorithm,
    H: HashingAlgorithm<N>,
{
    let Some(packet) = packet else {
        return Ok(None);
    };

    match packet {
        
        ServerRevokeInput::RevokeResponse(_) => {
            

            inner.terminated = true;

            Ok(Some(DriverState::Finished(request.take())))
        }
        _ => Ok(None), // ignore all other requests.
    }
}

#[cfg(test)]
mod tests {
    use std::task::Poll;

    use sha3::Sha3_256;
    use uuid::Uuid;

    use crate::{
        protocol::ProtocolKit, specials::{FauxChain, FauxKem}, testutil::BasicSetupDetails, DsaSystem, GetPublicKeyQuery, KeyFetchResponse, RevokeTokenQuery
    };

    use super::{ServerRevokeDriver, ServerRevokeInput, ServerRevokeOutput};

    #[test]
    pub fn test_revoke_happy() {
        let setup = BasicSetupDetails::<FauxChain>::new();

        let mut driver =
            ServerRevokeDriver::<FauxChain, FauxKem, Sha3_256, 32>::new(setup.server_sk.clone());

        // Generate request.
        let target = Uuid::new_v4();
        let (client_pk, client_sk) = FauxChain::generate().unwrap();
        let request = ProtocolKit::<FauxChain, FauxKem, Sha3_256, 32>::client_revoke_init(
            [0u8; 32], target, target, &client_sk,
        )
        .unwrap();

        // Send to the driver.
        driver.recv(Some(super::ServerRevokeInput::Request(request)));

        let ServerRevokeOutput::GetPublicKey(GetPublicKeyQuery { target, claimant }) = driver.poll_transmit().unwrap() else {
            panic!("Failed to see a public key fetch.");
        };
        assert_eq!(claimant, target);

        // Send the key.
        driver.recv(Some(ServerRevokeInput::KeyFetchResponse(crate::KeyFetchResult::Success(KeyFetchResponse {
            claimant: target,
            key: client_pk,
            is_admin: true,
            has_permissions: false,
        }))));

        let ServerRevokeOutput::Revoke(RevokeTokenQuery {
            client_id,
            token_hash,
        }) = driver.poll_transmit().unwrap()
        else {
            panic!("Revoke expected.");
        };

        assert_eq!(target, client_id);
        assert_eq!(token_hash, [0u8; 32]);

        // send another
        driver.recv(Some(ServerRevokeInput::RevokeResponse(crate::TokenRevocationStatus::Confirmed)));

        if let Poll::Ready(Ok(respo)) = driver.poll_result() {
        } else {
            panic!("Expected poll ready.");
        }
    }

    #[test]
    fn test_ignores_input_after_termination() {
        let setup = BasicSetupDetails::<FauxChain>::new();
        let mut driver =
            ServerRevokeDriver::<FauxChain, FauxKem, Sha3_256, 32>::new(setup.server_sk.clone());

        let target = Uuid::new_v4();
        let (client_pk, client_sk) = FauxChain::generate().unwrap();
        let request = ProtocolKit::<FauxChain, FauxKem, Sha3_256, 32>::client_revoke_init(
            [0u8; 32], target, target, &client_sk,
        )
        .unwrap();

        driver.recv(Some(ServerRevokeInput::Request(request)));
        driver.poll_transmit(); // consume GetPublicKey
        driver.recv(Some(ServerRevokeInput::KeyFetchResponse(crate::KeyFetchResult::Success(KeyFetchResponse {
            claimant: target,
            key: client_pk,
            is_admin: true,
            has_permissions: true,
        }))));
        driver.poll_transmit(); // consume Revoke
        driver.recv(Some(ServerRevokeInput::RevokeResponse(crate::TokenRevocationStatus::Confirmed)));

        // Already completed. Poll once.
        assert!(matches!(driver.poll_result(), Poll::Ready(Ok(_))));

        // Try feeding again — should be ignored silently.
        driver.recv(Some(ServerRevokeInput::KeyFetchResponse(crate::KeyFetchResult::InvalidClaimant)));
        assert!(driver.poll_transmit().is_none());
        assert!(matches!(driver.poll_result(), Poll::Pending));
    }

    #[test]
    fn test_mismatched_claimant_uuid_fails() {
        let setup = BasicSetupDetails::<FauxChain>::new();
        let mut driver =
            ServerRevokeDriver::<FauxChain, FauxKem, Sha3_256, 32>::new(setup.server_sk.clone());

        let target = Uuid::new_v4();
        let (client_pk, client_sk) = FauxChain::generate().unwrap();
        let request = ProtocolKit::<FauxChain, FauxKem, Sha3_256, 32>::client_revoke_init(
            [0u8; 32], target, target, &client_sk,
        )
        .unwrap();

        driver.recv(Some(ServerRevokeInput::Request(request)));
        driver.poll_transmit(); // consume GetPublicKey

        // Send wrong claimant ID
        let wrong_id = Uuid::new_v4();
        driver.recv(Some(ServerRevokeInput::KeyFetchResponse(crate::KeyFetchResult::Success(KeyFetchResponse {
            claimant: wrong_id,
            key: client_pk,
            is_admin: true,
            has_permissions: true,
        }))));

        if let Poll::Ready(Err(e)) = driver.poll_result() {
            match e {
                crate::ServerProtocolError::MalformedPkFetch => {} // expected
                _ => panic!("Unexpected error kind"),
            }
        } else {
            panic!("Expected immediate error from mismatched UUID.");
        }
    }

    #[test]
    fn test_public_key_fetch_unauthorized() {
        let setup = BasicSetupDetails::<FauxChain>::new();
        let mut driver =
            ServerRevokeDriver::<FauxChain, FauxKem, Sha3_256, 32>::new(setup.server_sk.clone());

        let target = Uuid::new_v4();
        let (_, client_sk) = FauxChain::generate().unwrap();
        let request = ProtocolKit::<FauxChain, FauxKem, Sha3_256, 32>::client_revoke_init(
            [0u8; 32], target, target, &client_sk,
        )
        .unwrap();

        driver.recv(Some(ServerRevokeInput::Request(request)));
        driver.poll_transmit(); // consume GetPublicKey

        driver.recv(Some(ServerRevokeInput::KeyFetchResponse(crate::KeyFetchResult::Success(KeyFetchResponse {
            claimant: target,
            key: FauxChain::generate().unwrap().0,
            is_admin: false,
            has_permissions: false,
        }))));

        if let Poll::Ready(Err(e)) = driver.poll_result() {
            match e {
                crate::ServerProtocolError::UnauthorizedTokenRequest => {}
                _ => panic!("Unexpected error type"),
            }
        } else {
            panic!("Expected error from unauthorized request.");
        }
    }

    #[test]
    fn test_invalid_claimant() {
        let setup = BasicSetupDetails::<FauxChain>::new();
        let mut driver =
            ServerRevokeDriver::<FauxChain, FauxKem, Sha3_256, 32>::new(setup.server_sk.clone());

        let target = Uuid::new_v4();
        let (_, client_sk) = FauxChain::generate().unwrap();
        let request = ProtocolKit::<FauxChain, FauxKem, Sha3_256, 32>::client_revoke_init(
            [0u8; 32], target, target, &client_sk,
        )
        .unwrap();

        driver.recv(Some(ServerRevokeInput::Request(request)));
        driver.poll_transmit(); // consume GetPublicKey

        driver.recv(Some(ServerRevokeInput::KeyFetchResponse(crate::KeyFetchResult::InvalidClaimant)));

        if let Poll::Ready(Err(e)) = driver.poll_result() {
            match e {
                crate::ServerProtocolError::InvalidClientUuid => {}
                _ => panic!("Unexpected error"),
            }
        } else {
            panic!("Expected InvalidClientUuid error");
        }
    }

    #[test]
    fn test_public_key_fetch_failure_message() {
        let setup = BasicSetupDetails::<FauxChain>::new();
        let mut driver =
            ServerRevokeDriver::<FauxChain, FauxKem, Sha3_256, 32>::new(setup.server_sk.clone());

        let target = Uuid::new_v4();
        let (_, client_sk) = FauxChain::generate().unwrap();
        let request = ProtocolKit::<FauxChain, FauxKem, Sha3_256, 32>::client_revoke_init(
            [0u8; 32], target, target, &client_sk,
        )
        .unwrap();

        driver.recv(Some(ServerRevokeInput::Request(request)));
        driver.poll_transmit(); // consume GetPublicKey

        let reason = "Database timeout".to_string();
        driver.recv(Some(ServerRevokeInput::KeyFetchResponse(crate::KeyFetchResult::Failure(reason.clone()))));

        if let Poll::Ready(Err(e)) = driver.poll_result() {
            match e {
                crate::ServerProtocolError::Misc(r) => assert_eq!(r, reason),
                _ => panic!("Unexpected error type"),
            }
        } else {
            panic!("Expected revocation failure message.");
        }
    }
}
