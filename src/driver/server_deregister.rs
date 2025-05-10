use std::{marker::PhantomData, task::Poll};

use ringbuffer::{GrowableAllocRingBuffer, RingBuffer};
use uuid::Uuid;

use crate::{
    ClientDeregister, DsaSystem, HashingAlgorithm, KemAlgorithm, ServerDeregister,
    ServerProtocolError, protocol::ProtocolKit,
};

use super::ServerPollResult;

pub struct ServerDeregisterDriver<S, K, H, const N: usize>
where
    S: DsaSystem,
    K: KemAlgorithm,
    H: HashingAlgorithm<N>,
{
    inner: ServerDeregisterDriverInner<S, K, H, N>,
    state: DriverState<S, N>,
}

struct ServerDeregisterDriverInner<S, K, H, const N: usize>
where
    S: DsaSystem,
    K: KemAlgorithm,
    H: HashingAlgorithm<N>,
{
    buffer: GrowableAllocRingBuffer<ServerDeregisterOutput>,
    server_sk: S::Private,
    terminated: bool,
    _h: PhantomData<H>,
    _k: PhantomData<K>,
    _s: PhantomData<S>,
}

pub enum ServerDeregisterInput<S, const N: usize>
where
    S: DsaSystem,
{
    Request(ClientDeregister<S::Signature, N>),

    InvalidClaimant,
    PublicKeyFetchFailure(String),
    KeyFetchResponse {
        claimant: Uuid,
        key: S::Public,
        is_admin: bool,
        has_permissions: bool,
    },
    DeregisterSuccess,
    DeregisterNotChanged,
    DeregisteredError(String),
}

pub enum ServerDeregisterOutput {
    GetPublicKey { target: Uuid, claimant: Uuid },
    Deregister { target: Uuid },
}

enum DriverState<S, const N: usize>
where
    S: DsaSystem,
{
    Init,

    WaitingForPublicKeyFetch(Option<ClientDeregister<S::Signature, N>>),
    WaitingForDeregister(Option<ServerDeregister<S::Signature, N>>),

    Finished(Option<ServerDeregister<S::Signature, N>>),
    Errored(Option<ServerProtocolError>),
    Vacant,
}

impl<S, K, H, const N: usize> ServerDeregisterDriver<S, K, H, N>
where
    S: DsaSystem,
    K: KemAlgorithm,
    H: HashingAlgorithm<N>,
{
    pub fn new(server_sk: S::Private) -> Self {
        Self {
            inner: ServerDeregisterDriverInner {
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
    pub fn recv(&mut self, packet: Option<ServerDeregisterInput<S, N>>) {
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
    pub fn poll_transmit(&mut self) -> Option<ServerDeregisterOutput> {
        self.inner.buffer.dequeue()
    }
    pub fn poll_result(&mut self) -> ServerPollResult<ServerDeregister<S::Signature, N>> {
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
    obj: &mut ServerDeregisterDriver<S, K, H, N>,
    packet: Option<ServerDeregisterInput<S, N>>,
) -> Result<(), ServerProtocolError>
where
    S: DsaSystem,
    K: KemAlgorithm,
    H: HashingAlgorithm<N>,
{
    let state = match &mut obj.state {
        DriverState::Init => handle_registry_init(&mut obj.inner, packet)?,
        DriverState::WaitingForPublicKeyFetch(pk_fetch) => {
            handle_public_key_fetch(&mut obj.inner, packet, pk_fetch)?
        }
        DriverState::WaitingForDeregister(request) => {
            handle_deregister(&mut obj.inner, packet, request)?
        }
        // DriverState::WaitingForPublicKeyFetch(req) =>
        //     handle_public_key_fetch(&mut obj.inner, packet, req)?,
        // DriverState::WaitingForRevocation {
        //     request,
        //     public_key,
        // } => handle_revocation_wait(&mut obj.inner, packet, request, public_key)?,
        _ => None, // The other states do not have any active behaviour.
    };

    if let Some(inner) = state {
        // If we output a new state, use said state.
        obj.state = inner;
    }

    Ok(())
}

fn handle_registry_init<S, K, H, const N: usize>(
    inner: &mut ServerDeregisterDriverInner<S, K, H, N>,
    packet: Option<ServerDeregisterInput<S, N>>,
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
        ServerDeregisterInput::Request(request) => {
            // Fetches
            inner.buffer.enqueue(ServerDeregisterOutput::GetPublicKey {
                target: request.target,
                claimant: request.claimant,
            });
            return Ok(Some(DriverState::WaitingForPublicKeyFetch(Some(request))));
        }
        _ => Ok(None), // ignore all other requests.
    }
}

fn handle_public_key_fetch<S, K, H, const N: usize>(
    inner: &mut ServerDeregisterDriverInner<S, K, H, N>,
    packet: Option<ServerDeregisterInput<S, N>>,
    request: &mut Option<ClientDeregister<S::Signature, N>>,
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
        ServerDeregisterInput::KeyFetchResponse {
            claimant,
            key,
            has_permissions,
            is_admin,
        } => {
            if !is_admin && !has_permissions {
                return Err(ServerProtocolError::UnauthorizedDeregisterRequest);
            }

            let request = request.take().unwrap();

            if claimant != request.claimant {
                return Err(ServerProtocolError::MalformedPkFetch);
            }

            let pro =
                ProtocolKit::<S, K, H, N>::server_deregister(&request, &key, &inner.server_sk)?;

            inner.buffer.enqueue(ServerDeregisterOutput::Deregister {
                target: request.target,
            });
            Ok(Some(DriverState::WaitingForDeregister(Some(pro))))
        }
        ServerDeregisterInput::InvalidClaimant => {
            Err(ServerProtocolError::DeregistrationClaimantNotFound)
        }
        ServerDeregisterInput::PublicKeyFetchFailure(_) => {
            Err(ServerProtocolError::MalformedPkFetch)
        }
        _ => Ok(None), // ignore all other requests.
    }
}

fn handle_deregister<S, K, H, const N: usize>(
    inner: &mut ServerDeregisterDriverInner<S, K, H, N>,
    packet: Option<ServerDeregisterInput<S, N>>,
    request: &mut Option<ServerDeregister<S::Signature, N>>,
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
        ServerDeregisterInput::DeregisterSuccess => {
            inner.terminated = true;
            Ok(Some(DriverState::Finished(Some(request.take().unwrap()))))
        }
        ServerDeregisterInput::DeregisterNotChanged => {
            Err(ServerProtocolError::DeregstrationUnchanged)
        }
        ServerDeregisterInput::DeregisteredError(reason) => {
            Err(ServerProtocolError::DeregistrationError(reason))
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
        DsaSystem, ServerDeregisterDriver, ServerProtocolError,
        protocol::ProtocolKit,
        specials::{FauxChain, FauxKem},
        testutil::BasicSetupDetails,
    };

    use super::{ServerDeregisterInput, ServerDeregisterOutput};

    #[test]
    fn test_deregister_happy_path() {
        let setup = BasicSetupDetails::<FauxChain>::new();

        let mut driver = ServerDeregisterDriver::<FauxChain, FauxKem, Sha3_256, 32>::new(
            setup.server_sk.clone(),
        );

        let target = Uuid::new_v4();
        let (c_pk, c_sk) = FauxChain::generate().unwrap();

        let request = ProtocolKit::<FauxChain, FauxKem, Sha3_256, 32>::client_deregister_init(
            target, target, &c_sk,
        )
        .unwrap();

        driver.recv(Some(ServerDeregisterInput::Request(request.clone())));

        let ServerDeregisterOutput::GetPublicKey { target, claimant } =
            driver.poll_transmit().unwrap()
        else {
            panic!("Get public key msg.");
        };

        assert_eq!(target, claimant);

        driver.recv(Some(ServerDeregisterInput::KeyFetchResponse {
            claimant: target,
            key: c_pk,
            is_admin: true,
            has_permissions: true,
        }));

        let ServerDeregisterOutput::Deregister { .. } = driver.poll_transmit().unwrap() else {
            panic!("Get public key msg.");
        };

        driver.recv(Some(ServerDeregisterInput::DeregisterSuccess));

        match driver.poll_result() {
            Poll::Ready(Ok(inner)) => {
                ProtocolKit::<FauxChain, FauxKem, Sha3_256, 32>::client_deregister_finish(
                    request.target,
                    request.claimant,
                    &inner,
                    &setup.server_pk,
                )
                .unwrap();
            }
            _ => panic!("should have returned proper pull"),
        }
    }

    #[test]
    fn test_deregister_invalid_claimant() {
        let setup = BasicSetupDetails::<FauxChain>::new();

        let mut driver = ServerDeregisterDriver::<FauxChain, FauxKem, Sha3_256, 32>::new(
            setup.server_sk.clone(),
        );

        let target = Uuid::new_v4();
        let (_c_pk, c_sk) = FauxChain::generate().unwrap();

        let request = ProtocolKit::<FauxChain, FauxKem, Sha3_256, 32>::client_deregister_init(
            target, target, &c_sk,
        )
        .unwrap();

        driver.recv(Some(ServerDeregisterInput::Request(request)));

        assert!(matches!(
            driver.poll_transmit(),
            Some(ServerDeregisterOutput::GetPublicKey { .. })
        ));

        driver.recv(Some(ServerDeregisterInput::InvalidClaimant));

        match driver.poll_result() {
            Poll::Ready(Err(ServerProtocolError::DeregistrationClaimantNotFound)) => {}
            _ => panic!("Expected DeregistrationClaimantNotFound"),
        }
    }

    #[test]
    fn test_deregister_claimant_mismatch() {
        let setup = BasicSetupDetails::<FauxChain>::new();

        let mut driver = ServerDeregisterDriver::<FauxChain, FauxKem, Sha3_256, 32>::new(
            setup.server_sk.clone(),
        );

        let target = Uuid::new_v4();
        let (c_pk, c_sk) = FauxChain::generate().unwrap();

        let request = ProtocolKit::<FauxChain, FauxKem, Sha3_256, 32>::client_deregister_init(
            target, target, &c_sk,
        )
        .unwrap();

        driver.recv(Some(ServerDeregisterInput::Request(request)));

        assert!(matches!(
            driver.poll_transmit(),
            Some(ServerDeregisterOutput::GetPublicKey { .. })
        ));

        // Pass a mismatched UUID
        let mismatched = Uuid::new_v4();

        driver.recv(Some(ServerDeregisterInput::KeyFetchResponse {
            claimant: mismatched,
            key: c_pk,
            is_admin: true,
            has_permissions: true,
        }));

        match driver.poll_result() {
            Poll::Ready(Err(ServerProtocolError::MalformedPkFetch)) => {}
            _ => panic!("Expected MalformedPkFetch"),
        }
    }

    #[test]
    fn test_deregister_key_fetch_failure() {
        let setup = BasicSetupDetails::<FauxChain>::new();

        let mut driver = ServerDeregisterDriver::<FauxChain, FauxKem, Sha3_256, 32>::new(
            setup.server_sk.clone(),
        );

        let target = Uuid::new_v4();
        let (_c_pk, c_sk) = FauxChain::generate().unwrap();

        let request = ProtocolKit::<FauxChain, FauxKem, Sha3_256, 32>::client_deregister_init(
            target, target, &c_sk,
        )
        .unwrap();

        driver.recv(Some(ServerDeregisterInput::Request(request)));

        assert!(driver.poll_transmit().is_some());

        driver.recv(Some(ServerDeregisterInput::PublicKeyFetchFailure(
            "net".into(),
        )));

        match driver.poll_result() {
            Poll::Ready(Err(ServerProtocolError::MalformedPkFetch)) => {}
            _ => panic!("Expected MalformedPkFetch"),
        }
    }

    #[test]
    fn test_deregister_unauthorized() {
        let setup = BasicSetupDetails::<FauxChain>::new();

        let mut driver = ServerDeregisterDriver::<FauxChain, FauxKem, Sha3_256, 32>::new(
            setup.server_sk.clone(),
        );

        let target = Uuid::new_v4();
        let (c_pk, c_sk) = FauxChain::generate().unwrap();

        let request = ProtocolKit::<FauxChain, FauxKem, Sha3_256, 32>::client_deregister_init(
            target, target, &c_sk,
        )
        .unwrap();

        driver.recv(Some(ServerDeregisterInput::Request(request)));

        driver.poll_transmit();

        driver.recv(Some(ServerDeregisterInput::KeyFetchResponse {
            claimant: target,
            key: c_pk,
            is_admin: false,
            has_permissions: false,
        }));

        match driver.poll_result() {
            Poll::Ready(Err(ServerProtocolError::UnauthorizedDeregisterRequest)) => {}
            _ => panic!("Expected UnauthorizedDeregisterRequest"),
        }
    }

    #[test]
    fn test_deregister_not_changed_error() {
        let setup = BasicSetupDetails::<FauxChain>::new();

        let mut driver = ServerDeregisterDriver::<FauxChain, FauxKem, Sha3_256, 32>::new(
            setup.server_sk.clone(),
        );

        let target = Uuid::new_v4();
        let (c_pk, c_sk) = FauxChain::generate().unwrap();

        let request = ProtocolKit::<FauxChain, FauxKem, Sha3_256, 32>::client_deregister_init(
            target, target, &c_sk,
        )
        .unwrap();

        driver.recv(Some(ServerDeregisterInput::Request(request)));

        driver.poll_transmit();

        driver.recv(Some(ServerDeregisterInput::KeyFetchResponse {
            claimant: target,
            key: c_pk,
            is_admin: true,
            has_permissions: true,
        }));

        driver.poll_transmit();

        driver.recv(Some(ServerDeregisterInput::DeregisterNotChanged));

        match driver.poll_result() {
            Poll::Ready(Err(ServerProtocolError::DeregstrationUnchanged)) => {}
            _ => panic!("Expected DeregstrationUnchanged"),
        }
    }

    #[test]
    fn test_deregister_server_error() {
        let setup = BasicSetupDetails::<FauxChain>::new();

        let mut driver = ServerDeregisterDriver::<FauxChain, FauxKem, Sha3_256, 32>::new(
            setup.server_sk.clone(),
        );

        let target = Uuid::new_v4();
        let (c_pk, c_sk) = FauxChain::generate().unwrap();

        let request = ProtocolKit::<FauxChain, FauxKem, Sha3_256, 32>::client_deregister_init(
            target, target, &c_sk,
        )
        .unwrap();

        driver.recv(Some(ServerDeregisterInput::Request(request)));

        driver.poll_transmit();

        driver.recv(Some(ServerDeregisterInput::KeyFetchResponse {
            claimant: target,
            key: c_pk,
            is_admin: true,
            has_permissions: true,
        }));

        driver.poll_transmit();

        driver.recv(Some(ServerDeregisterInput::DeregisteredError(
            "db unavailable".into(),
        )));

        match driver.poll_result() {
            Poll::Ready(Err(ServerProtocolError::DeregistrationError(e))) => {
                assert_eq!(e, "db unavailable");
            }
            _ => panic!("Expected DeregistrationError"),
        }
    }
}
