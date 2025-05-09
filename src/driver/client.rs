use std::{marker::PhantomData, task::Poll};

use ringbuffer::{ConstGenericRingBuffer, RingBuffer};
use uuid::Uuid;

use crate::core::crypto::{
    ClientProtocolError, ClientToken, CycleInit, DsaSystem, HashingAlgorithm, KEMAlgorithm,
    MsSinceEpoch, PrivateKey, ServerCycle, ServerToken,
    protocol::ProtocolKit,
    token::{Final, Pending, Token},
};

/// Represents the protocol execution from the client end.
///
/// It is driven with three methods:
///
/// - [ClientDriver::recv] which receives [ClientInput] and updates the state based
/// on that.
/// - [ClientDriver::poll_transmit] which gets all the messages that must be properly handled.
/// - [ClientDriver::poll_token] which gets the token (if it is ready).
///
/// NOTE: If you are looking for a simple way to interact with the protocol, chances are
/// this is not what you are looking for. This is the raw protocol driver, and is a stateful
/// wrapper built on [ProtocolKit].
pub struct ClientDriver<S, K, H, const HS: usize>
where
    S: DsaSystem,
    K: KEMAlgorithm,
{
    inner: ClientDriverInner<S, K, H, HS>,
    state: DriverState<S, K>,
}

struct ClientDriverInner<S, K, H, const HS: usize>
where
    S: DsaSystem,
    K: KEMAlgorithm,
{
    id: Uuid,
    private: S::Private,

    spec: ProtocolSpec,
    server_public: S::Public,
    transformer: fn(&mut Token<Pending>),
    output_buffer: ConstGenericRingBuffer<ClientOutput<S, K>, 3>,
    container: Option<InternalTokenContainer>,
    _k: PhantomData<K>,
    _h: PhantomData<H>,
    _hs: PhantomData<[u8; HS]>,
}

enum DriverState<S, K>
where
    S: DsaSystem,
    K: KEMAlgorithm,
{
    Init,
    AcquiringToken {
        token: Token<Pending>,
        dk: K::DecapsulationKey,
    },
    InitCycle,
    WaitingOnCycle {
        pending_private: S::Private,
        pending_public: S::Public,
    },
    Ready,
}

pub enum ClientInput<S, K, const HS: usize>
where
    S: DsaSystem,
    K: KEMAlgorithm,
{
    ServerPublicChange(S::Public),
    TokenResponseSuccess(ServerToken<HS, K, S::Signature>),
    TokenResponseFailure,

    CycleResponseSuccess(ServerCycle<HS, S::Signature>),
    CycleResponseFailure,
    NeedsCycle,
}

pub enum ClientOutput<S, K>
where
    S: DsaSystem,
    K: KEMAlgorithm,
{
    TokenRequest(ClientToken<S::Signature, K>),
    StoreNewCycleKey((S::Public, S::Private)),
    CycleRequest(CycleInit<S::Public, S::Signature>),
}

pub struct ProtocolSpec {
    pub protocol: u8,
    pub sub_protocol: u8,
}

struct InternalTokenContainer {
    token: Token<Final>,
    expiry: MsSinceEpoch,
}

impl ProtocolSpec {
    pub fn new(proto: u8, sub_proto: u8) -> Self {
        Self {
            protocol: proto,
            sub_protocol: sub_proto,
        }
    }
}

impl<S, K, H, const HS: usize> ClientDriver<S, K, H, HS>
where
    S: DsaSystem,
    K: KEMAlgorithm,
    H: HashingAlgorithm<HS>,
{
    /// Creates a new [ClientDriver] with the ID and the
    /// private key. These are assumed to be registered.
    pub fn new(
        id: Uuid,
        private: S::Private,
        spec: ProtocolSpec,
        server_public: S::Public,
    ) -> Self {
        Self::new_with_token_transform(id, private, spec, server_public, |_| {})
    }
    /// Creates a new [ClientDriver] with the ID and the
    /// private key. These are assumed to be registered.
    pub fn new_with_token_transform(
        id: Uuid,
        private: S::Private,
        spec: ProtocolSpec,
        server_public: S::Public,
        transform: fn(&mut Token<Pending>),
    ) -> Self {
        Self {
            inner: ClientDriverInner {
                id,
                private,
                container: None,
                spec,
                server_public,
                transformer: transform,
                output_buffer: ConstGenericRingBuffer::default(),
                _h: PhantomData,
                _hs: PhantomData,
                _k: PhantomData,
            },
            state: DriverState::Init,
        }
    }
    /// This accepts messages from the outside and will drive forward
    /// the state machine.
    ///
    /// The client will immediately try to acquire a token.
    pub fn recv(
        &mut self,
        time: MsSinceEpoch,
        packet: Option<ClientInput<S, K, HS>>,
    ) -> Result<(), ClientProtocolError> {
        if let Some(ClientInput::ServerPublicChange(inner)) = packet {
            self.inner.server_public = inner;
            return Ok(());
        }

        let state = match &self.state {
            DriverState::Init => handle_client_init_state(&mut self.inner, time, &packet)?,
            DriverState::AcquiringToken { token, dk } => {
                handle_acquiring_token_state(&mut self.inner, &packet, token, dk)?
            }
            // The ready state does not make any effort to parse the packet,
            // we are simply zen.
            DriverState::Ready => None,
            DriverState::InitCycle => handle_client_cycle_init(&mut self.inner)?,
            DriverState::WaitingOnCycle {
                pending_private,
                pending_public,
            } => handle_client_cycle_pending(
                &mut self.inner,
                &packet,
                &pending_private,
                &pending_public,
            )?,
        };

        if let Some(inner) = state {
            // If we output a new state, install said state.
            self.state = inner;
        }

        Ok(())
    }
    /// This should be polled until it is empty.
    pub fn poll_transmit(&mut self) -> Option<ClientOutput<S, K>> {
        self.inner.output_buffer.dequeue()
    }

    /// Polls the token. This should follow the poll transmit call. If the token
    /// is ready then [Poll::Ready] will be returned, else if we are in process,
    /// a [Poll::Pending] will be returned.
    pub fn poll_token(&mut self, time: MsSinceEpoch) -> Poll<&Token<Final>> {
        // Check if we actually even have a token.
        let Some(cont_inner) = &self.inner.container else {
            return Poll::Pending;
        };

        let token = &cont_inner.token;

        // Verify the token is still valid.
        if time > cont_inner.expiry {
            self.state = DriverState::Init;
            return Poll::Pending;
        }

        Poll::Ready(token)
    }
}

fn handle_client_init_state<S, K, H, const HS: usize>(
    driver: &mut ClientDriverInner<S, K, H, HS>,
    current_time: MsSinceEpoch,
    packet: &Option<ClientInput<S, K, HS>>
) -> Result<Option<DriverState<S, K>>, ClientProtocolError>
where
    S: DsaSystem,
    K: KEMAlgorithm,
    H: HashingAlgorithm<HS>,
{

    // If we need a cycle, we should do it. This is sort of a weird edge case
    // but it allows us to approach the state machine in a more natural way.
    if let Some(ClientInput::NeedsCycle) = packet {
        return Ok(Some(DriverState::InitCycle));
    }

    // Get the token response.
    let (request, dk) = ProtocolKit::<S, K, H, HS>::client_token_init(
        driver.spec.protocol,
        driver.spec.sub_protocol,
        current_time,
        &driver.private,
        driver.id,
        |t| (driver.transformer)(t),
    )?;

    // Get the active token to store it.
    let actual_token = (*request.body.token).clone();

    // Push the request onto the output buffer.
    driver
        .output_buffer
        .enqueue(ClientOutput::TokenRequest(request));

    // Switch to acquiring token.
    Ok(Some(DriverState::AcquiringToken {
        token: actual_token,
        dk,
    }))
}

fn handle_acquiring_token_state<S, K, H, const HS: usize>(
    driver: &mut ClientDriverInner<S, K, H, HS>,
    packet: &Option<ClientInput<S, K, HS>>,
    token: &Token<Pending>,
    dk: &K::DecapsulationKey,
) -> Result<Option<DriverState<S, K>>, ClientProtocolError>
where
    S: DsaSystem,
    K: KEMAlgorithm,
    H: HashingAlgorithm<HS>,
{
    let Some(packet) = packet else {
        // We need input here to advance.
        return Ok(None);
    };

    match packet {
        ClientInput::TokenResponseFailure => {
            // Return to the initialization state.
            return Ok(Some(DriverState::Init));
        }
        ClientInput::TokenResponseSuccess(response) => {
            let dd = ProtocolKit::<S, K, H, HS>::client_token_finish(
                &response,
                &token,
                &dk,
                &driver.server_public,
            )?;
            let expiry = response.body.expiry;

            driver.container = Some(InternalTokenContainer { token: dd, expiry });

            // We are now in the ready staate.
            return Ok(Some(DriverState::Ready));
        }
        ClientInput::NeedsCycle => {
            // Initiate a cycle.
            return Ok(Some(DriverState::InitCycle));
        }
        _ => { /* Unexpected! */ }
    }

    // Switch to acquiring token.
    Ok(None)
}

fn handle_client_cycle_init<S, K, H, const HS: usize>(
    driver: &mut ClientDriverInner<S, K, H, HS>,
) -> Result<Option<DriverState<S, K>>, ClientProtocolError>
where
    S: DsaSystem,
    K: KEMAlgorithm,
    H: HashingAlgorithm<HS>,
{
    // perform the cycle request.
    let (cycle_req, new_priv) =
        ProtocolKit::<S, K, H, HS>::client_cycle_init(driver.id, &driver.private)?;

    let extracted_public = (*cycle_req.body.new_public_key).clone();

    // Store the new cycle key, this is for returning to a consistent state.
    driver.output_buffer.push(ClientOutput::StoreNewCycleKey((
        extracted_public.clone(),
        new_priv.clone(),
    )));

    // Send the cycle request over the wire
    driver
        .output_buffer
        .push(ClientOutput::CycleRequest(cycle_req));

    // Send us into a waiting on cycle state.
    Ok(Some(DriverState::WaitingOnCycle {
        pending_public: extracted_public,
        pending_private: new_priv,
    }))
}

fn handle_client_cycle_pending<S, K, H, const HS: usize>(
    driver: &mut ClientDriverInner<S, K, H, HS>,
    packet: &Option<ClientInput<S, K, HS>>,
    pending_private: &S::Private,
    pending_public: &S::Public,
) -> Result<Option<DriverState<S, K>>, ClientProtocolError>
where
    S: DsaSystem,
    K: KEMAlgorithm,
    H: HashingAlgorithm<HS>,
{
    let Some(packet) = packet else {
        // We ned input to proceed.
        return Ok(None);
    };

    match packet {
        ClientInput::CycleResponseSuccess(success) => {
            ProtocolKit::<S, K, H, HS>::client_cycle_finish(
                success,
                driver.id,
                &pending_public,
                &driver.server_public,
            )?;
            driver.private = pending_private.clone();
            return Ok(Some(DriverState::Init));
        }
        ClientInput::CycleResponseFailure => {
            // send us back to origin.
            return Ok(Some(DriverState::Init));
        }
        _ => { /* no action :) */ }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use std::{task::Poll, time::Duration};

    use ringbuffer::RingBuffer;
    use sha3::Sha3_256;
    use uuid::Uuid;

    use crate::{
        algos::{fips203::MlKem512, fips204::MlDsa44},
        core::crypto::{
            DsaSystem, MsSinceEpoch, TokenValidityInterval,
            protocol::ProtocolKit,
            token::{Pending, Token},
        },
    };

    use super::{ClientDriver, ClientInput, ClientOutput, ProtocolSpec};

    #[test]
    pub fn test_driver_token_fetch_normal_operation() {
        let (client_pk, client_sk) = MlDsa44::generate().unwrap();
        let (server_pk, server_sk) = MlDsa44::generate().unwrap();

        let mut driver = ClientDriver::<MlDsa44, MlKem512, Sha3_256, 32>::new(
            Uuid::new_v4(),
            client_sk.clone(),
            ProtocolSpec::new(1, 0),
            server_pk.clone(),
        );

        // Client begins the token request process
        driver.recv(MsSinceEpoch(0), None).unwrap();

        // Pull the outbound request from the buffer
        let ClientOutput::TokenRequest(client_request) = driver.poll_transmit().unwrap() else {
            panic!("Expected token request");
        };

        // Server processes the request and creates a response
        let (response, server_tok) = ProtocolKit::<MlDsa44, MlKem512, Sha3_256, 32>::server_token(
            &client_request,
            &client_pk,
            &server_sk,
            &TokenValidityInterval::new(Duration::from_secs(30), Duration::from_secs(30)),
            MsSinceEpoch(0),
            Duration::from_secs(3),
        )
        .unwrap();

        // Feed the response back into the client
        driver
            .recv(
                MsSinceEpoch(0),
                Some(ClientInput::TokenResponseSuccess(response)),
            )
            .unwrap();

        // Poll for the token (should now be ready)
        match driver.poll_token(MsSinceEpoch(500)) {
            Poll::Ready(t) => {
                assert_eq!(*t, server_tok);
            }
            Poll::Pending => panic!("Token should be ready"),
        }
    }

    #[test]
    pub fn test_driver_token_cycle_flow() {
        use crate::{
            algos::{fips203::MlKem512, fips204::MlDsa44},
            core::crypto::{
                DsaSystem, MsSinceEpoch, TokenValidityInterval,
                protocol::ProtocolKit,
                token::{Pending, Token},
            },
        };
        use sha3::Sha3_256;
        use std::time::Duration;
        use uuid::Uuid;

        use super::{ClientDriver, ClientInput, ClientOutput, ProtocolSpec};
        use std::task::Poll;

        let (client_pk, client_sk) = MlDsa44::generate().unwrap();
        let (server_pk, server_sk) = MlDsa44::generate().unwrap();

        let mut driver = ClientDriver::<MlDsa44, MlKem512, Sha3_256, 32>::new(
            Uuid::new_v4(),
            client_sk.clone(),
            ProtocolSpec::new(1, 0),
            server_pk.clone(),
        );

        // Step 1: Start token request
        driver.recv(MsSinceEpoch(0), None).unwrap();

        // Step 2: Extract token request
        let ClientOutput::TokenRequest(client_request) = driver.poll_transmit().unwrap() else {
            panic!("Expected token request");
        };

        let (response, _server_tok) = ProtocolKit::<MlDsa44, MlKem512, Sha3_256, 32>::server_token(
            &client_request,
            &client_pk,
            &server_sk,
            &TokenValidityInterval::new(Duration::from_secs(30), Duration::from_secs(30)),
            MsSinceEpoch(0),
            Duration::from_secs(3),
        )
        .unwrap();

        // Step 3: Inject `NeedsCycle` from server before responding to token
        driver
            .recv(MsSinceEpoch(0), Some(ClientInput::NeedsCycle))
            .unwrap();

        assert!(driver.poll_transmit().is_none());

        driver.recv(MsSinceEpoch(0), None).unwrap();

        // Step 4: Client should emit cycle key storage and cycle request
        let store_key = driver.poll_transmit().unwrap();
        let ClientOutput::StoreNewCycleKey((new_pub, new_priv)) = store_key else {
            panic!("Expected new cycle key storage");
        };

        let ClientOutput::CycleRequest(cycle_request) = driver.poll_transmit().unwrap() else {
            panic!("Expected cycle request");
        };

        // Step 5: Simulate server response to cycle request
        let cycle_response = ProtocolKit::<MlDsa44, MlKem512, Sha3_256, 32>::server_cycle(
            &cycle_request,
            &client_pk,
            &server_sk,
        )
        .unwrap();

        // Step 6: Client receives cycle response
        driver
            .recv(
                MsSinceEpoch(0),
                Some(ClientInput::CycleResponseSuccess(cycle_response)),
            )
            .unwrap();

        // Step 7: Client should now re-enter Init state and request a new token
        driver.recv(MsSinceEpoch(1), None).unwrap();

        let ClientOutput::TokenRequest(_) = driver.poll_transmit().unwrap() else {
            panic!("Expected token request after cycle");
        };
    }

    #[test]
    pub fn test_driver_token_cycle_failure() {
        use crate::{
            algos::{fips203::MlKem512, fips204::MlDsa44},
            core::crypto::{
                DsaSystem, MsSinceEpoch, TokenValidityInterval,
                protocol::ProtocolKit,
                token::{Pending, Token},
            },
        };
        use sha3::Sha3_256;
        use std::time::Duration;
        use uuid::Uuid;

        use super::{ClientDriver, ClientInput, ClientOutput, ProtocolSpec};
        use std::task::Poll;

        let (client_pk, client_sk) = MlDsa44::generate().unwrap();
        let (server_pk, _server_sk) = MlDsa44::generate().unwrap();

        let mut driver = ClientDriver::<MlDsa44, MlKem512, Sha3_256, 32>::new(
            Uuid::new_v4(),
            client_sk.clone(),
            ProtocolSpec::new(1, 0),
            server_pk.clone(),
        );

        // Step 1: Start token request
        driver.recv(MsSinceEpoch(0), None).unwrap();

        // Step 2: Extract token request
        let ClientOutput::TokenRequest(_client_request) = driver.poll_transmit().unwrap() else {
            panic!("Expected token request");
        };

        // Step 3: Inject `NeedsCycle` from server before completing token flow
        driver
            .recv(MsSinceEpoch(0), Some(ClientInput::NeedsCycle))
            .unwrap();

        driver.recv(MsSinceEpoch(0), None).unwrap();

        // Step 4: Expect the client to emit key storage and a cycle request
        let store_key = driver.poll_transmit().unwrap();
        let ClientOutput::StoreNewCycleKey((_new_pub, _new_priv)) = store_key else {
            panic!("Expected new cycle key storage");
        };

        let cycle_req = driver.poll_transmit().unwrap();
        let ClientOutput::CycleRequest(_cycle_request) = cycle_req else {
            panic!("Expected cycle request");
        };

        // Step 5: Server returns a failure to the cycle request
        driver
            .recv(MsSinceEpoch(0), Some(ClientInput::CycleResponseFailure))
            .unwrap();

        // Step 6: Client should now return to Init and start a new token request again
        driver.recv(MsSinceEpoch(1), None).unwrap();

        let ClientOutput::TokenRequest(_) = driver.poll_transmit().unwrap() else {
            panic!("Expected new token request after cycle failure");
        };
    }

    #[test]
    fn test_token_response_failure_resets_to_init() {
        let (_, client_sk) = MlDsa44::generate().unwrap();
        let (server_pk, _) = MlDsa44::generate().unwrap();

        let mut driver = ClientDriver::<MlDsa44, MlKem512, Sha3_256, 32>::new(
            Uuid::new_v4(),
            client_sk,
            ProtocolSpec::new(1, 0),
            server_pk,
        );

        // Begin the token request process
        driver.recv(MsSinceEpoch(0), None).unwrap();

        // Should now be in AcquiringToken; simulate failure
        driver
            .recv(MsSinceEpoch(0), Some(ClientInput::TokenResponseFailure))
            .unwrap();

        // Re-entering recv with None should trigger another TokenRequest
        driver.recv(MsSinceEpoch(0), None).unwrap();
        let output = driver.poll_transmit();
        assert!(matches!(output, Some(ClientOutput::TokenRequest(_))));
    }

    #[test]
    fn test_cycle_failure_resets_to_init() {
        let (_, client_sk) = MlDsa44::generate().unwrap();
        let (server_pk, _) = MlDsa44::generate().unwrap();

        let mut driver = ClientDriver::<MlDsa44, MlKem512, Sha3_256, 32>::new(
            Uuid::new_v4(),
            client_sk,
            ProtocolSpec::new(1, 0),
            server_pk,
        );

        // Simulate NeedsCycle input
        driver
            .recv(MsSinceEpoch(0), Some(ClientInput::NeedsCycle))
            .unwrap();

        driver.recv(MsSinceEpoch(0), None).unwrap();

        println!("BUFfER SIZE: {:?}", driver.inner.output_buffer.len());

        // Extract and discard the CycleRequest
        let key_store = driver.poll_transmit();

        let cycle_req = driver.poll_transmit();
        
        assert!(matches!(cycle_req.unwrap(), ClientOutput::CycleRequest(_)));
        assert!(matches!(key_store.unwrap(), ClientOutput::StoreNewCycleKey(_)));

        // Simulate cycle failure
        driver
            .recv(MsSinceEpoch(0), Some(ClientInput::CycleResponseFailure))
            .unwrap();

        // Next call to recv should reinitiate token request
        driver.recv(MsSinceEpoch(0), None).unwrap();
        let output = driver.poll_transmit();
        assert!(matches!(output, Some(ClientOutput::TokenRequest(_))));
    }

    #[test]
    fn test_server_public_key_change_updates_key() {
        let (_, client_sk) = MlDsa44::generate().unwrap();
        let (original_pk, _) = MlDsa44::generate().unwrap();
        let (new_pk, _) = MlDsa44::generate().unwrap();

        let mut driver = ClientDriver::<MlDsa44, MlKem512, Sha3_256, 32>::new(
            Uuid::new_v4(),
            client_sk,
            ProtocolSpec::new(1, 0),
            original_pk.clone(),
        );

        // Replace server public key mid-flight
        driver
            .recv(
                MsSinceEpoch(0),
                Some(ClientInput::ServerPublicChange(new_pk.clone())),
            )
            .unwrap();

        // Confirm key was updated
        assert_eq!(
            format!("{:?}", driver.inner.server_public),
            format!("{:?}", new_pk)
        );
    }
    #[test]
    fn test_recv_none_does_nothing_in_acquiring_token() {
        let (client_pk, client_sk) = MlDsa44::generate().unwrap();
        let (server_pk, server_sk) = MlDsa44::generate().unwrap();

        let mut driver = ClientDriver::<MlDsa44, MlKem512, Sha3_256, 32>::new(
            Uuid::new_v4(),
            client_sk.clone(),
            ProtocolSpec::new(1, 0),
            server_pk.clone(),
        );

        // Begin token request
        driver.recv(MsSinceEpoch(0), None).unwrap();
        let ClientOutput::TokenRequest(client_request) = driver.poll_transmit().unwrap() else {
            panic!("Expected TokenRequest");
        };

        // At this point, we're in AcquiringToken
        // Feeding `None` should do nothing (stay pending)
        driver.recv(MsSinceEpoch(0), None).unwrap();

        // Feed real token response now
        let (response, expected_token) =
            ProtocolKit::<MlDsa44, MlKem512, Sha3_256, 32>::server_token(
                &client_request,
                &client_pk,
                &server_sk,
                &TokenValidityInterval::new(Duration::from_secs(30), Duration::from_secs(30)),
                MsSinceEpoch(0),
                Duration::from_secs(3),
            )
            .unwrap();

        driver
            .recv(
                MsSinceEpoch(0),
                Some(ClientInput::TokenResponseSuccess(response)),
            )
            .unwrap();

        match driver.poll_token(MsSinceEpoch(100)) {
            Poll::Ready(token) => assert_eq!(*token, expected_token),
            Poll::Pending => panic!("Expected token to be ready"),
        }
    }
}
