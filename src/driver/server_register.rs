use std::{marker::PhantomData, task::Poll};

use ringbuffer::{GrowableAllocRingBuffer, RingBuffer};
use uuid::Uuid;

use crate::{core::crypto::{
    protocol::ProtocolKit, ClientRegisterInit, DsaSystem, HashingAlgorithm, KemAlgorithm, MsSinceEpoch, ServerProtocolError, ServerRegister
}, StorageStatus, StoreRegistryQuery, VerifyRequestIntegrityQuery};

use super::ServerPollResult;

/// The driver for the server registry protocol. This works significantly
/// different than the client protocols. In this, the final result that we are
/// polling is the final response to be sent back to the client. As such, errors
/// are deferred to the end of the state machine.
///
///
/// # Example
/// ```
/// use quath::ServerRegistryDriver;
/// use quath::core::crypto::specials::{FauxChain, FauxKem};
/// use sha3::Sha3_256;
/// use quath::DsaSystem;
/// use quath::MsSinceEpoch;
/// 
///
///
/// pub type SvrDriver = ServerRegistryDriver<FauxChain, FauxKem, Sha3_256, 32>;
///
/// let (server_pk, server_sk) = FauxChain::generate().unwrap();
/// let mut driver = SvrDriver::new(server_sk);
///
/// driver.recv(MsSinceEpoch(0), None);
///
/// while let Some(out) = driver.poll_transmit() {
///     /* handle the output */
/// }
///
/// let result = driver.poll_result();
///
/// ```
pub struct ServerRegistryDriver<S, K, H, const N: usize>
where
    S: DsaSystem,
    K: KemAlgorithm,
{
    inner: ServerRegistryDriverInner<S, K, H, N>,
    state: DriverState<S, N>,
}

enum DriverState<S, const N: usize>
where
    S: DsaSystem,
{
    /// Waiting for a request.
    Init,
    /// Waiting for validation,
    PerformRegistryVerification {
        request: ClientRegisterInit<S::Public, S::Signature>,
    },
    /// Waiting for store
    WaitingForStore(Option<ServerRegister<S::Signature, N>>),

    Errored(Option<ServerProtocolError>),
    Finished(Option<ServerRegister<S::Signature, N>>),
    Vacant, // Bruh(PhantomData<S>)
}

pub enum ServerRegistryInput<S>
where
    S: DsaSystem,
{
    ClientRequest(ClientRegisterInit<S::Public, S::Signature>),
    VerificationResponse(VerifyRequestIntegrityResponse<S>),
    StoreResponse(StorageStatus)
}

pub enum ServerRegistryOutput<S, const N: usize>
where
    S: DsaSystem,
{
    /// The ID needs to be checked for uniqueness, alongsie
    /// the public key, and finally we need to fetch the corresponding
    /// administrator public key.
    VerifyRequestIntegrity(VerifyRequestIntegrityQuery<S>),
    StoreRegistry(StoreRegistryQuery<S>),
}

pub enum VerifyRequestIntegrityResponse<S>
where
    S: DsaSystem,
{
    Success { admin_public: S::Public },
    UuidNotUnique,
    NoAdminUuid,
    PublicKeyNotUnique,
    Other(String),
}

struct ServerRegistryDriverInner<S, K, H, const N: usize>
where
    S: DsaSystem,
    K: KemAlgorithm,
{
    server_sk: S::Private,
    buffer: GrowableAllocRingBuffer<ServerRegistryOutput<S, N>>,
    terminated: bool,
    _k: PhantomData<K>,
    _h: PhantomData<H>,
}

impl<S, K, H, const N: usize> ServerRegistryDriver<S, K, H, N>
where
    S: DsaSystem,
    K: KemAlgorithm,
    H: HashingAlgorithm<N>,
{
    pub fn new(server_sk: S::Private) -> Self {
        Self {
            inner: ServerRegistryDriverInner {
                server_sk,
                buffer: GrowableAllocRingBuffer::default(),
                terminated: false,
                _h: PhantomData,
                _k: PhantomData,
            },
            state: DriverState::Init,
        }
    }
    /// The state machine receives some message. This also is used to drive the
    /// state machine forward, even if there is no actual input present.
    pub fn recv(&mut self, current_time: MsSinceEpoch, packet: Option<ServerRegistryInput<S>>) {
        if self.inner.terminated {
            return; // if we are done do not rec.
        }

        match recv_internal(self, packet, current_time) {
            Ok(_) => { /* Nothing to do */ }
            Err(e) => {
                self.inner.terminated = true;
                self.state = DriverState::Errored(Some(e))
            }
        }
    }
    pub fn poll_transmit(&mut self) -> Option<ServerRegistryOutput<S, N>> {
        self.inner.buffer.dequeue()
    }
    pub fn poll_result(
        &mut self,
    ) -> ServerPollResult<ServerRegister<S::Signature, N>> {
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
    obj: &mut ServerRegistryDriver<S, K, H, N>,
    packet: Option<ServerRegistryInput<S>>,
    current_time: MsSinceEpoch
) -> Result<(), ServerProtocolError>
where
    S: DsaSystem,
    K: KemAlgorithm,
    H: HashingAlgorithm<N>,
{
    let state = match &mut obj.state {
        DriverState::Init => handle_registry_init(&mut obj.inner, packet)?,
        DriverState::PerformRegistryVerification { request } => {
            handle_server_regiser_wait_lookup(&mut obj.inner, packet, request, current_time)?
        }
        DriverState::Errored(_) => None,
        DriverState::Finished(_) => None,
        DriverState::Vacant => None,
        DriverState::WaitingForStore(inner) => {
            handle_server_finalize_registry(&mut obj.inner, packet, inner)?
        }
    };

    if let Some(inner) = state {
        // If we output a new state, use said state.
        obj.state = inner;
    }

    Ok(())
}

fn handle_registry_init<S, K, H, const HS: usize>(
    inner: &mut ServerRegistryDriverInner<S, K, H, HS>,
    packet: Option<ServerRegistryInput<S>>,
) -> Result<Option<DriverState<S, HS>>, ServerProtocolError>
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
        ServerRegistryInput::ClientRequest(client) => {
            // Queue an information request, this will usually be serviced by a database.
            inner
                .buffer
                .enqueue(ServerRegistryOutput::VerifyRequestIntegrity(VerifyRequestIntegrityQuery {
                    requested_id: client.body.identifier,
                    admin_id: client.body.admin_approval_id,
                    public_key: (*client.body.public_key).clone(),
                }));

            // Wait for the service to respond.
            return Ok(Some(DriverState::PerformRegistryVerification {
                request: client,
            }));
        }
        _ => {
            /* Nothig */
            return Ok(None);
        }
    }
}

fn handle_server_regiser_wait_lookup<S, K, H, const HS: usize>(
    inner: &mut ServerRegistryDriverInner<S, K, H, HS>,
    packet: Option<ServerRegistryInput<S>>,
    request: &ClientRegisterInit<S::Public, S::Signature>,
    current_time: MsSinceEpoch
) -> Result<Option<DriverState<S, HS>>, ServerProtocolError>
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
        ServerRegistryInput::VerificationResponse(response) => match response {
            VerifyRequestIntegrityResponse::NoAdminUuid => Err(ServerProtocolError::NoAdminFound)?,
            VerifyRequestIntegrityResponse::PublicKeyNotUnique => {
                Err(ServerProtocolError::PublicKeyNotUnique)?
            }
            VerifyRequestIntegrityResponse::UuidNotUnique => Err(ServerProtocolError::UuidTaken)?,
            VerifyRequestIntegrityResponse::Other(other) => Err(ServerProtocolError::Misc(other))?,
            VerifyRequestIntegrityResponse::Success { admin_public } => {
                let req = ProtocolKit::<S, K, H, HS>::server_register(
                    request,
                    &admin_public,
                    &inner.server_sk,
                )?;

                // inner.buffer.enqueue(ServerRegistryOutput::RegistryResponse(req));
                inner.buffer.enqueue(ServerRegistryOutput::StoreRegistry(StoreRegistryQuery { client_id: request.body.identifier, public_key: (*request.body.public_key).clone(), time: current_time }));
                return Ok(Some(DriverState::WaitingForStore(Some(req))));
            }
        },
        _ => Ok(None), // nothing
    }
}

fn handle_server_finalize_registry<S, K, H, const HS: usize>(
    inner: &mut ServerRegistryDriverInner<S, K, H, HS>,
    packet: Option<ServerRegistryInput<S>>,
    request: &mut Option<ServerRegister<S::Signature, HS>>,
) -> Result<Option<DriverState<S, HS>>, ServerProtocolError>
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
        ServerRegistryInput::StoreResponse(storage_res) => match storage_res {
            StorageStatus::Success => {
                inner.terminated = true;
                let response = request.take().unwrap();

                Ok(Some(DriverState::Finished(Some(response))))
            }
            StorageStatus::Failure(reason) => Err(ServerProtocolError::StoreFailure(reason))
        }
        _ => Ok(None), // nothing
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Deref;

    use super::*;
    use crate::{
        ViewBytes,
        core::crypto::{
            ServerRegister,
            protocol::ProtocolKit,
            specials::{FauxChain, FauxKem},
        },
        specials::{FauxPrivate, FauxPublic},
    };
    use sha3::Sha3_256;
    use uuid::Uuid;

    type Driver = ServerRegistryDriver<FauxChain, FauxKem, Sha3_256, 32>;

    struct SetupDetails {
        pub driver: Driver,
        pub client_id: Uuid,
        pub admin_id: Uuid,
        pub admin_pk: FauxPublic,
        pub admin_sk: FauxPrivate,
        pub server_pk: FauxPublic,
        pub server_sk: FauxPrivate,
    }

    fn setup_driver() -> SetupDetails {
        let (admin_pk, admin_sk) = FauxChain::generate().unwrap();
        let (server_pk, server_sk) = FauxChain::generate().unwrap();
        let client_id = Uuid::new_v4();
        let admin_id = Uuid::new_v4();

        let driver = Driver::new(server_sk.clone());

        SetupDetails {
            driver,
            client_id,
            admin_id,
            admin_sk,
            server_pk,
            admin_pk,
            server_sk,
        }
    }

    #[test]
    fn test_driver_happy_path() {
        let mut setup = setup_driver();

        let (request, client_sk) =
            ProtocolKit::<FauxChain, FauxKem, Sha3_256, 32>::client_register_init(
                setup.client_id,
                setup.admin_id,
                &setup.admin_sk,
            )
            .unwrap();

        let req_pub = request.body.public_key.clone();

        setup
            .driver
            .recv(MsSinceEpoch(0), Some(ServerRegistryInput::ClientRequest(request)));

        let output = setup
            .driver
            .poll_transmit()
            .expect("Expected VerifyRequestIntegrity");
        match output {
            ServerRegistryOutput::VerifyRequestIntegrity(VerifyRequestIntegrityQuery {
                requested_id,
                admin_id,
                public_key,
            }) => {
                assert_eq!(requested_id, setup.client_id);
                assert_eq!(admin_id, setup.admin_id);
                assert_eq!(public_key.view(), (*req_pub).clone().view());
            }
            _ => panic!("Unexpected output"),
        }

        setup
            .driver
            .recv(MsSinceEpoch(0), Some(ServerRegistryInput::VerificationResponse(
                VerifyRequestIntegrityResponse::Success {
                    admin_public: setup.admin_pk.clone(),
                },
            )));

        setup.driver.recv(MsSinceEpoch(0), Some(ServerRegistryInput::StoreResponse(StorageStatus::Success)));

        match setup.driver.poll_result() {
            Poll::Ready(Ok(server_reg)) => {
                ProtocolKit::<FauxChain, FauxKem, Sha3_256, 32>::client_register_finish(
                    &server_reg,
                    setup.client_id,
                    &setup.server_pk,
                )
                .unwrap();
            }
            _ => panic!("Expected successful registration"),
        }
    }

    #[test]
    fn test_duplicate_uuid_should_error() {
        let mut setup = setup_driver();

        let (request, _) = ProtocolKit::<FauxChain, FauxKem, Sha3_256, 32>::client_register_init(
            setup.client_id,
            setup.admin_id,
            &setup.admin_sk,
        )
        .unwrap();

        setup
            .driver
            .recv(MsSinceEpoch(0), Some(ServerRegistryInput::ClientRequest(request)));

        let _ = setup.driver.poll_transmit(); // Ignore actual contents

        setup
            .driver
            .recv(MsSinceEpoch(0), Some(ServerRegistryInput::VerificationResponse(
                VerifyRequestIntegrityResponse::UuidNotUnique,
            )));

        match setup.driver.poll_result() {
            Poll::Ready(Err(ServerProtocolError::UuidTaken)) => {}
            _ => panic!("Expected UuidTaken error"),
        }
    }

    #[test]
    fn test_duplicate_public_key_should_error() {
        let mut setup = setup_driver();

        let (request, _) = ProtocolKit::<FauxChain, FauxKem, Sha3_256, 32>::client_register_init(
            setup.client_id,
            setup.admin_id,
            &setup.admin_sk,
        )
        .unwrap();

        setup
            .driver
            .recv(MsSinceEpoch(0), Some(ServerRegistryInput::ClientRequest(request)));

        let _ = setup.driver.poll_transmit();

        setup
            .driver
            .recv(MsSinceEpoch(0), Some(ServerRegistryInput::VerificationResponse(
                VerifyRequestIntegrityResponse::PublicKeyNotUnique,
            )));

        match setup.driver.poll_result() {
            Poll::Ready(Err(ServerProtocolError::PublicKeyNotUnique)) => {}
            _ => panic!("Expected PublicKeyNotUnique error"),
        }
    }

    #[test]
    fn test_admin_uuid_not_found_should_error() {
        let mut setup = setup_driver();

        let (request, _) = ProtocolKit::<FauxChain, FauxKem, Sha3_256, 32>::client_register_init(
            setup.client_id,
            setup.admin_id,
            &setup.admin_sk,
        )
        .unwrap();

        setup
            .driver
            .recv(MsSinceEpoch(0), Some(ServerRegistryInput::ClientRequest(request)));

        let _ = setup.driver.poll_transmit();

        setup
            .driver
            .recv(MsSinceEpoch(0), Some(ServerRegistryInput::VerificationResponse(
                VerifyRequestIntegrityResponse::NoAdminUuid,
            )));

        match setup.driver.poll_result() {
            Poll::Ready(Err(ServerProtocolError::NoAdminFound)) => {}
            _ => panic!("Expected NoAdminFound error"),
        }
    }

    #[test]
    fn test_miscellaneous_error_should_propagate() {
        let mut setup = setup_driver();

        let (request, _) = ProtocolKit::<FauxChain, FauxKem, Sha3_256, 32>::client_register_init(
            setup.client_id,
            setup.admin_id,
            &setup.admin_sk,
        )
        .unwrap();

        setup
            .driver
            .recv(MsSinceEpoch(0), Some(ServerRegistryInput::ClientRequest(request)));

        let _ = setup.driver.poll_transmit();

        setup
            .driver
            .recv(MsSinceEpoch(0), Some(ServerRegistryInput::VerificationResponse(
                VerifyRequestIntegrityResponse::Other("failure".into()),
            )));

        match setup.driver.poll_result() {
            Poll::Ready(Err(ServerProtocolError::Misc(reason))) => {
                assert_eq!(reason, "failure");
            }
            _ => panic!("Expected miscellaneous error"),
        }
    }

    #[test]
    fn test_store_failure_should_error() {
        let mut setup = setup_driver();

        let (request, _) = ProtocolKit::<FauxChain, FauxKem, Sha3_256, 32>::client_register_init(
            setup.client_id,
            setup.admin_id,
            &setup.admin_sk,
        )
        .unwrap();

        setup
            .driver
            .recv(MsSinceEpoch(0), Some(ServerRegistryInput::ClientRequest(request)));
        let _ = setup.driver.poll_transmit();

        setup
            .driver
            .recv(MsSinceEpoch(0), Some(ServerRegistryInput::VerificationResponse(
                VerifyRequestIntegrityResponse::Success {
                    admin_public: setup.admin_pk.clone(),
                },
            )));

        setup.driver.recv(MsSinceEpoch(0), Some(ServerRegistryInput::StoreResponse(StorageStatus::Failure(
            "store failed".into(),
        ))));

        match setup.driver.poll_result() {
            Poll::Ready(Err(ServerProtocolError::StoreFailure(msg))) => {
                assert_eq!(msg, "store failed");
            }
            _ => panic!("Expected StoreFailure error"),
        }
    }

    #[test]
    fn test_input_after_termination_should_have_no_effect() {
        let mut setup = setup_driver();

        let (request, _) = ProtocolKit::<FauxChain, FauxKem, Sha3_256, 32>::client_register_init(
            setup.client_id,
            setup.admin_id,
            &setup.admin_sk,
        )
        .unwrap();

        setup
            .driver
            .recv(MsSinceEpoch(0), Some(ServerRegistryInput::ClientRequest(request)));
        let _ = setup.driver.poll_transmit();

        setup
            .driver
            .recv(MsSinceEpoch(0), Some(ServerRegistryInput::VerificationResponse(
                VerifyRequestIntegrityResponse::Success {
                    admin_public: setup.admin_pk.clone(),
                },
            )));

        setup.driver.recv(MsSinceEpoch(0), Some(ServerRegistryInput::StoreResponse(StorageStatus::Success)));
        let _ = setup.driver.poll_result();

        // This should not do anything:
        setup
            .driver
            .recv(MsSinceEpoch(0), Some(ServerRegistryInput::StoreResponse(StorageStatus::Failure("ignored".into()))));

        match setup.driver.poll_result() {
            Poll::Ready(_) => panic!("Should not emit anything after termination"),
            Poll::Pending => {}
        }
    }

    #[test]
    fn test_multiple_store_success_only_applies_first() {
        let mut setup = setup_driver();

        let (request, _) = ProtocolKit::<FauxChain, FauxKem, Sha3_256, 32>::client_register_init(
            setup.client_id,
            setup.admin_id,
            &setup.admin_sk,
        )
        .unwrap();
        setup
            .driver
            .recv(MsSinceEpoch(0), Some(ServerRegistryInput::ClientRequest(request)));

        setup.driver.poll_transmit();
        setup
            .driver
            .recv(MsSinceEpoch(0), Some(ServerRegistryInput::VerificationResponse(
                VerifyRequestIntegrityResponse::Success {
                    admin_public: setup.admin_pk.clone(),
                },
            )));

        setup.driver.recv(MsSinceEpoch(0), Some(ServerRegistryInput::StoreResponse(StorageStatus::Success)));

        assert!(matches!(setup.driver.poll_result(), Poll::Ready(Ok(_))));

        // Subsequent success does nothing
        setup.driver.recv(MsSinceEpoch(0), Some(ServerRegistryInput::StoreResponse(StorageStatus::Success)));
        assert!(matches!(setup.driver.poll_result(), Poll::Pending));
    }

    #[test]
    fn test_poll_transmit_returns_none_if_no_output() {
        let mut setup = setup_driver();
        assert!(setup.driver.poll_transmit().is_none());

        setup.driver.recv(MsSinceEpoch(0), None);
        assert!(setup.driver.poll_transmit().is_none());
    }

    #[test]
    fn test_out_of_order_store_success_is_ignored() {
        let mut setup = setup_driver();
        // Should be ignored because state isn't WaitingForStore
        setup.driver.recv(MsSinceEpoch(0), Some(ServerRegistryInput::StoreResponse(StorageStatus::Success)));
        assert!(setup.driver.poll_result().is_pending());
    }

    #[test]
    fn test_poll_result_multiple_calls_does_not_repeat() {
        let mut setup = setup_driver();

        let (request, _) = ProtocolKit::<FauxChain, FauxKem, Sha3_256, 32>::client_register_init(
            setup.client_id,
            setup.admin_id,
            &setup.admin_sk,
        )
        .unwrap();
        setup
            .driver
            .recv(MsSinceEpoch(0), Some(ServerRegistryInput::ClientRequest(request)));
        setup.driver.poll_transmit();

        setup
            .driver
            .recv(MsSinceEpoch(0), Some(ServerRegistryInput::VerificationResponse(
                VerifyRequestIntegrityResponse::Success {
                    admin_public: setup.admin_pk.clone(),
                },
            )));
        setup.driver.recv(MsSinceEpoch(0), Some(ServerRegistryInput::StoreResponse(StorageStatus::Success)));

        let result1 = setup.driver.poll_result();
        let result2 = setup.driver.poll_result();

        assert!(matches!(result1, Poll::Ready(Ok(_))));
        assert!(matches!(result2, Poll::Pending));
    }

    #[test]
    fn test_recv_none_in_each_state_does_not_panic() {
        let mut setup = setup_driver();

        // INIT
        setup.driver.recv(MsSinceEpoch(0), None);

        let (request, _) = ProtocolKit::<FauxChain, FauxKem, Sha3_256, 32>::client_register_init(
            setup.client_id,
            setup.admin_id,
            &setup.admin_sk,
        )
        .unwrap();
        setup
            .driver
            .recv(MsSinceEpoch(0), Some(ServerRegistryInput::ClientRequest(request)));
        setup.driver.poll_transmit();

        // PerformRegistryVerification
        setup.driver.recv(MsSinceEpoch(0), None);

        setup
            .driver
            .recv(MsSinceEpoch(0), Some(ServerRegistryInput::VerificationResponse(
                VerifyRequestIntegrityResponse::Success {
                    admin_public: setup.admin_pk.clone(),
                },
            )));

        // WaitingForStore
        setup.driver.recv(MsSinceEpoch(0), None);

        setup.driver.recv(MsSinceEpoch(0), Some(ServerRegistryInput::StoreResponse(StorageStatus::Success)));

        // Finished
        let _ = setup.driver.poll_result();

        // Vacant
        setup.driver.recv(MsSinceEpoch(0), None); // Should do nothing
    }

    #[test]
fn test_store_registry_output_after_successful_verification() {
    let mut setup = setup_driver();

    let (request, _) = ProtocolKit::<FauxChain, FauxKem, Sha3_256, 32>::client_register_init(setup.client_id, setup.admin_id, &setup.admin_sk).unwrap();


    let client_pk = request.body.public_key.deref().clone();

    // Send request
    setup.driver.recv(MsSinceEpoch(0), Some(ServerRegistryInput::ClientRequest(request)));

    // Clear the VerifyRequestIntegrity output
    let integrity_check = setup.driver.poll_transmit();
    match integrity_check {
        Some(ServerRegistryOutput::VerifyRequestIntegrity(VerifyRequestIntegrityQuery { requested_id, admin_id, .. })) => {
            assert_eq!(requested_id, setup.client_id);
            assert_eq!(admin_id, setup.admin_id);
        }
        _ => panic!("Expected VerifyRequestIntegrity output"),
    }

    // Send successful verification response
    setup.driver.recv(MsSinceEpoch(0), Some(ServerRegistryInput::VerificationResponse(
        VerifyRequestIntegrityResponse::Success {
            admin_public: setup.admin_pk.clone(),
        },
    )));

    // Check for StoreRegistry output
    let output = setup.driver.poll_transmit();
    match output {
        Some(ServerRegistryOutput::StoreRegistry(StoreRegistryQuery { client_id, public_key, time })) => {
            assert_eq!(client_id, setup.client_id);
            assert_eq!(public_key.view(), client_pk.view());
            // assert_eq!(time, setup.time);
        }
        _ => panic!("Expected StoreRegistry output"),
    }
}

}
