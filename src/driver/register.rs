use std::{marker::PhantomData, task::Poll};

use ringbuffer::{ConstGenericRingBuffer, RingBuffer};
use uuid::Uuid;

use crate::core::crypto::{
    protocol::ProtocolKit, ClientProtocolError, ClientRegisterInit, DsaSystem, HashingAlgorithm, KEMAlgorithm, ServerProtocolError, ServerRegister
};

/// Represents the protocol execution for registration in a SANS/IO manner.
/// 
/// It is driven with three methods:
///
/// - [RegistryDriver::recv] which receives [RegistryInput] and updates the state based
/// on that.
/// - [RegistryDriver::poll_transmit] which gets all the messages that must be properly handled.
/// - [RegistryDriver::poll_completion] which gets the token (if it is ready).
///
/// NOTE: If you are looking for a simple way to interact with the protocol, chances are
/// this is not what you are looking for. This is the raw protocol driver, and is a stateful
/// wrapper built on [ProtocolKit]. For information on how the protocol works, it is best to refer
/// to the [ProtocolKit] documentation.
/// 
/// # Example
/// ```
/// use quath::RegistryDriver;
/// use quath::algos::fips204::MlDsa44;
/// use quath::algos::fips203::MlKem512;
/// use sha3::Sha3_256;
/// use quath::core::crypto::DsaSystem;
/// use uuid::Uuid;
/// use quath::ProtocolSpec;
/// use quath::core::crypto::MsSinceEpoch;
/// use quath::core::crypto::specials::FauxChain;
/// use quath::core::crypto::specials::FauxKem;
/// 
/// 
/// 
/// let (client_pk, client_sk) = FauxChain::generate().unwrap();
/// let (server_pk, server_sk) = FauxChain::generate().unwrap();
/// let (admin_pk, admin_sk) = FauxChain::generate().unwrap();
/// 
/// let admin_id = Uuid::new_v4();
/// let client_id = Uuid::new_v4();
/// 
/// let mut driver = RegistryDriver::<FauxChain, FauxKem, Sha3_256, 32>::new(admin_id, admin_sk, client_id, server_pk);
/// 
/// // In a real example this would be driven differently.
/// for i in 0..1 {
///     /* Here you would pass in the inptus */
///     driver.recv(None).unwrap();
/// 
///     while let Some(transmit) = driver.poll_transmit() {
///         /* send out the packet */    
///     }
/// 
///     let details = driver.poll_completion();
/// }
/// ```
pub struct RegistryDriver<S, K, H, const HS: usize>
where
    S: DsaSystem,
    K: KEMAlgorithm,
{
    inner: RegistryDriverInner<S, K, H, HS>,
    state: DriverState<S>,
}

pub struct RegistryDetails<S>
where 
    S: DsaSystem
{
    pub admin_id: Uuid,
    pub admin_private: S::Private,
    pub client_id: Uuid,
    pub client_privte: S::Private
}

enum DriverState<S>
where
    S: DsaSystem,
{
    Init,
    Registering { pending_private: S::Private },
    Ready(Option<RegistryDetails<S>>),

    /// This state essentially means the state machine has elapsed, there
    /// is nothing more it can or will do.
    Vacated
}

pub enum RegistryInput<S, const N: usize>
where 
    S: DsaSystem
{
    UuidNotUnique,
    Response(ServerRegister<S::Signature, N>),
    RegistryFailure(ServerProtocolError)
}

pub enum RegistryOutput<S>
where
    S: DsaSystem,
{
    RegisterRequest(ClientRegisterInit<S::Public, S::Signature>),
}

struct RegistryDriverInner<S, K, H, const HS: usize>
where
    S: DsaSystem,
    K: KEMAlgorithm,
{
    admin_id: Uuid,
    admin_private: Option<S::Private>,
    client_id: Uuid,
    server_public:S::Public ,
    buffer: ConstGenericRingBuffer<RegistryOutput<S>, 2>,
    _k: PhantomData<K>,
    _h: PhantomData<H>,
}

impl<S, K, H, const HS: usize> RegistryDriver<S, K, H, HS>
where
    S: DsaSystem,
    K: KEMAlgorithm,
    H: HashingAlgorithm<HS>,
{
    /// Creates a new [RegistryDriver] with the ID and the private key.
    /// These are assumed to be registered.
    pub fn new(id: Uuid, private: S::Private, client_id: Uuid, server_public: S::Public) -> Self {
        Self {
            inner: RegistryDriverInner {
                admin_id: id,
                admin_private: Some(private),
                client_id: client_id,
                server_public,
                buffer: ConstGenericRingBuffer::default(),
                _k: PhantomData,
                _h: PhantomData,
            },
            state: DriverState::Init,
        }
    }

    /// Accepts messages from the outside and drives the state machine forward.
    ///
    /// If we receive a [RegistryInput::UuidNotUnique] packet then we will
    /// immediately regenerate the [Uuid] and restart.
    ///
    /// If there is an error, then we will return to the initialization state.
    pub fn recv(&mut self, packet: Option<RegistryInput<S, HS>>) -> Result<(), ClientProtocolError> {
        // If we are vacated we should not return more stuff.
        if let DriverState::Vacated = self.state { return Ok(()) };
        if let DriverState::Ready(_) = self.state { return Ok(() )};
        recv_internal(self, &packet).inspect_err(|_| self.state = DriverState::Init)
    }

    /// Gets the next messages that should be sent out on the wire. This should
    /// be repeatedly polled and handled until [Option::None] is returned.
    pub fn poll_transmit(&mut self) -> Option<RegistryOutput<S>> {
        self.inner.buffer.dequeue()
    }
    /// Checks if the machine is reayd.
    pub fn poll_completion(&mut self) -> Poll<RegistryDetails<S>> {
        match &mut self.state {
            DriverState::Ready(value) => {
                let inner = value.take();
                self.state = DriverState::Vacated;
                Poll::Ready(inner.unwrap())
            },
            _ => Poll::Pending
        }
    }
}

fn recv_internal<S, K, H, const HS: usize>(
    obj: &mut RegistryDriver<S, K, H, HS>,
    packet: &Option<RegistryInput<S, HS>>,
) -> Result<(), ClientProtocolError>
where
    S: DsaSystem,
    K: KEMAlgorithm,
    H: HashingAlgorithm<HS>,
{
    if let Some(RegistryInput::UuidNotUnique) = packet {
        obj.inner.client_id = Uuid::new_v4();
        obj.state = DriverState::Init;
        return Ok(());
    }

    let state = match &obj.state {
        DriverState::Init => handle_registry_init(&mut obj.inner)?,
        DriverState::Registering { pending_private } => handle_registry_pending(&mut obj.inner, &packet, &pending_private)?,
        DriverState::Ready(_) => { /* nothing */ None },
        DriverState::Vacated => { /* nothing */ None }
    };

    if let Some(inner) = state {
        // If we output a new state, use said state.
        obj.state = inner;
    }

    Ok(())
}

fn handle_registry_init<S, K, H, const HS: usize>(
    inner: &mut RegistryDriverInner<S, K, H, HS>,
) -> Result<Option<DriverState<S>>, ClientProtocolError>
where
    S: DsaSystem,
    K: KEMAlgorithm,
    H: HashingAlgorithm<HS>,
{
    let (request, new_private) = ProtocolKit::<S, K, H, HS>::client_register_init(
        inner.client_id,
        inner.admin_id,
        inner.admin_private.as_ref().unwrap(),
    )?;

    // Enqueue the new rquest.s
    inner.buffer.enqueue(RegistryOutput::RegisterRequest(request));

    Ok(Some(DriverState::Registering {
        pending_private: new_private,
    }))
}

fn handle_registry_pending<S, K, H, const HS: usize>(
    inner: &mut RegistryDriverInner<S, K, H, HS>,
    packet: &Option<RegistryInput<S, HS>>,
    pending_private: &S::Private
) -> Result<Option<DriverState<S>>, ClientProtocolError>
where
    S: DsaSystem,
    K: KEMAlgorithm,
    H: HashingAlgorithm<HS>,
{

    let Some(packet) = packet else {
        return Ok(None);
    };

    match packet {
        RegistryInput::Response(response) => {
            ProtocolKit::<S, K, H, HS>::client_register_finish(response, inner.client_id, &inner.server_public)?;

            return Ok(Some(DriverState::Ready(Some(RegistryDetails {
                admin_id: inner.admin_id,
                client_id: inner.client_id,
                admin_private: inner.admin_private.take().unwrap(),
                client_privte: pending_private.clone()
            }))));
        }
        RegistryInput::RegistryFailure(inner) => {

            return Err(ClientProtocolError::ServerError(inner.clone()))
            // return Ok(Some(DriverState::Init));
        }
        _ => { /* Nothing !! */ }
    }

    

    Ok(None)
}




#[cfg(test)]
mod tests {
    use std::task::Poll;

    use bincode::de;
    use fips204::ml_dsa_44::PrivateKey;
    use sha3::Sha3_256;
    use uuid::Uuid;

    use crate::{algos::{fips203::MlKem512, fips204::{MlDsa44, MlDsa44Public}}, core::crypto::{protocol::ProtocolKit, DsaSystem, ServerProtocolError}, driver::register::DriverState};

    use super::{RegistryDriver, RegistryInput, RegistryOutput};

    const HS: usize = 32;
    type Driver = RegistryDriver<MlDsa44, MlKem512, Sha3_256, HS>;

    struct SetupDetails {
        driver: Driver,
        client_pk: MlDsa44Public,
        client_sk: PrivateKey,
        admin_pk: MlDsa44Public,
        admin_sk: PrivateKey,
        server_pk: MlDsa44Public,
        server_sk: PrivateKey,
        client_id: Uuid,
        admin_id: Uuid,
    }

    fn setup_driver() -> SetupDetails {
        let (admin_pk, admin_sk) = MlDsa44::generate().unwrap();
        let (client_pk, client_sk) = MlDsa44::generate().unwrap();
        let (server_pk, server_sk) = MlDsa44::generate().unwrap();

        let admin_id = Uuid::new_v4();
        let client_id = Uuid::new_v4();

        let driver = Driver::new(admin_id, admin_sk.clone(), client_id, server_pk.clone());

        SetupDetails {
            driver,
            client_pk,
            client_sk,
            admin_pk,
            admin_sk,
            server_pk,
            server_sk,
            client_id,
            admin_id,
        }
    }

    #[test]
    fn test_register_fusing() {
        let mut setup = setup_driver();

        for _ in 0..5 {
            setup.driver.recv(None).unwrap();

            while let Some(_) = setup.driver.poll_transmit() {
                /* send out a packet */
            }
            let _ = setup.driver.poll_completion();

        }
    }

    #[test]
    fn test_register_success_path() {
        let mut setup = setup_driver();

        // Trigger the Init state
        setup.driver.recv(None).unwrap();

        // Grab the RegisterRequest output
        let req = match setup.driver.poll_transmit() {
            Some(RegistryOutput::RegisterRequest(msg)) => msg,
            _ => panic!("Expected RegisterRequest!!"),
        };

        // Simulate server processing and responding
        let response = ProtocolKit::<MlDsa44, MlKem512, Sha3_256, HS>::server_register(
            &req,
            &setup.admin_pk,
            &setup.server_sk,
        )
        .unwrap();

        setup
            .driver
            .recv(Some(RegistryInput::Response(response)))
            .unwrap();

        // Ensure it's ready
        match setup.driver.poll_completion() {
            Poll::Ready(details) => {
       
                assert_eq!(details.admin_id, setup.admin_id);
                assert_eq!(details.client_id, setup.client_id);
            }
            Poll::Pending => panic!("Driver should be ready"),
        }
    }

    #[test]
    fn test_uuid_not_unique_restarts_state() {
        let mut setup = setup_driver();

        // First call to init
        setup.driver.recv(None).unwrap();
        let old_client_id = setup.driver.inner.client_id;

        // Simulate UUID not unique response
        setup
            .driver
            .recv(Some(RegistryInput::UuidNotUnique))
            .unwrap();

        // Should have reset client_id
        let new_client_id = setup.driver.inner.client_id;
        assert_ne!(old_client_id, new_client_id);
    }

    #[test]
    fn test_registry_failure_resets_state() {
        let mut setup = setup_driver();

        // Begin registration
        setup.driver.recv(None).unwrap();

        // Submit failure
        let _ = setup
            .driver
            .recv(Some(RegistryInput::RegistryFailure(ServerProtocolError::EncapsulationFailed)));

        // Ensure we're back to Init state
        assert!(matches!(setup.driver.state, DriverState::Init));
    }

    #[test]
    fn test_poll_completion_returns_none_if_not_ready() {
        let mut setup = setup_driver();

        match setup.driver.poll_completion() {
            Poll::Ready(_) => panic!("Should not be ready"),
            Poll::Pending => {}
        }
    }
}