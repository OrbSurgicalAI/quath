use std::{marker::PhantomData, task::Poll};

use ringbuffer::{GrowableAllocRingBuffer, RingBuffer};
use uuid::Uuid;

use crate::{protocol::ProtocolKit, CycleInit, CycleVerifyQuery, DsaSystem, HashingAlgorithm, KemAlgorithm, MsSinceEpoch, ServerCycle, ServerProtocolError, StorageStatus, StoreRegistryQuery};

use super::ServerPollResult;


/// The driver for the server cycle protocol. This works signficantly different
/// than the client protocols. In this, the final result is acquired by polling the
/// [ServerCycleDriver::poll_result] method, which will return a result.
///
///
/// # Example
/// ```
/// use quath::ServerCycleDriver;
/// use quath::core::crypto::specials::{FauxChain, FauxKem};
/// use sha3::Sha3_256;
/// use quath::DsaSystem;
/// use quath::MsSinceEpoch;
/// 
///
///
/// pub type SvrDriver = ServerCycleDriver<FauxChain, FauxKem, Sha3_256, 32>;
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
pub struct ServerCycleDriver<S, K, H, const N: usize>
where
    S: DsaSystem,
    K: KemAlgorithm,
{
    inner: ServerCycleDriverInner<S, K, H, N>,
    state: DriverState<S, N>
}

pub struct ServerCycleDriverInner<S, K, H, const N: usize>
where 
    S: DsaSystem,
    K: KemAlgorithm
{
    server_sk: S::Private,
    buffer: GrowableAllocRingBuffer<ServerCycleOutput<S>>,
    terminated: bool,
    _h: PhantomData<H>,
    _k: PhantomData<K>

}

pub enum ServerCycleOutput<S>
where 
    S: DsaSystem
{

    VerificationRequest(CycleVerifyQuery<S>),
    StorageRequest(StoreRegistryQuery<S>)

}



pub enum ServerCycleInput<S>
where 
    S: DsaSystem,
{
    ReceiveRequest(CycleInit<S::Public, S::Signature>),
    VerificationResponse(CycleVerifyStatus<S>),
    StoreResponse(StorageStatus)
}

pub enum CycleVerifyStatus<S>
where 
    S: DsaSystem
{
    KeyNotUnique,
    Success {
        client_id: Uuid,
        original_public_key: S::Public,
        new_public_key: S::Public
    },
    Other(String)
}

enum DriverState<S, const N: usize> 
where 
    S: DsaSystem
{
    Init,
    WaitingForRequestVerification(CycleInit<S::Public, S::Signature>),
    Errored(Option<ServerProtocolError>),
    Finished(Option<ServerCycle<N, S::Signature>>),
    ServerStore(Option<ServerCycle<N, S::Signature>>),
    Vacant
}


impl<S, K, H, const N: usize> ServerCycleDriver<S, K, H, N>
where
    S: DsaSystem,
    K: KemAlgorithm,
    H: HashingAlgorithm<N>,
{
    pub fn new(server_sk: S::Private) -> Self {
        Self {
            inner: ServerCycleDriverInner {
                server_sk,
                buffer: GrowableAllocRingBuffer::default(),
                terminated: false,
                _h: PhantomData,
                _k: PhantomData
            },
            state: DriverState::Init
        }
    }
    pub fn recv(
        &mut self,
        time: MsSinceEpoch,
        packet: Option<ServerCycleInput<S>>
    ) {
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
    pub fn poll_transmit(
        &mut self
    ) -> Option<ServerCycleOutput<S>>
    {
        self.inner.buffer.dequeue()
    }
    pub fn poll_result(
        &mut self
    ) -> ServerPollResult<ServerCycle<N, S::Signature>>
    {
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
    obj: &mut ServerCycleDriver<S, K, H, N>,
    packet: Option<ServerCycleInput<S>>,
    current_time: MsSinceEpoch
) -> Result<(), ServerProtocolError>
where
    S: DsaSystem,
    K: KemAlgorithm,
    H: HashingAlgorithm<N>,
{
    let state = match &mut obj.state {
        DriverState::Init => handle_registry_init(&mut obj.inner, packet)?,
       DriverState::WaitingForRequestVerification(inner) => handle_verification(&mut obj.inner, packet, &inner, current_time)?,
       DriverState::ServerStore(inner) => handle_store_wait(&mut obj.inner, packet, inner)?,
        DriverState::Errored(_) => None,
        DriverState::Finished(_) => None,
        DriverState::Vacant => None,
      
    };

    if let Some(inner) = state {
        // If we output a new state, use said state.
        obj.state = inner;
    }

    Ok(())
}

fn handle_registry_init<S, K, H, const HS: usize>(
    inner: &mut ServerCycleDriverInner<S, K, H, HS>,
    packet: Option<ServerCycleInput<S>>,
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
        ServerCycleInput::ReceiveRequest(request) => {
            // Send out a verification request, this will also fetch the new key from the database with
            // which we can actually validate the request.
            inner.buffer.enqueue(ServerCycleOutput::VerificationRequest(CycleVerifyQuery { client_id: request.body.identifier, new_public_key: (*request.body.new_public_key).clone() }));
            return Ok(Some(DriverState::WaitingForRequestVerification(request)));
        }
        _ => {
            /* Nothig */
            return Ok(None);
        }
    }
}


fn handle_verification<S, K, H, const HS: usize>(
    inner: &mut ServerCycleDriverInner<S, K, H, HS>,
    packet: Option<ServerCycleInput<S>>,
    init_msg: &CycleInit<S::Public, S::Signature>,
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
        ServerCycleInput::VerificationResponse(response) => match response {
            CycleVerifyStatus::KeyNotUnique => Err(ServerProtocolError::PublicKeyNotUnique),
            CycleVerifyStatus::Other(reason) => Err(ServerProtocolError::Misc(reason)),
            CycleVerifyStatus::Success { client_id, original_public_key, new_public_key } => {
                // Verify the request and then issue a store operation.
                let response = ProtocolKit::<S, K, H, HS>::server_cycle(init_msg, &original_public_key, &inner.server_sk)?;
                inner.buffer.enqueue(ServerCycleOutput::StorageRequest(StoreRegistryQuery { client_id: client_id, public_key: new_public_key, time: current_time }));
                Ok(Some(DriverState::ServerStore(Some(response))))
            }
        }
        _ => {
            /* Nothig */
            return Ok(None);
        }
    }
}


fn handle_store_wait<S, K, H, const HS: usize>(
    inner: &mut ServerCycleDriverInner<S, K, H, HS>,
    packet: Option<ServerCycleInput<S>>,
    resp: &mut Option<ServerCycle<HS, S::Signature>>
) -> Result<Option<DriverState<S, HS>>, ServerProtocolError>
where
    
    S: DsaSystem,
    K: KemAlgorithm,
    H: HashingAlgorithm<HS>
{
    // We only want to proceed if the packet is not none.
    let Some(packet) = packet else {
        return Ok(None);
    };

    match packet {
        ServerCycleInput::StoreResponse(r) => match r {
            StorageStatus::Success => {
                // We have succesfully completed the operation.
                inner.terminated = true;
                return Ok(Some(DriverState::Finished(resp.take())))
            },
            StorageStatus::Failure(error) => {
                Err(ServerProtocolError::StoreFailure(error))
            }
        }
        _ => {
            /* Nothig */
            return Ok(None);
        }
    }
}


#[cfg(test)]
mod tests {
    use crate::{protocol::ProtocolKit, testutil::BasicSetupDetails, CycleVerifyQuery, DsaSystem, StorageStatus, StoreRegistryQuery};



    #[test]
fn test_server_cycle_happy_path() {
    use crate::{
        ServerCycleDriver, ServerCycleInput, ServerCycleOutput, CycleVerifyStatus,
        MsSinceEpoch,
    };
    use crate::core::crypto::specials::{FauxChain, FauxKem};
    use sha3::Sha3_256;

    const N: usize = 32;
    type Driver = ServerCycleDriver<FauxChain, FauxKem, Sha3_256, N>;

    let setup = BasicSetupDetails::<FauxChain>::new();
    let mut driver = Driver::new(setup.server_sk.clone());

    let (old_client_pk, old_client_sk) = FauxChain::generate().unwrap();

    let (cycle_init, new_private) = ProtocolKit::<FauxChain, FauxKem, Sha3_256, 32>::client_cycle_init(setup.client_id, &old_client_sk).unwrap();

    driver.recv(MsSinceEpoch(0), Some(ServerCycleInput::ReceiveRequest(cycle_init.clone())));

    let Some(ServerCycleOutput::VerificationRequest(CycleVerifyQuery { client_id, new_public_key: _ })) = driver.poll_transmit() else {
        panic!("Expected verification request to be queued");
    };
    assert_eq!(client_id, setup.client_id);

    driver.recv(MsSinceEpoch(10), Some(ServerCycleInput::VerificationResponse(
        CycleVerifyStatus::Success {
            client_id: setup.client_id,
            original_public_key: old_client_pk,
            new_public_key: (*cycle_init.body.new_public_key).clone(),
        }
    )));

    let Some(ServerCycleOutput::StorageRequest(StoreRegistryQuery { client_id, public_key: _, time })) = driver.poll_transmit() else {
        panic!("Expected storage request to be queued");
    };
    assert_eq!(client_id, setup.client_id);
    assert_eq!(time, MsSinceEpoch(10));

    driver.recv(MsSinceEpoch(20), Some(ServerCycleInput::StoreResponse(StorageStatus::Success)));
    let result = driver.poll_result();
    assert!(matches!(result, std::task::Poll::Ready(Ok(_))));
}

#[test]
fn test_server_cycle_sends_verification_request() {
    use crate::{ServerCycleDriver, ServerCycleInput, ServerCycleOutput, MsSinceEpoch};
    use crate::core::crypto::specials::{FauxChain, FauxKem};
    use sha3::Sha3_256;

    const N: usize = 32;
    type Driver = ServerCycleDriver<FauxChain, FauxKem, Sha3_256, N>;

    let setup = BasicSetupDetails::<FauxChain>::new();
    let mut driver = Driver::new(setup.server_sk.clone());

    let (_, old_client_sk) = FauxChain::generate().unwrap();
    let (cycle_init, _) = ProtocolKit::<FauxChain, FauxKem, Sha3_256, N>::client_cycle_init(setup.client_id, &old_client_sk).unwrap();

    driver.recv(MsSinceEpoch(0), Some(ServerCycleInput::ReceiveRequest(cycle_init.clone())));

    let Some(ServerCycleOutput::VerificationRequest(CycleVerifyQuery { client_id, .. })) = driver.poll_transmit() else {
        panic!("Expected verification request to be queued");
    };
    assert_eq!(client_id, setup.client_id);
}

#[test]
fn test_server_cycle_fails_on_key_not_unique() {
    use crate::{ServerCycleDriver, ServerCycleInput, CycleVerifyStatus, ServerPollResult, ServerProtocolError, MsSinceEpoch};
    use crate::core::crypto::specials::{FauxChain, FauxKem};
    use sha3::Sha3_256;

    const N: usize = 32;
    type Driver = ServerCycleDriver<FauxChain, FauxKem, Sha3_256, N>;

    let setup = BasicSetupDetails::<FauxChain>::new();
    let mut driver = Driver::new(setup.server_sk.clone());

    let (_, old_client_sk) = FauxChain::generate().unwrap();
    let (cycle_init, _) = ProtocolKit::<FauxChain, FauxKem, Sha3_256, N>::client_cycle_init(setup.client_id, &old_client_sk).unwrap();

    driver.recv(MsSinceEpoch(0), Some(ServerCycleInput::ReceiveRequest(cycle_init.clone())));

    driver.recv(MsSinceEpoch(10), Some(ServerCycleInput::VerificationResponse(CycleVerifyStatus::KeyNotUnique)));

    let ServerPollResult::Ready(Err(ServerProtocolError::PublicKeyNotUnique)) = driver.poll_result() else {
        panic!("Expected PublicKeyNotUnique error");
    };
}


#[test]
fn test_server_cycle_fails_on_misc_error() {
    use crate::{ServerCycleDriver, ServerCycleInput, CycleVerifyStatus, ServerPollResult, ServerProtocolError, MsSinceEpoch};
    use crate::core::crypto::specials::{FauxChain, FauxKem};
    use sha3::Sha3_256;

    const N: usize = 32;
    type Driver = ServerCycleDriver<FauxChain, FauxKem, Sha3_256, N>;

    let setup = BasicSetupDetails::<FauxChain>::new();
    let mut driver = Driver::new(setup.server_sk.clone());

    let (_, old_client_sk) = FauxChain::generate().unwrap();
    let (cycle_init, _) = ProtocolKit::<FauxChain, FauxKem, Sha3_256, N>::client_cycle_init(setup.client_id, &old_client_sk).unwrap();

    driver.recv(MsSinceEpoch(0), Some(ServerCycleInput::ReceiveRequest(cycle_init)));

    driver.recv(MsSinceEpoch(10), Some(ServerCycleInput::VerificationResponse(CycleVerifyStatus::Other("Bad Sig".to_string()))));

    let ServerPollResult::Ready(Err(ServerProtocolError::Misc(reason))) = driver.poll_result() else {
        panic!("Expected miscellaneous verification failure");
    };
    assert_eq!(reason, "Bad Sig");
}

#[test]
fn test_server_cycle_fails_on_storage_error() {
    use crate::{ServerCycleDriver, ServerCycleInput, ServerCycleOutput, CycleVerifyStatus, ServerPollResult, ServerProtocolError, MsSinceEpoch};
    use crate::core::crypto::specials::{FauxChain, FauxKem};
    use sha3::Sha3_256;

    const N: usize = 32;
    type Driver = ServerCycleDriver<FauxChain, FauxKem, Sha3_256, N>;

    let setup = BasicSetupDetails::<FauxChain>::new();
    let mut driver = Driver::new(setup.server_sk.clone());

    let (old_pk, old_sk) = FauxChain::generate().unwrap();
    let (cycle_init, _) = ProtocolKit::<FauxChain, FauxKem, Sha3_256, N>::client_cycle_init(setup.client_id, &old_sk).unwrap();

    driver.recv(MsSinceEpoch(0), Some(ServerCycleInput::ReceiveRequest(cycle_init.clone())));
    driver.poll_transmit(); // Skip verification request

    driver.recv(MsSinceEpoch(10), Some(ServerCycleInput::VerificationResponse(CycleVerifyStatus::Success {
        client_id: setup.client_id,
        original_public_key: old_pk,
        new_public_key: (*cycle_init.body.new_public_key).clone(),
    })));

    driver.poll_transmit(); // Skip storage request

    driver.recv(MsSinceEpoch(20), Some(ServerCycleInput::StoreResponse(StorageStatus::Failure("DB down".to_string()))));

    let ServerPollResult::Ready(Err(ServerProtocolError::StoreFailure(reason))) = driver.poll_result() else {
        panic!("Expected storage failure");
    };
    assert_eq!(reason, "DB down");
}

#[test]
fn test_server_cycle_ignores_after_error() {
    use crate::{ServerCycleDriver, ServerCycleInput, CycleVerifyStatus, ServerPollResult, ServerProtocolError, MsSinceEpoch};
    use crate::core::crypto::specials::{FauxChain, FauxKem};
    use sha3::Sha3_256;

    const N: usize = 32;
    type Driver = ServerCycleDriver<FauxChain, FauxKem, Sha3_256, N>;

    let setup = BasicSetupDetails::<FauxChain>::new();
    let mut driver = Driver::new(setup.server_sk.clone());

    let (_, old_sk) = FauxChain::generate().unwrap();
    let (cycle_init, _) = ProtocolKit::<FauxChain, FauxKem, Sha3_256, N>::client_cycle_init(setup.client_id, &old_sk).unwrap();

    driver.recv(MsSinceEpoch(0), Some(ServerCycleInput::ReceiveRequest(cycle_init.clone())));
    driver.recv(MsSinceEpoch(5), Some(ServerCycleInput::VerificationResponse(CycleVerifyStatus::Other("oops".to_string()))));

    // Should now be in error state
    driver.recv(MsSinceEpoch(10), Some(ServerCycleInput::StoreResponse(StorageStatus::Success)));
    assert!(matches!(driver.poll_result(), ServerPollResult::Ready(Err(ServerProtocolError::Misc(_)))));

    // All future recvs should be ignored
    driver.recv(MsSinceEpoch(15), Some(ServerCycleInput::StoreResponse(StorageStatus::Success)));
    assert!(matches!(driver.poll_result(), ServerPollResult::Pending));
}


#[test]
fn test_server_cycle_result_pending_if_incomplete() {
    use crate::{ServerCycleDriver, ServerCycleInput, ServerPollResult, MsSinceEpoch};
    use crate::core::crypto::specials::{FauxChain, FauxKem};
    use sha3::Sha3_256;

    const N: usize = 32;
    type Driver = ServerCycleDriver<FauxChain, FauxKem, Sha3_256, N>;

    let setup = BasicSetupDetails::<FauxChain>::new();
    let mut driver = Driver::new(setup.server_sk.clone());

    let (_, old_sk) = FauxChain::generate().unwrap();
    let (cycle_init, _) = ProtocolKit::<FauxChain, FauxKem, Sha3_256, N>::client_cycle_init(setup.client_id, &old_sk).unwrap();

    driver.recv(MsSinceEpoch(0), Some(ServerCycleInput::ReceiveRequest(cycle_init)));

    let result = driver.poll_result();
    assert!(matches!(result, ServerPollResult::Pending));
}


}