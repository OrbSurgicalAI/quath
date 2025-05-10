use std::{marker::PhantomData, task::Poll};

use ringbuffer::{ConstGenericRingBuffer, RingBuffer};
use uuid::Uuid;

use crate::{protocol::ProtocolKit, ClientDeregister, ClientProtocolError, DsaSystem, HashingAlgorithm, KemAlgorithm, ServerDeregister, ServerErrorResponse};

use super::ClientRevokeOutput;



pub struct ClientDeregisterDriver<S, K, H, const N: usize>
where
    S: DsaSystem,
    K: KemAlgorithm,
    H: HashingAlgorithm<N>
{
    inner: ClientDeregisterDriverInner<S, K, H, N>,
    state: DriverState
}


struct ClientDeregisterDriverInner<S, K, H, const N: usize>
where 
    S: DsaSystem,
    K: KemAlgorithm,
    H: HashingAlgorithm<N>
{
    target: Uuid,
    claimant_id: Uuid,
    claimant_sk: S::Private,
    server_pk: S::Public,
    buffer: ConstGenericRingBuffer<ClientDeregisterOutput<S, N>, 1>,
    terminated: bool,
    _k: PhantomData<K>,
    _h: PhantomData<H>

}

pub enum ClientDeregisterOutput<S, const N: usize>
where 
    S: DsaSystem
{
    Request(ClientDeregister<S::Signature, N>)
}

pub enum ClientDeregisterInput<S, const N: usize>
where 
    S: DsaSystem
{
    Response(ServerDeregister<S::Signature, N>),
    ErrorResponse(ServerErrorResponse)
}

enum DriverState {
    Init,
    WaitingOnServer,
    Errored(Option<ClientProtocolError>),
    ErrorResponse(Option<ServerErrorResponse>),
    Vacant,
    Finished
}


impl<S, K, H, const N: usize> ClientDeregisterDriver<S, K, H, N>
where 
    S: DsaSystem,
    K: KemAlgorithm,
    H: HashingAlgorithm<N>
{
    pub fn new(
        target: Uuid,
        claimant_id: Uuid,
        claimant_sk: S::Private,
        server_pk: S::Public,
    ) -> Self {

        Self {
            inner: ClientDeregisterDriverInner { 
                target,
                claimant_id,
                claimant_sk,
                server_pk,
                buffer: ConstGenericRingBuffer::default(),
                terminated: false,
                _h: PhantomData,
                _k: PhantomData
            },
            state: DriverState::Init
        }
        
    }

    pub fn recv(&mut self, packet: Option<ClientDeregisterInput<S, N>>) {
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

    pub fn poll_transmit(&mut self) -> Option<ClientDeregisterOutput<S, N>> {
        self.inner.buffer.dequeue()
    }
    pub fn poll_result(&mut self) -> Poll<Result<(), ClientProtocolError>> {
        match &mut self.state {
            DriverState::Errored(inner) => {
                let value = inner.take().unwrap();
                self.state = DriverState::Vacant;
                Poll::Ready(Err(value))
            },
            DriverState::Finished => {
                self.state = DriverState::Vacant;
                Poll::Ready(Ok(()))
            },
            DriverState::ErrorResponse(response) => {
                let value = response.take().unwrap();
                self.state = DriverState::Vacant;
                Poll::Ready(Err(ClientProtocolError::ServerErrorResponse(value)))
            }
            _ => Poll::Pending
        }
    }
}



fn recv_internal<S, K, H, const N: usize>(
    obj: &mut ClientDeregisterDriver<S, K, H, N>,
    packet: Option<ClientDeregisterInput<S, N>>,
) -> Result<(), ClientProtocolError>
where
    S: DsaSystem,
    K: KemAlgorithm,
    H: HashingAlgorithm<N>,
{
    let state = match &mut obj.state {
        DriverState::Init => handle_registry_init(&mut obj.inner, packet)?,
        DriverState::WaitingOnServer => handle_registry_done(&mut obj.inner, packet)?,
        _ => None, // The other states do not have any active behaviour.
    };

    if let Some(inner) = state {
        // If we output a new state, use said state.
        obj.state = inner;
    }

    Ok(())
}



fn handle_registry_init<S, K, H, const N: usize>(
    inner: &mut ClientDeregisterDriverInner<S, K, H, N>,
    packet: Option<ClientDeregisterInput<S, N>>,
) -> Result<Option<DriverState>, ClientProtocolError>
where
    S: DsaSystem,
    K: KemAlgorithm,
    H: HashingAlgorithm<N>,
{

    let request= ProtocolKit::<S, K, H, N>::client_deregister_init(inner.target, inner.claimant_id, &inner.claimant_sk)?;
    // Send out this request.
    inner.buffer.enqueue(ClientDeregisterOutput::Request(request));
    
    Ok(Some(DriverState::WaitingOnServer))
}

fn handle_registry_done<S, K, H, const N: usize>(
    inner: &mut ClientDeregisterDriverInner<S, K, H, N>,
    packet: Option<ClientDeregisterInput<S, N>>
) -> Result<Option<DriverState>, ClientProtocolError>
where
    S: DsaSystem,
    K: KemAlgorithm,
    H: HashingAlgorithm<N>,
{
    let Some(packet) = packet else {
        return Ok(None);
    };

    match packet {
        ClientDeregisterInput::Response(response) => {
            
            ProtocolKit::<S, K, H, N>::client_deregister_finish(inner.target, inner.claimant_id, &response, &inner.server_pk)?;

            
            Ok(Some(DriverState::Finished))
        }
        ClientDeregisterInput::ErrorResponse(error) => Ok(Some(DriverState::ErrorResponse(Some(error)))),
    }
}




#[cfg(test)]
mod tests {
    use std::task::Poll;

    use sha3::Sha3_256;
    use uuid::Uuid;

    use crate::{protocol::ProtocolKit, specials::{FauxChain, FauxKem}, testutil::BasicSetupDetails, DsaSystem};

    use super::{ClientDeregisterDriver, ClientDeregisterInput, ClientDeregisterOutput};


    #[test]
    pub fn test_deregister_happy_path() {

        let setup = BasicSetupDetails::<FauxChain>::new();

        let target_id = Uuid::new_v4();
        let (c_pk, c_sk) = FauxChain::generate().unwrap();
        let (s_pk, s_sk) = FauxChain::generate().unwrap();
        let mut driver = ClientDeregisterDriver::<FauxChain, FauxKem, Sha3_256, 32>::new(
            target_id,
            target_id,
            c_sk,
            s_pk
        );

        driver.recv(None);

        #[allow(irrefutable_let_patterns)]
        let ClientDeregisterOutput::Request(request) = driver.poll_transmit().unwrap() else {
            panic!("Failed to extract the request from the transmit poll.");
        };


        let response = ProtocolKit::<FauxChain, FauxKem, Sha3_256, 32>::server_deregister(
            &request,
            &c_pk,
            &s_sk
        ).unwrap();

        driver.recv(Some(ClientDeregisterInput::Response(response)));


        let Poll::Ready(Ok(())) = driver.poll_result() else {
            panic!("Polled to wrong sate.");
        };



  
    }
}