use std::{marker::PhantomData, task::Poll};
use ringbuffer::{GrowableAllocRingBuffer, RingBuffer};
use uuid::Uuid;

use crate::{protocol::ProtocolKit, ClientProtocolError, ClientRevoke, DsaSystem, HashingAlgorithm, KemAlgorithm, ServerErrorResponse, ServerRevoke};



pub struct ClientRevokeDriver<S, K, H, const N: usize>
where 
    S: DsaSystem,
    K: KemAlgorithm,
    H: HashingAlgorithm<N>
{
    inner: ClientRevokeDriverInner<S, K, H, N>,
    state: DriverState<S>
}


struct ClientRevokeDriverInner<S, K, H, const N: usize>
where 
    S: DsaSystem,
    K: KemAlgorithm,
    H: HashingAlgorithm<N>
{

    target: Uuid,
    claimant_id: Uuid,
    claimant_sk: S::Private,
    token_hash: [u8; N],
    server_pk: S::Public,
    buffer: GrowableAllocRingBuffer<ClientRevokeOutput<S, N>>,
    terminated: bool,
    _k: PhantomData<K>,
    _h: PhantomData<H>
}

pub enum ClientRevokeInput<S, const N: usize>
where 
    S: DsaSystem
{
    Response(ServerRevoke<S::Signature, N>),
    ErrorResponse(ServerErrorResponse)
}

pub enum ClientRevokeOutput<S, const N: usize>
where 
    S: DsaSystem
{
    Request(ClientRevoke<S::Signature, N>)
}

enum DriverState<S>
where 
    S: DsaSystem
{
    Init,
    Errored(Option<ClientProtocolError>),
    ErrorResponse(Option<ServerErrorResponse>),
    WaitingOnServer(S::Signature),
    Finished,
    Vacant
}

impl<S, K, H, const N: usize> ClientRevokeDriver<S, K, H, N>
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
        token_hash: [u8; N]
    ) -> Self {

        Self {
            inner: ClientRevokeDriverInner { 
                target,
                claimant_id,
                claimant_sk,
                server_pk,
                buffer: GrowableAllocRingBuffer::default(),
                terminated: false,
                token_hash,
                _h: PhantomData,
                _k: PhantomData
            },
            state: DriverState::Init
        }
        
    }

    pub fn recv(&mut self, packet: Option<ClientRevokeInput<S, N>>) {
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

    pub fn poll_transmit(&mut self) -> Option<ClientRevokeOutput<S, N>> {
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
    obj: &mut ClientRevokeDriver<S, K, H, N>,
    packet: Option<ClientRevokeInput<S, N>>,
) -> Result<(), ClientProtocolError>
where
    S: DsaSystem,
    K: KemAlgorithm,
    H: HashingAlgorithm<N>,
{
    let state = match &mut obj.state {
        DriverState::Init => handle_registry_init(&mut obj.inner, packet)?,
        DriverState::WaitingOnServer(sig) => handle_registry_done(&mut obj.inner, packet, sig)?,
        _ => None, // The other states do not have any active behaviour.
    };

    if let Some(inner) = state {
        // If we output a new state, use said state.
        obj.state = inner;
    }

    Ok(())
}


fn handle_registry_init<S, K, H, const N: usize>(
    inner: &mut ClientRevokeDriverInner<S, K, H, N>,
    packet: Option<ClientRevokeInput<S, N>>,
) -> Result<Option<DriverState<S>>, ClientProtocolError>
where
    S: DsaSystem,
    K: KemAlgorithm,
    H: HashingAlgorithm<N>,
{

    let request= ProtocolKit::<S, K, H, N>::client_revoke_init(
        inner.token_hash.clone(),
        inner.target,
        inner.claimant_id,
        &inner.claimant_sk
    )?;

    let signature = (*request.proof).clone();

    // Send out this request.
    inner.buffer.enqueue(ClientRevokeOutput::Request(request));
    
    Ok(Some(DriverState::WaitingOnServer(signature)))
}

fn handle_registry_done<S, K, H, const N: usize>(
    inner: &mut ClientRevokeDriverInner<S, K, H, N>,
    packet: Option<ClientRevokeInput<S, N>>,
    sig: &mut S::Signature
) -> Result<Option<DriverState<S>>, ClientProtocolError>
where
    S: DsaSystem,
    K: KemAlgorithm,
    H: HashingAlgorithm<N>,
{
    let Some(packet) = packet else {
        return Ok(None);
    };

    match packet {
        ClientRevokeInput::Response(response) => {
            ProtocolKit::<S, K, H, N>::client_revoke_finish(&response, &inner.token_hash, sig, &inner.server_pk)?;
            
            Ok(Some(DriverState::Finished))
        }
        ClientRevokeInput::ErrorResponse(error) => Ok(Some(DriverState::ErrorResponse(Some(error)))),
    }
}


#[cfg(test)]
mod tests {
    use std::task::Poll;

    use sha3::Sha3_256;

    use crate::{protocol::ProtocolKit, specials::{FauxChain, FauxKem}, testutil::BasicSetupDetails, DsaSystem};

    use super::{ClientRevokeDriver, ClientRevokeOutput};



    #[test]
    pub fn test_client_revoke_happy() {
        let setup = BasicSetupDetails::<FauxChain>::new();

        let (c_pk, c_sk) = FauxChain::generate().unwrap();
        let (s_pk, s_sk) = FauxChain::generate().unwrap();

        let mut driver = ClientRevokeDriver::<FauxChain, FauxKem, Sha3_256, 32>::new(setup.client_id, setup.client_id, c_sk, s_pk, [0u8; 32]);

        // start
        driver.recv(None);

        #[allow(irrefutable_let_patterns)]
        let ClientRevokeOutput::Request(request) = driver.poll_transmit().unwrap() else {
            panic!("No requst.")
        };

        let server_response = ProtocolKit::<FauxChain, FauxKem, Sha3_256, 32>::server_revoke(
            &request,
            &c_pk,
            &s_sk
        ).unwrap();

        driver.recv(Some(super::ClientRevokeInput::Response(server_response)));

        let Poll::Ready(Ok(())) = driver.poll_result() else {
            panic!("Failed to drive to succesful completion.");
        };
    

    }

    #[test]
fn test_client_revoke_signature_verification_failure() {
    let setup = BasicSetupDetails::<FauxChain>::new();

    let (c_pk, c_sk) = FauxChain::generate().unwrap();
    let (_, bad_server_sk) = FauxChain::generate().unwrap(); // Wrong server key

    let (good_server_pk, _) = FauxChain::generate().unwrap(); // Public key expected

    let mut driver = ClientRevokeDriver::<FauxChain, FauxKem, Sha3_256, 32>::new(
        setup.client_id,
        setup.client_id,
        c_sk,
        good_server_pk,
        [0u8; 32],
    );

    driver.recv(None);

    let ClientRevokeOutput::Request(request) = driver.poll_transmit().unwrap() else {
        panic!("Expected request output");
    };

    let forged_response = ProtocolKit::<FauxChain, FauxKem, Sha3_256, 32>::server_revoke(
        &request,
        &c_pk,
        &bad_server_sk,
    )
    .unwrap();

    driver.recv(Some(super::ClientRevokeInput::Response(forged_response)));

    let Poll::Ready(Err(_)) = driver.poll_result() else {
        panic!("Expected signature verification failure.");
    };
}

#[test]
fn test_client_revoke_receives_error_response() {
    let setup = BasicSetupDetails::<FauxChain>::new();

    let (_, c_sk) = FauxChain::generate().unwrap();
    let (s_pk, _) = FauxChain::generate().unwrap();

    let mut driver = ClientRevokeDriver::<FauxChain, FauxKem, Sha3_256, 32>::new(
        setup.client_id,
        setup.client_id,
        c_sk,
        s_pk,
        [0u8; 32],
    );

    driver.recv(None);
    let _ = driver.poll_transmit();

    let error_response = super::ServerErrorResponse {
        name: "Hello",
        error: "wow".to_string()
    };

    driver.recv(Some(super::ClientRevokeInput::ErrorResponse(error_response)));

    let Poll::Ready(Err(_)) = driver.poll_result() else {
        panic!("Expected poll_result to go to error");
    };
}



}