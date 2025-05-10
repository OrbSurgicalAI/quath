use std::{marker::PhantomData, task::Poll};

use uuid::Uuid;

use crate::{
    ClientDeregister, ClientProtocolError, DsaSystem, HashingAlgorithm, KemAlgorithm,
    ServerDeregister, ServerErrorResponse, protocol::ProtocolKit,
};

use super::{ClientSingleDriver, ClientSingleInput};

type InnerSingleDriver<S, SIG, const N: usize> = ClientSingleDriver<DegisterCtx<S>, (), ClientDeregister<SIG, N>, ServerDeregister<SIG, N>>;

pub struct ClientDeregisterDriver<S, K, H, const N: usize>
where
    S: DsaSystem,
    K: KemAlgorithm,
    H: HashingAlgorithm<N>,
{
    inner: InnerSingleDriver<S, S::Signature, N>,
    _k: PhantomData<K>,
    _h: PhantomData<H>,
}

struct DegisterCtx<S>
where
    S: DsaSystem,
{
    target: Uuid,
    claimant_id: Uuid,
    claimant_sk: S::Private,
    server_pk: S::Public,
}

pub enum ClientDeregisterOutput<S, const N: usize>
where
    S: DsaSystem,
{
    Request(ClientDeregister<S::Signature, N>),
}

pub enum ClientDeregisterInput<S, const N: usize>
where
    S: DsaSystem,
{
    Response(ServerDeregister<S::Signature, N>),
    ErrorResponse(ServerErrorResponse),
}


impl<S, K, H, const N: usize> ClientDeregisterDriver<S, K, H, N>
where
    S: DsaSystem,
    K: KemAlgorithm,
    H: HashingAlgorithm<N>,
{
    pub fn new(
        target: Uuid,
        claimant_id: Uuid,
        claimant_sk: S::Private,
        server_pk: S::Public,
    ) -> Self {
        Self {
            inner: ClientSingleDriver::new(
                DegisterCtx {
                    target,
                    claimant_id,
                    claimant_sk,
                    server_pk,
                },
                init_function::<S, K, H, N>,
                done_function::<S, K, H, N>,
            ),
            _h: PhantomData,
            _k: PhantomData,
        }
    }

    pub fn recv(&mut self, packet: Option<ClientDeregisterInput<S, N>>) {
        self.inner.recv(packet.map(|inner| match inner {
                ClientDeregisterInput::ErrorResponse(respo) => ClientSingleInput::ErrorResponse(respo),
                ClientDeregisterInput::Response(respo) => ClientSingleInput::Response(respo)
             }));
    }

    pub fn poll_transmit(&mut self) -> Option<ClientDeregisterOutput<S, N>> {
        Some(ClientDeregisterOutput::Request(self.inner.poll_transmit()?))
    }
    pub fn poll_result(&mut self) -> Poll<Result<(), ClientProtocolError>> {
        self.inner.poll_result()
    }
}

fn init_function<S, K, H, const N: usize>(
    ctx: &mut DegisterCtx<S>,
) -> Result<(ClientDeregister<S::Signature, N>, ()), ClientProtocolError>
where
    S: DsaSystem,
    K: KemAlgorithm,
    H: HashingAlgorithm<N>,
{
    Ok((
        ProtocolKit::<S, K, H, N>::client_deregister_init(
            ctx.target,
            ctx.claimant_id,
            &ctx.claimant_sk,
        )?,
        (),
    ))
}

fn done_function<S, K, H, const N: usize>(
    response: ServerDeregister<S::Signature, N>,
    ctx: &mut DegisterCtx<S>,
    _: &mut (),
) -> Result<(), ClientProtocolError>
where
    S: DsaSystem,
    K: KemAlgorithm,
    H: HashingAlgorithm<N>,
{
    ProtocolKit::<S, K, H, N>::client_deregister_finish(
        ctx.target,
        ctx.claimant_id,
        &response,
        &ctx.server_pk,
    )
}

#[cfg(test)]
mod tests {
    use std::task::Poll;

    use sha3::Sha3_256;
    use uuid::Uuid;

    use crate::{
        DsaSystem,
        protocol::ProtocolKit,
        specials::{FauxChain, FauxKem},
        testutil::BasicSetupDetails,
    };

    use super::{ClientDeregisterDriver, ClientDeregisterInput, ClientDeregisterOutput};

    #[test]
    pub fn test_deregister_happy_path() {
        let _ = BasicSetupDetails::<FauxChain>::new();

        let target_id = Uuid::new_v4();
        let (c_pk, c_sk) = FauxChain::generate().unwrap();
        let (s_pk, s_sk) = FauxChain::generate().unwrap();
        let mut driver = ClientDeregisterDriver::<FauxChain, FauxKem, Sha3_256, 32>::new(
            target_id, target_id, c_sk, s_pk,
        );

        driver.recv(None);

        #[allow(irrefutable_let_patterns)]
        let ClientDeregisterOutput::Request(request) = driver.poll_transmit().unwrap() else {
            panic!("Failed to extract the request from the transmit poll.");
        };

        let response = ProtocolKit::<FauxChain, FauxKem, Sha3_256, 32>::server_deregister(
            &request, &c_pk, &s_sk,
        )
        .unwrap();

        driver.recv(Some(ClientDeregisterInput::Response(response)));

        let Poll::Ready(Ok(())) = driver.poll_result() else {
            panic!("Polled to wrong sate.");
        };
    }
}
