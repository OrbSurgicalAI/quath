use std::{marker::PhantomData, task::Poll, time::Duration};

use bitvec::array::BitArray;
use uuid::Uuid;

use crate::{
    token::{Final, Token}, CheckTokenStatus, ClientDeregister, ClientRegisterInit, ClientRevoke, ClientToken, CycleInit, CycleVerifyStatus, DeregisterStatus, DsaSystem, HashingAlgorithm, KemAlgorithm, MsSinceEpoch, ServerCycle, ServerCycleDriver, ServerCycleOutput, ServerDeregister, ServerDeregisterDriver, ServerDeregisterInput, ServerDeregisterOutput, ServerProtocolError, ServerRegister, ServerRegistryDriver, ServerRegistryInput, ServerRegistryOutput, ServerRevoke, ServerRevokeDriver, ServerRevokeInput, ServerRevokeOutput, ServerToken, ServerTokenDriver, ServerTokenInput, ServerTokenOutput, ServerVerifyDriver, ServerVerifyInput, ServerVerifyOutput, Signature, TokenValidityInterval, TokenVerifyStatus, VerifyRequestIntegrityResponse
};

pub struct ServerExecutor<S, K, H, const N: usize>
where
    S: DsaSystem,
{
    pub store_registry: fn(StoreRegistryQuery<S>) -> StorageStatus,
    pub verify_register_integrity: fn(VerifyRequestIntegrityQuery<S>) -> VerifyRequestIntegrityResponse<S>,
    pub deregister_public_key_fetch: fn(GetPublicKeyQuery) -> KeyFetchResult<S>,
    pub deregister_entity: fn(DeregisterEntityQuery) -> DeregisterStatus,
    pub revoke_token: fn(RevokeTokenQuery<N>) -> TokenRevocationStatus,
    pub store_token: fn(StoreTokenQuery<N>) -> StorageStatus,
    pub verify_token: fn(VerifyTokenQuery<N>) -> TokenVerifyStatus<S>,
    pub check_token: fn(CheckTokenQuery<N>) -> CheckTokenStatus,
    pub cycle_verify: fn(CycleVerifyQuery<S>) -> CycleVerifyStatus<S>,
    pub server_sk: S::Private,
    pub validity_interval: TokenValidityInterval,
    pub token_lifetime: Duration,
    pub _s: PhantomData<S>,
    pub _k: PhantomData<K>,
    pub _h: PhantomData<H>,
}


pub enum StorageStatus {
    Success,
    Failure(String)
}

pub struct VerifyTokenQuery<const N: usize> {
    pub client_id: Uuid,
    pub token_hash: [u8; N]
}

pub struct RevokeTokenQuery<const N: usize> {
    pub client_id: Uuid,
    pub token_hash: [u8; N]
}


pub struct StoreTokenQuery<const N: usize> {
    pub client_id: Uuid,
    pub token_hash: [u8; N],
    pub token_stamp_time: MsSinceEpoch,
    pub token_expiry_time: MsSinceEpoch
}

pub struct GetPublicKeyQuery {
    pub target: Uuid,
    pub claimant: Uuid
}

pub struct DeregisterEntityQuery {
    pub target: Uuid
}

pub struct CycleVerifyQuery<S: DsaSystem> {
    pub client_id: Uuid,
    pub new_public_key: S::Public
}

pub struct CheckTokenQuery<const N: usize> {
    pub client_id: Uuid,
    pub array: BitArray<[u8; 16]>,
    pub token_hash: [u8; N]
}

pub struct StoreRegistryQuery<S: DsaSystem> {
    pub client_id: Uuid,
    pub public_key: S::Public,
    pub time: MsSinceEpoch
}

pub struct VerifyRequestIntegrityQuery<S: DsaSystem> {
    pub requested_id: Uuid,
    pub admin_id:  Uuid,
    pub public_key: S::Public
}

pub struct KeyFetchResponse<S: DsaSystem> {
    pub claimant: Uuid,
    pub key: S::Public,
    pub is_admin: bool,
    pub has_permissions: bool
}

pub enum TokenRevocationStatus {
    Confirmed,
    Failure(String)
}

pub enum KeyFetchResult<S: DsaSystem> {
    Success(KeyFetchResponse<S>),
    InvalidClaimant,
    Failure(String)
}

impl<S, K, H, const N: usize> ServerExecutor<S, K, H, N>
where
    S: DsaSystem,
    K: KemAlgorithm,
    H: HashingAlgorithm<N>,
{
    pub fn register(
        &self,
        time: MsSinceEpoch,
        request: ClientRegisterInit<S::Public, S::Signature>,
    ) -> Result<ServerRegister<S::Signature, N>, ServerProtocolError> {
        let mut machine = ServerRegistryDriver::<S, K, H, N>::new(self.server_sk.clone());
        machine.recv(
            time,
            Some(crate::ServerRegistryInput::ClientRequest(request)),
        );

        let mut poll = Poll::Pending;

        while poll.is_pending() {
            if let Some(transmit) = machine.poll_transmit() {
                match transmit {
                    ServerRegistryOutput::StoreRegistry(query)
                        => machine.recv(time, Some(ServerRegistryInput::StoreResponse((self.store_registry)(query)))),
                    ServerRegistryOutput::VerifyRequestIntegrity(query)=> {
                        machine.recv(
                            time,
                            Some(ServerRegistryInput::VerificationResponse((self
                                .verify_register_integrity)(
                                query
                            ))),
                        );
                    }
                }
            }

            poll = machine.poll_result();
        }

        let Poll::Ready(terminated) = poll else {
            panic!("While loop invariant broken.");
        };

        terminated
    }
    pub fn deregister(
        &self,
        request: ClientDeregister<S::Signature, N>
    ) -> Result<ServerDeregister<S::Signature, N>, ServerProtocolError> {
        let mut machine = ServerDeregisterDriver::<S, K, H, N>::new(self.server_sk.clone());
        machine.recv(
            Some(crate::ServerDeregisterInput::Request(request)),
        );

        let mut poll = Poll::Pending;

        while poll.is_pending() {
            if let Some(transmit) = machine.poll_transmit() {
                match transmit {
                    ServerDeregisterOutput::GetPublicKey(query) => {
                        machine.recv(Some(ServerDeregisterInput::KeyFetchResponse((self.deregister_public_key_fetch)(query))))
                    },
                    ServerDeregisterOutput::Deregister(query) => {
                        machine.recv(Some(ServerDeregisterInput::DeregisterResponse((self.deregister_entity)(query))));
                    }
                }
            }

            poll = machine.poll_result();
        }

        let Poll::Ready(terminated) = poll else {
            panic!("While loop invariant broken.");
        };

        terminated
    }
    pub fn token(
        &mut self,
        time: MsSinceEpoch,
        request: ClientToken<S::Signature, K>
    ) -> Result<ServerToken<N, K, S::Signature>, ServerProtocolError> {
        let mut machine = ServerTokenDriver::<S, K, H, N>::new(self.server_sk.clone(), self.validity_interval.clone(), self.token_lifetime);
        machine.recv(
            time,
            Some(ServerTokenInput::ReceiveRequest(request)),
        );

        let mut poll = Poll::Pending;

        while poll.is_pending() {
            if let Some(transmit) = machine.poll_transmit() {
                match transmit {
                    ServerTokenOutput::Revoke(query) => {
                        machine.recv(time, Some(ServerTokenInput::RevokeResponse((self.revoke_token)(query))));
                    }
                    ServerTokenOutput::StorageRequest(query) => {
                        machine.recv(time, Some(ServerTokenInput::StorageResponse(((self.store_token)(query)))));
                    }
                    ServerTokenOutput::VerificationRequest(query) => {
                        machine.recv(time, Some(ServerTokenInput::VerifyResponse((self.verify_token)(query))));
                    }
                }
            }

            poll = machine.poll_result();
        }

        let Poll::Ready(terminated) = poll else {
            panic!("While loop invariant broken.");
        };

        terminated
    }
    pub fn revoke(
        &mut self,
        request: ClientRevoke<S::Signature, N> 
    ) -> Result<ServerRevoke<S::Signature, N>, ServerProtocolError>
    {
        let mut machine = ServerRevokeDriver::<S, K, H, N>::new(self.server_sk.clone());
        machine.recv(
            Some(ServerRevokeInput::Request(request)),
        );

        let mut poll = Poll::Pending;

        while poll.is_pending() {
            if let Some(transmit) = machine.poll_transmit() {
                match transmit {
                    ServerRevokeOutput::GetPublicKey(query) =>
                        machine.recv(Some(ServerRevokeInput::KeyFetchResponse((self.deregister_public_key_fetch)(query)))),
                    ServerRevokeOutput::Revoke(query) =>
                        machine.recv(Some(ServerRevokeInput::RevokeResponse((self.revoke_token)(query))))
                }
            }

            poll = machine.poll_result();
        }

        let Poll::Ready(terminated) = poll else {
            panic!("While loop invariant broken.");
        };

        terminated

    }
    pub fn verify(
        &mut self,
        time: MsSinceEpoch,
        token: Token<Final>
    ) -> Result<Token<Final>, ServerProtocolError> {
        let mut machine = ServerVerifyDriver::<H, N>::new(self.validity_interval.clone());
        machine.recv(
            time,
            Some(ServerVerifyInput::Request(token)),
        );

        let mut poll = Poll::Pending;

        while poll.is_pending() {
            if let Some(transmit) = machine.poll_transmit() {
                match transmit {
                    ServerVerifyOutput::CheckToken(query) => {
                        machine.recv(time, Some(ServerVerifyInput::TokenResponse((self.check_token)(query))))
                    }
                }
            }

            poll = machine.poll_result();
        }

        let Poll::Ready(terminated) = poll else {
            panic!("While loop invariant broken.");
        };

        terminated
    }
    pub fn cycle(
        &mut self,
        time: MsSinceEpoch,
        request: CycleInit<S::Public, S::Signature>
    ) -> Result<ServerCycle<N, S::Signature>, ServerProtocolError>
    {
        let mut machine = ServerCycleDriver::<S, K, H, N>::new(self.server_sk.clone());
        machine.recv(
            time,
            Some(crate::ServerCycleInput::ReceiveRequest(request)),
        );

        let mut poll = Poll::Pending;

        while poll.is_pending() {
            if let Some(transmit) = machine.poll_transmit() {
                match transmit {
                    ServerCycleOutput::VerificationRequest(query)
                        => machine.recv(time, Some(crate::ServerCycleInput::VerificationResponse((self.cycle_verify)(query)))),
                    ServerCycleOutput::StorageRequest(query)
                        => machine.recv(time, Some(crate::ServerCycleInput::StoreResponse((self.store_registry)(query))))
                }
            }

            poll = machine.poll_result();
        }

        let Poll::Ready(terminated) = poll else {
            panic!("While loop invariant broken.");
        };

        terminated

    }
}
