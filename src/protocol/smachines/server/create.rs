use std::task::Poll;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{
    protocol::{
        smachines::{
            common::{ServerStateMachine, StateMachineState},
            container::State,
        },
        spec::details::Protocol,
    },
    token::{
        signature::{B64Public, KeyChain, PublicKey},
        token::GenericToken,
    },
};

use super::{
    context::ServerContext,
    message::{DatabaseQuery, DatabaseResponse, ServerResponse, SvrMsg},
};

enum CreateState {
    Fresh,
    WaitingOnDatabaseResponse,
    Success,
    Failed(CreateEntityError),
}

pub struct CreateEntityBinding<KC>
where
    KC: KeyChain,
{
    state: State<CreateState>,
    svc_entity_id: Uuid,
    key: KC::Public,
    protocol: Protocol,
}

#[derive(Debug)]
pub enum CreateEntityError {
    StateMachineFailure(String),
    IncompaibleProtocol {
        binding_protocol: Protocol,
        context_protocol: Protocol,
    },
    Conflict,
}

impl<KC> CreateEntityBinding<KC>
where
    KC: KeyChain,
{
    pub fn create(id: Uuid, key: KC::Public, protocol: Protocol) -> Self {
        Self {
            state: State::new(CreateState::Fresh),
            svc_entity_id: id,
            key: key,
            protocol,
        }
    }
    fn send_to_error(&mut self, error: CreateEntityError) {
        self.state.handle().set(CreateState::Failed(error));
    }
}

impl<KC> ServerStateMachine<SvrMsg, ServerResponse> for CreateEntityBinding<KC>
where
    KC: KeyChain,
{
    type Error = CreateEntityError;
    type Result = ();

    fn poll_transmit<C: ServerContext>(&mut self, ctx: &C) -> Option<SvrMsg> {
        if ctx.protocol() != self.protocol {
            // If the protocols are incompatible at any point we just immediately go to an errored state.
            self.send_to_error(CreateEntityError::IncompaibleProtocol {
                binding_protocol: self.protocol,
                context_protocol: ctx.protocol(),
            });
            return None;
        }

        let mut state = self.state.handle();

        match *state {
            CreateState::Fresh => {
                state.set(CreateState::WaitingOnDatabaseResponse);
                Some(SvrMsg::DbQuery(DatabaseQuery::CreateEntity {
                    entity_id: self.svc_entity_id,
                    key: B64Public::from_public_key(&self.key),
                }))
            }
            _ => None,
        }
    }

    fn input<C: ServerContext>(&mut self, ctx: &C, inner: ServerResponse) {
        let mut state = self.state.handle();

        match *state {
            CreateState::WaitingOnDatabaseResponse => match inner {
                ServerResponse::DbResult(result) => match result {
                    DatabaseResponse::StoreError(string) => {
                        self.send_to_error(CreateEntityError::StateMachineFailure(format!(
                            "DB Store Issue: {string}"
                        )));
                    }
                    DatabaseResponse::CreateEntitySuccess => {
                        state.set(CreateState::Success);
                    }
                    DatabaseResponse::SvcEntityConflict => {
                        state.set(CreateState::Failed(CreateEntityError::Conflict));
                    }
                    _ => {
                        self.send_to_error(CreateEntityError::StateMachineFailure(format!("The statre machine was expecting either: StoreError, CreateEntitySuccess, or SvcEntityConflict!")));
                    }
                },
                _ => {
                    self.send_to_error(CreateEntityError::StateMachineFailure(format!(
                        "Protocol received an input it could not handle."
                    )));
                    return;
                }
            },
            _ => {}
        }
    }

    fn poll_result<C>(&mut self, _: &C) -> core::task::Poll<Result<Self::Result, Self::Error>> {
        if self.state.handle().completed() {
            self.state.take(); // Invalidate the state.
            Poll::Ready(Ok(()))
        } else if self.state.handle().failed() {
            let CreateState::Failed(error) = self.state.take() else {
                unreachable!(); // We already checked this condition.
            };

            Poll::Ready(Err(error))
        } else {
            Poll::Pending
        }
    }
}

impl StateMachineState for CreateState {
    type Error = CreateEntityError;
    fn failed(&self) -> bool {
        if let Self::Failed(_) = self {
            true
        } else {
            false
        }
    }
    fn completed(&self) -> bool {
        if let Self::Success = self {
            true
        } else {
            false
        }
    }
    fn err(self) -> Option<Self::Error> {
        if let Self::Failed(e) = self {
            Some(e)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{task::Poll, time::Duration};

    use base64::{Engine, prelude::BASE64_URL_SAFE};
    use chrono::DateTime;
    use uuid::{Uuid, uuid};

    use crate::{
        protocol::{
            smachines::{
                common::ServerStateMachine,
                server::{
                    context::ServerContext,
                    message::{DatabaseQuery, DatabaseResponse, ServerResponse, SvrMsg},
                    put::PutTokenResult,
                },
            },
            spec::details::Protocol,
        },
        testing::{DummyKeyChain, DummyServerContext, ExampleProtocol, ExampleType},
        token::{
            signature::{KeyChain, PrivateKey, PublicKey},
            token::{FluidToken, TimestampToken},
        },
    };

    use super::{CreateEntityBinding, CreateState};

    #[test]
    pub fn test_correct_entity_creation_run() {
        // Set up the binding, generate & sign a token.
        let mid = uuid!("1a3c4730-86ae-49c2-b3c4-7ed1088980e6");
        let (public, private) = DummyKeyChain::generate();
        let mut binding: CreateEntityBinding<DummyKeyChain> =
            CreateEntityBinding::create(mid, public.clone(), Protocol("Example"));
        let mut context = DummyServerContext::new();
        context.protocol = Protocol("Example");

        if let CreateState::Fresh = *binding.state.handle() {
        } else {
            panic!("The binding did not start in the fresh state.");
        }

        if let Some(SvrMsg::DbQuery(DatabaseQuery::CreateEntity { entity_id, key })) =
            binding.poll_transmit(&context)
        {
            assert_eq!(entity_id, mid);
            assert_eq!(
                key.as_str(),
                BASE64_URL_SAFE.encode(public.as_bytes()).as_str()
            );
        } else {
            panic!("The binding did not send out a create enity request as expected");
        }

        if let CreateState::WaitingOnDatabaseResponse = *binding.state.handle() {
        } else {
            panic!("The binding did not go into the waiting state.");
        }

        binding.input(
            &context,
            ServerResponse::DbResult(DatabaseResponse::CreateEntitySuccess),
        );

        if let CreateState::Success = *binding.state.handle() {
        } else {
            panic!(
                "The binding should have been kicked up to a succesful state after receiving a succesful binding."
            );
        }

        if let Poll::Ready(inner) = binding.poll_result(&context) {
            assert!(inner.is_ok());
        } else {
            panic!("Did not receive a ready poll when expected.");
        }
    }
}
