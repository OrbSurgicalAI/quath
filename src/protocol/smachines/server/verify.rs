use std::task::Poll;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{
    protocol::{
        smachines::{common::{ServerStateMachine, StateMachineState}, container::State}, spec::details::Protocol,
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

enum VerifyState {
    Fresh,
    WaitingOnDatabaseResponse,
    Verified,
    NotVerified,
    Failed(VerifyError),
}

pub struct VerifyTokenBinding
{
    state: State<VerifyState>,
    svc_entity_id: Uuid,
    token: Option<GenericToken>
}

#[derive(Debug)]
pub enum VerifyError {
    DbError(String),
    StateMachineFailure(String)
}

impl VerifyTokenBinding
{
    pub fn create(id: Uuid, token: GenericToken) -> Self
    {
        Self {
            state: State::new(VerifyState::Fresh),
            svc_entity_id: id,
            token: Some(token)
        }
    }
    fn send_to_error(&mut self, error: VerifyError) {
        self.state.handle().set(VerifyState::Failed(error));
    }
}



impl ServerStateMachine<SvrMsg, ServerResponse> for VerifyTokenBinding
{
    type Error = VerifyError;
    type Result = ();


    fn poll_transmit<C: ServerContext>(&mut self, _: &C) -> Option<SvrMsg>
    {
        let mut state = self.state.handle();

        match *state {
            VerifyState::Fresh => {
                state.set(VerifyState::WaitingOnDatabaseResponse);
                Some(SvrMsg::DbQuery(DatabaseQuery::CheckTokenValidity { token: self.token.take().unwrap() }))
            }
            _ => {
                None
            }
        }
    }

    fn input<C: ServerContext>(&mut self, _: &C, inner: ServerResponse) {

        let mut state = self.state.handle();

        match *state {
            VerifyState::WaitingOnDatabaseResponse => {
                match inner {
                    ServerResponse::DbResult(result) => match result {
                        DatabaseResponse::TokenValidityResponse(verdict) => {
                            if verdict {
                                state.set(VerifyState::Verified);
                            } else {
                                state.set(VerifyState::NotVerified);
                            }
                        }
                        DatabaseResponse::QueryError(inner) => {
                            self.send_to_error(VerifyError::DbError(inner));
                        }
                        _ => {
                            self.send_to_error(VerifyError::StateMachineFailure(format!("The statre machine was expecting either: StoreError, CreateEntitySuccess, or SvcEntityConflict!")));
                        }
                    },
                    _ => {
                        self.send_to_error(VerifyError::StateMachineFailure(format!("Protocol received an input it could not handle.")));
                        return;
                    }
                }
            }
            _ => {}
        }
    }

    fn poll_result<C>(&mut self, _: &C) -> core::task::Poll<Result<Self::Result, Self::Error>> {
        if self.state.handle().completed() {
            self.state.take(); // Invalidate the state.
            Poll::Ready(Ok(()))
        } else if self.state.handle().failed() {
            let VerifyState::Failed(error) = self.state.take() else {
                unreachable!(); // We already checked this condition.
            };

            Poll::Ready(Err(error))
        } else {
            Poll::Pending
        }
    }
}



impl StateMachineState for VerifyState {
    type Error = VerifyError;
    fn failed(&self) -> bool {
        if let Self::Failed(_) = self {
            true
        } else {
            false
        }
    }
    fn completed(&self) -> bool {
        if let Self::Verified = self {
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

    use base64::{prelude::BASE64_URL_SAFE, Engine};
    use chrono::DateTime;
    use uuid::{uuid, Uuid};

    use crate::{protocol::{smachines::{common::ServerStateMachine, server::{context::ServerContext, message::{DatabaseQuery, DatabaseResponse, ServerResponse, SvrMsg}, put::PutTokenResult}}, spec::{details::Protocol, time::MsSinceEpoch}}, testing::{DummyKeyChain, DummyServerContext, ExampleProtocol, ExampleType}, token::{signature::{KeyChain, PrivateKey, PublicKey}, token::{FluidToken, TimestampToken}}};

    use super::{VerifyTokenBinding, VerifyState};




    #[test]
    pub fn test_correct_token_verification_run() {
        // Set up the binding, generate & sign a token.
        let mid = uuid!("1a3c4730-86ae-49c2-b3c4-7ed1088980e6");
        let (public, private) = DummyKeyChain::generate();
        let dummy = FluidToken::from_raw(ExampleProtocol(0), ExampleType(0), Uuid::nil(), MsSinceEpoch::from_timestamp_millis(0), [0u8; 32], [0u8; 16]);
        let mut binding = VerifyTokenBinding::create(mid, dummy.generic().generic());
        let mut context = DummyServerContext::new();
        context.protocol = Protocol::DUMMY;


        if let VerifyState::Fresh = *binding.state.handle() {} else {
            panic!("The binding did not start in the fresh state.");
        }

        if let Some(SvrMsg::DbQuery(DatabaseQuery::CheckTokenValidity { token })) = binding.poll_transmit(&context) {
            assert_eq!(token.as_bytes(), dummy.generic().generic().as_bytes());
        } else {
            panic!("The binding did not send out a check token request as expected");
        }

        if let VerifyState::WaitingOnDatabaseResponse = *binding.state.handle() {} else {
            panic!("The binding did not go into the waiting state.");
        }

        binding.input(&context, ServerResponse::DbResult(DatabaseResponse::TokenValidityResponse(true)));

        
        if let VerifyState::Verified = *binding.state.handle() {} else {
            panic!("The binding should have been kicked up to a succesful state after receiving a succesful binding.");
        }

        if let Poll::Ready(inner) = binding.poll_result(&context) {
            assert!(inner.is_ok());
        } else {
            panic!("Did not receive a ready poll when expected.");
        }


        
    }
}