use std::task::Poll;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{
    protocol::{
        smachines::{common::{ServerStateMachine, StateMachineState}, container::State}, spec::traits::TimeObj,
    },
    token::{
        signature::{KeyChain, PublicKey},
        token::GenericToken,
    },
};

use super::{
    context::ServerContext,
    message::{DatabaseQuery, DatabaseResponse, ServerResponse, SvrMsg},
};

enum VerifyTokenState {
    Fresh,
    WaitingForPublicKey,
    StoreToken,
    WaitingForStore,

    Completed,
    Failed(PutTokenError),
}

pub struct PutTokenBinding<KC>
where
    KC: KeyChain,
{
    state: State<VerifyTokenState>,
    token: Option<GenericToken>,
    expiry: Option<DateTime<Utc>>,
    svc_entity_id: Uuid,
    signature: KC::Signature,
}

#[derive(Debug)]
pub enum PutTokenError {
    CycleRequired,
    StateMachineFailure(String),
    NoEntityFound,
    CouldNotVerify,
    OutsideOfTolerance,
}

impl<KC> PutTokenBinding<KC>
where
    KC: KeyChain,
{
    pub fn create(id: Uuid, token: GenericToken, signature: KC::Signature) -> Self {
        Self {
            signature,
            state: State::new(VerifyTokenState::Fresh),
            svc_entity_id: id,
            token: Some(token),
            expiry: None
        }
    }
    fn send_to_error(&mut self, error: PutTokenError) {
        self.state.handle().set(VerifyTokenState::Failed(error));
    }
}

#[derive(Debug, PartialEq)]
pub struct PutTokenResult {
    pub token: GenericToken,
    pub expiry: DateTime<Utc>
}

impl<KC> ServerStateMachine<SvrMsg, ServerResponse> for PutTokenBinding<KC>
where 
    KC: KeyChain
{
    type Error = PutTokenError;
    type Result = PutTokenResult;

    fn poll_transmit<C: ServerContext>(&mut self, ctx: &C) -> Option<SvrMsg>
    {
        let mut state = self.state.handle();
        match *state {
            VerifyTokenState::Fresh => {
                state.set(VerifyTokenState::WaitingForPublicKey);
                Some(SvrMsg::DbQuery(DatabaseQuery::GetPublicKey {
                    entity_id: self.svc_entity_id,
                }))
            }
            VerifyTokenState::StoreToken => {
                state.set(VerifyTokenState::WaitingForStore);

                // This will modify the token!
                self.token = Some(ctx.modify_token(self.token.take().unwrap()));
                self.expiry = Some(ctx.issue_expiry());

                Some(SvrMsg::DbQuery(DatabaseQuery::StoreToken { entity_id: self.svc_entity_id, token_hash: self.token.as_ref().unwrap().hash(), expiry: *self.expiry.as_ref().unwrap() }))
            }
            _ => None 
        }
    }

    fn input<C: ServerContext>(&mut self, ctx: &C, inner: ServerResponse) {

        let mut state = self.state.handle();

        match *state {
            
            /* Acquire the public key */
            VerifyTokenState::WaitingForPublicKey => {
                if let ServerResponse::DbResult(DatabaseResponse::NoEntityFound) = inner {
                    self.send_to_error(PutTokenError::NoEntityFound);
                    return;
                };

                let ServerResponse::DbResult(DatabaseResponse::PkDetails {
                    entity_id:_,
                    public,
                    last_renewal_time,
                }) = inner
                else {
                    self.send_to_error(PutTokenError::StateMachineFailure("The state machine should have received public key details but instead received a different message.".to_string()));
                    return;
                };

                if last_renewal_time
                    .seconds_since_epoch()
                    .abs_diff(ctx.current_time().seconds_since_epoch())
                    > ctx.key_renewal_period().as_secs()
                {
                    // We need to renew the key.
                    self.send_to_error(PutTokenError::CycleRequired);
                    return;
                }

                if !KC::Public::from_b64(&public).verify(self.token.as_ref().unwrap().as_bytes(), &self.signature) {
                    /* Could not verify the signature */
                    self.send_to_error(PutTokenError::CouldNotVerify);
                    return;
                }

                if !ctx.token_tolerance().check(&self.token.as_ref().unwrap(), ctx.current_time()) {
                    /* Not within tolerance. */
                    self.send_to_error(PutTokenError::OutsideOfTolerance);
                    return;
                }


                state.set(VerifyTokenState::StoreToken);
            }
            VerifyTokenState::WaitingForStore => {

                match inner {
                    ServerResponse::DbResult(result) => match  result {
                        DatabaseResponse::StoreError(x) => {
                            self.send_to_error(PutTokenError::StateMachineFailure(x));
                            return;
                        },
                        DatabaseResponse::StoreTokenSuccess => {

                            state.set(VerifyTokenState::Completed)
                        }
                        _ => {
                            state.set(VerifyTokenState::WaitingForStore)
                        }
                    }

                }
            }
            /* In these states we just ignore any sort of input. */
            _ => {}
        }
    }

    fn poll_result<C>(&mut self, _: &C) -> core::task::Poll<Result<PutTokenResult, Self::Error>> {
        if self.state.handle().completed() {
            self.state.take(); // Invalidate the state.
            Poll::Ready(Ok(PutTokenResult {
                token: self.token.take().expect("This cannot be polled succesfully multiple times"),
                expiry: self.expiry.take().expect("This future cannot be polled multiple times.")
            }))
        } else if self.state.handle().failed() {
            let VerifyTokenState::Failed(error) = self.state.take() else {
                unreachable!(); // We already checked this condition.
            };

            Poll::Ready(Err(error))
        } else {
            Poll::Pending
        }
    }
}



impl StateMachineState for VerifyTokenState {
    type Error = PutTokenError;
    fn failed(&self) -> bool {
        if let Self::Failed(_) = self {
            true
        } else {
            false
        }
    }
    fn completed(&self) -> bool {
        if let Self::Completed = self {
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

    use chrono::DateTime;
    use uuid::{uuid, Uuid};

    use crate::{protocol::{smachines::{common::ServerStateMachine, server::{context::ServerContext, message::{DatabaseQuery, DatabaseResponse, ServerResponse, SvrMsg}, put::PutTokenResult}}, spec::traits::TimeObj}, testing::{DummyKeyChain, DummyServerContext, ExampleProtocol, ExampleType}, token::{signature::{KeyChain, PrivateKey, PublicKey}, token::{FluidToken, TimestampToken}}};

    use super::{PutTokenBinding, VerifyTokenState};



    #[test]
    pub fn test_correct_put_token_run() {
        // Set up the binding, generate & sign a token.
        let (public_key, private_key) = DummyKeyChain::generate();
        let dummy = FluidToken::from_raw(ExampleProtocol(0), ExampleType(0), Uuid::nil(), DateTime::from_millis_since_epoch(0), [0u8; 32], [0u8; 16]);
        let signature = private_key.sign(&dummy.to_bytes()).unwrap();
        let mid = uuid!("3a964718-9731-4ac8-a3d0-4419917d018c");
        let mut binding: PutTokenBinding<DummyKeyChain> = PutTokenBinding::create(mid, dummy.generic().generic(), signature);
        let mut ctx = DummyServerContext::new();
    

        // Set the binding to have expiry times of 500ms
        ctx.expiry_times = Duration::from_millis(500);
        


        if let VerifyTokenState::Fresh = *binding.state.handle() {} else {
            panic!("Should have been in the fresh state to begin with.")
        };

        if let Some(SvrMsg::DbQuery(DatabaseQuery::GetPublicKey { entity_id })) = binding.poll_transmit(&ctx) {
            assert_eq!(entity_id, mid);
        } else {
            panic!("Should have executed a public key query.");
        }

        if let VerifyTokenState::WaitingForPublicKey = *binding.state.handle() {} else {
            panic!("Should have been in the public key stae to begin with.")
        };

        // Send the private key to the binding.
        binding.input(&ctx, ServerResponse::DbResult(DatabaseResponse::PkDetails { entity_id: mid, public: public_key.as_b64(), last_renewal_time: ctx.current_time() }));

        if let VerifyTokenState::StoreToken = *binding.state.handle() {} else {
            panic!("The binding should have been ready to store the token on the next poll.")
        };

        if let Some(SvrMsg::DbQuery(DatabaseQuery::StoreToken { entity_id, token_hash, expiry })) = binding.poll_transmit(&ctx) {
            assert_eq!(entity_id, mid);
            assert_eq!(dummy.hash(), token_hash);
            assert_eq!(expiry, DateTime::from_timestamp_millis(500).unwrap());


        } else {
            panic!("Binding not sending a token storage request.")
        }

        if let VerifyTokenState::WaitingForStore = *binding.state.handle() {} else {
            panic!("The binding should have been ready to store the token.")
        };

        // Send a succesful store to the binding.
        binding.input(&ctx, ServerResponse::DbResult(DatabaseResponse::StoreTokenSuccess));


        if let VerifyTokenState::Completed = *binding.state.handle() {} else {
            panic!("The binding is complete.")
        };



        if let Poll::Ready(inner) = binding.poll_result(&ctx) {
            assert_eq!(inner.unwrap(), PutTokenResult {
                token: dummy.generic().generic(),
                expiry: ctx.issue_expiry()
            });
        } else {
            panic!("Binding was not ready when it should have been.");
        }





        
    }
}