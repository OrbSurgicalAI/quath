use std::task::Poll;

use uuid::Uuid;

use crate::{protocol::{executor::{FixedByteRepr, TimeObj}, smachines::container::State}, token::{signature::{KeyChain, PublicKey}, token::{GenericToken, TimestampToken}}};

use super::{context::ServerContext, message::{DatabaseQuery, DatabaseResponse, ServerResponse, SvrMsg}};


enum VerifyTokenState {
    Fresh,
    WaitingForPublicKey,
    StoreToken,
    WaitingForStore,

    Completed(bool),
    Failed(PutTokenError)
}


pub struct PutTokenBinding<KC>
where   
    KC: KeyChain
{
    state: Option<VerifyTokenState>,
    token: GenericToken,
    svc_entity_id: Uuid,
    signature: KC::Signature
}


pub enum PutTokenError {
    CycleRequired,
    StateMachineFailure(String),
    NoEntityFound,
    CouldNotVerify,
    OutsideOfTolerance
}

impl<KC> PutTokenBinding<KC>
where 
    KC: KeyChain
{
    pub fn create(id: Uuid, token: GenericToken, signature: KC::Signature) -> Self {
        Self {
            signature,
            state: Option::Some(VerifyTokenState::Fresh),
            svc_entity_id: id,
            token
        }
    }
    fn send_to_error(&mut self, error: PutTokenError) {
        self.state = Some(VerifyTokenState::Failed(error));
    }
    pub fn poll_transmit(&mut self) -> Option<SvrMsg> {

        match self.state.take().unwrap() {
            VerifyTokenState::Fresh => {
                self.state = Some(VerifyTokenState::WaitingForPublicKey);
                Some(SvrMsg::DbQuery(DatabaseQuery::GetPublicKey { entity_id: self.svc_entity_id }))
            },
            VerifyTokenState::Completed(b) => {
                self.state = Some(VerifyTokenState::Completed(b));
                None
            }
            VerifyTokenState::Failed(f) => {
                self.state = Some(VerifyTokenState::Failed(f));
                None
            }
            VerifyTokenState::WaitingForPublicKey => {
                self.state = Some(VerifyTokenState::WaitingForPublicKey);
                None
            }
        }
    }
    pub fn handle_input<C>(&mut self, ctx: &C, message: Option<ServerResponse<KC, C::Time>>)
    where  
        C: ServerContext,
        C::Time: TimeObj + FixedByteRepr<8>
    {
        let Some(inner) = message else { return };
        
        match self.state.take().unwrap() {
            /* In these states we just ignore any sort of input. */
            VerifyTokenState::Fresh => {
                self.state = Some(VerifyTokenState::Fresh);
            }
            VerifyTokenState::Completed(b) => {
                self.state = Some(VerifyTokenState::Completed(b));
            },
            VerifyTokenState::Failed(f) => {
                self.state = Some(VerifyTokenState::Failed(f));
            }
            /* Acquire the public key */
            VerifyTokenState::WaitingForPublicKey => {

                if let ServerResponse::DbResult(DatabaseResponse::NoEntityFound) = inner {
                    self.send_to_error(PutTokenError::NoEntityFound);
                    return;
                };

                let ServerResponse::DbResult(DatabaseResponse::PkDetails { entity_id, public, last_renewal_time }) = inner else {
                    self.send_to_error(PutTokenError::StateMachineFailure("The state machine should have received public key details but instead received a different message.".to_string()));
                    return;
                };

                if last_renewal_time.seconds_since_epoch().abs_diff(ctx.current_time().seconds_since_epoch()) > ctx.key_renewal_period().as_secs() {
                    // We need to renew the key.
                    self.send_to_error(PutTokenError::CycleRequired);
                    return;
                }

                if !public.verify(self.token.as_bytes(), &self.signature) {
                    /* Could not verify the signature */
                    self.send_to_error(PutTokenError::CouldNotVerify);
                    return;
                }

                
                if !ctx.token_tolerance().check(&self.token, ctx.current_time()) {
                    /* Not within tolerance. */
                    self.send_to_error(PutTokenError::OutsideOfTolerance);
                    return;
                }


                self.state = Some(VerifyTokenState::StoreToken);
            }
            VerifyTokenState::StoreToken => {
                self.state = Some(VerifyTokenState::StoreToken);
            }
            VerifyTokenState::WaitingForStore => {
                self.state = Some(VerifyTokenState::WaitingForStore)
            }
        }
        

    }
    fn is_failed(&self) -> bool {
        if let Some(VerifyTokenState::Failed(_)) = self.state {
            true
        } else {
            false
        }
    }
    pub fn poll_result(&mut self) -> Poll<Result<GenericToken, PutTokenError>> {
        if self.is_failed() {
            let Some(VerifyTokenState::Failed(error)) = self.state.take() else {
                panic!("Error");
            };
            
            Poll::Ready(Err(error))
        } else {
            Poll::Pending
        }
    }
}