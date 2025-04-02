use std::{task::Poll, time::Duration};

use chrono::{DateTime, Utc};
use http::{HeaderValue, StatusCode, header::AUTHORIZATION};
use serde::{Serialize, de};
use uuid::Uuid;

use crate::{
    protocol::{
        error::FluidError,
        spec::{registry::SvcEntity, traits::{FixedByteRepr, ProtocolCtx, TimeObj}},
        web::{
            body::FullResponse, container::rfc3339::Rfc3339, http::{form_cycle_request, form_service_entity_create_request, form_token_put, prep_request}, payload::PostTokenResponse, server::{create::RegisterVerdict, cycle::CycleVerdict, verdict::Verdict}
        },
    },
    token::{signature::{KeyChain, PrivateKey}, token::{AliveToken, FluidToken, TimestampToken}},
};

use super::message::Message;

enum TokenState
{
    /// This is a fresh pair of credentials and thus we need to
    /// run through the registration protocol.
    Fresh,
    /// Wait a certain amount of time.
    Wait(Duration),
    /// We are waiting for the registry service response.
    WaitingForTokenConfirmation {
        pending: TimestampToken
    },

    CycleRequired
}

/// This is the protocol executor for when we want to register with the server.
/// 
/// NOTE: This binding is fused, meaning that it CAN be reused.
pub struct TokenBinding<M, KC>
where
    KC: KeyChain,
{
    details: SvcEntity<KC, M>,
    token: Option<AliveToken>,
    state: Option<TokenState>
}

impl<M, KC> TokenBinding<M, KC>
where
    KC: KeyChain
{
    pub fn from_svc_entity(details: SvcEntity<KC, M>) -> Self {
        Self {
            details,
            token: None,
            state: Some(TokenState::Fresh)
        }
    }
    pub fn into_svc_entity(self) -> SvcEntity<KC, M> {
        self.details
    }

    /// Generates a specialized token and then proceeds to sign it. This
    /// process will convert the special token into a generic one.
    fn gen_token_and_sign<CTX>(
        &mut self,
        ctx: &CTX
    ) -> Result<(TimestampToken, KC::Signature), FluidError>
    where
        CTX::TokenType: FixedByteRepr<1>,
        CTX: ProtocolCtx,
        CTX::Protocol: FixedByteRepr<1>,
    {
        let token =
            FluidToken::<CTX::TokenType, CTX::Protocol>::generate(ctx, self.details.id, ctx.get_token_type(), ctx.protocol());
        let signature = self
            .details
            .private
            .sign(&token.to_bytes())
            .or(Err(FluidError::PrivateKeySigningFailure))?;

        Ok((token.generic(), signature))
    }
    /// Checks if the current token is valid.
    pub fn is_current_valid<CTX>(&self, ctx: &CTX) -> bool
    where
        CTX: ProtocolCtx
    {
        if let Some(token) = &self.token {
            token.is_alive(ctx)
        } else {
            false // we have no token so naturally it is not valid.
        }
    }
    /// This polls the registry binding for a transmission.
    pub fn poll_transmit<C>(&mut self, ctx: &C) -> Result<Option<Message>, FluidError>
    where
        C: ProtocolCtx,
        M: Serialize,
        C::Protocol: Serialize + FixedByteRepr<1>,
        C::TokenType: FixedByteRepr<1>
    {
        match &self.state.as_ref().unwrap() {
            TokenState::Fresh => {
                /* We need to prepare the request and kick up our state. */
            
                if self.is_current_valid(ctx) {
                    /* If the current token is valid we do not have to do anything. */
                    Ok(None)
                } else {
                    let (token, signature) = self.gen_token_and_sign(ctx)?;
                    let form = form_token_put::<KC>(ctx.connection(), &token, &signature)?;
                    let serialized = prep_request(form).or(Err(FluidError::FailedFormingTokenPostRequest))?;


                

                    // We are now waiting for the registry service response.
                    self.state = Some(TokenState::WaitingForTokenConfirmation { pending: token });
                    Ok(Some(Message::Request(serialized)))
                }

                
            }
            TokenState::Wait(d) => {
                /* Switch back to fresh and instruct the caller to wait. */
                let d = *d;
                self.state = Some(TokenState::Fresh);
                Ok(Some(Message::Wait(d)))
            }
            TokenState::WaitingForTokenConfirmation { .. } => {
                /* If we are still waiting there is nothing to transmit! */
                Ok(None)
            }
            TokenState::CycleRequired => {
                /* If we are done there is nothing to transmit! */
                Ok(None)
            }
        }
    }
    pub fn handle_input<C>(&mut self, ctx: &C, response: FullResponse) -> Result<(), FluidError>
    where
        C: ProtocolCtx
    {
        match self.state.take().unwrap() {
            TokenState::Fresh => {
                /* In this state we are not expecting any output. */
                self.state = Some(TokenState::Fresh);
            }
            TokenState::WaitingForTokenConfirmation { .. } => {
                /* If we receive input here it is almost ceraintly the servers response */
                let result: ExecResponse = parse_stamp_response(response)?;
              
                match result {
                    ExecResponse::Return { token, expiry } => {
                        // TODO: Verify fields line up.
                        println!("Returned: {:?} {:?} {:?}", token.get_bytes(), expiry.to_rfc3339().to_string(), token.timestamp());
                        println!("Wow {} {}", token.timestamp().seconds_since_epoch() + expiry.seconds_since_epoch(), ctx.current_time().seconds_since_epoch());
                        self.token = Some(AliveToken::from_raw(token, expiry));
                        println!("IsVALID: {:?}", self.is_current_valid(ctx));
                        
                        self.state = Some(TokenState::Fresh);
                    },
                    ExecResponse::Recoverable => {
                        self.state = Some(TokenState::Wait(ctx.retry_cooldown()));
                    }
                    ExecResponse::Invalid(_) => {
                        /* Unrecoverable. */
                        Err(FluidError::FailedFormingTokenPostResponse)?;
                    },
                    ExecResponse::CycleRequired => {
                        self.state = Some(TokenState::CycleRequired)
                    }
                }
            }
            TokenState::Wait(d) => {
                /* Nothing to do while we wait. */
                self.state = Some(TokenState::Wait(d));
            
            }
            TokenState::CycleRequired => {
                /* Nothing to do, we are already done. */
                self.state = Some(TokenState::CycleRequired);
            }

        }
        Ok(())
    }
    pub fn poll_result<C>(&mut self, ctx: &C) -> TokenPoll<'_>
    where 
        C: ProtocolCtx
    {
        if let Some(TokenState::CycleRequired) = self.state {
            TokenPoll::CycleRequired
        } else if self.is_current_valid(ctx) {
            TokenPoll::Ready(self.token.as_ref().unwrap())
        } else {
            TokenPoll::Pending
        }
    }
}

pub enum TokenPoll<'a> {
    Ready(&'a AliveToken),
    CycleRequired,
    Pending
}

impl TokenPoll<'_> {
    pub fn is_pending(&self) -> bool {
        if let Self::Pending = self {
            true
        } else {
            false
        }
    }
}

pub enum ExecResponse {
    Return {
        token: TimestampToken,
        expiry: DateTime<Utc>
    },
    CycleRequired,
    Recoverable,
    Invalid(StatusCode),
}


/// Parse the stamp response into a usable set of data.
fn parse_stamp_response(raw: FullResponse) -> Result<ExecResponse, FluidError>
{
    if raw.status() == StatusCode::RESET_CONTENT {
        // Needs a cycle.
        Ok(ExecResponse::CycleRequired)
    } else if [StatusCode::FORBIDDEN, StatusCode::CONFLICT, StatusCode::INTERNAL_SERVER_ERROR].contains(&raw.status()) {
        Ok(ExecResponse::Recoverable)
    } else if raw.status() == StatusCode::CREATED {
        // Created the token.
        let ptr: PostTokenResponse<DateTime<Utc>> = raw
            .parse_json()
            .map_err(|e| FluidError::FailedDeserializingPtr(e))?;
        Ok(ExecResponse::Return { token: ptr.token.inner(), expiry: ptr.expiry.inner() })
    } else {
        Ok(ExecResponse::Invalid(raw.status()))
    }
}



#[cfg(test)]
mod tests {
    use std::task::Poll;

    use chrono::DateTime;
    use http::{HeaderValue, header::AUTHORIZATION};
    use uuid::Uuid;

   

    use crate::{protocol::{smachines::client::{message::Message, token::{TokenPoll, TokenState}}, spec::{registry::SvcEntity, traits::{ProtocolCtx, TimeObj}}, web::{body::FullResponse, http::form_post_token_response, server::token::TokenVerdict}}, testing::{DummyKeyChain, TestExecutor, TestTimeStub}, token::{signature::KeyChain, token::TimestampToken}};

    use super::TokenBinding;

    #[test]
    pub fn test_unrecoverable_token_post_errors() {
        /* Tests a succesful run */

        let (_, privk) = DummyKeyChain::generate();
        let mut register_binding: TokenBinding<&str, DummyKeyChain> = TokenBinding::from_svc_entity(SvcEntity {
            id: Uuid::new_v4(),
            metadata: Some("hello"),
            private: privk
        });
        let context = TestExecutor::generic();

        // We should not be ready yet.
        assert!(register_binding.poll_result(&context).is_pending());

        // Check to see if we are transmitting the registraton.
        let initial = register_binding.poll_transmit(&context).unwrap();
        if let Some(Message::Request(req)) = initial {
        } else {
            panic!("The register binding should have started by transmitting the request.");
        }

        // Verify the state is correct.
        if let Some(TokenState::WaitingForTokenConfirmation { .. }) = register_binding.state {
        } else {
            panic!(
                "The service should have been waiting for a response yet that was not the state."
            );
        }

        // We send something the registry binding cannot recover from, this
        // should cause an error to be thrown here.
        let server_resp = form_post_token_response(TokenVerdict::BadTokenFormat).unwrap();
        assert!(
            register_binding
                .handle_input(&context, FullResponse::from_raw(server_resp))
                .is_err()
        );
    }

    #[test]
    pub fn test_recoverable_token_post_error() {
        /* Tests a succesful run */
        let (_, privk) = DummyKeyChain::generate();
        let mut register_binding: TokenBinding<&str, DummyKeyChain> = TokenBinding::from_svc_entity(SvcEntity {
            id: Uuid::new_v4(),
            metadata: Some("hello"),
            private: privk
        });
        let context = TestExecutor::generic();

       

        // We should not be ready yet.
        assert!(register_binding.poll_result(&context).is_pending());

        // Check to see if we are transmitting the registraton.
        let initial = register_binding.poll_transmit(&context).unwrap();
        if let Some(Message::Request(req)) = initial {
        } else {
            panic!("The register binding should have started by transmitting the request.");
        }

        // Verify the state is correct.
        if let Some(TokenState::WaitingForTokenConfirmation { .. }) = register_binding.state {
        } else {
            panic!(
                "The service should have been waiting for a response yet that was not the state."
            );
        }

        // The server approves it, this should be the end.
        let server_resp = form_post_token_response(TokenVerdict::InternalServerError).unwrap();
        register_binding
            .handle_input(&context, FullResponse::from_raw(server_resp))
            .unwrap();

        // Verify we have been put into a retries state.
        if let Some(TokenState::Wait(_)) = register_binding.state {
        } else {
            panic!("The service should have been completed by now but this was not the case..");
        }

        // Make sure
        if let Some(Message::Wait(d)) = register_binding.poll_transmit(&context).unwrap() {
            assert_eq!(d, context.retry_cooldown());
        } else {
            panic!("The registry binding should have returned a wait instruction but did not.")
        }

        // Right here we would actually perform a real wait.

        // Now we want to make sure the client was put back into the fresh state.
        if let Some(TokenState::Fresh) = register_binding.state {
        } else {
            panic!("The client should have re-entered the fresh state.");
        }


    }



    #[test]
    pub fn run_token_post_succesful() {
        /* Tests a succesful run */
        let (_, privk) = DummyKeyChain::generate();
        let mut register_binding: TokenBinding<&str, DummyKeyChain> = TokenBinding::from_svc_entity(SvcEntity {
            id: Uuid::new_v4(),
            metadata: Some("hello"),
            private: privk.clone()
        });
        let context = TestExecutor::generic();

        // We should not be ready yet.
        assert!(register_binding.poll_result(&context).is_pending());

        // Check to see if we are transmitting the registraton.
        let initial = register_binding.poll_transmit(&context).unwrap();
        if let Some(Message::Request(req)) = initial {
        } else {
            panic!("The register binding should have started by transmitting the request.");
        }

        // Verify the state is correct.
        let mut pending_token: TimestampToken;
        if let Some(TokenState::WaitingForTokenConfirmation { pending }) = &register_binding.state {
            pending_token = pending.clone();
        } else {
            panic!(
                "The service should have been waiting for a response yet that was not the state."
            );
        }

        // println!("Premod: {:?}", pending_token.get_bytes());

        // let pending_token = pending_token.randomize_body().randomize_body();

        // println!("Modified: {:?}", pending_token.get_bytes());

        // The server approves it, this should be the end.
        let server_resp = form_post_token_response(TokenVerdict::Success { token: pending_token.clone().randomize_body(), expiry: DateTime::from_millis_since_epoch(100 * 1000) }).unwrap();
        register_binding
            .handle_input(&context, FullResponse::from_raw(server_resp))
            .unwrap();

        // Verify the state is correct.
        if let Some(TokenState::Fresh) = &register_binding.state {
        } else {
            panic!("The service should have been completed by now but this was not the case..");
        }

        // Verify we can pull out the registration details.
        let TokenPoll::Ready(new_entity) = register_binding.poll_result(&context) else {
            panic!("The service was ready but did not yield any results.");
        };

        assert_ne!(new_entity.token().get_bytes(), pending_token.get_bytes());
    }
}
