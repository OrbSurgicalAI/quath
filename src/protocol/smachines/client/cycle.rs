use std::{task::Poll, time::Duration};

use http::{HeaderValue, StatusCode, header::AUTHORIZATION};
use serde::{Serialize, de};
use uuid::Uuid;

use crate::{
    protocol::{
        error::FluidError,
        executor::ProtocolCtx,
        http::prep_request,
        spec::registry::SvcEntity,
        web::{
            body::FullResponse,
            http::{form_cycle_request, form_service_entity_create_request},
            server::{create::RegisterVerdict, cycle::CycleVerdict, verdict::Verdict},
        },
    },
    token::signature::KeyChain,
};

use super::message::Message;

enum CycleState<KC>
where 
    KC: KeyChain
{
    /// This is a fresh pair of credentials and thus we need to
    /// run through the registration protocol.
    Fresh,
    /// Wait a certain amount of time.
    Wait(Duration),
    /// We are waiting for the registry service response.
    WaitingForCycleCompletion {
        new_private_key: KC::Private
    },

    Complete,
}

/// This is the protocol executor for when we want to register with the server.
pub struct CycleBinding<M, KC>
where
    KC: KeyChain,
{
    details: Option<SvcEntity<KC, M>>,
    state: Option<CycleState<KC>>
}

impl<M, KC> CycleBinding<M, KC>
where
    KC: KeyChain,
{
    pub fn from_svc_entity(details: SvcEntity<KC, M>) -> Self {
        Self {
            details: Some(details),
            state: Some(CycleState::Fresh)
        }
    }
    fn details_unchecked(&self) -> &SvcEntity<KC, M> {
        self.details.as_ref().unwrap()
    }
    /// This polls the registry binding for a transmission.
    pub fn poll_transmit<C, D>(&mut self, ctx: &C) -> Result<Option<Message>, FluidError>
    where
        C: ProtocolCtx<D>,
        M: Serialize,
        C::Protocol: Serialize,
    {
        match &self.state.as_ref().unwrap() {
            CycleState::Fresh => {
                /* We need to prepare the request and kick up our state. */
                let protocol = ctx.protocol();
                let details = self.details_unchecked();

                let (new_public, new_private ) = KC::generate();

                let mut request = form_cycle_request::<D, C::Protocol, KC, M>(ctx.connection(), &protocol, details.id, &new_public, &details.private, &details.metadata)?;

          
                /* Prepare this request, we will pass it to the caller to send out. */
                let serialized = prep_request(request)
                    .or(Err(FluidError::FailedFormingCycleResponse))?;

                // We are now waiting for the registry service response.
                self.state = Some(CycleState::WaitingForCycleCompletion { new_private_key: new_private });
                Ok(Some(Message::Request(serialized)))
            }
            CycleState::Wait(d) => {
                /* Switch back to fresh and instruct the caller to wait. */
                let d = *d;
                self.state = Some(CycleState::Fresh);
                Ok(Some(Message::Wait(d)))
            }
            CycleState::WaitingForCycleCompletion { .. } => {
                /* If we are still waiting there is nothing to transmit! */
                Ok(None)
            }
            CycleState::Complete => {
                /* If we are done there is nothing to transmit! */
                Ok(None)
            }
        }
    }
    pub fn handle_input<C, D>(&mut self, ctx: &C, response: FullResponse) -> Result<(), FluidError>
    where
        C: ProtocolCtx<D>,
    {
        match self.state.take().unwrap() {
            CycleState::Fresh => {
                /* In this state we are not expecting any output. */
                self.state = Some(CycleState::Fresh);
            }
            CycleState::WaitingForCycleCompletion { new_private_key } => {
                /* If we receive input here it is almost ceraintly the servers response */
                let result = CycleVerdict::try_from(response.status())?;
                match result {
                    CycleVerdict::Success => {
                        /* We are done. */
                        self.details.as_mut().unwrap().private = new_private_key;
                        self.state = Some(CycleState::Complete);
                    }
                    CycleVerdict::InternalServerError => {
                        /* We can recover from this. */
                        self.state = Some(CycleState::Wait(ctx.retry_cooldown()));
                    },
                    x => {
                        /* The others we cannot recover from. */
                        let verdict: Verdict<()> = x.into();
                        Err(FluidError::RegistrationFailed(
                            verdict
                                .to_json_string()
                                .or(Err(FluidError::RegistrationFailed(
                                    "Failed to form error".to_string(),
                                )))?,
                        ))?;
                    }
                }
            }
            CycleState::Wait(d) => {
                /* Nothing to do while we wait. */
                self.state = Some(CycleState::Wait(d));
            
            }
            CycleState::Complete => {
                /* Nothing to do, we are already done. */
                self.state = Some(CycleState::Complete);
            }
        }
        Ok(())
    }
    pub fn poll_result(&mut self) -> Poll<SvcEntity<KC, M>> {
        if let Some(CycleState::Complete) = self.state {
            Poll::Ready(self.details.take().expect("Once a result has been polled it cannot be polled again. In this case it seems like it was polled again."))
        } else {
            Poll::Pending
        }
    }
}



#[cfg(test)]
mod tests {
    use std::task::Poll;

    use http::{HeaderValue, header::AUTHORIZATION};
    use uuid::Uuid;

   

    use crate::{protocol::{executor::ProtocolCtx, smachines::client::{cycle::CycleState, message::Message}, spec::registry::SvcEntity, web::{body::FullResponse, http::form_cycle_response, server::cycle::CycleVerdict}}, testing::{DummyKeyChain, TestExecutor}, token::signature::KeyChain};

    use super::CycleBinding;

    #[test]
    pub fn test_unrecoverable_cycle_errors() {
        /* Tests a succesful run */

        let (_, privk) = DummyKeyChain::generate();
        let mut register_binding: CycleBinding<&str, DummyKeyChain> = CycleBinding::from_svc_entity(SvcEntity {
            id: Uuid::new_v4(),
            metadata: Some("hello"),
            private: privk
        });
        let context = TestExecutor::generic();

        // We should not be ready yet.
        assert!(register_binding.poll_result().is_pending());

        // Check to see if we are transmitting the registraton.
        let initial = register_binding.poll_transmit(&context).unwrap();
        if let Some(Message::Request(req)) = initial {
        } else {
            panic!("The register binding should have started by transmitting the request.");
        }

        // Verify the state is correct.
        if let Some(CycleState::WaitingForCycleCompletion { .. }) = register_binding.state {
        } else {
            panic!(
                "The service should have been waiting for a response yet that was not the state."
            );
        }

        // We send something the registry binding cannot recover from, this
        // should cause an error to be thrown here.
        let server_resp = form_cycle_response(CycleVerdict::Unauthorized).unwrap();
        assert!(
            register_binding
                .handle_input(&context, FullResponse::from_raw(server_resp))
                .is_err()
        );
    }

    #[test]
    pub fn run_register_with_internal_server_error() {
        /* Tests a succesful run */
        let (_, privk) = DummyKeyChain::generate();
        let mut register_binding: CycleBinding<&str, DummyKeyChain> = CycleBinding::from_svc_entity(SvcEntity {
            id: Uuid::new_v4(),
            metadata: Some("hello"),
            private: privk
        });
        let context = TestExecutor::generic();

       

        // We should not be ready yet.
        assert!(register_binding.poll_result().is_pending());

        // Check to see if we are transmitting the registraton.
        let initial = register_binding.poll_transmit(&context).unwrap();
        if let Some(Message::Request(req)) = initial {
        } else {
            panic!("The register binding should have started by transmitting the request.");
        }

        // Verify the state is correct.
        if let Some(CycleState::WaitingForCycleCompletion { .. }) = register_binding.state {
        } else {
            panic!(
                "The service should have been waiting for a response yet that was not the state."
            );
        }

        // The server approves it, this should be the end.
        let server_resp = form_cycle_response(CycleVerdict::InternalServerError).unwrap();
        register_binding
            .handle_input(&context, FullResponse::from_raw(server_resp))
            .unwrap();

        // Verify we have been put into a retries state.
        if let Some(CycleState::Wait(_)) = register_binding.state {
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
        if let Some(CycleState::Fresh) = register_binding.state {
        } else {
            panic!("The client should have re-entered the fresh state.");
        }


    }



    #[test]
    pub fn run_correct_register() {
        /* Tests a succesful run */
        let (_, privk) = DummyKeyChain::generate();
        let mut register_binding: CycleBinding<&str, DummyKeyChain> = CycleBinding::from_svc_entity(SvcEntity {
            id: Uuid::new_v4(),
            metadata: Some("hello"),
            private: privk.clone()
        });
        let context = TestExecutor::generic();

        // We should not be ready yet.
        assert!(register_binding.poll_result().is_pending());

        // Check to see if we are transmitting the registraton.
        let initial = register_binding.poll_transmit(&context).unwrap();
        if let Some(Message::Request(req)) = initial {
        } else {
            panic!("The register binding should have started by transmitting the request.");
        }

        // Verify the state is correct.
        if let Some(CycleState::WaitingForCycleCompletion { .. }) = register_binding.state {
        } else {
            panic!(
                "The service should have been waiting for a response yet that was not the state."
            );
        }

        // The server approves it, this should be the end.
        let server_resp = form_cycle_response(CycleVerdict::Success).unwrap();
        register_binding
            .handle_input(&context, FullResponse::from_raw(server_resp))
            .unwrap();

        // Verify the state is correct.
        if let Some(CycleState::Complete) = register_binding.state {
        } else {
            panic!("The service should have been completed by now but this was not the case..");
        }

        // Verify we can pull out the registration details.
        let Poll::Ready(new_entity) = register_binding.poll_result() else {
            panic!("The service was ready but did not yield any results.");
        };

        assert_ne!(new_entity.private.as_ref(), privk.as_ref());
    }
}
