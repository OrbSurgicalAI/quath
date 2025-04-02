use std::{task::Poll, time::Duration};

use http::HeaderValue;
use serde::Serialize;
use uuid::Uuid;

use crate::
    protocol::{
        error::FluidError, spec::traits::ProtocolCtx, web::{
            body::FullResponse,
            http::{form_service_entity_deletion_request, prep_request},
            server::{delete::DeletionVerdict, verdict::Verdict},
        }
    }
;

use super::message::Message;

enum DeleteState {
    /// This is a fresh pair of credentials and thus we need to
    /// run through the registration protocol.
    Fresh,
    /// Wait a certain amount of time.
    Wait(Duration),
    /// We are waiting for the registry service response.
    WaitingForServiceResponse,

    Deleted,
    NotFound
}

/// This is the protocol executor for when we want to register with the server.
pub struct DeletionBinding {
    id: Uuid,
    state: DeleteState,
    authorization: HeaderValue,
}

// TODO: Authorization id.
impl DeletionBinding {
    /// Creates a new deletion binding with a certain ID.
    pub fn new(id: Uuid, authorization: HeaderValue) -> Self {
        Self {
            id,
            authorization,
            state: DeleteState::Fresh,
        }
    }

    /// This polls the registry binding for a transmission.
    pub fn poll_transmit<C>(&mut self, ctx: &C) -> Result<Option<Message>, FluidError>
    where
        C: ProtocolCtx,
        C::Protocol: Serialize,
    {
        match &self.state {
            DeleteState::Fresh => {
                /* We need to prepare the request and kick up our state. */
                let request = form_service_entity_deletion_request(
                    ctx.connection(),
                    self.id,
                    self.authorization.clone(),
                )?;

                /* Prepare this request, we will pass it to the caller to send out. */
                let serialized = prep_request(request)
                    .or(Err(FluidError::FailedFormingDeletionResponse))?;

                // We are now waiting for the registry service response.
                self.state = DeleteState::WaitingForServiceResponse;
                Ok(Some(Message::Request(serialized)))
            },
            DeleteState::Wait(d) => {
                /* Switch back to fresh and instruct the caller to wait. */
                let d = *d;
                self.state = DeleteState::Fresh;
                Ok(Some(Message::Wait(d)))
            },
            DeleteState::WaitingForServiceResponse => {
                /* If we are still waiting there is nothing to transmit! */
                Ok(None)
            }
            DeleteState::Deleted => {
                /* If we are done there is nothing to transmit! */
                Ok(None)
            },
            DeleteState::NotFound => {
                /* No entity to delete so we are all good */
                Ok(None)
            }
        }
    }
    pub fn handle_input<C>(&mut self, ctx: &C, response: FullResponse) -> Result<(), FluidError>
    where
        C: ProtocolCtx,
    {
        match &self.state {
            DeleteState::Fresh => { /* In this state we are not expecting any output. */ }
            DeleteState::WaitingForServiceResponse => {
                /* If we receive input here it is almost ceraintly the servers response */
                let result: DeletionVerdict = DeletionVerdict::try_from(response.status())?;
                match result {
                    DeletionVerdict::Success => {
                        /* We are done. */
                        self.state = DeleteState::Deleted;
                    },
                    DeletionVerdict::NotFound => {
                        self.state = DeleteState::NotFound;
                    }
                    DeletionVerdict::InternalServerError => {
                        /* We can recover from this. */
                        self.state = DeleteState::Wait(ctx.retry_cooldown());
                    }
                    x => {
                        /* The others we cannot recover from. */
                        let verdict: Verdict<()> = x.into();
                        Err(FluidError::RegistrationFailed(
                            verdict
                                .to_json_string()
                                .or(Err(FluidError::DeletionFailed(
                                    "Failed to form error".to_string(),
                                )))?,
                        ))?;
                    }
                }
            }
            DeleteState::Wait(..) => { /* Nothing to do while we wait. */ }
            DeleteState::Deleted => { /* Nothing to do, we are already done. */ }
            DeleteState::NotFound => { /* Nothing to do, we are already done. */ }
        }
        Ok(())
    }
    /// This will yield (return a ready state)
    /// an option. If the option has an ID, the ID
    /// has been deleted, else there was nothing to delete
    /// (NOTFOUND)
    pub fn poll_deleted(&mut self) -> Poll<Option<Uuid>> {
        if let DeleteState::Deleted = self.state {
            Poll::Ready(Some(self.id))
        } else if let DeleteState::NotFound = self.state {
            Poll::Ready(None)  
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

    use crate::{
        protocol::{
            smachines::client::{delete::DeleteState, message::Message}, spec::traits::ProtocolCtx, web::{
                body::FullResponse, http::{form_deletion_response, form_register_response}, server::{create::RegisterVerdict, delete::DeletionVerdict},
            }
        },
        testing::{DummyKeyChain, TestExecutor},
    };

    use super::DeletionBinding;

    #[test]
    pub fn test_unrecoverable_deletion_errors() {
        /* Tests a succesful run */
        let mut register_binding = DeletionBinding::new(Uuid::new_v4(), HeaderValue::from_static("Bearer 123"));
        let context = TestExecutor::generic();

       

        // We should not be ready yet.
        assert!(register_binding.poll_deleted().is_pending());

        // Check to see if we are transmitting the registraton.
        let initial = register_binding.poll_transmit(&context).unwrap();
        if let Some(Message::Request(req)) = initial {
            assert_eq!(req.headers().get(AUTHORIZATION).unwrap(), "Bearer 123");
        } else {
            panic!("The register binding should have started by transmitting the request.");
        }

        // Verify the state is correct.
        if let DeleteState::WaitingForServiceResponse = register_binding.state {
        } else {
            panic!(
                "The service should have been waiting for a response yet that was not the state."
            );
        }

        // We send something the registry binding cannot recover from, this
        // should cause an error to be thrown here.
        let server_resp = form_deletion_response(DeletionVerdict::Unauthorized).unwrap();
        assert!(
            register_binding
                .handle_input(&context, FullResponse::from_raw(server_resp))
                .is_err()
        );
    }

    #[test]
    pub fn run_deletion_with_internal_server_error() {
        /* Tests a succesful run */

        let id_to_delete = Uuid::new_v4();

        let mut register_binding = DeletionBinding::new(id_to_delete, HeaderValue::from_static("Bearer 123"));
        let context = TestExecutor::generic();

       

        // We should not be ready yet.
        assert!(register_binding.poll_deleted().is_pending());

        // Check to see if we are transmitting the registraton.
        let initial = register_binding.poll_transmit(&context).unwrap();
        if let Some(Message::Request(req)) = initial {
            assert_eq!(req.headers().get(AUTHORIZATION).unwrap(), "Bearer 123");
        } else {
            panic!("The register binding should have started by transmitting the request.");
        }

        // Verify the state is correct.
        if let DeleteState::WaitingForServiceResponse = register_binding.state {
        } else {
            panic!(
                "The service should have been waiting for a response yet that was not the state."
            );
        }

        // The server approves it, this should be the end.
        let server_resp = form_deletion_response(DeletionVerdict::InternalServerError)
        .unwrap();
        register_binding
            .handle_input(&context, FullResponse::from_raw(server_resp))
            .unwrap();

        // Verify we have been put into a retries state.
        if let DeleteState::Wait(_) = register_binding.state {
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
        if let DeleteState::Fresh = register_binding.state {
        } else {
            panic!("The client should have re-entered the fresh state.");
        }

    
    }

    #[test]
    pub fn run_deletion_not_found() {
        /* Tests a succesful run */

        let id_to_delete = Uuid::new_v4();

        let mut register_binding = DeletionBinding::new(id_to_delete, HeaderValue::from_static("Bearer 123"));
        let context = TestExecutor::generic();

        // We should not be ready yet.
        assert!(register_binding.poll_deleted().is_pending());

        // Check to see if we are transmitting the registraton.
        let initial = register_binding.poll_transmit(&context).unwrap();
        if let Some(Message::Request(req)) = initial {
            assert_eq!(req.headers().get(AUTHORIZATION).unwrap(), "Bearer 123");
        } else {
            panic!("The register binding should have started by transmitting the request.");
        }

        // Verify the state is correct.
        if let DeleteState::WaitingForServiceResponse = register_binding.state {
        } else {
            panic!(
                "The service should have been waiting for a response yet that was not the state."
            );
        }

        // The server approves it, this should be the end.
        let server_resp = form_deletion_response(DeletionVerdict::NotFound).unwrap();
        register_binding
            .handle_input(&context, FullResponse::from_raw(server_resp))
            .unwrap();

        // Verify the state is correct.
        if let DeleteState::NotFound = register_binding.state {
        } else {
            panic!("The service should have been completed by now but this was not the case..");
        }

        // Verify we can pull out the registration details.
        let Poll::Ready(inner) = register_binding.poll_deleted() else {
            panic!("The service was ready but did not yield any results.");
            
        };
        // Since it was succesfully deleted, it should be returned here.
        assert_eq!(inner, None);
    }

    #[test]
    pub fn run_correct_deletion() {
        /* Tests a succesful run */

        let id_to_delete = Uuid::new_v4();

        let mut register_binding = DeletionBinding::new(id_to_delete, HeaderValue::from_static("Bearer 123"));
        let context = TestExecutor::generic();

        // We should not be ready yet.
        assert!(register_binding.poll_deleted().is_pending());

        // Check to see if we are transmitting the registraton.
        let initial = register_binding.poll_transmit(&context).unwrap();
        if let Some(Message::Request(req)) = initial {
            assert_eq!(req.headers().get(AUTHORIZATION).unwrap(), "Bearer 123");
        } else {
            panic!("The register binding should have started by transmitting the request.");
        }

        // Verify the state is correct.
        if let DeleteState::WaitingForServiceResponse = register_binding.state {
        } else {
            panic!(
                "The service should have been waiting for a response yet that was not the state."
            );
        }

        // The server approves it, this should be the end.
        let server_resp = form_deletion_response(DeletionVerdict::Success).unwrap();
        register_binding
            .handle_input(&context, FullResponse::from_raw(server_resp))
            .unwrap();

        // Verify the state is correct.
        if let DeleteState::Deleted = register_binding.state {
        } else {
            panic!("The service should have been completed by now but this was not the case..");
        }

        // Verify we can pull out the registration details.
        let Poll::Ready(inner) = register_binding.poll_deleted() else {
            panic!("The service was ready but did not yield any results.");
            
        };
        // Since it was succesfully deleted, it should be returned here.
        assert_eq!(inner, Some(id_to_delete));
    }
}
