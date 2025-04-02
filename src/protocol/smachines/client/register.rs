use std::{task::Poll, time::Duration};

use http::{header::AUTHORIZATION, HeaderValue, StatusCode};
use serde::Serialize;
use uuid::Uuid;

use crate::{
    protocol::{
        error::FluidError, spec::{registry::SvcEntity, traits::ProtocolCtx}, web::{
            body::FullResponse,
            http::{form_service_entity_create_request, prep_request},
            server::{create::RegisterVerdict, verdict::Verdict},
        }
    },
    token::signature::KeyChain,
};

use super::message::Message;

enum RegisterState {
    /// This is a fresh pair of credentials and thus we need to
    /// run through the registration protocol.
    Fresh,
    /// Wait a certain amount of time.
    Wait(Duration),
    /// We are waiting for the registry service response.
    WaitingForServiceResponse,

    Complete
}

/// This is the protocol executor for when we want to register with the server.
pub struct RegisterBinding<M, KC>
where
    KC: KeyChain,
{
    id: Uuid,
    private: Option<KC::Private>,
    public: KC::Public,
    metadata: Option<M>,
    state: RegisterState,
    authorization: HeaderValue
}

// TODO: Authorization id.
impl<M, KC> RegisterBinding<M, KC>
where
    KC: KeyChain,
    
{
    /// This will create a fresh register binding
    /// with a random [Uuid] and also a random keypair.
    pub fn generate(metadata: M, authorization: HeaderValue) -> Self {
        Self::generate_with_id(Uuid::new_v4(), metadata, authorization)
    }
    /// This will create a fresh pair of keys but with the user
    /// specified ID.
    pub fn generate_with_id(id: Uuid, metadata: M, authorization: HeaderValue) -> Self {
        let (pubk, privk) = KC::generate();
        Self {
            id,
            private: Some(privk),
            public: pubk,
            metadata: Some(metadata),
            state: RegisterState::Fresh,
            authorization
        }
    }
    pub fn id(&self) -> Uuid {
        self.id
    }
    /// This polls the registry binding for a transmission.
    pub fn poll_transmit<C>(&mut self, ctx: &C) -> Result<Option<Message>, FluidError>
    where
        C: ProtocolCtx,
        M: Serialize,
        C::Protocol: Serialize,
    {
        match &self.state {
            RegisterState::Fresh => {
                /* We need to prepare the request and kick up our state. */
                let protocol = ctx.protocol();
                let mut request: http::Request<
                    crate::protocol::web::payload::CreateServiceEntityRequest<
                        '_,
                        <C as ProtocolCtx>::Protocol,
                        M,
                        KC,
                    >,
                > = form_service_entity_create_request(
                    ctx.connection(),
                    self.id,
                    &protocol,
                    &self.public,
                    &self.metadata,
                )?;

                // Insert authorization.
                request.headers_mut().insert(AUTHORIZATION, self.authorization.clone());

                

                /* Prepare this request, we will pass it to the caller to send out. */
                let serialized = prep_request(request)
                    .or(Err(FluidError::FailedFormingEntityCreationRequest))?;

                // We are now waiting for the registry service response.
                self.state = RegisterState::WaitingForServiceResponse;
                Ok(Some(Message::Request(serialized)))
            },
            RegisterState::Wait(d) => {
                /* Switch back to fresh and instruct the caller to wait. */
                let d = *d;
                self.state = RegisterState::Fresh;
                Ok(Some(Message::Wait(d)))
            }
            RegisterState::WaitingForServiceResponse => {
                /* If we are still waiting there is nothing to transmit! */
                Ok(None)
            }
            RegisterState::Complete => {
                /* If we are done there is nothing to transmit! */
                Ok(None)
            }
        }
    }
    pub fn handle_input<C>(&mut self, ctx: &C, response: FullResponse) -> Result<(), FluidError>
    where
        C: ProtocolCtx,
    {
        match &self.state {
            RegisterState::Fresh => { /* In this state we are not expecting any output. */ }
            RegisterState::WaitingForServiceResponse => {
                /* If we receive input here it is almost ceraintly the servers response */
                let result = parse_initial_service_response(response)?;
                match result {
                    RegisterVerdict::Success => {
                        /* We are done. */
                        self.state = RegisterState::Complete;
                    }
                    RegisterVerdict::Conflict { .. } => {
                        /* We can recover from this. */
                        self.id = Uuid::new_v4(); // regenerate the ID.
                        self.state = RegisterState::Wait(ctx.retry_cooldown());
                    },
                    RegisterVerdict::InternalServerError { .. } => {
                        /* We can recover from this. */
                        self.state = RegisterState::Wait(ctx.retry_cooldown());
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
            },
            RegisterState::Wait(..) => {
                /* Nothing to do while we wait. */
            }
            RegisterState::Complete => {
                /* Nothing to do, we are already done. */
            }
        }
        Ok(())
    }
    pub fn get_registration(&mut self) -> Poll<SvcEntity<KC, M>> {
        if let RegisterState::Complete = self.state {
            Poll::Ready(SvcEntity { id: self.id, private: self.private.take().expect("Once a binding is complete it cannot be polled twice."), metadata: self.metadata.take() })
        } else {
            Poll::Pending
        }
    }
}

fn parse_initial_service_response(response: FullResponse) -> Result<RegisterVerdict, FluidError> {
    if response.status() == StatusCode::CREATED {
        /* The entity was created, operation succesful! */
        Ok(RegisterVerdict::Success)
    } else if response.status() == StatusCode::INTERNAL_SERVER_ERROR {
        /* The server had a problem */
        Ok(RegisterVerdict::InternalServerError)
    } else if response.status() == StatusCode::CONFLICT {
        /* This ID is in use. */
        Ok(RegisterVerdict::Conflict {
            conflicting_id: Uuid::nil(),
        })
    } else if response.status() == StatusCode::NOT_IMPLEMENTED {
        /* The requested protocol is not implemented on the server. */
        Ok(RegisterVerdict::NotImplemented(String::new()))
    } else if response.status() == StatusCode::UNPROCESSABLE_ENTITY {
        /* The request was malformed. */
        Ok(RegisterVerdict::KeyProcessError)
    } else {
        Err(FluidError::CreationResponseMalformed)
    }
}


#[cfg(test)]
mod tests {
    use std::task::Poll;

    use http::{header::AUTHORIZATION, HeaderValue};
    use uuid::Uuid;

    use crate::{protocol::{smachines::client::{message::Message, register::RegisterState}, spec::traits::ProtocolCtx, web::{body::FullResponse, http::form_register_response, server::create::RegisterVerdict}}, testing::{DummyKeyChain, TestExecutor}};

    use super::RegisterBinding;

   

    #[test]
    pub fn test_unrecoverable_registry_errors() {

        /* Tests a succesful run */
        let mut register_binding: RegisterBinding<&str, DummyKeyChain> = RegisterBinding::generate("hello", HeaderValue::from_static("Bearer 123"));
        let context  = TestExecutor::generic();


        // We should not be ready yet.
        assert!(register_binding.get_registration().is_pending());

        // Check to see if we are transmitting the registraton.
        let initial = register_binding.poll_transmit(&context).unwrap();
        if let Some(Message::Request(req)) = initial {
            assert_eq!(req.headers().get(AUTHORIZATION).unwrap(), "Bearer 123");
        } else {
            panic!("The register binding should have started by transmitting the request.");
        }

        // Verify the state is correct.
        if let RegisterState::WaitingForServiceResponse = register_binding.state {} else {
            panic!("The service should have been waiting for a response yet that was not the state.");
        }
       
        // We send something the registry binding cannot recover from, this
        // should cause an error to be thrown here.
        let server_resp = form_register_response(RegisterVerdict::KeyProcessError).unwrap();
        assert!(register_binding.handle_input(&context, FullResponse::from_raw(server_resp)).is_err());

      

        
    }

    #[test]
    pub fn run_register_with_internal_server_error() {

        /* Tests a succesful run */
        let mut register_binding: RegisterBinding<&str, DummyKeyChain> = RegisterBinding::generate("hello", HeaderValue::from_static("Bearer 123"));
        let context  = TestExecutor::generic();

        let initial_id = register_binding.id();

        // We should not be ready yet.
        assert!(register_binding.get_registration().is_pending());

        // Check to see if we are transmitting the registraton.
        let initial = register_binding.poll_transmit(&context).unwrap();
        if let Some(Message::Request(req)) = initial {
            assert_eq!(req.headers().get(AUTHORIZATION).unwrap(), "Bearer 123");
        } else {
            panic!("The register binding should have started by transmitting the request.");
        }

        // Verify the state is correct.
        if let RegisterState::WaitingForServiceResponse = register_binding.state {} else {
            panic!("The service should have been waiting for a response yet that was not the state.");
        }
       
        // The server approves it, this should be the end.
        let server_resp = form_register_response(RegisterVerdict::InternalServerError).unwrap();
        register_binding.handle_input(&context, FullResponse::from_raw(server_resp)).unwrap();

        // Verify we have been put into a retries state.
        if let RegisterState::Wait(_) = register_binding.state {} else {
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
        if let RegisterState::Fresh = register_binding.state {} else {
            panic!("The client should have re-entered the fresh state.");
        }
        
        // Make sure these are actually different.
        assert_eq!(initial_id, register_binding.id());

        
    }

    #[test]
    pub fn run_conflicting_register() {

        /* Tests a succesful run */
        let mut register_binding: RegisterBinding<&str, DummyKeyChain> = RegisterBinding::generate("hello", HeaderValue::from_static("Bearer 123"));
        let context  = TestExecutor::generic();

        let initial_id = register_binding.id();

        // We should not be ready yet.
        assert!(register_binding.get_registration().is_pending());

        // Check to see if we are transmitting the registraton.
        let initial = register_binding.poll_transmit(&context).unwrap();
        if let Some(Message::Request(req)) = initial {
            assert_eq!(req.headers().get(AUTHORIZATION).unwrap(), "Bearer 123");
        } else {
            panic!("The register binding should have started by transmitting the request.");
        }

        // Verify the state is correct.
        if let RegisterState::WaitingForServiceResponse = register_binding.state {} else {
            panic!("The service should have been waiting for a response yet that was not the state.");
        }
       
        // The server approves it, this should be the end.
        let server_resp = form_register_response(RegisterVerdict::Conflict { conflicting_id: Uuid::nil() }).unwrap();
        register_binding.handle_input(&context, FullResponse::from_raw(server_resp)).unwrap();

        // Verify we have been put into a retries state.
        if let RegisterState::Wait(_) = register_binding.state {} else {
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
        if let RegisterState::Fresh = register_binding.state {} else {
            panic!("The client should have re-entered the fresh state.");
        }
        
        // Make sure these are actually different.
        assert_ne!(initial_id, register_binding.id());

        
    }


    #[test]
    pub fn run_correct_register() {

        /* Tests a succesful run */
        let mut register_binding: RegisterBinding<&str, DummyKeyChain> = RegisterBinding::generate("hello", HeaderValue::from_static("Bearer 123"));
        let context  = TestExecutor::generic();

        // We should not be ready yet.
        assert!(register_binding.get_registration().is_pending());

        // Check to see if we are transmitting the registraton.
        let initial = register_binding.poll_transmit(&context).unwrap();
        if let Some(Message::Request(req)) = initial {
            assert_eq!(req.headers().get(AUTHORIZATION).unwrap(), "Bearer 123");
        } else {
            panic!("The register binding should have started by transmitting the request.");
        }

        // Verify the state is correct.
        if let RegisterState::WaitingForServiceResponse = register_binding.state {} else {
            panic!("The service should have been waiting for a response yet that was not the state.");
        }
       
        // The server approves it, this should be the end.
        let server_resp = form_register_response(RegisterVerdict::Success).unwrap();
        register_binding.handle_input(&context, FullResponse::from_raw(server_resp)).unwrap();

        // Verify the state is correct.
        if let RegisterState::Complete = register_binding.state {} else {
            panic!("The service should have been completed by now but this was not the case..");
        }

        // Verify we can pull out the registration details.
        let Poll::Ready(_) = register_binding.get_registration() else {
            panic!("The service was ready but did not yield any results.");
        };
    }
}