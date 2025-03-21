use std::{marker::PhantomData, task::Poll, time::Duration};

use http::StatusCode;
use serde::Serialize;
use uuid::Uuid;

use crate::{
    protocol::{
        error::FluidError, executor::ProtocolCtx, http::prep_request, spec::registry::SvcEntity, web::{
            body::FullResponse,
            http::form_service_entity_create_request,
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

    Complete,
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
    state: Option<RegisterState>,
}

// TODO: Authorization id.
impl<M, KC> RegisterBinding<M, KC>
where
    KC: KeyChain,
{
    /// This will create a fresh register binding
    /// with a random [Uuid] and also a random keypair.
    pub fn generate(metadata: M) -> Self {
        Self::generate_with_id(Uuid::new_v4(), metadata)
    }
    /// This will create a fresh pair of keys but with the user
    /// specified ID.
    pub fn generate_with_id(id: Uuid, metadata: M) -> Self {
        let (pubk, privk) = KC::generate();
        Self {
            id,
            private: Some(privk),
            public: pubk,
            metadata: Some(metadata),
            state: Some(RegisterState::Fresh),
        }
    }
    /// This polls the registry binding for a transmission.
    pub fn poll_transmit<C, D>(&mut self, ctx: &C) -> Result<Option<Message>, FluidError>
    where
        C: ProtocolCtx<D>,
        M: Serialize,
        C::Protocol: Serialize,
    {
        match self.state.as_ref().unwrap() {
            RegisterState::Fresh => {
                /* We need to prepare the request and kick up our state. */
                let protocol = ctx.protocol();
                let request: http::Request<
                    crate::protocol::web::payload::CreateServiceEntityRequest<
                        '_,
                        <C as ProtocolCtx<D>>::Protocol,
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

                /* Prepare this request, we will pass it to the caller to send out. */
                let serialized = prep_request(request)
                    .or(Err(FluidError::FailedFormingEntityCreationRequest))?;

                // We are now waiting for the registry service response.
                self.state = Some(RegisterState::WaitingForServiceResponse);
                Ok(Some(Message::Request(serialized)))
            },
            RegisterState::Wait(d) => {
                /* Switch back to fresh and instruct the caller to wait. */
                let d = *d;
                self.state = Some(RegisterState::Fresh);
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
    pub fn handle_input<C, D>(&mut self, ctx: &C, response: FullResponse) -> Result<(), FluidError>
    where
        C: ProtocolCtx<D>,
    {
        match self.state.as_ref().unwrap() {
            RegisterState::Fresh => { /* In this state we are not expecting any output. */ }
            RegisterState::WaitingForServiceResponse => {
                /* If we receive input here it is almost ceraintly the servers response */
                let result = parse_initial_service_response(response)?;
                match result {
                    RegisterVerdict::Success => {
                        /* We are done. */
                        self.state = Some(RegisterState::Complete);
                    }
                    RegisterVerdict::Conflict { .. } => {
                        /* We can recover from this. */
                        self.id = Uuid::new_v4(); // regenerate the ID.
                        self.state = Some(RegisterState::Wait(ctx.retry_cooldown()));
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
        if let Some(RegisterState::Complete) = self.state {
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
    use crate::testing::DummyKeyChain;

    use super::RegisterBinding;



    #[test]
    pub fn run_correct_register() {

        let register_binding: RegisterBinding<&str, DummyKeyChain> = RegisterBinding::generate("hello");

    }
}