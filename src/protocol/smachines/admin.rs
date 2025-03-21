use std::marker::PhantomData;

use serde::Serialize;
use uuid::Uuid;

use crate::{protocol::web::body::FullResponse, token::signature::KeyChain};

use super::message::Message;


enum RegisterState {
    Idle,
    Complete
}

/// This is the protocol executor for when we want to register with the server.
pub struct RegisterBinding<M, KC>
where 
    KC: KeyChain
{
    id: Uuid,
    private: KC::Private,
    public: KC::Public,
    metadata: M,
    _type: PhantomData<D>,
    _wow: PhantomData<KC>
}

impl<KC> RegisterBinding<KC>
where 
    KC: KeyChain
{

    /// This will create a fresh register binding
    /// with a random [Uuid] and also a random keypair.
    pub fn generate(metadata: M) -> Self {
        Self::with_id(Uuid::new_v4(), metadata)
    }
    pub fn with_id(id: Uuid, metadata: M) -> Self {
        let (pubk, privk) = KC::generate();
        Self {
            id,
            private: privk,
            public: pubk
        }

    }
    pub fn poll_transmit(&mut self) -> Option<Message> {
        None
    }
    pub fn handle_input(&mut self, response: FullResponse) {

    }
}