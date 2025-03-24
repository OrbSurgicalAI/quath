use std::{ops::Sub, time::Duration};

use uuid::Uuid;

use crate::{protocol::executor::{FixedByteRepr, TimeObj}, token::{signature::KeyChain, token::GenericToken}};


pub struct SvcEntity<KC, M>
where 
    KC: KeyChain
{
    pub id: Uuid,
    pub private: KC::Private,
    pub metadata: Option<M>
}

