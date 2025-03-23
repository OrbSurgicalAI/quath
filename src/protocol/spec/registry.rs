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

pub struct TokenTolerance {
    pub forward: Duration,
    pub backwards: Duration
}

impl TokenTolerance {
    pub fn check<D>(&self, token: &GenericToken, current: D) -> bool
    where 
        D: TimeObj + FixedByteRepr<8>
    {
        let token = D::from_fixed_repr(token.get_time_field());
        

        todo!()
    }
}

