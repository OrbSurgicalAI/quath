use uuid::Uuid;

use crate::token::signature::KeyChain;


pub struct SvcEntity<KC, M>
where 
    KC: KeyChain
{
    pub id: Uuid,
    pub private: KC::Private,
    pub metadata: Option<M>
}