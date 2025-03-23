use uuid::Uuid;

use crate::{protocol::executor::TimeObj, token::signature::KeyChain};


pub enum SvrMsg {
    DbQuery(DatabaseQuery)
}

pub enum DatabaseQuery {
    GetPublicKey {
        entity_id: Uuid
    }
}


pub enum ServerResponse<KC, D>
where 
    KC: KeyChain
{
    DbResult(DatabaseResponse<KC, D>)
}

pub enum DatabaseResponse<KC, D>
where
    KC: KeyChain
{
    PkDetails {
        entity_id: Uuid,
        public: KC::Public,
        last_renewal_time: D
    },
    NoEntityFound
}