use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{protocol::executor::TimeObj, token::{signature::KeyChain, token::GenericToken}};


pub enum SvrMsg {
    DbQuery(DatabaseQuery)
}

pub enum DatabaseQuery {
    GetPublicKey {
        entity_id: Uuid
    },
    StoreToken {
        entity_id: Uuid,
        token_hash: [u8; 32],
        expiry: DateTime<Utc>
    }
}


pub enum ServerResponse<KC>
where 
    KC: KeyChain
{
    DbResult(DatabaseResponse<KC>)
}

pub enum DatabaseResponse<KC>
where
    KC: KeyChain
{
    PkDetails {
        entity_id: Uuid,
        public: KC::Public,
        last_renewal_time: DateTime<Utc>
    },
    NoEntityFound,
    StoreSuccess,
    StoreError(String)
}