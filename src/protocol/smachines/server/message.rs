use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{token::{signature::{B64Public, KeyChain}, token::GenericToken}};


pub enum SvrMsg {
    DbQuery(DatabaseQuery)
}

pub enum DatabaseQuery
{
    GetPublicKey {
        entity_id: Uuid
    },
    CreateEntity {
        entity_id: Uuid,
        key: B64Public
    },
    StoreToken {
        entity_id: Uuid,
        token_hash: [u8; 32],
        expiry: DateTime<Utc>
    },
    CheckTokenValidity {
        token: GenericToken
    }
}


pub enum ServerResponse
{
    DbResult(DatabaseResponse)
}

pub enum DatabaseResponse
{
    PkDetails {
        entity_id: Uuid,
        public: B64Public,
        last_renewal_time: DateTime<Utc>
    },
    NoEntityFound,
    StoreTokenSuccess,
    StoreError(String),
    CreateEntitySuccess,
    SvcEntityConflict,
    TokenValidityResponse(bool),
    QueryError(String)
}