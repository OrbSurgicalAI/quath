use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{protocol::spec::time::MsSinceEpoch, token::{signature::{B64Public, KeyChain}, token::GenericToken}};


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
        expiry: MsSinceEpoch
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
        last_renewal_time: MsSinceEpoch
    },
    NoEntityFound,
    StoreTokenSuccess,
    StoreError(String),
    CreateEntitySuccess,
    SvcEntityConflict,
    TokenValidityResponse(bool),
    QueryError(String)
}