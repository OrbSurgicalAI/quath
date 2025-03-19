use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::token::{signature::{B64Owned, B64Ref, KeyChain}, token::GenericToken};

#[derive(Serialize)]
pub struct CycleRequest<'a, P, M, KC>
where
    P: Serialize,
    M: Serialize,
    KC: KeyChain,
{
    pub id: Uuid,
    pub protocol: &'a P,
    pub key: B64Ref<'a, KC::Public>,
    pub signature: B64Owned<KC::Signature>,
    pub metadata: &'a Option<M>,
}

#[derive(Serialize)]
pub struct TokenStampRequest<'a, D, KC>
where 
    KC: KeyChain
{
    pub token: B64Ref<'a, GenericToken<D>>,
    pub signature: B64Ref<'a, KC::Signature>
}


#[derive(Deserialize)]
pub struct PostTokenResponse<D>
{
    expiry: D
}