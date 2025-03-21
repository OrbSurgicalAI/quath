use http::{
    header::{self, AUTHORIZATION, CONTENT_TYPE}, HeaderValue, Method, Request, Response, StatusCode
};
use http_body_util::Empty;
use hyper::body::Bytes;
use serde::Serialize;
use uuid::Uuid;

use crate::{
    protocol::{error::FluidError, executor::Connection},
    token::{
        signature::{KeyChain, PrivateKey, PublicKey},
        token::GenericToken,
    },
};

use super::{
    container::{
        b64::{B64Owned, B64Ref},
        rfc3339::Rfc3339,
    },
    payload::{CreateServiceEntityRequest, CycleRequest, DeleteSvcEntityRequest, PostTokenResponse, TokenStampRequest},
    server::{create::RegisterVerdict, cycle::CycleVerdict, delete::DeletionVerdict, token::TokenVerdict, verdict::Verdict},
};

pub(crate) fn form_post_token_response<D>(
    verdict: TokenVerdict<'_, D>,
) -> Result<Response<String>, FluidError>
where
    D: Rfc3339,
{
    let verdict: Verdict<PostTokenResponse<D>> = verdict.into();
    let code = verdict.code();

    Response::builder()
        .status(code)
        .header(CONTENT_TYPE, "application/json")
        .body(verdict.to_json_string().or(Err(FluidError::SerdeError))?)
        .or(Err(FluidError::FailedFormingTokenPostResponse))
}

pub(crate) fn form_cycle_response(
    verdict: CycleVerdict<'_>,
) -> Result<Response<String>, FluidError> {
    let verdict: Verdict<()> = verdict.into();
    let code = verdict.code();

    Response::builder()
        .status(code)
        .header(CONTENT_TYPE, "application/json")
        .body(verdict.to_json_string().or(Err(FluidError::SerdeError))?)
        .or(Err(FluidError::FailedFormingCycleResponse))
}

pub(crate) fn form_register_response(
    verdict: RegisterVerdict,
) -> Result<Response<String>, FluidError> {
    let verdict: Verdict<()> = verdict.into();
    let code = verdict.code();

    Response::builder()
        .status(code)
        .header(CONTENT_TYPE, "application/json")
        .body(verdict.to_json_string().or(Err(FluidError::SerdeError))?)
        .or(Err(FluidError::FailedFormingRegisterResponse))
}

pub(crate) fn form_deletion_response(
    verdict: DeletionVerdict,
) -> Result<Response<String>, FluidError> {
    let verdict: Verdict<()> = verdict.into();
    let code = verdict.code();

    Response::builder()
        .status(code)
        .header(CONTENT_TYPE, "application/json")
        .body(verdict.to_json_string().or(Err(FluidError::SerdeError))?)
        .or(Err(FluidError::FailedFormingDeletionResponse))
}

/// Forms a cycle request as an HTTP reequest.
///
/// This will automatically perform the necessary
/// signing to generate a valid request.
pub(crate) fn form_cycle_request<'a, D, P, KC: KeyChain, M>(
    conn: &'a Connection,
    protocol: &'a P,
    id: Uuid,
    new_public: &'a KC::Public,
    old_private: &'a KC::Private,
    metadata: &'a Option<M>,
) -> Result<Request<CycleRequest<'a, P, M, KC>>, FluidError>
where
    P: Serialize,
    M: Serialize,
{
    let signature = old_private
        .sign(new_public.as_bytes())
        .or(Err(FluidError::FailedSigningNewKey))?;

    hyper::Request::builder()
        .method(Method::PATCH)
        .uri(conn.uri())
        .header(header::CONTENT_TYPE, "application/json")
        .body(CycleRequest {
            id,
            protocol,
            key: B64Ref(new_public),
            signature: B64Owned(signature),
            metadata,
        })
        .or(Err(FluidError::FailedFormingTokenPostRequest))
}

/// Forms a token posting request.
pub(crate) fn form_token_put<'a, D, KC>(
    conn: &'a Connection,
    token: &'a GenericToken<D>,
    signature: &'a KC::Signature,
) -> Result<Request<TokenStampRequest<'a, D, KC>>, FluidError>
where
    KC: KeyChain,
{
    hyper::Request::builder()
        .method(hyper::Method::PUT)
        .uri(conn.uri())
        .header(header::CONTENT_TYPE, "application/json")
        .body(TokenStampRequest {
            token: B64Ref(token),
            signature: B64Ref(signature),
        })
        .or(Err(FluidError::FailedFormingTokenPostRequest))
}



pub(crate) fn form_service_entity_deletion_request(
    conn: &Connection,
    id: Uuid,
    authorization: HeaderValue
) -> Result<Request<DeleteSvcEntityRequest>, FluidError>
{
    hyper::Request::builder()
        .method(hyper::Method::DELETE)
        .uri(conn.uri())
        .header(header::CONTENT_TYPE, "application/json")
        .header(AUTHORIZATION, authorization)
        .body(DeleteSvcEntityRequest {
            id
        })
        .or(Err(FluidError::FailedFormingDeletionResponse))
}

/// Forms a token posting request.
pub(crate) fn form_service_entity_create_request<'a, KC, P, M>(
    conn: &'a Connection,
    id: Uuid,
    protocol: &'a P,
    key: &'a KC::Public,
    metadata: &'a Option<M>
) -> Result<Request<CreateServiceEntityRequest<'a, P, M, KC>>, FluidError>
where
    KC: KeyChain,
    M: Serialize,
    P: Serialize
{
    hyper::Request::builder()
        .method(hyper::Method::POST)
        .uri(conn.uri())
        .header(header::CONTENT_TYPE, "application/json")
        .body(CreateServiceEntityRequest {
            id,
            key: B64Ref(key),
            metadata,
            protocol
        })
        .or(Err(FluidError::FailedFormingEntityCreationRequest))
}
