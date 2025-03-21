use http::{header::{self, CONTENT_TYPE}, Method, Request, Response, StatusCode};
use http_body_util::Empty;
use hyper::body::Bytes;
use serde::Serialize;
use uuid::Uuid;

use crate::{protocol::{error::FluidError, executor::Connection}, token::{signature::{B64Owned, B64Ref, KeyChain, PrivateKey, PublicKey}, token::GenericToken}};

use super::{payload::{CycleRequest, PostTokenResponse, TokenStampRequest}, server::{cycle::CycleVerdict, token::TokenVerdict}};

pub(crate) fn form_post_token_response<D>(verdict: TokenVerdict<'_, D>) -> Result<Response<String>, FluidError>
where 
    D: Serialize
{
    let verdict = verdict.get_message();
    let code = verdict.code();

    Response::builder()
        .status(code)
        .header(CONTENT_TYPE, "application/json")
        .body(verdict.to_json_string().or(Err(FluidError::SerdeError))?).or(Err(FluidError::FailedFormingTokenPostResponse))
}


pub(crate) fn form_cycle_response(verdict: CycleVerdict<'_>) -> Result<Response<String>, http::Error> {
    match verdict {
        CycleVerdict::Success => Response::builder()
            .status(StatusCode::OK)
            .body(String::new()),
        CycleVerdict::InternalServerError => Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body("Server failed to process the request. Please retry.".to_string()),
        CycleVerdict::NotImplemented(protocol) => Response::builder()
            .status(StatusCode::NOT_IMPLEMENTED)
            .body(format!("The server does not support protocol \"{protocol}\".")),
        CycleVerdict::Unauthorized => Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(format!("The signed public key that was proposed was not signed by the currently active private key."))
    }
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
        .method(Method::PUT)
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
pub(crate) fn form_token_post<'a, D, KC>(
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
