use http::StatusCode;

use crate::protocol::web::payload::PostTokenResponse;

use super::verdict::{format_verdict, Verdict};

pub enum TokenVerdict<'a, D> {
    /// The token may be valid, however the key itself must
    /// be cycled before this request can be handled.
    NeedsCycle,
    /// The protocol requested is simply not supported by the server.
    NotImplemented(&'a str),
    /// The protocol requested is not in line with what the client was registered with.
    ProtocolMismatch { actual: String },
    /// The timestamp is invalid.
    TimestampInvalid,
    /// The token had a bad format and thus could not be read by the server.
    BadTokenFormat,
    /// The server had an internal error that prevented it from completing the request,
    /// and the client should retry.
    InternalServerError,
    /// The token was succesfully created.
    Success { expiry: D },
    /// There is already a token that exists with this identity
    Conflict 
}




impl<D> TokenVerdict<'_, D> {
    pub fn get_message(self) -> Verdict<PostTokenResponse<D>> {
        match self {
            Self::NeedsCycle => format_verdict(
                "NeedsCycle",
                StatusCode::RESET_CONTENT,
                "The token may be valid however the key itself is expired and must be cycled before we may continue to process requests. This error may also be caused if this is your first time making a request with a certain keypair.",
            ),
            Self::ProtocolMismatch { actual } => format_verdict(
                "ProtocolMismatch",
                StatusCode::BAD_REQUEST,
                format!(
                    "The protocol in the response does not correspond to how the entity was registered. The entity in question was registered with protocol: \"{}\"",
                    actual
                ),
            ),
            Self::BadTokenFormat => format_verdict("BadTokenFormat", StatusCode::UNPROCESSABLE_ENTITY,"The token was not correctly formed and thus could not be read by the server."),
            Self::InternalServerError => format_verdict("InternalServerError", StatusCode::INTERNAL_SERVER_ERROR, "The server failed to process the request because of some internal error, please try again."),
            Self::NotImplemented(requested) => format_verdict(
                "NotImplemented",
                StatusCode::NOT_IMPLEMENTED,
                format!("The request was using the \"{requested}\" protocol which the server does not support.")
            ),
            Self::TimestampInvalid => format_verdict(
                "TimestampInvalid",
                StatusCode::FORBIDDEN,
                format!("The timestamp was either too old or in the future.")
            ),
            Self::Success { expiry } => Verdict::Result { obj: PostTokenResponse { expiry }, code: StatusCode::CREATED },
            Self::Conflict => format_verdict("Conflict", StatusCode::CONFLICT, "A token already exists with these details")
        }
    }
}

