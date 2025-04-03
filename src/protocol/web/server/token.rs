use chrono::{DateTime, Utc};
use http::StatusCode;

use crate::{protocol::{spec::time::MsSinceEpoch, web::{container::{b64::B64Owned, rfc3339::{Rfc3339, Rfc3339Container}}, payload::PostTokenResponse}}, token::token::TimestampToken};

use super::verdict::Verdict;
pub enum TokenVerdict<'a> {
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
    Success { token: TimestampToken, expiry: MsSinceEpoch },
    /// There is already a token that exists with this identity
    Conflict 
}



impl Into<Verdict<PostTokenResponse>> for TokenVerdict<'_>
{
    fn into(self) -> Verdict<PostTokenResponse> {
        match self {
            Self::NeedsCycle => Verdict::custom(
                "NeedsCycle",
                StatusCode::RESET_CONTENT,
                "The token may be valid however the key itself is expired and must be cycled before we may continue to process requests. This error may also be caused if this is your first time making a request with a certain keypair.",
            ),
            Self::ProtocolMismatch { actual } => Verdict::custom(
                "ProtocolMismatch",
                StatusCode::BAD_REQUEST,
                format!(
                    "The protocol in the response does not correspond to how the entity was registered. The entity in question was registered with protocol: \"{}\"",
                    actual
                ),
            ),
            Self::BadTokenFormat => Verdict::custom("BadTokenFormat", StatusCode::UNPROCESSABLE_ENTITY,"The token was not correctly formed and thus could not be read by the server."),
            Self::InternalServerError => Verdict::internal_server_error(),
            Self::NotImplemented(requested) => Verdict::not_implemented(requested),
            Self::TimestampInvalid => Verdict::custom(
                "TimestampInvalid",
                StatusCode::FORBIDDEN,
                format!("The timestamp was either too old or in the future.")
            ),
            Self::Success { token, expiry } => Verdict::Result { obj: PostTokenResponse { token: B64Owned(token), expiry: Rfc3339Container(expiry) }, code: StatusCode::CREATED },
            Self::Conflict => Verdict::custom("Conflict", StatusCode::CONFLICT, "A token already exists with these details")
        }
    }
}



#[cfg(test)]
mod tests {
    use serde_json::Value;

    use crate::{protocol::web::http::form_post_token_response, testing::TestTimeStub};

    use super::TokenVerdict;


    #[test]
    pub fn check_server_token_verdict_response() {


        /* Makes sure that the server is properly making responses. */
        let formulated = form_post_token_response(TokenVerdict::Conflict).unwrap();

        let body: Value = serde_json::from_str(&formulated.into_body()).unwrap();
        assert!(body.get("code").is_some_and(Value::is_string));
        assert!(body.get("message").is_some_and(Value::is_string));
        

    }
}