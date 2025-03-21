use http::StatusCode;
use uuid::Uuid;

use crate::protocol::web::{container::rfc3339::{Rfc3339, Rfc3339Container}, payload::PostTokenResponse};

use super::verdict::Verdict;
pub enum RegisterVerdict<'a> {

    /// To no fault of the client, the server has failed processing this
    /// request and it must be resubmitted.
    InternalServerError,
    /// The server could not read the key
    KeyProcessError,
    /// The requested protocol is not supported.
    NotImplemented(&'a str),
    /// There is already a service entity that exists with this identity
    Conflict {
        conflicting_id: Uuid
    }
}



impl<D> Into<Verdict<PostTokenResponse<D>>> for TokenVerdict<'_, D>
where 
    D: Rfc3339
{
    fn into(self) -> Verdict<PostTokenResponse<D>> {
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
            Self::InternalServerError => Verdict::custom("InternalServerError", StatusCode::INTERNAL_SERVER_ERROR, "The server failed to process the request because of some internal error, please try again."),
            Self::NotImplemented(requested) => Verdict::custom(
                "NotImplemented",
                StatusCode::NOT_IMPLEMENTED,
                format!("The request was using the \"{requested}\" protocol which the server does not support.")
            ),
            Self::TimestampInvalid => Verdict::custom(
                "TimestampInvalid",
                StatusCode::FORBIDDEN,
                format!("The timestamp was either too old or in the future.")
            ),
            Self::Success { expiry } => Verdict::Result { obj: PostTokenResponse { expiry: Rfc3339Container(expiry) }, code: StatusCode::CREATED },
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
        let formulated = form_post_token_response::<TestTimeStub>(TokenVerdict::Conflict).unwrap();

        let body: Value = serde_json::from_str(&formulated.into_body()).unwrap();
        assert!(body.get("code").is_some_and(Value::is_string));
        assert!(body.get("message").is_some_and(Value::is_string));
        

    }
}