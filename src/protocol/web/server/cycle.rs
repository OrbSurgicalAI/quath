use http::StatusCode;

use super::verdict::Verdict;

pub enum CycleVerdict<'a> {
    /// The protocol that the client requested is not supported by the server.
    NotImplemented(&'a str),
    /// The signature on the new key does NOT correspond to the old key.
    Unauthorized,
    /// The server failed to properly handle the request. This is NOT due to
    /// any particular fault of the client and should be retried.
    InternalServerError,
    /// The request was succesful.
    Success,
}

impl<'a> Into<Verdict<()>> for CycleVerdict<'a> {
    fn into(self) -> Verdict<()> {
        match self {
            CycleVerdict::InternalServerError => Verdict::custom(
                "InternalServerError",
                StatusCode::INTERNAL_SERVER_ERROR,
                "The server failed to process this request. Please retry.",
            ),
            CycleVerdict::NotImplemented(requested) => Verdict::custom(
                "NotImplemented",
                StatusCode::NOT_IMPLEMENTED,
                format!(
                    "The request used the protocol \"{requested}\" but this is not supported by the server."
                ),
            ),
            CycleVerdict::Success => Verdict::Result {
                obj: (),
                code: StatusCode::OK,
            },
            CycleVerdict::Unauthorized => Verdict::custom(
                "Unauthorized",
                StatusCode::UNAUTHORIZED,
                "The key signing was incorrect",
            ),
        }
    }
}
