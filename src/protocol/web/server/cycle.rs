use http::StatusCode;

use crate::protocol::error::FluidError;

use super::verdict::Verdict;

pub enum CycleVerdict {
    /// The protocol that the client requested is not supported by the server.
    NotImplemented(String),
    /// The signature on the new key does NOT correspond to the old key.
    Unauthorized,
    /// The server failed to properly handle the request. This is NOT due to
    /// any particular fault of the client and should be retried.
    InternalServerError,
    /// The request was succesful.
    Success,
}

impl Into<Verdict<()>> for CycleVerdict {
    fn into(self) -> Verdict<()> {
        match self {
            CycleVerdict::InternalServerError => Verdict::internal_server_error(),
            CycleVerdict::NotImplemented(requested) => Verdict::not_implemented(&requested),
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


impl TryFrom<StatusCode> for CycleVerdict {
    type Error = FluidError;
    fn try_from(value: StatusCode) -> Result<Self, Self::Error> {
        Ok(match value {
            StatusCode::OK => Self::Success,
            StatusCode::UNAUTHORIZED => Self::Unauthorized,
            StatusCode::NOT_IMPLEMENTED => Self::NotImplemented(String::new()),
            StatusCode::INTERNAL_SERVER_ERROR => Self::InternalServerError,
            _ => Err(FluidError::FailedFormingCycleResponse)?
        })
    }
}