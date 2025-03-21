use http::StatusCode;
use uuid::Uuid;

use crate::protocol::{error::FluidError, web::{container::rfc3339::{Rfc3339, Rfc3339Container}, payload::PostTokenResponse}};

use super::verdict::Verdict;

/// There are two okay outcomes with deletion: 
/// 1. The entity never acually existed.
/// 2. The entity was deleted.
pub enum DeletionVerdict {

    /// To no fault of the client, the server has failed processing this
    /// request and it must be resubmitted.
    InternalServerError,
    /// The server could not read the key
    NotFound,
    /// We do not have sufficient permissions to create this.
    Unauthorized,
    Success
}



impl<'a> Into<Verdict<()>> for DeletionVerdict
{
    fn into(self) -> Verdict<()> {
        match self {
            Self::InternalServerError => Verdict::internal_server_error(),
            Self::NotFound => Verdict::Result { obj: (), code: StatusCode::NOT_FOUND },
            Self::Unauthorized => Verdict::unauthorized(),
            Self::Success => Verdict::Result { obj: (), code: StatusCode::NO_CONTENT }
        }
    }
}

impl TryFrom<StatusCode> for DeletionVerdict {
    type Error = FluidError;
    fn try_from(value: StatusCode) -> Result<Self, Self::Error> {
        Ok(match value {
            StatusCode::NOT_FOUND => Self::NotFound,
            StatusCode::NO_CONTENT => Self::Success,
            StatusCode::INTERNAL_SERVER_ERROR => Self::InternalServerError,
            StatusCode::UNAUTHORIZED => Self::Unauthorized,
            _ => Err(FluidError::FailedDeserializingDeletionResponse)?
        })
    }
}



