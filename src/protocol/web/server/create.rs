use http::StatusCode;
use uuid::Uuid;

use crate::protocol::web::{container::rfc3339::{Rfc3339, Rfc3339Container}, payload::PostTokenResponse};

use super::verdict::Verdict;
pub enum RegisterVerdict {

    /// To no fault of the client, the server has failed processing this
    /// request and it must be resubmitted.
    InternalServerError,
    /// The server could not read the key
    KeyProcessError,
    /// The requested protocol is not supported.
    NotImplemented(String),
    /// There is already a service entity that exists with this identity
    Conflict {
        conflicting_id: Uuid
    },
    /// We do not have sufficient permissions to create this.
    Unauthorized,
    Success
}



impl<'a> Into<Verdict<()>> for RegisterVerdict
{
    fn into(self) -> Verdict<()> {
        match self {
            Self::InternalServerError => Verdict::internal_server_error(),
            Self::NotImplemented(requested) => Verdict::not_implemented(&requested),
            Self::Conflict { .. } => Verdict::custom("Conflict", StatusCode::CONFLICT, "There is already a service entity with this ID."),
            Self::KeyProcessError => Verdict::custom("KeyProcessError", StatusCode::UNPROCESSABLE_ENTITY, "Could not parse the key according to the protocol."),
            Self::Unauthorized => Verdict::unauthorized(),
            Self::Success => Verdict::Result { obj: (), code: StatusCode::CREATED }
        }
    }
}




