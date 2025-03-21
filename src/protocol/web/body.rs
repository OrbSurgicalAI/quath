use http::{response::Parts, Response, StatusCode};
use hyper::body::Bytes;
use serde::Deserialize;

/// This is a response that has been fully received.
pub struct FullResponse {
    parts: Parts,
    received: Bytes
}


impl FullResponse {
    pub fn status(&self) -> StatusCode {
        self.parts.status
    }
    pub fn parts(&self) -> &Parts {
        &self.parts
    }
    pub fn bytes(&self) -> &Bytes {
        &self.received
    }
    pub fn from_raw<O>(resp: Response<O>) -> FullResponse
    where 
        O: AsRef<[u8]> + Send + 'static
    {
        let (parts, body) = resp.into_parts();
        FullResponse { parts, received: Bytes::from_owner(body) }

    }
    pub fn parse_json<O>(&self) -> Result<O, serde_json::Error>
    where 
        O: for<'de> Deserialize<'de>
    {
        serde_json::from_slice(&self.received)
    }
}