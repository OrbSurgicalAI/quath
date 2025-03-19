use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, body::Bytes};
use hyper_tls::HttpsConnector;
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::TokioExecutor,
};
use serde::{Deserialize, Serialize};

use thiserror::Error;

pub(crate) struct NetworkClient {
    client: Client<HttpsConnector<HttpConnector>, Full<Bytes>>,
}


#[derive(Error, Debug)]
pub(crate) enum NetworkError {
    #[error("Serialization/deserialization failed as part of the request preparation")]
    SerdeError(#[from] serde_json::Error),
    #[error("Request error")]
    HyperClientError(#[from] hyper_util::client::legacy::Error),
    #[error("Error with the hyper library")]
    HyperError(#[from] hyper::Error)
}



impl NetworkClient {
    pub async fn new() -> Self {
        Self {
            client: Client::builder(TokioExecutor::new())
                .build::<_, Full<Bytes>>(HttpsConnector::new()),
        }
    }
    pub async fn request_json<S, O>(
        &self,
        request: Request<S>,
    ) -> Result<Response<O>, NetworkError>
    where
        S: Serialize,
        O: for<'de> Deserialize<'de>
    {
        // Formulate the actual request.
        let request_new = Bytes::from_owner(serde_json::to_vec(request.body())?);

        let (parts, _) = request.into_parts();

        let modified = Request::from_parts(parts, Full::from(request_new));
        let (parts, incoming) = self.client.request(modified).await?.into_parts();

        // Receive the request bytes.
        let received = incoming.collect().await?.to_bytes();

  

        // Deserialize as the desired type.
        let full: O = serde_json::from_slice(&*received)?;

        Ok(Response::from_parts(parts, full))
    }
}
