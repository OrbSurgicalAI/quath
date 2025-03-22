use std::{cmp::Ordering, marker::PhantomData, task::Poll, time::Duration};

use base64::{Engine, prelude::BASE64_URL_SAFE};
use chrono::{DateTime, Utc};
use http_body_util::Full;
use hyper::{
    Error, Method, Request, Response, StatusCode, Uri,
    body::{Body, Bytes},
    header,
};
use uuid::Uuid;

use crate::{
    protocol::{http::prep_request, web::http::form_token_put},
    token::{
        signature::{KeyChain, PrivateKey},
        token::{AliveToken, FluidToken, GenericToken},
    },
};


use super::{
    config::Configuration,
    error::FluidError,
    web::{
        body::FullResponse, container::rfc3339::Rfc3339, http::form_cycle_request, payload::{CycleRequest, PostTokenResponse, TokenStampRequest}
    },
};
use serde::{Deserialize, Serialize};

/// Manages the context of the protocol.
pub trait ProtocolCtx<D> {
    type Protocol;
    type TokenType;
    /// Compares the current time against another time.
    fn current_time(&self) -> D;
    fn config(&self) -> &Configuration;
    fn connection(&self) -> &Connection;
    fn protocol(&self) -> Self::Protocol;
    fn retry_cooldown(&self) -> Duration;
    fn get_token_type(&self) -> Self::TokenType;
}

pub trait TimeObj {
    fn cmp_within(&self, other: &Self, bound: i64) -> Ordering {
        (self.seconds_since_epoch() + bound).cmp(&(other.seconds_since_epoch()))
    }
    fn from_millis_since_epoch(seconds: i64) -> Self;
    fn seconds_since_epoch(&self) -> i64;
}

impl TimeObj for DateTime<Utc> {
    fn from_millis_since_epoch(seconds: i64) -> Self {
        Self::from_timestamp_millis(seconds).unwrap()
    }
    fn seconds_since_epoch(&self) -> i64 {
        self.timestamp()
    }
}

pub trait FixedByteRepr<const N: usize> {
    fn to_fixed_repr(&self) -> [u8; N];
    fn from_fixed_repr(val: [u8; N]) -> Self;
}

pub struct Registered;

enum ClientState<KC, D>
where 
    KC: KeyChain
{
    Idle,
    Registered,
    SendingToken {
        outstanding: GenericToken<D>
    },
    ReceivedStampResponse {
        decision: ExecResponse<D>,
        outstanding: GenericToken<D>
    },
    CyclingKey {
        new_private_key: KC::Private,
        new_public_key: KC::Public
    }
}



type Container<D> = Option<D>;
pub struct ClientProtocol<D, KC>
where
    KC: KeyChain,
{
    id: Option<Uuid>,
    private_key: Option<KC::Private>,
    active_token: Option<AliveToken<D>>,
    state: Container<ClientState<KC, D>>,
    transmit: Vec<Request<Full<Bytes>>>,
}

pub struct Connection {
    uri: Uri,
}

impl Connection {
    pub fn from_uri(uri: Uri) -> Self {
        Self { uri }
    }
    pub fn uri(&self) -> &Uri {
        &self.uri
    }
}

impl Connection {
    pub fn new(uri: Uri) -> Self {
        Self { uri }
    }
}

impl<D, KC> ClientProtocol<D, KC>
where
    D: TimeObj + FixedByteRepr<8> + Rfc3339,
    KC: KeyChain,
{
    pub fn new() -> Self {
        Self {
            active_token: None,
            id: None,
            private_key: None,
            state: Container::Some(ClientState::Idle),
            transmit: vec![],
        }
    }
    /// Installs a new keychain to the client, recall
    /// that this does not naturally register the client.
    pub fn generate(&mut self) {
        let (_, private) = KC::generate();
        self.private_key = Some(private);
        self.id = Some(Uuid::new_v4());
        
    }
    /// Checks and sees if the client is already registered.
    pub fn is_registered(&self) -> bool {
        self.active_token.is_some() && self.id.is_some()
    }
    /// Checks if the current token is valid.
    pub fn is_current_valid<CTX>(&self, ctx: &CTX) -> bool
    where
        CTX: ProtocolCtx<D>,
    {
        if let Some(token) = &self.active_token {
            token.is_alive(ctx)
        } else {
            false // we have no token so naturally it is not valid.
        }
    }
    /// Generates a specialized token and then proceeds to sign it. This
    /// process will convert the special token into a generic one.
    fn gen_token_and_sign<T, CTX>(
        &mut self,
        ctx: &CTX,
        token_type: T
    ) -> Result<(GenericToken<D>, KC::Signature), FluidError>
    where
        T: FixedByteRepr<1>,
        CTX: ProtocolCtx<D>,
        CTX::Protocol: FixedByteRepr<1>
    {
        let token =
            FluidToken::<D, T, CTX::Protocol>::generate(ctx, self.id.unwrap(), token_type, ctx.protocol());
        let signature = self
            .private_key
            .as_ref()
            .ok_or(FluidError::ClientNoPrivateKey)?
            .sign(&token.to_bytes())
            .or(Err(FluidError::PrivateKeySigningFailure))?;

        Ok((token.generic(), signature))
    }
    pub fn get_transmit(&mut self) -> Option<Request<Full<Bytes>>> {
        self.transmit.pop()
    }
    /// This formulates and sends a new token request.
    /// 
    /// This will also drive us into the sending token state.
    fn new_tok_req<T, CTX>(
        &mut self,
        ctx: &CTX,
        token_type: T
    ) -> Result<(), FluidError>
    where
        T: FixedByteRepr<1>,
        CTX: ProtocolCtx<D>,
        CTX::Protocol: FixedByteRepr<1>
    {
        // We should be in the registered state when sending this out.
        assert!(matches!(self.state.as_ref().unwrap(), ClientState::Registered));
        let (token, signature) = self.gen_token_and_sign(ctx, token_type)?;
        let form = form_token_put::<D, KC>(ctx.connection(), &token, &signature)?;
        let serialized = prep_request(form).or(Err(FluidError::SerdeError))?;

        // Enqueue this request.
        self.transmit.push(serialized);

        self.state = Some(ClientState::SendingToken { outstanding: token });

        Ok(())
    }
    pub fn handle_input(&mut self, response: FullResponse) -> Result<(), FluidError> {
        match self.state.take().unwrap() {
            ClientState::Idle => panic!("Client handled input while in idle."),
            ClientState::Registered => panic!("Client handled input while in registered."),
            ClientState::SendingToken { outstanding } => {
                let parsed = parse_stamp_response(response)?;
                self.state = Some(ClientState::ReceivedStampResponse {
                    decision: parsed,
                    outstanding: outstanding
                });
            }
            ClientState::ReceivedStampResponse { .. } => {
                /* Illegal transition:  */
                panic!("Received stamp response twice in a row?")
            },
            ClientState::CyclingKey { new_private_key, .. } => {
                /* Handling these are quite trivial. */
                if response.status() == StatusCode::OK {
                    self.private_key = Some(new_private_key);
                    self.state = Some(ClientState::Registered);
                } else {
                    /* Error: How do we want to handle this. */
                }
            }
        }

        Ok(())
    }
    fn return_poll_active_token(&mut self) -> Result<Poll<&GenericToken<D>>, FluidError> {
        Ok(Poll::Ready(self.active_token.as_ref().unwrap().token()))
    }
    fn new_cycle_request<C>(&mut self, ctx: &C) -> Result<(), FluidError>
    where 
        C: ProtocolCtx<D>,
        C::Protocol: Serialize
    {
        let protocol = ctx.protocol();
        let (new_public_key, new_private_key) = KC::generate();
        let request = form_cycle_request::<D, _, KC, String>(ctx.connection(), &protocol, self.id.unwrap(), &new_public_key, self.private_key.as_ref().unwrap(), &None)?;
        let serialized = prep_request(request).or(Err(FluidError::FailedSerializingCycleRequest))?;

        // Send the request.
        self.transmit.push(serialized);

        // Set the state to cycling.
        self.state = Some(ClientState::CyclingKey { new_private_key, new_public_key });

        Ok(())
    }
    fn poll_rcv_stamp_response<C>(&mut self, ctx: &C) -> Result<Poll<&GenericToken<D>>, FluidError>
    where 
        C: ProtocolCtx<D>,
        C::Protocol: Serialize
    {
        if let ClientState::ReceivedStampResponse { decision, .. } = self.state.take().unwrap() {
            /* We have received a response, we now will process it. */
            match decision {
                ExecResponse::Return { token, expiry } => {
                    /* Success */
                    // TODO: CHECK TO SEE IF THE OUTSTANDING AND THE NEW ONE HAVE MATCHING FILDS
                    self.active_token = Some(AliveToken::from_raw(token, expiry));
                    self.state = Some(ClientState::Registered);
                    self.return_poll_active_token()
                },
                ExecResponse::Invalid(status) => {
                    /* Invalid response? */
                    unreachable!()
                },
                ExecResponse::CycleRequired => {
                    self.new_cycle_request(ctx)?;
                    Ok(Poll::Pending)
                }
            }
        } else {
            panic!("Erroneously called the poll receive stamp response.")
        }
    }   
    /// Gets the authorization token from the client.
    pub fn poll_token<T, C>(
        &mut self,
        ctx: &C,
        token_type: T
    ) -> Result<Poll<&GenericToken<D>>, FluidError>
    where
        T: FixedByteRepr<1>,
        C: ProtocolCtx<D>,
        C::Protocol: FixedByteRepr<1>,
        C::Protocol: Serialize
    {
        match &self.state.as_ref().unwrap() {
            ClientState::Idle => return Err(FluidError::ClientNotRegisstered),
            ClientState::Registered => {
                // If we are in the registered state we may have a valid token but this is not a certainty.
                if self.is_current_valid(ctx) {
                    // Check to see if we can use our active protocol.
                    self.return_poll_active_token()
                } else {
                    // We need to refresh it.
                    self.new_tok_req(ctx, token_type)?;
                    Ok(Poll::Pending)
                }
            }
            ClientState::SendingToken { outstanding: _o } => {
                /* If we are still in this state we cannot proceed */
                Ok(Poll::Pending)
            },
            ClientState::CyclingKey { .. } => {
                /* We are in the process of cycling the key. */
                Ok(Poll::Pending)
            }
            ClientState::ReceivedStampResponse { .. }=> {
                self.poll_rcv_stamp_response(ctx)
            }
        }
    }
}


/// Parse the stamp response into a usable set of data.
fn parse_stamp_response<D>(raw: FullResponse) -> Result<ExecResponse<D>, FluidError>
where
    D: Rfc3339 + FixedByteRepr<8>
{
    if raw.status() == StatusCode::RESET_CONTENT {
        // Needs a cycle.
        Ok(ExecResponse::CycleRequired)
    } else if raw.status() == StatusCode::CREATED {
        // Created the token.
        let ptr: PostTokenResponse<D> = raw
            .parse_json()
            .map_err(|e| FluidError::FailedDeserializingPtr(e))?;
        Ok(ExecResponse::Return { token: ptr.token.inner(), expiry: ptr.expiry.inner() })
    } else {
        Ok(ExecResponse::Invalid(raw.status()))
    }
}



pub enum ExecResponse<D> {
    Return {
        token: GenericToken<D>,
        expiry: D
    },
    CycleRequired,
    Invalid(StatusCode),
}

#[derive(Serialize)]
pub struct Hello {
    wow: String,
}

#[cfg(test)]
mod tests {
    use std::task::Poll;

    use chrono::{DateTime, Utc};
    use http_body_util::{BodyExt, Empty, Full};
    use hyper::{
        Method, Response,
        body::{self, Body, Bytes},
    };
    use hyper_tls::HttpsConnector;
    use hyper_util::{client::legacy::Client, rt::TokioExecutor};
    use rand::Rng;
    use serde_json::Value;
    use smol::net::TcpStream;

    use crate::{
        protocol::{
            config::Configuration,
            error::FluidError,
            executor::{form_token_put, ClientState, Connection, ExecResponse, Hello, TimeObj},
            http::NetworkClient, web::{body::FullResponse, http::form_post_token_response, server::token::TokenVerdict},
        },
        testing::{
            DummyClientSyncStruct, DummyKeyChain, ExampleProtocol, ExampleType, TestExecutor,
            TestTimeStub,
        },
        token::token::GenericToken,
    };

    use super::{ClientProtocol, ProtocolCtx};

    #[test]
    pub fn test_correct_workflow_registered() {
        /* This test runs what should be a fully correct workflow! */
        let mut executor = ClientProtocol::<TestTimeStub, DummyKeyChain>::new();
        executor.generate();
        
        // We will assume this is registered here (to test correct flow)
        // AND that this is not their first time exchanging with the server
        // so that the key cycle is not triggred.
        executor.state = Some(ClientState::Registered);

        let contex = TestExecutor::generic();


        // This should trigger a token request.
        let initial = executor.poll_token(&contex, ExampleType(0)).unwrap();
        assert!(initial.is_pending());

        // We should be in the sending token state.
        let inner_token: GenericToken<TestTimeStub>;
        if let ClientState::SendingToken { outstanding } = executor.state.as_ref().unwrap() {
            inner_token = GenericToken::try_from(outstanding.get_bytes().to_vec()).unwrap();
        } else {
            panic!("The client was not in the sending token state after being polled!");
        }
        let inner_token = inner_token.randomize_body();
        

        // There should be an item in the queue.
        assert_eq!(executor.transmit.len(), 1);
        let _ = executor.get_transmit().as_ref().unwrap();

        // We will emulate the server approving this.
        let success = form_post_token_response(TokenVerdict::Success { 
            token: inner_token.clone(),
            expiry: TestTimeStub::from_millis_since_epoch(100)
        }).unwrap();

        // Handle this input.
        executor.handle_input(FullResponse::from_raw(success)).unwrap();

        
        // Verify the state is correct.
        if let ClientState::ReceivedStampResponse { decision, .. } = executor.state.as_ref().unwrap() {
            if let ExecResponse::Return { .. } = decision {} else {
                panic!("Should have received a return but did not.");
            }
        } else {
            panic!("After receiving the response the client should be in the receiving state but they are not.");
        }
        

        // Advance the state machine
        let partway = executor.poll_token(&contex, ExampleType(0)).unwrap();
        assert!(partway.is_ready());
        let Poll::Ready(tok) = partway else {
            panic!("Could not get the token out of the poll object.");
        };

        // Verify that the client is using the modified bytes.
        assert_eq!(tok.get_bytes(), inner_token.get_bytes());

        // Execution is complete!

    }

    #[test]
    pub fn test_token_poll_not_registered() {
        let mut executor = ClientProtocol::<TestTimeStub, DummyKeyChain>::new();

        let context = TestExecutor::generic();

        assert!(matches!(executor.state.as_ref().unwrap(), ClientState::Idle));

        assert_eq!(
            executor
                .poll_token(&context, ExampleType(0))
                .err()
                .unwrap()
                .to_string(),
            FluidError::ClientNotRegisstered.to_string()
        );

        // We will force the client into a registered state.
    }

    #[tokio::test]
    pub async fn test_hyper() {
        let client = NetworkClient::new().await;

        // let mut executor = DummyClientSyncStruct {
        //     context: TestExecutor {
        //         configuration: Configuration {
        //             stamping_timeout_secs: 10
        //         },
        //         internal_clock: 0
        //     },
        //     current_token: None,
        //     faux_server: super::FauxDummyServer { keys: HashMap::new().into() },
        //     id: None,
        //     private_key: None
        // };

        // let wow = form_token_post(&Connection {
        //     uri: "https://echo.zuplo.io".parse().unwrap()
        // }, , signature)

        let res: Response<Value> = client
            .request_json(
                hyper::Request::builder()
                    .method(Method::POST)
                    .uri("https://echo.zuplo.io")
                    .body(Hello {
                        wow: "yes".to_string(),
                    })
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(res.status(), 200);

        println!("BODY: {:?}", res.into_body());

        // panic!("Yo");

        // let mut bruh: u32 = rand::rng().random();
        // println!("Original: {:032b}", bruh);

        // let mut bruh = 0u16;

        // bruh = 0x0003 | 0x0100;

        // println!("Modified: {:032b}", bruh);

        // panic!("");
    }
}
