use core::task::Poll;

use serde::Serialize;

use crate::{
    protocol::{
        error::FluidError,
        executor::{FixedByteRepr, ProtocolCtx, TimeObj},
        spec::registry::SvcEntity,
        web::{body::FullResponse, container::rfc3339::Rfc3339},
    },
    token::{signature::KeyChain, token::TimestampToken},
};

use super::{
    cycle::CycleBinding,
    message::Message,
    token::{TokenBinding, TokenPoll},
};

enum InnerMachine<KC, M, D>
where
    KC: KeyChain,
{
    Token(TokenBinding<M, KC, D>),
    Key(CycleBinding<M, KC>),
}

pub struct ClientMachine<KC, M, D>
where
    KC: KeyChain,
{
    inner: Option<InnerMachine<KC, M, D>>,
}

impl<KC, M, D> ClientMachine<KC, M, D>
where
    KC: KeyChain,
    D: Rfc3339,
{
    pub fn from_svc_entity(details: SvcEntity<KC, M>) -> Self {
        Self {
            inner: Some(InnerMachine::Token(TokenBinding::from_svc_entity(details))),
        }
    }
    pub fn poll_transmit<C>(&mut self, ctx: &C) -> Result<Option<Message>, FluidError>
    where
        C: ProtocolCtx<D>,
        M: Serialize,
        C::Protocol: Serialize + FixedByteRepr<1>,
        D: FixedByteRepr<8> + TimeObj,
        C::TokenType: FixedByteRepr<1>,
    {
        match self.inner.as_mut().unwrap() {
            InnerMachine::Key(key) => key.poll_transmit(ctx),
            InnerMachine::Token(key) => key.poll_transmit(ctx),
        }
    }
    pub fn handle_input<C>(&mut self, ctx: &C, response: FullResponse) -> Result<(), FluidError>
    where
        C: ProtocolCtx<D>,
        M: Serialize,
        C::Protocol: Serialize + FixedByteRepr<1>,
        D: FixedByteRepr<8> + TimeObj,
    {
        match self.inner.as_mut().unwrap() {
            InnerMachine::Key(key) => key.handle_input(ctx, response),
            InnerMachine::Token(key) => key.handle_input(ctx, response),
        }
    }
    pub fn poll_result<C>(&mut self, ctx: &C) -> Poll<TimestampToken<D>>
    where
        C: ProtocolCtx<D>,
        D: TimeObj + Clone,
    {
        match self.inner.take().unwrap() {
            InnerMachine::Token(mut key) => {
                let tok_poll = key.poll_result(ctx);
                match tok_poll {
                    TokenPoll::CycleRequired => {
                        println!("Flag A");
                        self.inner = Some(InnerMachine::Key(CycleBinding::from_svc_entity(
                            key.into_svc_entity(),
                        )));
                        Poll::Pending
                    }
                    TokenPoll::Pending => {
                        println!("Flag B");
                        self.inner = Some(InnerMachine::Token(key));
                        Poll::Pending
                    }
                    TokenPoll::Ready(ready) => {
                        println!("Flag C");
                        let tok = ready.token().clone();
                        self.inner = Some(InnerMachine::Token(key));
                        Poll::Ready(tok)
                    }
                }
            }
            InnerMachine::Key(mut key) => {
                let key_poll = key.poll_result();
                match key_poll {
                    Poll::Pending => {
                        self.inner = Some(InnerMachine::Key(key));
                        Poll::Pending
                    }
                    Poll::Ready(result) => {
                        self.inner =
                            Some(InnerMachine::Token(TokenBinding::from_svc_entity(result)));
                        Poll::Pending
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use http::{
        Extensions, HeaderMap, Method, StatusCode, Version,
        response::{Builder, Parts},
    };
    use http_body_util::BodyExt;
    use hyper::body::Bytes;
    use uuid::Uuid;

    use crate::{
        protocol::{
            executor::TimeObj, smachines::client::{message::Message, operate::InnerMachine}, spec::registry::SvcEntity, web::{body::FullResponse, http::form_post_token_response, server::token::TokenVerdict}
        },
        testing::{DummyKeyChain, TestExecutor, TestTimeStub},
        token::{signature::KeyChain, token::TimestampToken},
    };

    use super::ClientMachine;

    #[test]
    pub fn client_machine_basic_check() {
        let (_, private) = DummyKeyChain::generate();
        let mut binding: ClientMachine<DummyKeyChain, &str, TestTimeStub> =
            ClientMachine::from_svc_entity(SvcEntity {
                id: Uuid::nil(),
                metadata: Some("Whats up"),
                private,
            });
        let mut ctx = TestExecutor::generic();
        ctx.configuration.stamping_timeout_secs = 5;
        ctx.internal_clock = 0;
        ctx.retry_cooldown = Duration::from_secs(5);

        // We should not yet have a token.
        assert!(binding.poll_result(&ctx).is_pending());

        // The initial internal binding should be the token state machine.
        let Some(InnerMachine::Token(..)) = binding.inner else {
            panic!("The inner token machine was not a key machine.");
        };

        // The first thing the binding should do is send out a put request.
        if let Some(Message::Request(yo)) = binding.poll_transmit(&ctx).unwrap() {
            assert_eq!(yo.method(), Method::PUT);
        } else {
            panic!("The first request from the client machine was not a token put request.");
        };

        // We will reply with a key cycle request (this is pretty standard)
        binding
            .handle_input(
                &ctx,
                FullResponse::dummy_with_status(StatusCode::RESET_CONTENT).unwrap(),
            )
            .unwrap();


        // We now poll the thing.
        assert!(binding.poll_result(&ctx).is_pending());


        // The internal binding should now be a key machine.
        let Some(InnerMachine::Key(..)) = binding.inner else {
            panic!("Switchover did not occur to the key state mach");
        };

        // The internal binding should now send out a patch request to cycle the key.
        if let Some(Message::Request(yo)) = binding.poll_transmit(&ctx).unwrap() {
            assert_eq!(yo.method(), Method::PATCH);
        } else {
            panic!("The internal binding did not send out a patch request and thus broke protocol.");
        };

        // // Let us approve this request.
        binding.handle_input(&ctx, FullResponse::dummy_with_status(StatusCode::OK).unwrap()).unwrap();

        // Poll again, still pending.
        assert!(binding.poll_result(&ctx).is_pending());

        // The initial internal binding should be back to the token amchen.
        let Some(InnerMachine::Token(..)) = binding.inner else {
            panic!("The inner token machine was not a key machine.");
        };

        // Binding should be active.
        assert!(binding.poll_result(&ctx).is_pending());

        // The first thing the binding should do is send out a put request.
        if let Some(Message::Request(yo)) = binding.poll_transmit(&ctx).unwrap() {
            assert_eq!(yo.method(), Method::PUT);
        
        } else {
            panic!("The first request from the client machine was not a token put request.");
        };

        // Approve the token.
        binding
            .handle_input(
                &ctx,
                FullResponse::from_raw(form_post_token_response(TokenVerdict::Success {
                    token: TimestampToken::random_with_ts(TestTimeStub::from_millis_since_epoch(0)),
                    expiry: TestTimeStub::from_millis_since_epoch(1000)
                }).unwrap()),
            )
            .unwrap();

        // Token should be ready.
        assert!(binding.poll_result(&ctx).is_ready());



    }
}
