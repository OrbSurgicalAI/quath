use crate::protocol::executor::ProtocolCtx;

use super::server::context::ServerContext;




pub trait ServerStateMachine<M, I> {
    type Error;
    type Result;

    fn poll_transmit<C: ServerContext>(&mut self, context: &C) -> Option<M>;
    fn input<C: ServerContext>(&mut self, context: &C, input: Option<I>);
    fn poll_result<C: ServerContext>(&mut self, context: &C) -> core::task::Poll<Result<Self::Result, Self::Error>>;
}

pub trait ClientStateMachine<M, I> {
    type Error;
    type Result;

    fn poll_transmit<C: ProtocolCtx>(&mut self, context: &C) -> Option<M>;
    fn input<C: ProtocolCtx>(&mut self, context: &C, input: Option<I>);
    fn poll_result<C: ProtocolCtx>(&mut self, context: &C) -> core::task::Poll<Result<Self::Result, Self::Error>>;
}