use std::{marker::PhantomData, task::Poll};

use ringbuffer::{ConstGenericRingBuffer, RingBuffer};

use crate::{
    ClientProtocolError, ServerErrorResponse,
};


pub(crate) struct ClientSingleDriver<C, CO, REQ, RES> {
    inner: ClientSingleDriverInner<C, CO, REQ, RES>,
    state: DriverState<CO>,
    _res: PhantomData<RES>,
}

struct ClientSingleDriverInner<C, CO, REQ, RES> {
    context: C,
    buffer: ConstGenericRingBuffer<REQ, 1>,
    terminated: bool,
    init_fn: fn(&mut C) -> Result<(REQ, CO), ClientProtocolError>,
    resp_fn: fn(RES, &mut C, &mut CO) -> Result<(), ClientProtocolError>,
}

// pub enum ClientDeregisterOutput<S, const N: usize>
// where
//     S: DsaSystem
// {
//     Request(ClientDeregister<S::Signature, N>)
// }

pub(crate) enum ClientSingleInput<RES> {
    Response(RES),
    ErrorResponse(ServerErrorResponse),
}

enum DriverState<CO> {
    Init,
    // Contains the carry over context.
    WaitingOnServer(CO),
    Errored(Option<ClientProtocolError>),
    ErrorResponse(Option<ServerErrorResponse>),
    Vacant,
    Finished,
}

impl<C, CO, REQ, RES> ClientSingleDriver<C, CO, REQ, RES> {
    pub fn new(
        context: C,
        init_fn: fn(&mut C) -> Result<(REQ, CO), ClientProtocolError>,
        resp_fn: fn(RES, &mut C, &mut CO) -> Result<(), ClientProtocolError>,
    ) -> Self {
        Self {
            inner: ClientSingleDriverInner {
                context,
                buffer: ConstGenericRingBuffer::default(),
                terminated: false,
                init_fn,
                resp_fn,
            },
            state: DriverState::Init,
            _res: PhantomData,
        }
    }

    pub fn recv(&mut self, packet: Option<ClientSingleInput<RES>>) {
        if self.inner.terminated {
            return;
        }

        match recv_internal(self, packet) {
            Ok(_) => { /* Nothing to do */ }
            Err(e) => {
                self.inner.terminated = true;
                self.state = DriverState::Errored(Some(e))
            }
        }
    }

    pub fn poll_transmit(&mut self) -> Option<REQ> {
        self.inner.buffer.dequeue()
    }
    pub fn poll_result(&mut self) -> Poll<Result<(), ClientProtocolError>> {
        match &mut self.state {
            DriverState::Errored(inner) => {
                let value = inner.take().unwrap();
                self.state = DriverState::Vacant;
                Poll::Ready(Err(value))
            }
            DriverState::Finished => {
                self.state = DriverState::Vacant;
                Poll::Ready(Ok(()))
            }
            DriverState::ErrorResponse(response) => {
                let value = response.take().unwrap();
                self.state = DriverState::Vacant;
                Poll::Ready(Err(ClientProtocolError::ServerErrorResponse(value)))
            }
            _ => Poll::Pending,
        }
    }
}

fn recv_internal<C, CO, REQ, RES>(
    obj: &mut ClientSingleDriver<C, CO, REQ, RES>,
    packet: Option<ClientSingleInput<RES>>,
) -> Result<(), ClientProtocolError> {
    let state = match &mut obj.state {
        DriverState::Init => handle_registry_init(&mut obj.inner)?,
        DriverState::WaitingOnServer(context) => {
            handle_registry_done(&mut obj.inner, packet, context)?
        }
        _ => None, // The other states do not have any active behaviour.
    };

    if let Some(inner) = state {
        // If we output a new state, use said state.
        obj.state = inner;
    }

    Ok(())
}

fn handle_registry_init<C, CO, REQ, RES>(
    obj: &mut ClientSingleDriverInner<C, CO, REQ, RES>,
) -> Result<Option<DriverState<CO>>, ClientProtocolError> {
    let (request, context) = (obj.init_fn)(&mut obj.context)?;
    obj.buffer.enqueue(request);

    Ok(Some(DriverState::WaitingOnServer(context)))
}

fn handle_registry_done<C, CO, REQ, RES>(
    obj: &mut ClientSingleDriverInner<C, CO, REQ, RES>,
    packet: Option<ClientSingleInput<RES>>,
    context: &mut CO,
) -> Result<Option<DriverState<CO>>, ClientProtocolError> {
    let Some(packet) = packet else {
        return Ok(None);
    };

    match packet {
        ClientSingleInput::Response(response) => {
            (obj.resp_fn)(response, &mut obj.context, context)?;

            Ok(Some(DriverState::Finished))
        }
        ClientSingleInput::ErrorResponse(error) => {
            Ok(Some(DriverState::ErrorResponse(Some(error))))
        }
    }
}
