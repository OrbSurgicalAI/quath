
pub enum CycleVerdict<'a> {
    /// The protocol that the client requested is not supported by the server.
    NotImplemented(&'a str),
    /// The signature on the new key does NOT correspond to the old key.
    Unauthorized,
    /// The server failed to properly handle the request. This is NOT due to
    /// any particular fault of the client and should be retried.
    InternalServerError,
    /// The request was succesful.
    Success
}