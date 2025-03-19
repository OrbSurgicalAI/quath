
#[derive(Debug)]
pub enum FluidError {
    FailedDeserializingId,
    FailedDeserializingPermissions,
    FailedDeserTimestamp,
    FailedDeserBody,
    ServerRejectedToken,
    ServerRejectedCycle,
    ClientNotRegistered,
    ClientNoPrivateKey,
    PrivateKeySigningFailure,
    FailedFormingTokenPostRequest,
    FailedSigningNewKey
}