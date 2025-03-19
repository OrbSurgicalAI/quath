
#[derive(Debug)]
pub enum FluidError {
    FailedDeserializingId,
    FailedDeserializingPermissions,
    FailedDeserTimestamp,
    FailedDeserBody
}