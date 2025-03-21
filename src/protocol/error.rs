use thiserror::Error;


#[derive(Error, Debug)]
pub enum FluidError {
    #[error("Failed deserializing an ID value.")]
    FailedDeserializingId,
    #[error("Failed to deserialize the token permissions.")]
    FailedDeserializingPermissions,
    #[error("Failed to deserialize the token timestamp.")]
    FailedDeserTimestamp,
    #[error("Failed to deserialize the token body.")]
    FailedDeserBody,
    #[error("The server rejected the token.")]
    ServerRejectedToken,
    #[error("The server rejected the cycle request.")]
    ServerRejectedCycle,
    #[error("The client is not registered.")]
    ClientNotRegisstered,
    #[error("The client does not have a private key.")]
    ClientNoPrivateKey,
    #[error("Failed to sign the private key.")]
    PrivateKeySigningFailure,
    #[error("Failed to form a token post request.")]
    FailedFormingTokenPostRequest,
    #[error("Failed to sign the key")]
    FailedSigningNewKey,
    #[error("Generic serde")]
    SerdeError,
    #[error("Failed to deserialzie the post token response")]
    FailedDeserializingPtr(serde_json::Error),
    #[error("Failed to create the cycling request")]
    FailedSerializingCycleRequest,
    #[error("The server has failed to form a token post response")]
    FailedFormingTokenPostResponse,
    #[error("The server has failed to form a entity creation request")]
    FailedFormingEntityCreationRequest,
    #[error("The server has failed to form a regiser response")]
    FailedFormingRegisterResponse,
    #[error("The server has failed to form a delete response")]
    FailedFormingDeletionResponse,
    #[error("The server has failed to form a cycle response")]
    FailedFormingCycleResponse,
    #[error("The response to the service entity creation requested was malformed.")]
    CreationResponseMalformed,
    #[error("Registration Failure")]
    RegistrationFailed(String),
    #[error("Deletion Failure")]
    DeletionFailed(String),
    #[error("Failed")]
    FailedDeserializingDeletionResponse
}