use thiserror::Error;

#[derive(Error, Debug)]
pub enum ContainerError {
    #[error("Failed to parse the string as RFC3339")]
    Rfc3339ParseFailure
}