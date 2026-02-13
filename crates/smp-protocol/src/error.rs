use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProtocolError {
    #[error("Invalid packet format")]
    InvalidFormat,

    #[error("Unsupported version")]
    UnsupportedVersion,

    #[error("Signature verification failed")]
    SignatureInvalid,
}
