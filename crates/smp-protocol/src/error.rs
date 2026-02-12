use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProtocolError {
    #[error("Invalid packet format")]
    InvalidFormat,

    #[error("Signature verification failed")]
    SignatureInvalid,
}
