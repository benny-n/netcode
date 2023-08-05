use socket2::Socket;
use thiserror::Error;

#[derive(Error, Debug)]
#[error("failed to create and bind udp socket: {source}")]
pub struct SocketError {
    #[from]
    source: std::io::Error,
}

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("invalid public key size")]
    InvalidPublicKeySize,
    #[error("buffer size mismatch")]
    BufferSizeMismatch,
    #[error("failed to encrypt: {0}")]
    Failed(#[from] chacha20poly1305::aead::Error),
    #[error("failed to generate key: {0}")]
    GenerateKey(chacha20poly1305::aead::rand_core::Error),
}

#[derive(Error, Debug)]
pub enum NetcodeError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Socket(#[from] SocketError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error("the data for key `{0}` is not available")]
    Redaction(String),
    #[error("invalid header (expected {expected:?}, found {found:?})")]
    InvalidHeader { expected: String, found: String },
    #[error("unknown data store error")]
    Unknown,
    #[error("would block")]
    WouldBlock,
}
