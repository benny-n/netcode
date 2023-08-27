use thiserror::Error;

/// The result type for all the public methods that can return an error in this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// An error that can occur in the `netcode` crate.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    #[error("buffer size mismatch, expected {0} but got {1}")]
    SizeMismatch(usize, usize),
    #[error("tried to send a packet to a client that doesn't exist")]
    ClientNotFound,
    #[error("clock went backwards (did you invent a time machine?): {0}")]
    SystemTime(#[from] std::time::SystemTimeError),
    #[error("invalid connect token: {0}")]
    InvalidToken(crate::token::InvalidTokenError),
    #[error(transparent)]
    Socket(#[from] crate::socket::Error),
    #[error(transparent)]
    Crypto(#[from] crate::crypto::Error),
    #[error("invalid packet: {0}")]
    Packet(#[from] crate::packet::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
