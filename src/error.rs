use thiserror::Error;

#[derive(Error, Debug)]
pub enum NetcodeError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Socket(#[from] crate::server::Error),
    #[error(transparent)]
    Crypto(#[from] crate::crypto::Error),
    #[error("invalid packet")]
    InvalidPacket,
    #[error("would block")]
    WouldBlock,
    #[error("invalid packet: {0}")]
    Packet(#[from] crate::packet::Error),
}
