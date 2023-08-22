use thiserror::Error;

#[derive(Error, Debug)]
pub enum NetcodeError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Socket(#[from] crate::socket::Error),
    #[error(transparent)]
    Crypto(#[from] crate::crypto::Error),
    #[error("invalid packet")]
    InvalidPacket,
    #[error("invalid packet: {0}")]
    Packet(#[from] crate::packet::Error),
    #[error("clock went backwards (did you invent a time machine?): {0}")]
    SystemTimeError(#[from] std::time::SystemTimeError),
    #[error("empty packet")]
    EmptyPacket,
    #[error("packet size exceeded, got {0} but max is 1175)")]
    PacketSizeExceeded(usize),
    #[error("tried to send a packet to a client that doesn't exist")]
    ClientNotFound,
    #[error("buffer size mismatch, expected {0} but got {1}")]
    BufferSizeMismatch(usize, usize),
    #[error("invalid connect token: {0}")]
    InvalidConnectToken(std::io::Error),
    #[error("client has no more servers to to connect to")]
    NoMoreServers,
}
