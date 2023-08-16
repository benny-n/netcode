use std::net::SocketAddr;

use crate::error::NetcodeError;

/// A trait for sending and receiving data.
///
/// This trait is implemented for `NetcodeSocket` and `NetworkSimulator`.
///
/// The server uses a statically dispatched generic type transceiver to send and receive data.
pub trait Transceiver {
    type Error: Into<NetcodeError>;
    fn recv(&self, buf: &mut [u8]) -> Result<(usize, Option<SocketAddr>), Self::Error>;
    fn send(&self, buf: &[u8], addr: SocketAddr) -> Result<usize, Self::Error>;
}
