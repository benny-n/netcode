use std::net::SocketAddr;

use crate::error::Error;

/// A trait for sending and receiving data.
///
/// Both the server and client use a statically dispatched generic type `T: Transceiver` to send and receive data,
/// which allows you to use any type that implements this trait as your network socket for a `netcode` server or client.
///
/// See [`NetcodeSocket`](https://github.com/benny-n/netcode/blob/0147a2d11cb48dea59a637ca2f017912f3f6d9aa/src/socket.rs#L37) for an example implementation.
/// This is also the default implementation used by the server and client.
pub trait Transceiver {
    type IntoError: Into<Error>;
    /// Returns the local address of the socket (i.e. the address it is bound to).
    ///
    /// Mostly used for generating and validating [`ConnectTokens`](crate::ConnectToken).
    fn addr(&self) -> SocketAddr;
    /// Receives a packet from the socket, if one is available.
    ///
    /// Should **NOT** block if no packet is available.
    fn recv(&self, buf: &mut [u8]) -> Result<Option<(usize, SocketAddr)>, Self::IntoError>;
    /// Sends a packet to the specified address.
    ///
    /// Should **NOT** block if the packet cannot be sent.
    fn send(&self, buf: &[u8], addr: SocketAddr) -> Result<usize, Self::IntoError>;
}
