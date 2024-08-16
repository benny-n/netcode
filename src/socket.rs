use std::io::{self};
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};

use socket2::{Domain, Protocol, Socket, Type};

use crate::transceiver::Transceiver;

#[derive(thiserror::Error, Debug)]
#[error("failed to create and bind udp socket: {0}")]
pub struct Error(#[from] std::io::Error);

pub type Result<T> = std::result::Result<T, Error>;

/// A wrapper around `UdpSocket` that implements the `Transceiver` trait for use in the netcode protocol.
///
/// `NetcodeSocket` is responsible for creating and managing a UDP socket, handling non-blocking
/// send and receive operations, and providing the local address of the socket.
///
/// # Note
///
/// This is a lower-level component and should not be used directly unless you have a specific use case.
/// For most applications, it is recommended to use higher-level abstractions such as `Client::new` or
/// `Client::with_config` to create and manage clients.
///
/// # Example
///
/// ```
/// use netcode::NetcodeSocket;
/// use std::net::SocketAddr;
///
/// let addr = "127.0.0.1:41235";
/// let send_buf_size = 256 * 1024;
/// let recv_buf_size = 256 * 1024;
/// let socket = NetcodeSocket::new(addr, send_buf_size, recv_buf_size).unwrap();
/// ```
pub struct NetcodeSocket(UdpSocket);

impl NetcodeSocket {
    pub fn new(
        addr: impl ToSocketAddrs,
        send_buf_size: usize,
        recv_buf_size: usize,
    ) -> Result<Self> {
        let addr = addr.to_socket_addrs()?.next().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "no socket addresses found")
        })?;
        let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
        if addr.is_ipv6() {
            socket.set_only_v6(true)?;
        }
        socket.set_send_buffer_size(send_buf_size)?;
        socket.set_recv_buffer_size(recv_buf_size)?;
        socket.bind(&addr.into())?;
        socket.set_nonblocking(true)?;
        Ok(NetcodeSocket(socket.into()))
    }
}

impl Transceiver for NetcodeSocket {
    type IntoError = Error;

    fn addr(&self) -> SocketAddr {
        self.0.local_addr().expect("address should be bound")
    }

    fn recv(&self, buf: &mut [u8]) -> Result<Option<(usize, SocketAddr)>> {
        match self.0.recv_from(buf) {
            Ok((len, addr)) if len > 0 => Ok(Some((len, addr))),
            Ok(_) => Ok(None),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(Error::from(e)),
        }
    }

    fn send(&self, buf: &[u8], addr: SocketAddr) -> Result<usize> {
        match self.0.send_to(buf, addr) {
            Ok(len) => Ok(len),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(0),
            Err(e) => Err(Error::from(e)),
        }
    }
}
