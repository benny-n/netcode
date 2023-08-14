use std::io::{self};
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};

use socket2::{Domain, Protocol, Socket, Type};

use crate::consts::{SERVER_SOCKET_RECV_BUF_SIZE, SERVER_SOCKET_SEND_BUF_SIZE};
use crate::transceiver::Transceiver;

#[derive(thiserror::Error, Debug)]
#[error("failed to create and bind udp socket: {0}")]
pub struct Error(#[from] std::io::Error);

pub type Result<T> = std::result::Result<T, Error>;

pub struct NetcodeSocket(pub UdpSocket);

impl NetcodeSocket {
    pub fn new(addr: impl ToSocketAddrs) -> Result<Self> {
        let addr = addr.to_socket_addrs()?.next().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "no socket addresses found")
        })?;
        let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
        if addr.is_ipv6() {
            socket.set_only_v6(true)?;
        }
        socket.set_send_buffer_size(SERVER_SOCKET_SEND_BUF_SIZE)?;
        socket.set_recv_buffer_size(SERVER_SOCKET_RECV_BUF_SIZE)?;
        socket.bind(&addr.into())?;
        socket.set_nonblocking(true)?;
        Ok(NetcodeSocket(socket.into()))
    }
}

impl Transceiver for NetcodeSocket {
    type Error = Error;

    fn recv(&self, buf: &mut [u8]) -> Result<(usize, Option<SocketAddr>)> {
        match self.0.recv_from(buf) {
            Ok((len, addr)) => Ok((len, Some(addr))),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok((0, None)),
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
