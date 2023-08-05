use std::io::{self};
use std::net::{SocketAddr, UdpSocket};

use socket2::{Domain, Protocol, Socket, Type};

use crate::{
    consts::{SERVER_SOCKET_RECV_BUF_SIZE, SERVER_SOCKET_SEND_BUF_SIZE},
    error::{NetcodeError, SocketError},
};

pub struct Server {
    socket: UdpSocket,
}

pub(crate) fn create_socket(addr: SocketAddr) -> Result<UdpSocket, SocketError> {
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_send_buffer_size(SERVER_SOCKET_SEND_BUF_SIZE)?;
    socket.set_recv_buffer_size(SERVER_SOCKET_RECV_BUF_SIZE)?;
    socket.bind(&addr.into())?;
    socket.set_nonblocking(true)?;
    Ok(socket.into())
}

impl Server {
    pub fn new(addr: SocketAddr) -> Result<Self, NetcodeError> {
        let socket = create_socket(addr)?;
        Ok(Self { socket })
    }

    fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, Option<SocketAddr>), NetcodeError> {
        match self.socket.recv_from(buf) {
            Ok((len, addr)) => Ok((len, Some(addr))),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok((0, None)),
            Err(e) => Err(SocketError::from(e).into()),
        }
    }

    fn send_to(&self, buf: &[u8], addr: SocketAddr) -> Result<usize, NetcodeError> {
        match self.socket.send_to(buf, addr) {
            Ok(len) => Ok(len),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(0),
            Err(e) => Err(SocketError::from(e).into()),
        }
    }
}
