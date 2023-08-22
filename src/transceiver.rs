use std::{cell::RefCell, net::SocketAddr, rc::Rc};

use crate::error::NetcodeError;

/// A trait for sending and receiving data.
///
/// This trait is implemented for `NetcodeSocket` and `NetworkSimulator`.
///
/// The server uses a statically dispatched generic type transceiver to send and receive data.
pub trait Transceiver {
    type Error: Into<NetcodeError>;
    fn addr(&self) -> SocketAddr;
    fn recv(&self, buf: &mut [u8]) -> Result<(usize, Option<SocketAddr>), Self::Error>;
    fn send(&self, buf: &[u8], addr: SocketAddr) -> Result<usize, Self::Error>;
}

impl<T> Transceiver for Rc<RefCell<T>>
where
    T: Transceiver,
{
    type Error = T::Error;
    fn addr(&self) -> SocketAddr {
        self.borrow().addr()
    }
    fn recv(&self, buf: &mut [u8]) -> Result<(usize, Option<SocketAddr>), Self::Error> {
        self.borrow().recv(buf)
    }
    fn send(&self, buf: &[u8], addr: SocketAddr) -> Result<usize, Self::Error> {
        self.borrow().send(buf, addr)
    }
}
