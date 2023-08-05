use byteorder::{LittleEndian, WriteBytesExt};

// struct netcode_connect_token_private_t
// {
//     uint64_t client_id;
//     int timeout_seconds;
//     int num_server_addresses;
//     struct netcode_address_t server_addresses[NETCODE_MAX_SERVERS_PER_CONNECT];
//     uint8_t client_to_server_key[NETCODE_KEY_BYTES];
//     uint8_t server_to_client_key[NETCODE_KEY_BYTES];
//     uint8_t user_data[NETCODE_USER_DATA_BYTES];
// };
use crate::{
    bytes::Bytes,
    consts::{NETCODE_VERSION_BYTES, NETCODE_VERSION_BYTES_LEN, PRIVATE_KEY_BYTES},
    crypto,
    error::NetcodeError,
};

use std::{
    io::{self, Write},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
};

pub const MAX_SERVERS_PER_CONNECT: usize = 32;
pub const USER_DATA_BYTES: usize = 256;

#[derive(Debug, Clone, Copy)]
pub struct ServerAddresses {
    len: u32,
    addrs: [Option<SocketAddr>; MAX_SERVERS_PER_CONNECT],
}

impl ServerAddresses {
    const IPV4: u8 = 1;
    const IPV6: u8 = 2;
    pub fn new(addrs: impl ToSocketAddrs) -> Result<Self, NetcodeError> {
        let mut server_addresses = Self {
            addrs: [None; MAX_SERVERS_PER_CONNECT],
            len: 0,
        };

        for (i, addr) in addrs.to_socket_addrs()?.enumerate() {
            if i >= MAX_SERVERS_PER_CONNECT {
                break;
            }

            server_addresses.addrs[i] = Some(addr);
            server_addresses.len += 1;
        }

        Ok(server_addresses)
    }
    pub fn len(&self) -> u32 {
        self.len
    }
    pub fn iter(&self) -> ServerAddrsIter {
        ServerAddrsIter {
            addrs: &self.addrs,
            index: 0,
        }
    }
}

pub struct ServerAddrsIter<'a> {
    addrs: &'a [Option<SocketAddr>; MAX_SERVERS_PER_CONNECT],
    index: usize,
}

impl<'a> Iterator for ServerAddrsIter<'a> {
    type Item = SocketAddr;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= MAX_SERVERS_PER_CONNECT {
            return None;
        }

        let addr = self.addrs[self.index];
        self.index += 1;
        addr
    }
}

impl Bytes for ServerAddresses {
    fn write(&self, buf: &mut impl io::Write) -> Result<(), io::Error> {
        buf.write_u32::<LittleEndian>(self.len())?;
        for addr in self.addrs.iter().flatten() {
            match addr {
                SocketAddr::V4(addr_v4) => {
                    buf.write_u8(Self::IPV4)?;
                    buf.write_u16::<LittleEndian>(addr_v4.port())?;
                    buf.write_all(&addr_v4.ip().octets())?;
                }
                SocketAddr::V6(addr_v6) => {
                    buf.write_u8(Self::IPV6)?;
                    buf.write_u16::<LittleEndian>(addr_v6.port())?;
                    buf.write_all(&addr_v6.ip().octets())?;
                }
            }
        }
        Ok(())
    }

    fn read(reader: &mut impl byteorder::ReadBytesExt) -> Result<Self, io::Error> {
        let len = reader.read_u32::<LittleEndian>()?;
        let mut addrs = [None; MAX_SERVERS_PER_CONNECT];

        for i in 0..len {
            let addr_type = reader.read_u8()?;
            let port = reader.read_u16::<LittleEndian>()?;
            addrs[i as usize] = Some(match addr_type {
                Self::IPV4 => {
                    let mut octets = [0; 4];
                    reader.read_exact(&mut octets)?;
                    SocketAddr::from((Ipv4Addr::from(octets), port))
                }
                Self::IPV6 => {
                    let mut octets = [0; 16];
                    reader.read_exact(&mut octets)?;
                    SocketAddr::from((Ipv6Addr::from(octets), port))
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "invalid ip address type",
                    ))
                }
            });
        }

        Ok(Self { len, addrs })
    }
}

pub struct ConnectTokenPrivate {
    client_id: u64,
    timeout_seconds: i32,
    server_addresses: ServerAddresses,
    client_to_server_key: [u8; PRIVATE_KEY_BYTES],
    server_to_client_key: [u8; PRIVATE_KEY_BYTES],
    user_data: [u8; USER_DATA_BYTES],
}

impl ConnectTokenPrivate {
    const NUM_BYTES: usize = 1024;
    pub fn new(
        client_id: u64,
        timeout_seconds: i32,
        server_addresses: ServerAddresses,
        user_data: [u8; USER_DATA_BYTES],
    ) -> Result<Self, NetcodeError> {
        Ok(Self {
            client_id,
            timeout_seconds,
            server_addresses,
            client_to_server_key: crypto::generate_key()?,
            server_to_client_key: crypto::generate_key()?,
            user_data,
        })
    }

    fn aead(
        protocol_id: u64,
        expire_timestamp: u64,
    ) -> Result<[u8; NETCODE_VERSION_BYTES_LEN + std::mem::size_of::<u64>() * 2], io::Error> {
        let mut aead = [0; NETCODE_VERSION_BYTES_LEN + std::mem::size_of::<u64>() * 2];
        let mut cursor = io::Cursor::new(&mut aead[..]);
        cursor.write_all(NETCODE_VERSION_BYTES)?;
        cursor.write_u64::<LittleEndian>(protocol_id)?;
        cursor.write_u64::<LittleEndian>(expire_timestamp)?;
        Ok(aead)
    }

    pub fn encrypt(
        &self,
        protocol_id: u64,
        expire_timestamp: u64,
        nonce: u64,
        private_key: &[u8; PRIVATE_KEY_BYTES],
    ) -> Result<[u8; Self::NUM_BYTES], NetcodeError> {
        let aead = Self::aead(protocol_id, expire_timestamp)?;
        let mut buf = [0u8; Self::NUM_BYTES - crypto::AUTH_TAG_BYTES]; // NOTE: token buffer needs 16-bytes overhead for auth tag
        let mut cursor = io::Cursor::new(&mut buf[..]);
        self.write(&mut cursor)?;
        let encrypted = crypto::encrypt(&mut buf, Some(&aead), nonce, private_key)?;
        Ok(encrypted)
    }

    pub fn decrypt(
        encrypted: &mut [u8; Self::NUM_BYTES],
        protocol_id: u64,
        expire_timestamp: u64,
        nonce: u64,
        private_key: &[u8; PRIVATE_KEY_BYTES],
    ) -> Result<Self, NetcodeError> {
        let aead = Self::aead(protocol_id, expire_timestamp)?;
        crypto::decrypt::<{ Self::NUM_BYTES }>(encrypted, Some(&aead), nonce, private_key)?;
        let mut cursor = io::Cursor::new(&encrypted[..]);
        Ok(Self::read(&mut cursor)?)
    }
}

impl Bytes for ConnectTokenPrivate {
    fn write(&self, buf: &mut impl io::Write) -> Result<(), io::Error> {
        buf.write_u64::<LittleEndian>(self.client_id)?;
        buf.write_i32::<LittleEndian>(self.timeout_seconds)?;
        self.server_addresses.write(buf)?;
        buf.write_all(&self.client_to_server_key)?;
        buf.write_all(&self.server_to_client_key)?;
        buf.write_all(&self.user_data)?;
        Ok(())
    }

    fn read(reader: &mut impl byteorder::ReadBytesExt) -> Result<Self, io::Error> {
        let client_id = reader.read_u64::<LittleEndian>()?;
        let timeout_seconds = reader.read_i32::<LittleEndian>()?;
        let server_addresses = ServerAddresses::read(reader)?;

        let mut client_to_server_key = [0; PRIVATE_KEY_BYTES];
        reader.read_exact(&mut client_to_server_key)?;

        let mut server_to_client_key = [0; PRIVATE_KEY_BYTES];
        reader.read_exact(&mut server_to_client_key)?;

        let mut user_data = [0; USER_DATA_BYTES];
        reader.read_exact(&mut user_data)?;

        Ok(Self {
            client_id,
            timeout_seconds,
            server_addresses,
            client_to_server_key,
            server_to_client_key,
            user_data,
        })
    }
}

#[test]
fn encrypt_decrypt_private_token() {
    use super::*;

    let private_key = crypto::generate_key().unwrap();
    let protocol_id = 1;
    let expire_timestamp = 2;
    let nonce = 3;
    let client_id = 4;
    let timeout_seconds = 5;
    let server_addresses = ServerAddresses::new(
        &[
            SocketAddr::from(([127, 0, 0, 1], 1)),
            SocketAddr::from(([127, 0, 0, 1], 2)),
            SocketAddr::from(([127, 0, 0, 1], 3)),
            SocketAddr::from(([127, 0, 0, 1], 4)),
        ][..],
    )
    .unwrap();
    let user_data = [0x11; USER_DATA_BYTES];

    let private_token =
        ConnectTokenPrivate::new(client_id, timeout_seconds, server_addresses, user_data).unwrap();

    let mut encrypted = private_token
        .encrypt(protocol_id, expire_timestamp, nonce, &private_key)
        .unwrap();

    let private_token = ConnectTokenPrivate::decrypt(
        &mut encrypted,
        protocol_id,
        expire_timestamp,
        nonce,
        &private_key,
    )
    .unwrap();

    assert_eq!(private_token.client_id, client_id);
    assert_eq!(private_token.timeout_seconds, timeout_seconds);
    private_token
        .server_addresses
        .iter()
        .zip(server_addresses.iter())
        .for_each(|(have, expected)| {
            assert_eq!(have, expected);
        });
    assert_eq!(private_token.user_data, user_data);
    assert_eq!(
        private_token.server_to_client_key,
        private_token.server_to_client_key
    );
    assert_eq!(
        private_token.client_to_server_key,
        private_token.client_to_server_key
    );
}
