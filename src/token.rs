use byteorder::{LittleEndian, WriteBytesExt};

use crate::{
    bytes::Bytes,
    consts::{
        DEFAULT_CONNECTION_TIMEOUT_SECONDS, DEFAULT_TOKEN_EXPIRE_SECONDS, NETCODE_VERSION,
        PRIVATE_KEY_SIZE, USER_DATA_SIZE,
    },
    crypto::{self, Key},
    error::NetcodeError,
    free_list::{FreeList, FreeListIter},
};

use std::{
    io::{self, Write},
    mem::size_of,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
};

pub const MAX_SERVERS_PER_CONNECT: usize = 32;

#[derive(Debug, Clone, Copy)]
pub struct AddressList {
    addrs: FreeList<SocketAddr, MAX_SERVERS_PER_CONNECT>,
}

impl AddressList {
    const IPV4: u8 = 1;
    const IPV6: u8 = 2;
    pub fn new(addrs: impl ToSocketAddrs) -> Result<Self, NetcodeError> {
        let mut server_addresses = FreeList::new();

        for (i, addr) in addrs.to_socket_addrs()?.enumerate() {
            if i >= MAX_SERVERS_PER_CONNECT {
                break;
            }

            server_addresses.insert(addr);
        }

        Ok(AddressList {
            addrs: server_addresses,
        })
    }
    pub fn len(&self) -> usize {
        self.addrs.len()
    }
    pub fn is_empty(&self) -> bool {
        self.addrs.len() == 0
    }
    pub fn iter(&self) -> FreeListIter<SocketAddr, MAX_SERVERS_PER_CONNECT> {
        FreeListIter {
            free_list: &self.addrs,
            index: 0,
        }
    }
}

impl std::ops::Index<usize> for AddressList {
    type Output = SocketAddr;

    fn index(&self, index: usize) -> &Self::Output {
        self.addrs.get(index).expect("index out of bounds")
    }
}

impl Bytes for AddressList {
    const SIZE: usize = size_of::<u32>() + MAX_SERVERS_PER_CONNECT * (1 + size_of::<u16>() + 16);
    fn write_to(&self, buf: &mut impl io::Write) -> Result<(), io::Error> {
        buf.write_u32::<LittleEndian>(self.len() as u32)?;
        for addr in self.iter() {
            match addr {
                SocketAddr::V4(addr_v4) => {
                    buf.write_u8(Self::IPV4)?;
                    buf.write_all(&addr_v4.ip().octets())?;
                    buf.write_u16::<LittleEndian>(addr_v4.port())?;
                }
                SocketAddr::V6(addr_v6) => {
                    buf.write_u8(Self::IPV6)?;
                    buf.write_all(&addr_v6.ip().octets())?;
                    buf.write_u16::<LittleEndian>(addr_v6.port())?;
                }
            }
        }
        Ok(())
    }

    fn read_from(reader: &mut impl byteorder::ReadBytesExt) -> Result<Self, io::Error> {
        let len = reader.read_u32::<LittleEndian>()?;
        let mut addrs = FreeList::new();

        for _ in 0..len {
            let addr_type = reader.read_u8()?;
            let addr = match addr_type {
                Self::IPV4 => {
                    let mut octets = [0; 4];
                    reader.read_exact(&mut octets)?;
                    let port = reader.read_u16::<LittleEndian>()?;
                    SocketAddr::from((Ipv4Addr::from(octets), port))
                }
                Self::IPV6 => {
                    let mut octets = [0; 16];
                    reader.read_exact(&mut octets)?;
                    let port = reader.read_u16::<LittleEndian>()?;
                    SocketAddr::from((Ipv6Addr::from(octets), port))
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "invalid ip address type",
                    ))
                }
            };
            addrs.insert(addr);
        }

        Ok(Self { addrs })
    }
}

pub(crate) struct ConnectTokenPrivate {
    pub(crate) client_id: u64,
    pub(crate) timeout_seconds: i32,
    pub(crate) server_addresses: AddressList,
    pub(crate) client_to_server_key: Key,
    pub(crate) server_to_client_key: Key,
    pub(crate) user_data: [u8; USER_DATA_SIZE],
}

impl ConnectTokenPrivate {
    fn aead(
        protocol_id: u64,
        expire_timestamp: u64,
    ) -> Result<[u8; NETCODE_VERSION.len() + std::mem::size_of::<u64>() * 2], NetcodeError> {
        let mut aead = [0; NETCODE_VERSION.len() + std::mem::size_of::<u64>() * 2];
        let mut cursor = io::Cursor::new(&mut aead[..]);
        cursor.write_all(NETCODE_VERSION)?;
        cursor.write_u64::<LittleEndian>(protocol_id)?;
        cursor.write_u64::<LittleEndian>(expire_timestamp)?;
        Ok(aead)
    }

    pub fn encrypt(
        &self,
        protocol_id: u64,
        expire_timestamp: u64,
        nonce: u64,
        private_key: &Key,
    ) -> Result<[u8; Self::SIZE], NetcodeError> {
        let aead = Self::aead(protocol_id, expire_timestamp)?;
        let mut buf = [0u8; Self::SIZE]; // NOTE: token buffer needs 16-bytes overhead for auth tag
        let mut cursor = io::Cursor::new(&mut buf[..]);
        self.write_to(&mut cursor)?;
        crypto::encrypt(&mut buf, Some(&aead), nonce, private_key)?;
        Ok(buf)
    }

    pub fn decrypt(
        encrypted: &mut [u8],
        protocol_id: u64,
        expire_timestamp: u64,
        nonce: u64,
        private_key: &Key,
    ) -> Result<Self, NetcodeError> {
        let aead = Self::aead(protocol_id, expire_timestamp)?;
        crypto::decrypt(encrypted, Some(&aead), nonce, private_key)?;
        let mut cursor = io::Cursor::new(encrypted);
        Ok(Self::read_from(&mut cursor)?)
    }
}

impl Bytes for ConnectTokenPrivate {
    const SIZE: usize = 1024; // always padded to 1024 bytes
    fn write_to(&self, buf: &mut impl io::Write) -> Result<(), io::Error> {
        buf.write_u64::<LittleEndian>(self.client_id)?;
        buf.write_i32::<LittleEndian>(self.timeout_seconds)?;
        self.server_addresses.write_to(buf)?;
        buf.write_all(&self.client_to_server_key)?;
        buf.write_all(&self.server_to_client_key)?;
        buf.write_all(&self.user_data)?;
        Ok(())
    }

    fn read_from(reader: &mut impl byteorder::ReadBytesExt) -> Result<Self, io::Error> {
        let client_id = reader.read_u64::<LittleEndian>()?;
        let timeout_seconds = reader.read_i32::<LittleEndian>()?;
        let server_addresses = AddressList::read_from(reader)?;

        let mut client_to_server_key = [0; PRIVATE_KEY_SIZE];
        reader.read_exact(&mut client_to_server_key)?;

        let mut server_to_client_key = [0; PRIVATE_KEY_SIZE];
        reader.read_exact(&mut server_to_client_key)?;

        let mut user_data = [0; USER_DATA_SIZE];
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

pub(crate) struct ChallengeToken {
    pub(crate) client_id: u64,
    pub(crate) user_data: [u8; USER_DATA_SIZE],
}

impl ChallengeToken {
    pub(crate) const SIZE: usize = 300;
    pub fn encrypt(
        &self,
        sequence: u64,
        private_key: &Key,
    ) -> Result<[u8; Self::SIZE], NetcodeError> {
        let mut buf = [0u8; Self::SIZE]; // NOTE: token buffer needs 16-bytes overhead for auth tag
        let mut cursor = io::Cursor::new(&mut buf[..]);
        self.write_to(&mut cursor)?;
        crypto::encrypt(&mut buf, None, sequence, private_key)?;
        Ok(buf)
    }

    pub fn decrypt(
        encrypted: &mut [u8; Self::SIZE],
        sequence: u64,
        private_key: &Key,
    ) -> Result<Self, NetcodeError> {
        crypto::decrypt(encrypted, None, sequence, private_key)?;
        let mut cursor = io::Cursor::new(&encrypted[..]);
        Ok(Self::read_from(&mut cursor)?)
    }
}

impl Bytes for ChallengeToken {
    const SIZE: usize = size_of::<u64>() + USER_DATA_SIZE;
    fn write_to(&self, buf: &mut impl io::Write) -> Result<(), io::Error> {
        buf.write_u64::<LittleEndian>(self.client_id)?;
        buf.write_all(&self.user_data)?;
        Ok(())
    }

    fn read_from(reader: &mut impl byteorder::ReadBytesExt) -> Result<Self, io::Error> {
        let client_id = reader.read_u64::<LittleEndian>()?;
        let mut user_data = [0; USER_DATA_SIZE];
        reader.read_exact(&mut user_data)?;
        Ok(Self {
            client_id,
            user_data,
        })
    }
}

// TODO: document
pub struct ConnectToken {
    pub version_info: [u8; NETCODE_VERSION.len()],
    pub protocol_id: u64,
    pub create_timestamp: u64,
    pub expire_timestamp: u64,
    pub nonce: u64,
    pub private_data: [u8; ConnectTokenPrivate::SIZE],
    pub timeout_seconds: i32,
    pub server_addresses: AddressList,
    pub client_to_server_key: Key,
    pub server_to_client_key: Key,
}

// TODO: document
pub struct ConnectTokenBuilder<A: ToSocketAddrs> {
    protocol_id: u64,
    client_id: u64,
    expire_seconds: i32,
    nonce: u64,
    timeout_seconds: i32,
    public_server_addresses: A,
    internal_server_addresses: Option<AddressList>,
    private_key: Option<Key>,
    user_data: [u8; USER_DATA_SIZE],
}

impl<A: ToSocketAddrs> ConnectTokenBuilder<A> {
    fn new(server_addresses: A, protocol_id: u64, client_id: u64, nonce: u64) -> Self {
        Self {
            protocol_id,
            client_id,
            expire_seconds: DEFAULT_TOKEN_EXPIRE_SECONDS,
            nonce,
            timeout_seconds: DEFAULT_CONNECTION_TIMEOUT_SECONDS,
            public_server_addresses: server_addresses,
            internal_server_addresses: None,
            private_key: None,
            user_data: [0; USER_DATA_SIZE],
        }
    }
    /// Sets the time in seconds that the token will be valid for.
    pub fn expire_seconds(mut self, expire_seconds: i32) -> Self {
        self.expire_seconds = expire_seconds;
        self
    }
    /// Sets the time in seconds that a connection will be kept alive without any packets being received.
    pub fn timeout_seconds(mut self, timeout_seconds: i32) -> Self {
        self.timeout_seconds = timeout_seconds;
        self
    }
    /// Sets the user data that will be added to the token, this can be any data you want.
    pub fn user_data(mut self, user_data: [u8; USER_DATA_SIZE]) -> Self {
        self.user_data = user_data;
        self
    }
    /// Sets the private key that will be used to encrypt the token.
    pub fn private_key(mut self, private_key: Key) -> Self {
        self.private_key = Some(private_key);
        self
    }
    /// Sets the *internal* server addresses in the private data of the token. <br>
    /// If this field is not set, the *public* server addresses provided when creating the builder will be used instead.
    ///
    /// This is useful for when you bind your server to a local address that is not accessible from the internet, <br>
    /// but you want to provide a public address that is accessible to the client.
    ///
    /// The client will always use the *public* server addresses list to connect to the server, never the *internal* ones.
    pub fn internal_address_list(mut self, internal_addresses: A) -> Result<Self, NetcodeError> {
        self.internal_server_addresses = Some(AddressList::new(internal_addresses)?);
        Ok(self)
    }
    /// Generates the token and consumes the builder.
    pub fn generate(self) -> Result<ConnectToken, NetcodeError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let expire_timestamp = if self.expire_seconds < 0 {
            u64::MAX
        } else {
            now + self.expire_seconds as u64
        };
        let public_server_addresses = AddressList::new(self.public_server_addresses)?;
        let internal_server_addresses = match self.internal_server_addresses {
            Some(addresses) => addresses,
            None => public_server_addresses,
        };
        let private_key = match self.private_key {
            Some(key) => key,
            None => crypto::generate_key()?,
        };
        let client_to_server_key = crypto::generate_key()?;
        let server_to_client_key = crypto::generate_key()?;

        let private_data = ConnectTokenPrivate {
            client_id: self.client_id,
            timeout_seconds: self.timeout_seconds,
            server_addresses: internal_server_addresses,
            client_to_server_key,
            server_to_client_key,
            user_data: self.user_data,
        }
        .encrypt(self.protocol_id, expire_timestamp, self.nonce, &private_key)?;

        Ok(ConnectToken {
            version_info: *NETCODE_VERSION,
            protocol_id: self.protocol_id,
            create_timestamp: now,
            expire_timestamp,
            nonce: self.nonce,
            private_data,
            timeout_seconds: self.timeout_seconds,
            server_addresses: public_server_addresses,
            client_to_server_key,
            server_to_client_key,
        })
    }
}

impl ConnectToken {
    pub fn build<A: ToSocketAddrs>(
        server_addresses: A,
        protocol_id: u64,
        client_id: u64,
        nonce: u64,
    ) -> ConnectTokenBuilder<A> {
        ConnectTokenBuilder::new(server_addresses, protocol_id, client_id, nonce)
    }

    pub fn try_into_bytes(self) -> Result<[u8; Self::SIZE], io::Error> {
        let mut buf = [0u8; Self::SIZE];
        let mut cursor = io::Cursor::new(&mut buf[..]);
        self.write_to(&mut cursor)?;
        Ok(buf)
    }
}

impl Bytes for ConnectToken {
    const SIZE: usize = 2048; // always padded to 2048 bytes
    fn write_to(&self, buf: &mut impl io::Write) -> Result<(), io::Error> {
        buf.write_all(&self.version_info)?;
        buf.write_u64::<LittleEndian>(self.protocol_id)?;
        buf.write_u64::<LittleEndian>(self.create_timestamp)?;
        buf.write_u64::<LittleEndian>(self.expire_timestamp)?;
        buf.write_u64::<LittleEndian>(self.nonce)?;
        buf.write_all(&self.private_data)?;
        buf.write_i32::<LittleEndian>(self.timeout_seconds)?;
        self.server_addresses.write_to(buf)?;
        buf.write_all(&self.client_to_server_key)?;
        buf.write_all(&self.server_to_client_key)?;
        Ok(())
    }

    fn read_from(reader: &mut impl byteorder::ReadBytesExt) -> Result<Self, io::Error> {
        let mut version_info = [0; NETCODE_VERSION.len()];
        reader.read_exact(&mut version_info)?;

        let protocol_id = reader.read_u64::<LittleEndian>()?;
        let create_timestamp = reader.read_u64::<LittleEndian>()?;
        let expire_timestamp = reader.read_u64::<LittleEndian>()?;
        let nonce = reader.read_u64::<LittleEndian>()?;

        let mut private_data = [0; ConnectTokenPrivate::SIZE];
        reader.read_exact(&mut private_data)?;

        let timeout_seconds = reader.read_i32::<LittleEndian>()?;

        let server_addresses = AddressList::read_from(reader)?;

        let mut client_to_server_key = [0; PRIVATE_KEY_SIZE];
        reader.read_exact(&mut client_to_server_key)?;

        let mut server_to_client_key = [0; PRIVATE_KEY_SIZE];
        reader.read_exact(&mut server_to_client_key)?;

        Ok(Self {
            version_info,
            protocol_id,
            create_timestamp,
            expire_timestamp,
            nonce,
            private_data,
            timeout_seconds,
            server_addresses,
            client_to_server_key,
            server_to_client_key,
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_private_token() {
        let private_key = crypto::generate_key().unwrap();
        let protocol_id = 1;
        let expire_timestamp = 2;
        let nonce = 3;
        let client_id = 4;
        let timeout_seconds = 5;
        let server_addresses = AddressList::new(
            &[
                SocketAddr::from(([127, 0, 0, 1], 1)),
                SocketAddr::from(([127, 0, 0, 1], 2)),
                SocketAddr::from(([127, 0, 0, 1], 3)),
                SocketAddr::from(([127, 0, 0, 1], 4)),
            ][..],
        )
        .unwrap();
        let user_data = [0x11; USER_DATA_SIZE];

        let private_token = ConnectTokenPrivate {
            client_id,
            timeout_seconds,
            server_addresses,
            user_data,
            client_to_server_key: crypto::generate_key().unwrap(),
            server_to_client_key: crypto::generate_key().unwrap(),
        };

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

    #[test]
    fn encrypt_decrypt_challenge_token() {
        let private_key = crypto::generate_key().unwrap();
        let sequence = 1;
        let client_id = 2;
        let user_data = [0x11; USER_DATA_SIZE];

        let challenge_token = ChallengeToken {
            client_id,
            user_data,
        };

        let mut encrypted = challenge_token.encrypt(sequence, &private_key).unwrap();

        let challenge_token =
            ChallengeToken::decrypt(&mut encrypted, sequence, &private_key).unwrap();

        assert_eq!(challenge_token.client_id, client_id);
        assert_eq!(challenge_token.user_data, user_data);
    }

    #[test]
    fn connect_token_read_write() {
        let private_key = crypto::generate_key().unwrap();
        let protocol_id = 1;
        let expire_timestamp = 2;
        let nonce = 3;
        let client_id = 4;
        let timeout_seconds = 5;
        let server_addresses = AddressList::new(
            &[
                SocketAddr::from(([127, 0, 0, 1], 1)),
                SocketAddr::from(([127, 0, 0, 1], 2)),
                SocketAddr::from(([127, 0, 0, 1], 3)),
                SocketAddr::from(([127, 0, 0, 1], 4)),
            ][..],
        )
        .unwrap();
        let user_data = [0x11; USER_DATA_SIZE];

        let private_token = ConnectTokenPrivate {
            client_id,
            timeout_seconds,
            server_addresses,
            user_data,
            client_to_server_key: crypto::generate_key().unwrap(),
            server_to_client_key: crypto::generate_key().unwrap(),
        };

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

        let mut private_data = [0; ConnectTokenPrivate::SIZE];
        let mut cursor = io::Cursor::new(&mut private_data[..]);
        private_token.write_to(&mut cursor).unwrap();

        let connect_token = ConnectToken {
            version_info: *NETCODE_VERSION,
            protocol_id,
            create_timestamp: 0,
            expire_timestamp,
            nonce,
            private_data,
            timeout_seconds,
            server_addresses,
            client_to_server_key: private_token.client_to_server_key,
            server_to_client_key: private_token.server_to_client_key,
        };

        let mut buf = Vec::new();
        connect_token.write_to(&mut buf).unwrap();

        let connect_token = ConnectToken::read_from(&mut buf.as_slice()).unwrap();

        assert_eq!(connect_token.version_info, *NETCODE_VERSION);
        assert_eq!(connect_token.protocol_id, protocol_id);
        assert_eq!(connect_token.create_timestamp, 0);
        assert_eq!(connect_token.expire_timestamp, expire_timestamp);
        assert_eq!(connect_token.nonce, nonce);
        assert_eq!(connect_token.private_data, private_data);
        assert_eq!(connect_token.timeout_seconds, timeout_seconds);
        connect_token
            .server_addresses
            .iter()
            .zip(server_addresses.iter())
            .for_each(|(have, expected)| {
                assert_eq!(have, expected);
            });
    }

    #[test]
    fn connect_token_builder() {
        let protocol_id = 1;
        let nonce = 3;
        let client_id = 4;
        let server_addresses = "127.0.0.1:12345";

        let connect_token = ConnectToken::build(server_addresses, protocol_id, client_id, nonce)
            .private_key([0x42; PRIVATE_KEY_SIZE])
            .user_data([0x11; USER_DATA_SIZE])
            .timeout_seconds(5)
            .expire_seconds(6)
            .internal_address_list("0.0.0.0:0")
            .expect("failed to parse address")
            .generate()
            .unwrap();

        assert_eq!(connect_token.version_info, *NETCODE_VERSION);
        assert_eq!(connect_token.protocol_id, protocol_id);
        assert_eq!(connect_token.nonce, nonce);
        assert_eq!(connect_token.timeout_seconds, 5);
        assert_eq!(
            connect_token.expire_timestamp,
            connect_token.create_timestamp + 6
        );
        connect_token
            .server_addresses
            .iter()
            .zip(server_addresses.to_socket_addrs().into_iter().flatten())
            .for_each(|(have, expected)| {
                assert_eq!(have, expected);
            });
    }
}
