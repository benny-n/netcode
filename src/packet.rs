use std::{
    io::{self, Read, Write},
    mem::size_of,
};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use crate::{
    bytes::Bytes,
    consts::{
        MAC_SIZE, MAX_PAYLOAD_SIZE, MAX_PKT_BUF_SIZE, NETCODE_VERSION, NETCODE_VERSION_SIZE,
        NONCE_BYTES_SIZE, PRIVATE_KEY_SIZE, USER_DATA_SIZE,
    },
    crypto,
    error::NetcodeError,
    replay::ReplayProtection,
    token::{ChallengeToken, ConnectTokenPrivate},
    Key,
};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("packet type {0} is invalid")]
    InvalidType(u8),
    #[error("sequence bytes {0} are out of range [1, 8]")]
    InvalidSequenceBytes(u8),
    #[error("packet length is less than 1")]
    TooSmall,
    #[error("packet length is greater than 1200")]
    TooLarge,
    #[error("bad packet length, expected {expected} but got {actual}")]
    LengthMismatch { expected: usize, actual: usize },
    #[error("bad version info")]
    BadVersion,
    #[error("wrong protocol id, expected {expected} but got {actual}")]
    BadProtocolId { expected: u64, actual: u64 },
    #[error("connect token expired")]
    TokenExpired,
    #[error("sequence {0} already received")]
    AlreadyReceived(u64),
}

pub struct RequestPacket {
    pub version_info: [u8; NETCODE_VERSION_SIZE],
    pub protocol_id: u64,
    pub expire_timestamp: u64,
    pub token_nonce: [u8; NONCE_BYTES_SIZE],
    pub token_data: [u8; ConnectTokenPrivate::SIZE],
}

impl RequestPacket {
    pub(crate) fn validate(&self, protocol_id: u64, current_timestamp: u64) -> Result<(), Error> {
        if &self.version_info != NETCODE_VERSION {
            return Err(Error::BadVersion);
        }
        if self.protocol_id != protocol_id {
            return Err(Error::BadProtocolId {
                expected: protocol_id,
                actual: self.protocol_id,
            });
        }
        if self.expire_timestamp <= current_timestamp {
            return Err(Error::TokenExpired);
        }
        Ok(())
    }

    pub(crate) fn decrypt_token_data(&mut self, private_key: Key) -> Result<(), NetcodeError> {
        let decrypted = ConnectTokenPrivate::decrypt(
            &mut self.token_data,
            self.protocol_id,
            self.expire_timestamp,
            u64::from_le_bytes(
                self.token_nonce[4..]
                    .try_into()
                    .map_err(|_| NetcodeError::InvalidPacket)?,
            ),
            &private_key,
        )?;
        let mut token_data = std::io::Cursor::new(&mut self.token_data[..]);
        decrypted.write_to(&mut token_data)?;
        Ok(())
    }
}

impl Bytes for RequestPacket {
    fn write_to(&self, writer: &mut impl WriteBytesExt) -> Result<(), io::Error> {
        writer.write_all(&self.version_info)?;
        writer.write_u64::<LittleEndian>(self.protocol_id)?;
        writer.write_u64::<LittleEndian>(self.expire_timestamp)?;
        writer.write_all(&self.token_nonce)?;
        writer.write_all(&self.token_data)?;
        Ok(())
    }

    fn read_from(reader: &mut impl byteorder::ReadBytesExt) -> Result<Self, io::Error> {
        let mut version_info = [0; NETCODE_VERSION_SIZE];
        reader.read_exact(&mut version_info)?;
        let protocol_id = reader.read_u64::<LittleEndian>()?;
        let expire_timestamp = reader.read_u64::<LittleEndian>()?;
        let mut token_nonce = [0; NONCE_BYTES_SIZE];
        reader.read_exact(&mut token_nonce)?;
        let mut token_data = [0; ConnectTokenPrivate::SIZE];
        reader.read_exact(&mut token_data)?;
        Ok(Self {
            version_info,
            protocol_id,
            expire_timestamp,
            token_nonce,
            token_data,
        })
    }
}

pub struct DeniedPacket {}
impl DeniedPacket {
    pub(crate) fn create() -> Packet {
        Packet::Denied(DeniedPacket {})
    }
}
impl Bytes for DeniedPacket {
    fn write_to(&self, _writer: &mut impl WriteBytesExt) -> Result<(), io::Error> {
        Ok(())
    }

    fn read_from(_reader: &mut impl byteorder::ReadBytesExt) -> Result<Self, io::Error> {
        Ok(Self {})
    }
}

pub struct ChallengePacket {
    pub sequence: u64,
    pub token: [u8; ChallengeToken::SIZE],
}
impl ChallengePacket {
    pub(crate) fn create(sequence: u64, token_bytes: [u8; ChallengeToken::SIZE]) -> Packet {
        Packet::Challenge(ChallengePacket {
            sequence,
            token: token_bytes,
        })
    }
}

impl Bytes for ChallengePacket {
    fn write_to(&self, writer: &mut impl WriteBytesExt) -> Result<(), io::Error> {
        writer.write_u64::<LittleEndian>(self.sequence)?;
        writer.write_all(&self.token)?;
        Ok(())
    }

    fn read_from(reader: &mut impl byteorder::ReadBytesExt) -> Result<Self, io::Error> {
        let sequence = reader.read_u64::<LittleEndian>()?;
        let mut token = [0; ChallengeToken::SIZE];
        reader.read_exact(&mut token)?;
        Ok(Self { sequence, token })
    }
}

pub struct ResponsePacket {
    pub sequence: u64,
    pub token: [u8; ChallengeToken::SIZE],
}
impl Bytes for ResponsePacket {
    fn write_to(&self, writer: &mut impl WriteBytesExt) -> Result<(), io::Error> {
        writer.write_u64::<LittleEndian>(self.sequence)?;
        writer.write_all(&self.token)?;
        Ok(())
    }

    fn read_from(reader: &mut impl byteorder::ReadBytesExt) -> Result<Self, io::Error> {
        let sequence = reader.read_u64::<LittleEndian>()?;
        let mut token = [0; ChallengeToken::SIZE];
        reader.read_exact(&mut token)?;
        Ok(Self { sequence, token })
    }
}

pub struct KeepAlivePacket {
    pub client_index: i32,
    pub max_clients: i32,
}
impl KeepAlivePacket {
    pub(crate) fn create(client_index: i32, max_clients: i32) -> Packet {
        Packet::KeepAlive(KeepAlivePacket {
            client_index,
            max_clients,
        })
    }
}
impl Bytes for KeepAlivePacket {
    fn write_to(&self, writer: &mut impl WriteBytesExt) -> Result<(), io::Error> {
        writer.write_i32::<LittleEndian>(self.client_index)?;
        writer.write_i32::<LittleEndian>(self.max_clients)?;
        Ok(())
    }

    fn read_from(reader: &mut impl byteorder::ReadBytesExt) -> Result<Self, io::Error> {
        let client_index = reader.read_i32::<LittleEndian>()?;
        let max_clients = reader.read_i32::<LittleEndian>()?;
        Ok(Self {
            client_index,
            max_clients,
        })
    }
}

pub struct PayloadPacket {
    pub payload: Vec<u8>,
}

pub struct DisconnectPacket {}
impl DisconnectPacket {
    pub(crate) fn create() -> Packet {
        Packet::Disconnect(Self {})
    }
}
impl Bytes for DisconnectPacket {
    fn write_to(&self, _writer: &mut impl WriteBytesExt) -> Result<(), io::Error> {
        Ok(())
    }

    fn read_from(_reader: &mut impl byteorder::ReadBytesExt) -> Result<Self, io::Error> {
        Ok(Self {})
    }
}

pub enum Packet {
    Request(RequestPacket),
    Denied(DeniedPacket),
    Challenge(ChallengePacket),
    Response(ResponsePacket),
    KeepAlive(KeepAlivePacket),
    Payload(PayloadPacket),
    Disconnect(DisconnectPacket),
}

impl std::fmt::Display for Packet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Packet::Request(_) => write!(f, "connection request"),
            Packet::Response(_) => write!(f, "connection response"),
            Packet::KeepAlive(_) => write!(f, "keep alive packet"),
            Packet::Payload(_) => write!(f, "payload packet"),
            Packet::Disconnect(_) => write!(f, "disconnect packet"),
            Packet::Denied(_) => write!(f, "denied packet"),
            Packet::Challenge(_) => write!(f, "challenge packet"),
        }
    }
}

pub type PacketKind = u8;

impl Packet {
    pub(crate) const REQUEST: PacketKind = 0;
    pub(crate) const DENIED: PacketKind = 1;
    pub(crate) const CHALLENGE: PacketKind = 2;
    pub(crate) const RESPONSE: PacketKind = 3;
    pub(crate) const KEEP_ALIVE: PacketKind = 4;
    pub(crate) const PAYLOAD: PacketKind = 5;
    pub(crate) const DISCONNECT: PacketKind = 6;
    fn kind(&self) -> PacketKind {
        match self {
            Packet::Request(_) => Packet::REQUEST,
            Packet::Denied(_) => Packet::DENIED,
            Packet::Challenge(_) => Packet::CHALLENGE,
            Packet::Response(_) => Packet::RESPONSE,
            Packet::KeepAlive(_) => Packet::KEEP_ALIVE,
            Packet::Payload(_) => Packet::PAYLOAD,
            Packet::Disconnect(_) => Packet::DISCONNECT,
        }
    }
    fn prefix_byte(&self, sequence: u64) -> u8 {
        sequence_len(sequence) << 4 | self.kind()
    }
    pub(crate) fn seq_len_and_pkt_kind(first_byte: u8) -> (usize, PacketKind) {
        ((first_byte >> 4) as usize, first_byte & 0xF)
    }
    pub(crate) fn is_connection_request(first_byte: u8) -> bool {
        first_byte == Packet::REQUEST
    }
    pub fn write(
        &self,
        out: &mut [u8],
        sequence: u64,
        packet_key: &Key,
        protocol_id: u64,
    ) -> Result<usize, NetcodeError> {
        let len = out.len();
        let mut cursor = std::io::Cursor::new(&mut out[..]);
        if let Packet::Request(pkt) = self {
            cursor.write_u8(Packet::REQUEST)?;
            pkt.write_to(&mut cursor)?;
            return Ok(cursor.position() as usize);
        }
        cursor.write_u8(self.prefix_byte(sequence))?;
        for shift in 0..sequence_len(sequence) {
            cursor.write_u8(((sequence >> shift as u64) & 0xFF) as u8)?;
        }
        let encryption_start = cursor.position() as usize;
        match self {
            Packet::Denied(pkt) => pkt.write_to(&mut cursor)?,
            Packet::Challenge(pkt) => pkt.write_to(&mut cursor)?,
            Packet::Response(pkt) => pkt.write_to(&mut cursor)?,
            Packet::KeepAlive(pkt) => pkt.write_to(&mut cursor)?,
            Packet::Disconnect(pkt) => pkt.write_to(&mut cursor)?,
            Packet::Payload(PayloadPacket { payload }) => cursor.write_all(payload)?,
            _ => unreachable!(), // Packet::Request variant is handled above
        }
        if cursor.position() as usize > len - MAC_SIZE {
            return Err(Error::TooLarge.into());
        }
        let encryption_end = cursor.position() as usize + MAC_SIZE;

        // Encrypt the per-packet packet written with the prefix byte, protocol id and version as the associated data.
        // This must match to decrypt.
        let mut aead = [0u8; NETCODE_VERSION_SIZE + size_of::<u64>() + size_of::<u8>()];
        let mut aead_cursor = std::io::Cursor::new(&mut aead[..]);
        aead_cursor.write_all(NETCODE_VERSION)?;
        aead_cursor.write_u64::<LittleEndian>(protocol_id)?;
        aead_cursor.write_u8(self.prefix_byte(sequence))?;

        crypto::encrypt(
            &mut out[encryption_start..encryption_end],
            Some(&aead),
            sequence,
            packet_key,
        )?;

        Ok(encryption_end)
    }
    pub fn read(
        buf: &mut [u8], // buffer needs to be mutable to perform decryption in-place
        protocol_id: u64,
        timestamp: u64,
        key: Key,
        replay_protection: Option<&mut ReplayProtection>,
    ) -> Result<Self, NetcodeError> {
        let buf_len = buf.len();
        if buf_len < 1 {
            return Err(Error::TooSmall.into());
        }
        if buf_len > MAX_PKT_BUF_SIZE {
            return Err(Error::TooLarge.into());
        }
        let mut cursor = std::io::Cursor::new(&mut buf[..]);
        let prefix_byte = cursor.read_u8()?;
        if prefix_byte == Packet::REQUEST {
            // connection request packet: first byte should be 0x00
            let mut packet = RequestPacket::read_from(&mut cursor)?;
            packet.validate(protocol_id, timestamp)?;
            packet.decrypt_token_data(key)?;
            return Ok(Packet::Request(packet));
        }
        let (sequence_len, pkt_kind) = Packet::seq_len_and_pkt_kind(prefix_byte);
        if buf_len < size_of::<u8>() + sequence_len + MAC_SIZE {
            // should at least have prefix byte, sequence and mac
            return Err(Error::TooSmall.into());
        }
        let mut sequence = [0; 8];
        cursor.read_exact(&mut sequence[..sequence_len])?;
        let sequence = u64::from_le_bytes(sequence);

        // Replay protection
        if let Some(replay_protection) = replay_protection.as_ref() {
            if pkt_kind >= Packet::KEEP_ALIVE && replay_protection.is_already_received(sequence) {
                return Err(Error::AlreadyReceived(sequence).into());
            }
        }

        let mut aead = [0u8; NETCODE_VERSION_SIZE + size_of::<u64>() + size_of::<u8>()];
        let mut aead_cursor = std::io::Cursor::new(&mut aead[..]);
        aead_cursor.write_all(NETCODE_VERSION)?;
        aead_cursor.write_u64::<LittleEndian>(protocol_id)?;
        aead_cursor.write_u8(prefix_byte)?;

        let decryption_start = cursor.position() as usize;
        let decryption_end = buf_len;
        crypto::decrypt(
            &mut cursor.get_mut()[decryption_start..decryption_end],
            Some(&aead),
            sequence,
            &key,
        )?;
        // make sure cursor position is at the start of the decrypted data, so we can read it into a valid packet
        cursor.set_position(decryption_start as u64);

        if let Some(replay_protection) = replay_protection {
            if pkt_kind >= Packet::KEEP_ALIVE {
                replay_protection.advance_sequence(sequence);
            }
        }

        let packet = match pkt_kind {
            Packet::REQUEST => Packet::Request(RequestPacket::read_from(&mut cursor)?),
            Packet::DENIED => Packet::Denied(DeniedPacket::read_from(&mut cursor)?),
            Packet::CHALLENGE => Packet::Challenge(ChallengePacket::read_from(&mut cursor)?),
            Packet::RESPONSE => Packet::Response(ResponsePacket::read_from(&mut cursor)?),
            Packet::KEEP_ALIVE => Packet::KeepAlive(KeepAlivePacket::read_from(&mut cursor)?),
            Packet::DISCONNECT => Packet::Disconnect(DisconnectPacket::read_from(&mut cursor)?),
            Packet::PAYLOAD => {
                let mut payload = vec![0; decryption_end - decryption_start - MAC_SIZE];
                cursor.read_exact(&mut payload)?;
                Packet::Payload(PayloadPacket { payload })
            }
            t => return Err(Error::InvalidType(t).into()),
        };
        Ok(packet)
    }
}

pub fn sequence_len(sequence: u64) -> u8 {
    std::cmp::max(8 - sequence.leading_zeros() as u8 / 8, 1)
}

#[cfg(test)]
mod tests {
    use crate::{crypto::generate_key, token::AddressList};

    use super::*;

    #[test]
    fn sequence_number_bytes_required() {
        assert_eq!(sequence_len(0), 1);
        assert_eq!(sequence_len(1), 1);
        assert_eq!(sequence_len(0x1_00), 2);
        assert_eq!(sequence_len(0x1_00_00), 3);
        assert_eq!(sequence_len(0x1_00_00_00), 4);
        assert_eq!(sequence_len(0x1_00_00_00_00), 5);
        assert_eq!(sequence_len(0x1_00_00_00_00_00), 6);
        assert_eq!(sequence_len(0x1_00_00_00_00_00_00), 7);
        assert_eq!(sequence_len(0x1_00_00_00_00_00_00_00), 8);
        assert_eq!(sequence_len(0x80_00_00_00_00_00_00_00), 8);
    }

    #[test]
    fn request_packet() {
        let client_id = 0x1234;
        let timeout_seconds = -1;
        let server_addresses = AddressList::new("127.0.0.1:40000").unwrap();
        let user_data = [0u8; USER_DATA_SIZE];
        let private_key = generate_key().unwrap();
        let packet_key = generate_key().unwrap();
        let protocol_id = 0x1234_5678_9abc_def0;
        let expire_timestamp = u64::MAX;
        let sequence = 0u64;
        let token_nonce = [0u8; NONCE_BYTES_SIZE];
        let mut replay_protection = ReplayProtection::new();
        let token_data =
            ConnectTokenPrivate::new(client_id, timeout_seconds, server_addresses, user_data)
                .unwrap();

        let token_data = token_data
            .encrypt(protocol_id, expire_timestamp, sequence, &private_key)
            .unwrap();

        let packet = Packet::Request(RequestPacket {
            version_info: *NETCODE_VERSION,
            protocol_id,
            expire_timestamp,
            token_nonce,
            token_data,
        });

        let mut buf = [0u8; MAX_PAYLOAD_SIZE];
        let size = packet
            .write(&mut buf, sequence, &packet_key, protocol_id)
            .unwrap();

        let packet = Packet::read(
            &mut buf[..size],
            protocol_id,
            0,
            private_key,
            Some(&mut replay_protection),
        )
        .unwrap();

        let Packet::Request (req_pkt) = packet else {
            panic!("wrong packet type");
        };

        assert_eq!(req_pkt.version_info, *NETCODE_VERSION);
        assert_eq!(req_pkt.protocol_id, protocol_id);
        assert_eq!(req_pkt.expire_timestamp, expire_timestamp);
        assert_eq!(req_pkt.token_nonce, token_nonce);

        let mut reader = std::io::Cursor::new(req_pkt.token_data);
        let connect_token_private = ConnectTokenPrivate::read_from(&mut reader).unwrap();
        assert_eq!(connect_token_private.client_id, client_id);
        assert_eq!(connect_token_private.timeout_seconds, timeout_seconds);
        connect_token_private
            .server_addresses
            .iter()
            .zip(server_addresses.iter())
            .for_each(|(have, expected)| {
                assert_eq!(have, expected);
            });
        assert_eq!(connect_token_private.user_data, user_data);
    }

    #[test]
    fn denied_packet() {
        let packet_key = generate_key().unwrap();
        let protocol_id = 0x1234_5678_9abc_def0;
        let sequence = 0u64;
        let mut replay_protection = ReplayProtection::new();

        let packet = Packet::Denied(DeniedPacket {});

        let mut buf = [0u8; MAX_PKT_BUF_SIZE];
        let size = packet
            .write(&mut buf, sequence, &packet_key, protocol_id)
            .unwrap();

        let packet = Packet::read(
            &mut buf[..size],
            protocol_id,
            0,
            packet_key,
            Some(&mut replay_protection),
        )
        .unwrap();

        let Packet::Denied (_denied_pkt) = packet else {
            panic!("wrong packet type");
        };
    }

    #[test]
    pub fn challenge_packet() {
        let token = [0u8; ChallengeToken::SIZE];
        let packet_key = generate_key().unwrap();
        let protocol_id = 0x1234_5678_9abc_def0;
        let sequence = 0u64;
        let mut replay_protection = ReplayProtection::new();

        let packet = Packet::Challenge(ChallengePacket { sequence, token });

        let mut buf = [0u8; MAX_PKT_BUF_SIZE];
        let size = packet
            .write(&mut buf, sequence, &packet_key, protocol_id)
            .unwrap();

        let packet = Packet::read(
            &mut buf[..size],
            protocol_id,
            0,
            packet_key,
            Some(&mut replay_protection),
        )
        .unwrap();

        let Packet::Challenge (challenge_pkt) = packet else {
            panic!("wrong packet type");
        };

        assert_eq!(challenge_pkt.token, token);
        assert_eq!(challenge_pkt.sequence, sequence);
    }

    #[test]
    pub fn keep_alive_packet() {
        let packet_key = generate_key().unwrap();
        let protocol_id = 0x1234_5678_9abc_def0;
        let sequence = 0u64;
        let client_index = 0;
        let max_clients = 32;
        let mut replay_protection = ReplayProtection::new();

        let packet = Packet::KeepAlive(KeepAlivePacket {
            client_index,
            max_clients,
        });

        let mut buf = [0u8; MAX_PKT_BUF_SIZE];
        let size = packet
            .write(&mut buf, sequence, &packet_key, protocol_id)
            .unwrap();

        let packet = Packet::read(
            &mut buf[..size],
            protocol_id,
            0,
            packet_key,
            Some(&mut replay_protection),
        )
        .unwrap();

        let Packet::KeepAlive (keep_alive_pkt) = packet else {
            panic!("wrong packet type");
        };

        assert_eq!(keep_alive_pkt.client_index, client_index);
        assert_eq!(keep_alive_pkt.max_clients, max_clients);
    }

    #[test]
    pub fn disconnect_packet() {
        let packet_key = generate_key().unwrap();
        let protocol_id = 0x1234_5678_9abc_def0;
        let sequence = 0u64;
        let mut replay_protection = ReplayProtection::new();

        let packet = Packet::Disconnect(DisconnectPacket {});

        let mut buf = [0u8; MAX_PKT_BUF_SIZE];
        let size = packet
            .write(&mut buf, sequence, &packet_key, protocol_id)
            .unwrap();

        let packet = Packet::read(
            &mut buf[..size],
            protocol_id,
            0,
            packet_key,
            Some(&mut replay_protection),
        )
        .unwrap();

        let Packet::Disconnect (_disconnect_pkt) = packet else {
            panic!("wrong packet type");
        };
    }

    #[test]
    pub fn payload_packet() {
        let packet_key = generate_key().unwrap();
        let protocol_id = 0x1234_5678_9abc_def0;
        let sequence = 0u64;
        let mut replay_protection = ReplayProtection::new();

        let packet = Packet::Payload(PayloadPacket {
            payload: vec![0u8; 100],
        });

        let mut buf = [0u8; MAX_PAYLOAD_SIZE];
        let size = packet
            .write(&mut buf, sequence, &packet_key, protocol_id)
            .unwrap();

        let packet = Packet::read(
            &mut buf[..size],
            protocol_id,
            0,
            packet_key,
            Some(&mut replay_protection),
        )
        .unwrap();

        let Packet::Payload (data_pkt) = packet else {
            panic!("wrong packet type");
        };

        assert_eq!(data_pkt.payload.len(), 100);
    }
}
