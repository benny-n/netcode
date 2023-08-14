use std::collections::HashMap;
use std::f32::consts::E;
use std::io::{self};
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};

use socket2::{Domain, Protocol, Socket, Type};

use crate::consts::{
    MAX_PAYLOAD_SIZE, PRIVATE_KEY_SIZE, SERVER_SOCKET_RECV_BUF_SIZE, SERVER_SOCKET_SEND_BUF_SIZE,
};
use crate::error::NetcodeError;
use crate::packet::Packet;
use crate::replay::ReplayProtection;
use crate::socket::NetcodeSocket;
use crate::token::ConnectTokenPrivate;
use crate::transceiver::Transceiver;
use crate::utils::{time_now_secs, time_now_secs_f64};

pub type Result<T> = std::result::Result<T, NetcodeError>;

// int num_encryption_mappings;
// int timeout[NETCODE_MAX_ENCRYPTION_MAPPINGS];
// double expire_time[NETCODE_MAX_ENCRYPTION_MAPPINGS];
// double last_access_time[NETCODE_MAX_ENCRYPTION_MAPPINGS];
// struct netcode_address_t address[NETCODE_MAX_ENCRYPTION_MAPPINGS];
// int client_index[NETCODE_MAX_ENCRYPTION_MAPPINGS];
// uint8_t send_key[NETCODE_KEY_BYTES*NETCODE_MAX_ENCRYPTION_MAPPINGS];
// uint8_t receive_key[NETCODE_KEY_BYTES*NETCODE_MAX_ENCRYPTION_MAPPINGS];

struct EncryptionMapping {
    timeout: i32,
    expire_time: f64,
    last_access_time: f64,
    send_key: [u8; PRIVATE_KEY_SIZE],
    receive_key: [u8; PRIVATE_KEY_SIZE],
    replay_protection: ReplayProtection,
}

struct EncryptionManager {
    map: HashMap<SocketAddr, EncryptionMapping>,
    time: f64,
}

impl EncryptionManager {
    fn new(server_time: f64) -> Self {
        Self {
            map: HashMap::new(),
            time: server_time,
        }
    }
    fn add_mapping(&mut self, addr: SocketAddr, mapping: EncryptionMapping) {
        self.map.insert(addr, mapping);
    }
    fn remove_mapping(&mut self, addr: SocketAddr) {
        self.map.remove(&addr);
    }
    fn is_mapping_expired(mapping: &EncryptionMapping, time: f64) -> bool {
        (0.0..time).contains(&mapping.expire_time)
            || (0.0..time - mapping.last_access_time).contains(&(mapping.timeout as f64))
    }
    fn is_expired(&self, addr: SocketAddr) -> bool {
        self.map
            .get(&addr)
            .is_some_and(|mapping| Self::is_mapping_expired(mapping, self.time))
    }
    fn update(&mut self, time: f64) {
        self.time = time;
        self.map
            .retain(|_, mapping| !Self::is_mapping_expired(mapping, self.time));
    }
}

pub struct Server<T: Transceiver> {
    time: f64,
    protocol_id: u64,
    private_key: [u8; PRIVATE_KEY_SIZE],
    transceiver: T,
    encrpytion_mgr: EncryptionManager,
}

impl Server<NetcodeSocket> {
    pub fn new(addr: impl ToSocketAddrs, protocol_id: u64) -> Result<Self> {
        let time = time_now_secs_f64()?;
        Ok(Self {
            time,
            protocol_id,
            private_key: [0u8; PRIVATE_KEY_SIZE],
            transceiver: NetcodeSocket::new(addr)?,
            encrpytion_mgr: EncryptionManager::new(time),
        })
    }
}

// #[cfg(test)]
// use crate::simulator::NetworkSimulator;
// #[cfg(test)]
// impl Server<NetworkSimulator> {
//     pub fn new() -> Result<Self> {
//         Ok(Self {
//             transceiver: NetworkSimulator::default(),
//         })
//     }
// }

impl<T: Transceiver> Server<T> {
    fn process_packet(&mut self, client_idx: usize, packet: Packet) -> Result<()> {
        match packet {
            Packet::Request(pkt) => {
                todo!()
            }
            Packet::KeepAlive { .. } => {
                todo!()
            }
            Packet::Disconnect { .. } => {
                todo!()
            }
            Packet::Payload { .. } => {
                todo!()
            }
            _ => todo!(),
        }
    }
    pub fn update(&mut self, time: f64) -> Result<()> {
        self.time = time;
        Ok(())
    }
    pub fn receive_packets(&mut self) -> Result<()> {
        let now = time_now_secs()?;
        let mut payload = [0u8; MAX_PAYLOAD_SIZE];
        let (size, addr) = self.transceiver.recv(&mut payload).map_err(|e| e.into())?;
        let Some(addr) = addr else {
            // No packet received
            return Ok(());
        };
        if size <= 1 {
            // Too small to be a packet
            return Ok(());
        }
        let (_, kind) = Packet::seq_len_and_pkt_kind(payload[0]);
        let Some(encryption_mapping) = self.encrpytion_mgr.map.get_mut(&addr) else {
            // New client
            if kind != Packet::REQUEST {
                // Not a connect packet
                return Ok(());
            }
            // connect client for the first time
            todo!()
        };
        let packet = Packet::read(
            &mut payload[..size],
            encryption_mapping.receive_key,
            self.protocol_id,
            now,
            self.private_key,
            Some(&mut encryption_mapping.replay_protection),
        )?;
        Ok(())
    }
    pub fn send_packets(&mut self) -> Result<()> {
        todo!()
    }
    pub fn check_for_timeouts(&mut self) -> Result<()> {
        todo!();
    }
}
