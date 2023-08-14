use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::f32::consts::E;
use std::io::{self};
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket};

use socket2::{Domain, Protocol, Socket, Type};

use crate::bytes::Bytes;
use crate::consts::{
    MAC_SIZE, MAX_CLIENTS, MAX_PAYLOAD_SIZE, MAX_PKT_BUF_SIZE, PRIVATE_KEY_SIZE,
    SERVER_SOCKET_RECV_BUF_SIZE, SERVER_SOCKET_SEND_BUF_SIZE,
};
use crate::error::NetcodeError;
use crate::packet::{
    ChallengePacket, DeniedPacket, DisconnectPacket, KeepAlivePacket, Packet, RequestPacket,
    ResponsePacket,
};
use crate::replay::ReplayProtection;
use crate::socket::NetcodeSocket;
use crate::token::{ChallengeToken, ConnectTokenPrivate};
use crate::transceiver::Transceiver;
use crate::utils::{time_now_secs, time_now_secs_f64};
use crate::{crypto, Key};

pub type Result<T> = std::result::Result<T, NetcodeError>;

// int num_encryption_mappings;
// int timeout[NETCODE_MAX_ENCRYPTION_MAPPINGS];
// double expire_time[NETCODE_MAX_ENCRYPTION_MAPPINGS];
// double last_access_time[NETCODE_MAX_ENCRYPTION_MAPPINGS];
// struct netcode_address_t address[NETCODE_MAX_ENCRYPTION_MAPPINGS];
// int client_index[NETCODE_MAX_ENCRYPTION_MAPPINGS];
// uint8_t send_key[NETCODE_KEY_BYTES*NETCODE_MAX_ENCRYPTION_MAPPINGS];
// uint8_t receive_key[NETCODE_KEY_BYTES*NETCODE_MAX_ENCRYPTION_MAPPINGS];

struct TokenEntry {
    time: f64,
    mac: [u8; 16],
}

struct Connection {
    connected: bool,
    addr: SocketAddr,
    timeout: i32,
    expire_time: f64,
    last_access_time: f64,
    last_send_time: f64,
    last_receive_time: f64,
    send_key: Key,
    receive_key: Key,
    sequence: u64,
    replay_protection: ReplayProtection,
}

impl Connection {
    fn connect(&mut self) {
        self.connected = true;
    }
    fn is_connected(&self) -> bool {
        self.connected
    }
}

pub type ClientId = u64;

struct ConnectionCache {
    map: HashMap<ClientId, Connection>,
    addr_to_id: HashMap<SocketAddr, ClientId>, // optimization for finding client_id from addr
    time: f64,
}

impl ConnectionCache {
    fn new(server_time: f64) -> Self {
        Self {
            map: HashMap::new(),
            addr_to_id: HashMap::new(),
            time: server_time,
        }
    }
    fn add(
        &mut self,
        client_id: u64,
        addr: SocketAddr,
        timeout: i32,
        expire_time: f64,
        send_key: Key,
        receive_key: Key,
    ) {
        let conn = Connection {
            connected: false,
            addr,
            timeout,
            expire_time,
            last_access_time: self.time,
            last_send_time: 0.0,
            last_receive_time: 0.0,
            send_key,
            receive_key,
            sequence: 0, // TODO: check if this can simply be grabbed from the replay protection
            replay_protection: ReplayProtection::new(),
        };
        self.map.insert(client_id, conn);
        self.addr_to_id.insert(addr, client_id);
    }
    fn remove(&mut self, client_id: ClientId) {
        if let Some((_, conn)) = self.map.remove_entry(&client_id) {
            self.addr_to_id.remove(&conn.addr);
        };
    }
    fn get_client_id(&self, addr: SocketAddr) -> Option<ClientId> {
        self.addr_to_id.get(&addr).copied()
    }
    fn find(&mut self, client_id: ClientId) -> Option<&mut Connection> {
        self.map.get_mut(&client_id).map(|conn| {
            conn.last_access_time = self.time;
            conn
        })
    }
    fn find_by_addr(&mut self, addr: SocketAddr) -> Option<&mut Connection> {
        self.get_client_id(addr)
            .and_then(|client_id| self.find(client_id))
    }
    fn is_connection_expired(conn: &Connection, time: f64) -> bool {
        (0.0..time).contains(&conn.expire_time)
            || (0.0..time - conn.last_access_time).contains(&(conn.timeout as f64))
    }
    fn is_expired(&self, client_id: u64) -> bool {
        self.map
            .get(&client_id)
            .is_some_and(|conn| Self::is_connection_expired(conn, self.time))
    }
    fn update(&mut self, time: f64) {
        self.time = time;
        self.map
            .retain(|_, conn| !Self::is_connection_expired(conn, self.time));
    }
}

pub struct ServerConfig {
    num_disconnect_packets: usize,
}
impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            num_disconnect_packets: 10,
        }
    }
}

pub struct Server<T: Transceiver> {
    public_addr: SocketAddr,
    transceiver: T,
    time: f64,
    private_key: Key,
    max_clients: usize,
    sequence: u64,
    challenge_sequence: u64,
    challenge_key: Key,
    protocol_id: u64,
    conn_cache: ConnectionCache,
    token_entries: HashMap<SocketAddr, TokenEntry>,
    cfg: ServerConfig,
    // token_cache: HashMap<...>, // TODO: implement token cache?
}

impl Server<NetcodeSocket> {
    pub fn new(addr: SocketAddr, protocol_id: u64, private_key: Option<Key>) -> Result<Self> {
        let time = time_now_secs_f64()?;
        Ok(Self {
            public_addr: addr,
            transceiver: NetcodeSocket::new((Ipv4Addr::UNSPECIFIED, 0))?,
            time,
            private_key: private_key.unwrap_or(crypto::generate_key()?),
            max_clients: MAX_CLIENTS,
            protocol_id,
            sequence: 0,
            challenge_sequence: 0,
            challenge_key: crypto::generate_key()?,
            conn_cache: ConnectionCache::new(time),
            token_entries: HashMap::new(),
            cfg: ServerConfig::default(),
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
    fn process_packet(&mut self, addr: SocketAddr, packet: Packet) -> Result<()> {
        match packet {
            Packet::Request(packet) => self.process_connection_request(addr, packet),
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
    pub fn recv(&mut self, buf: &mut [u8]) -> Result<()> {
        let now = time_now_secs()?;
        let (size, addr) = self.transceiver.recv(buf).map_err(|e| e.into())?;
        let Some(addr) = addr else {
            // No packet received
            return Ok(());
        };
        if size <= 1 {
            // Too small to be a packet
            return Ok(());
        }
        let (_, kind) = Packet::seq_len_and_pkt_kind(buf[0]);
        let (key, replay_protection) = match self.conn_cache.find_by_addr(addr) {
            Some(conn) => {
                // New client
                if kind != Packet::REQUEST {
                    // Not a connect packet
                    return Ok(());
                }
                (conn.receive_key, Some(&mut conn.replay_protection))
            }
            None => (self.private_key, None),
        };
        let packet = Packet::read(
            &mut buf[..size],
            self.protocol_id,
            now,
            key,
            replay_protection,
        )?;
        self.process_packet(addr, packet)?;
        Ok(())
    }
    fn send_to_addr(&mut self, packet: Packet, addr: SocketAddr, key: Key) -> Result<()> {
        let mut buf = [0u8; MAX_PKT_BUF_SIZE];
        packet.write(&mut buf, self.sequence, &key, self.protocol_id)?;
        self.transceiver.send(&buf, addr).map_err(|e| e.into())?;
        self.sequence += 1;
        Ok(())
    }
    fn send_to_client(&mut self, packet: Packet, id: ClientId) -> Result<()> {
        let mut buf = [0u8; MAX_PKT_BUF_SIZE];
        let Some(conn) = self.conn_cache.find(id) else {
            log::trace!("client connection not found");
            return Ok(());
        };
        packet.write(&mut buf, conn.sequence, &conn.send_key, self.protocol_id)?;
        self.transceiver
            .send(&buf, conn.addr)
            .map_err(|e| e.into())?;
        conn.last_send_time = self.time;
        conn.sequence += 1;
        Ok(())
    }
    fn disconnect_client(&mut self, client_id: u64) -> Result<()> {
        log::trace!("server disconnected client {}", client_id);
        for _ in 0..self.cfg.num_disconnect_packets {
            self.send_to_client(DisconnectPacket::new(), client_id)?;
        }
        self.conn_cache.remove(client_id);
        Ok(())
    }
    fn disconnect_all(&mut self) -> Result<()> {
        log::trace!("server disconnecting all clients");
        // keys must be collected first because `disconnect_client` mutates the cache and can possibly remove existing keys
        let clients = self.conn_cache.map.keys().copied().collect::<Vec<_>>();
        for client_id in clients {
            self.disconnect_client(client_id)?;
        }
        Ok(())
    }
    fn process_connection_request(
        &mut self,
        from: SocketAddr,
        mut packet: RequestPacket,
    ) -> Result<()> {
        let mut reader = std::io::Cursor::new(&mut packet.token_data[..]);
        let Ok(token) = ConnectTokenPrivate::read_from(&mut reader) else {
            log::trace!("server ignored connection request. failed to read connect token");
            return Ok(());
        };
        if !token
            .server_addresses
            .iter()
            .any(|addr| addr == self.public_addr)
        {
            log::trace!(
                "server ignored connection request. server address not in connect token whitelist"
            );
            return Ok(());
        };
        if self.conn_cache.addr_to_id.get(&from).is_some() {
            log::trace!("server ignored connection request. a client with this address is already connected");
            return Ok(());
        };
        if self.conn_cache.find(token.client_id).is_some() {
            log::trace!(
                "server ignored connection request. a client with this id is already connected"
            );
            return Ok(());
        };
        let mac: [u8; MAC_SIZE] = packet.token_data
            [ConnectTokenPrivate::SIZE - MAC_SIZE..ConnectTokenPrivate::SIZE]
            .try_into()
            .map_err(|_| NetcodeError::InvalidPacket)?;
        let token_entry = self.token_entries.entry(from).or_insert(TokenEntry {
            time: self.time,
            mac,
        });
        if token_entry.mac == mac {
            log::trace!("server ignored connection request. connect token has already been used");
            return Ok(());
        }
        token_entry.time = self.time;
        token_entry.mac = mac;
        if self.conn_cache.map.len() >= self.max_clients {
            log::trace!("server denied connection request. server is full");
            self.send_to_addr(DeniedPacket::new(), from, token.server_to_client_key)?;
            return Ok(());
        };
        let expire_time = if token.timeout_seconds >= 0 {
            self.time + token.timeout_seconds as f64
        } else {
            -1.0
        };
        self.conn_cache.add(
            token.client_id,
            from,
            token.timeout_seconds,
            expire_time,
            token.server_to_client_key,
            token.client_to_server_key,
        );
        let Ok(challenge_token_encrypted) = ChallengeToken {
            client_id: token.client_id,
            user_data: token.user_data,
        }
        .encrypt(self.challenge_sequence, &self.challenge_key) else {
            log::trace!("server ignored connection request. failed to encrypt challenge token");
            return Ok(());
        };
        self.send_to_addr(
            ChallengePacket::new(self.challenge_sequence, challenge_token_encrypted),
            from,
            token.server_to_client_key,
        )?;
        log::trace!("server sent connection challenge packet");
        self.challenge_sequence += 1;
        Ok(())
    }
    fn process_connection_response(
        &mut self,
        from: SocketAddr,
        mut packet: ResponsePacket,
    ) -> Result<()> {
        let Ok(challenge_token) = ChallengeToken::decrypt(&mut packet.token, packet.sequence, &self.challenge_key) else {
            log::trace!("server ignored connection response. failed to decrypt challenge token");
            return Ok(());
        };
        let num_clients = self.conn_cache.map.len();
        let Some(send_key) = self.conn_cache.find(challenge_token.client_id).map(|conn| conn.send_key) else {
            log::trace!("server ignored connection response. no packet send key");
            return Ok(());
        };
        if num_clients >= self.max_clients {
            log::trace!("server denied connection request. server is full");
            self.send_to_addr(DeniedPacket::new(), from, send_key)?;
            return Ok(());
        };
        self.conn_cache
            .map
            .entry(challenge_token.client_id)
            .and_modify(|conn| {
                conn.connect();
                conn.expire_time = -1.0; // TODO: check if this is correct
                conn.sequence = 0;
                conn.last_send_time = self.time;
                conn.last_receive_time = self.time;
            });
        log::debug!("server accepted client {}", challenge_token.client_id);
        self.send_to_addr(
            KeepAlivePacket::new(
                // self.conn_cache
                //     .map
                //     .keys()
                //     .position(|&id| id == challenge_token.client_id)
                //     .unwrap() as i32, // unwrap is guaranteed to succeed because the client id is guaranteed to be in the map at this point
                0, // TODO: come back to this
                self.max_clients as i32,
            ),
            from,
            send_key,
        )?;
        Ok(())
    }
    pub fn check_for_timeouts(&mut self) -> Result<()> {
        todo!()
    }
}
