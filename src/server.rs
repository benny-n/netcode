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
use crate::free_list::FreeList;
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

#[derive(Debug, Clone, Copy)]
struct Connection {
    confirmed: bool,
    connected: bool,
    client_id: u64,
    addr: SocketAddr,
    timeout: i32,
    expire_time: f64,
    last_access_time: f64,
    last_send_time: f64,
    last_receive_time: f64,
    send_key: Key,
    receive_key: Key,
    sequence: u64,
}

impl Connection {
    fn confirm(&mut self) {
        self.confirmed = true;
    }
    fn connect(&mut self) {
        self.connected = true;
    }
    fn is_confirmed(&self) -> bool {
        self.confirmed
    }
    fn is_connected(&self) -> bool {
        self.connected
    }
}

pub type ClientId = u64;
pub type ClientIndex = usize;

struct ConnectionCache {
    // this somewhat mimics the original C implementation, but it's not exactly the same
    clients: FreeList<Connection, MAX_CLIENTS>,

    // we are not using a free-list here to not allocate memory up-front, since `ReplayProtection` is biggish (~2kb)
    replay_protection: HashMap<ClientIndex, ReplayProtection>,

    // optimization for finding client_index from addr or id quickly
    addr_to_idx: HashMap<SocketAddr, ClientIndex>,
    id_to_idx: HashMap<ClientId, ClientIndex>,

    // corresponds to the server time
    time: f64,
}

impl ConnectionCache {
    fn new(server_time: f64) -> Self {
        Self {
            clients: FreeList::new(),
            replay_protection: HashMap::new(),
            addr_to_idx: HashMap::new(),
            id_to_idx: HashMap::new(),
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
            confirmed: false,
            connected: false,
            client_id,
            addr,
            timeout,
            expire_time,
            last_access_time: self.time,
            last_send_time: 0.0,
            last_receive_time: 0.0,
            send_key,
            receive_key,
            sequence: 0, // TODO: check if this can simply be grabbed from the replay protection
        };
        let client_idx = self.clients.insert(conn);
        self.replay_protection
            .insert(client_idx, ReplayProtection::new());
        self.addr_to_idx.insert(addr, client_idx);
        self.id_to_idx.insert(client_id, client_idx);
    }
    fn remove(&mut self, client_idx: ClientIndex) {
        let Some(conn) = self.clients.get_mut(client_idx) else {
            return;
        };
        if !conn.is_connected() {
            return;
        }
        self.addr_to_idx.remove(&conn.addr);
        self.id_to_idx.remove(&conn.client_id);
        self.replay_protection.remove(&client_idx);
        self.clients.remove(client_idx);
    }
    fn get_client_idx(&self, addr: SocketAddr) -> Option<ClientIndex> {
        self.addr_to_idx.get(&addr).copied()
    }
    fn find_by_id(&mut self, client_id: ClientId) -> Option<(usize, &mut Connection)> {
        self.id_to_idx.get(&client_id).map(|&idx| {
            self.clients[idx].last_access_time = self.time;
            (idx, &mut self.clients[idx])
        })
    }
    fn find_by_addr(&mut self, addr: SocketAddr) -> Option<&mut Connection> {
        self.addr_to_idx
            .get(&addr)
            .map(|&idx| &mut self.clients[idx])
    }
    fn is_connection_expired(conn: &Connection, time: f64) -> bool {
        (0.0..time).contains(&conn.expire_time)
            || (0.0..time - conn.last_access_time).contains(&(conn.timeout as f64))
    }
    fn is_expired(&self, client_id: u64) -> bool {
        self.id_to_idx
            .get(&client_id)
            .is_some_and(|&idx| Self::is_connection_expired(&self.clients[idx], self.time))
    }
    fn update(&mut self, time: f64) {
        self.time = time;
        let expired_indices = self
            .clients
            .iter_mut()
            .enumerate()
            .filter(|(_, conn)| Self::is_connection_expired(&conn, time))
            .map(|(idx, _)| idx)
            .collect::<Vec<_>>();
        for idx in expired_indices {
            self.remove(idx);
        }
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
    fn touch_client(&mut self, client_idx: Option<ClientIndex>) -> Result<()> {
        let Some(idx) = client_idx else {
            return Ok(());
        };
        let Some(conn) = self.conn_cache.clients.get_mut(idx) else {
            return Ok(());
        };
        conn.last_receive_time = self.time;
        if !conn.is_confirmed() {
            log::trace!("server confirmed connection with client {idx}");
            conn.confirm();
        }
        Ok(())
    }
    fn process_packet(&mut self, addr: SocketAddr, packet: Packet) -> Result<()> {
        let client_idx = self.conn_cache.get_client_idx(addr);
        log::trace!(
            "server received {} from {}",
            packet.to_string(),
            client_idx
                .map(|idx| format!("client {}", idx))
                .unwrap_or_else(|| addr.to_string())
        );
        match packet {
            Packet::Request(packet) => self.process_connection_request(addr, packet),
            Packet::Response(packet) => self.process_connection_response(addr, packet),
            Packet::KeepAlive(_) => self.touch_client(client_idx),
            Packet::Payload(_) => {
                self.touch_client(client_idx)?;
                todo!("process payload packet")
            }
            Packet::Disconnect(_) => {
                if let Some(idx) = client_idx {
                    self.disconnect_client(idx)?;
                }
                Ok(())
            }
            _ => Err(NetcodeError::InvalidPacket)?,
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
        let (key, replay_protection) = match self.conn_cache.addr_to_idx.get(&addr) {
            Some(client_idx) => (
                self.conn_cache.clients[*client_idx].receive_key,
                self.conn_cache.replay_protection.get_mut(client_idx),
            ),
            None if Packet::is_connection_request(buf[0]) => (self.private_key, None),
            None => {
                // Not a connection request packet, and not a known client, so ignore
                log::trace!(
                    "server ignored non-connection-request packet from unknown address {addr}"
                );
                return Ok(());
            }
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
    fn send_to_client(&mut self, packet: Packet, idx: ClientIndex) -> Result<()> {
        let mut buf = [0u8; MAX_PKT_BUF_SIZE];
        let Some(conn) = self.conn_cache.clients.get_mut(idx) else {
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
    fn disconnect_client(&mut self, client_idx: usize) -> Result<()> {
        log::trace!("server disconnected client {}", client_idx);
        for _ in 0..self.cfg.num_disconnect_packets {
            self.send_to_client(DisconnectPacket::create(), client_idx)?;
        }
        self.conn_cache.remove(client_idx);
        Ok(())
    }
    fn disconnect_all(&mut self) -> Result<()> {
        log::trace!("server disconnecting all clients");
        let disconnect_indices = self
            .conn_cache
            .clients
            .iter()
            .enumerate()
            .filter(|(_, conn)| conn.is_connected())
            .map(|(idx, _)| idx)
            .collect::<Vec<_>>();
        for idx in disconnect_indices {
            self.disconnect_client(idx)?;
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
        if self.conn_cache.addr_to_idx.get(&from).is_some() {
            log::trace!("server ignored connection request. a client with this address is already connected");
            return Ok(());
        };
        if self.conn_cache.find_by_id(token.client_id).is_some() {
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
        if self.conn_cache.clients.len() >= self.max_clients {
            log::trace!("server denied connection request. server is full");
            self.send_to_addr(DeniedPacket::create(), from, token.server_to_client_key)?;
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
            ChallengePacket::create(self.challenge_sequence, challenge_token_encrypted),
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
        let num_clients = self.conn_cache.clients.len();
        let Some((idx, _)) = self.conn_cache.find_by_id(challenge_token.client_id) else {
            log::trace!("server ignored connection response. no packet send key");
            return Ok(());
        };
        if num_clients >= self.max_clients {
            log::trace!("server denied connection request. server is full");
            self.send_to_addr(
                DeniedPacket::create(),
                from,
                self.conn_cache.clients[idx].send_key,
            )?;
            return Ok(());
        };
        self.conn_cache.clients[idx].connect();
        self.conn_cache.clients[idx].expire_time = -1.0; // TODO: check if this is correct
        self.conn_cache.clients[idx].sequence = 0;
        self.conn_cache.clients[idx].last_send_time = self.time;
        self.conn_cache.clients[idx].last_receive_time = self.time;
        log::debug!("server accepted client {}", challenge_token.client_id);
        self.send_to_addr(
            KeepAlivePacket::create(idx as i32, self.max_clients as i32),
            from,
            self.conn_cache.clients[idx].send_key,
        )?;
        Ok(())
    }
    pub fn check_for_timeouts(&mut self) -> Result<()> {
        todo!()
    }
}
