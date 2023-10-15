use std::collections::{HashMap, VecDeque};
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    bytes::Bytes,
    crypto::{self, Key},
    error::{Error, Result},
    free_list::FreeList,
    packet::{
        ChallengePacket, DeniedPacket, DisconnectPacket, KeepAlivePacket, Packet, PayloadPacket,
        RequestPacket, ResponsePacket,
    },
    replay::ReplayProtection,
    socket::NetcodeSocket,
    token::{ChallengeToken, ConnectToken, ConnectTokenBuilder, ConnectTokenPrivate},
    transceiver::Transceiver,
    MAC_BYTES, MAX_PACKET_SIZE, MAX_PKT_BUF_SIZE, PACKET_SEND_RATE_SEC,
};

pub const MAX_CLIENTS: usize = 256;
const RECV_BUF_SIZE: usize = 4 * 1024 * 1024;
const SEND_BUF_SIZE: usize = 4 * 1024 * 1024;

#[derive(Clone, Copy)]
struct TokenEntry {
    time: f64,
    mac: [u8; 16],
    addr: SocketAddr,
}

struct TokenEntries {
    inner: Vec<TokenEntry>,
}

impl TokenEntries {
    fn new() -> Self {
        Self { inner: Vec::new() }
    }
    fn find_or_insert(&mut self, entry: TokenEntry) -> bool {
        let (mut oldest, mut matching) = (None, None);
        let mut oldest_time = f64::INFINITY;
        // Perform a linear search for the oldest and matching entries at the same time
        for (idx, saved_entry) in self.inner.iter().enumerate() {
            if entry.time < oldest_time {
                oldest_time = saved_entry.time;
                oldest = Some(idx);
            }
            if entry.mac == saved_entry.mac {
                matching = Some(idx);
            }
        }
        let Some(oldest) = oldest else {
            // If there is no oldest entry then the list is empty, so just insert the entry
            self.inner.push(entry);
            return true;
        };
        if let Some(matching) = matching {
            // Allow reusing tokens only if the address matches
            self.inner[matching].addr == entry.addr
        } else {
            // If there is no matching entry, replace the oldest one
            self.inner[oldest] = entry;
            true
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Connection {
    confirmed: bool,
    connected: bool,
    client_id: ClientId,
    addr: SocketAddr,
    timeout: i32,
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

/// The client id from a connect token, must be unique for each client.
///
/// Note that this is not the same as the [`ClientIndex`](ClientIndex), which is used by the server to identify clients.
pub type ClientId = u64;

/// Newtype over `usize` used by the server to identify clients.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ClientIndex(pub(crate) usize);

impl<T> std::ops::Index<ClientIndex> for [T] {
    type Output = T;
    fn index(&self, index: ClientIndex) -> &Self::Output {
        &self[index.0]
    }
}

impl<T> std::ops::IndexMut<ClientIndex> for [T] {
    fn index_mut(&mut self, index: ClientIndex) -> &mut Self::Output {
        &mut self[index.0]
    }
}

impl std::fmt::Display for ClientIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

struct ConnectionCache {
    // this somewhat mimics the original C implementation,
    // the main difference being that `Connection` includes the encryption mapping as well.
    clients: FreeList<Connection, MAX_CLIENTS>,

    // we are not using a free-list here to not allocate memory up-front, since `ReplayProtection` is biggish (~2kb)
    replay_protection: HashMap<ClientIndex, ReplayProtection>,

    // packet queue for all clients
    packet_queue: VecDeque<(Vec<u8>, ClientIndex)>,

    // corresponds to the server time
    time: f64,
}

impl ConnectionCache {
    fn new(server_time: f64) -> Self {
        Self {
            clients: FreeList::new(),
            replay_protection: HashMap::with_capacity(MAX_CLIENTS),
            packet_queue: VecDeque::with_capacity(MAX_CLIENTS * 2),
            time: server_time,
        }
    }
    fn add(
        &mut self,
        client_id: ClientId,
        addr: SocketAddr,
        timeout: i32,
        send_key: Key,
        receive_key: Key,
    ) {
        if let Some((_, ref mut existing)) = self.find_by_addr(&addr) {
            existing.client_id = client_id;
            existing.timeout = timeout;
            existing.send_key = send_key;
            existing.receive_key = receive_key;
            existing.last_access_time = self.time;
            return;
        }
        let conn = Connection {
            confirmed: false,
            connected: false,
            client_id,
            addr,
            timeout,
            last_access_time: self.time,
            last_send_time: f64::NEG_INFINITY,
            last_receive_time: f64::NEG_INFINITY,
            send_key,
            receive_key,
            sequence: 0,
        };
        let client_idx = ClientIndex(self.clients.insert(conn));
        self.replay_protection
            .insert(client_idx, ReplayProtection::new());
    }
    fn remove(&mut self, client_idx: ClientIndex) {
        let Some(conn) = self.clients.get_mut(client_idx.0) else {
            return;
        };
        if !conn.is_connected() {
            return;
        }
        self.replay_protection.remove(&client_idx);
        self.clients.remove(client_idx.0);
    }
    fn find_by_addr(&self, addr: &SocketAddr) -> Option<(ClientIndex, Connection)> {
        self.clients
            .iter()
            .find_map(|(idx, conn)| (conn.addr == *addr).then_some((ClientIndex(idx), conn)))
    }
    fn find_by_id(&self, client_id: ClientId) -> Option<(ClientIndex, Connection)> {
        self.clients.iter().find_map(|(idx, conn)| {
            (conn.client_id == client_id).then_some((ClientIndex(idx), conn))
        })
    }
    fn update(&mut self, time: f64) {
        self.time = time;
    }
}
type Callback<Ctx> = Box<dyn FnMut(ClientIndex, &mut Ctx) + Send + Sync + 'static>;
/// Configuration for a server.
///
/// * `num_disconnect_packets` - The number of redundant disconnect packets that will be sent to a client when the server is disconnecting it.
/// * `keep_alive_send_rate` - The rate at which keep-alive packets will be sent to clients.
/// * `on_connect` - A callback that will be called when a client is connected to the server.
/// * `on_disconnect` - A callback that will be called when a client is disconnected from the server.
///
/// # Example
/// ```
/// # let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 40005));
/// # let protocol_id = 0x123456789ABCDEF0;
/// # let private_key = [42u8; 32];
/// use std::sync::{Arc, Mutex};
/// use netcode::{Server, ServerConfig};
///
/// let thread_safe_counter = Arc::new(Mutex::new(0));
/// let cfg = ServerConfig::with_context(thread_safe_counter).on_connect(|idx, ctx| {
///     let mut counter = ctx.lock().unwrap();
///     *counter += 1;
///     println!("client {} connected, counter: {idx}", counter);
/// });
/// let server = Server::with_config(addr, protocol_id, private_key, cfg).unwrap();
/// ```
pub struct ServerConfig<Ctx> {
    num_disconnect_packets: usize,
    keep_alive_send_rate: f64,
    context: Ctx,
    on_connect: Option<Callback<Ctx>>,
    on_disconnect: Option<Callback<Ctx>>,
}
impl Default for ServerConfig<()> {
    fn default() -> Self {
        Self {
            num_disconnect_packets: 10,
            keep_alive_send_rate: PACKET_SEND_RATE_SEC,
            context: (),
            on_connect: None,
            on_disconnect: None,
        }
    }
}

impl<Ctx> ServerConfig<Ctx> {
    /// Create a new, default server configuration with no context.
    pub fn new() -> ServerConfig<()> {
        ServerConfig::<()>::default()
    }
    /// Create a new server configuration with context that will be passed to the callbacks.
    pub fn with_context(ctx: Ctx) -> Self {
        Self {
            num_disconnect_packets: 10,
            keep_alive_send_rate: PACKET_SEND_RATE_SEC,
            context: ctx,
            on_connect: None,
            on_disconnect: None,
        }
    }
    /// Set the number of redundant disconnect packets that will be sent to a client when the server is disconnecting it. <br>
    /// The default is 10 packets.
    pub fn num_disconnect_packets(mut self, num: usize) -> Self {
        self.num_disconnect_packets = num;
        self
    }
    /// Set the rate (in seconds) at which keep-alive packets will be sent to clients. <br>
    /// The default is 10 packets per second. (`0.1` seconds)
    pub fn keep_alive_send_rate(mut self, rate_seconds: f64) -> Self {
        self.keep_alive_send_rate = rate_seconds;
        self
    }
    /// Provide a callback that will be called when a client is connected to the server. <br>
    /// The callback will be called with the client index and the context that was provided (provide a `None` context if you don't need one).
    ///
    /// See [`ServerConfig`](ServerConfig) for an example.
    pub fn on_connect<F>(mut self, cb: F) -> Self
    where
        F: FnMut(ClientIndex, &mut Ctx) + Send + Sync + 'static,
    {
        self.on_connect = Some(Box::new(cb));
        self
    }
    /// Provide a callback that will be called when a client is disconnected from the server. <br>
    /// The callback will be called with the client index and the context that was provided (provide a `None` context if you don't need one).
    ///
    /// See [`ServerConfig`](ServerConfig) for an example.
    pub fn on_disconnect<F>(mut self, cb: F) -> Self
    where
        F: FnMut(ClientIndex, &mut Ctx) + Send + Sync + 'static,
    {
        self.on_disconnect = Some(Box::new(cb));
        self
    }
}

/// The `netcode` server.
///
/// Responsible for accepting connections from clients and communicating with them using the netcode protocol. <br>
/// The server should be run in a loop to process incoming packets, send updates to clients, and maintain stable connections.
///
/// # Example
///
/// ```
/// # use netcode::Server;
/// # use std::net::{SocketAddr, Ipv4Addr};
/// # use std::time::{Instant, Duration};
/// # use std::thread;
/// let private_key = netcode::generate_key();
/// let protocol_id = 0x123456789ABCDEF0;
/// let addr = "127.0.0.1:41235";
/// let mut server = Server::new(addr, protocol_id, private_key).unwrap();
///
/// let start = Instant::now();
/// let tick_rate = Duration::from_secs_f64(1.0 / 60.0);
///
/// loop {
///     server.update(start.elapsed().as_secs_f64());
///     if let Some((received, from)) = server.recv() {
///         // ...
///     }
///     thread::sleep(tick_rate);
///     # break;
/// }
/// ```
///
pub struct Server<T: Transceiver, Ctx = ()> {
    transceiver: T,
    time: f64,
    private_key: Key,
    sequence: u64,
    token_sequence: u64,
    challenge_sequence: u64,
    challenge_key: Key,
    protocol_id: u64,
    conn_cache: ConnectionCache,
    token_entries: TokenEntries,
    cfg: ServerConfig<Ctx>,
}

impl Server<NetcodeSocket> {
    /// Create a new server with a default configuration.
    ///
    /// For a custom configuration, use [`Server::with_config`](Server::with_config) instead.
    pub fn new(bind_addr: impl ToSocketAddrs, protocol_id: u64, private_key: Key) -> Result<Self> {
        let server: Server<_, ()> = Server {
            transceiver: NetcodeSocket::new(bind_addr, SEND_BUF_SIZE, RECV_BUF_SIZE)?,
            time: 0.0,
            private_key,
            protocol_id,
            sequence: 1 << 63,
            token_sequence: 0,
            challenge_sequence: 0,
            challenge_key: crypto::generate_key(),
            conn_cache: ConnectionCache::new(0.0),
            token_entries: TokenEntries::new(),
            cfg: ServerConfig::default(),
        };
        log::info!("server started on {}", server.transceiver.addr());
        Ok(server)
    }
}

impl<Ctx> Server<NetcodeSocket, Ctx> {
    /// Create a new server with a custom configuration. <br>
    /// Callbacks with context can be registered with the server to be notified when the server changes states. <br>
    /// See [`ServerConfig`](ServerConfig) for more details.
    ///
    /// # Example
    /// ```
    /// use netcode::{Server, ServerConfig};
    /// use std::net::{SocketAddr, Ipv4Addr};
    ///
    /// let private_key = netcode::generate_key();
    /// let protocol_id = 0x123456789ABCDEF0;
    /// let addr = "127.0.0.1:40002";
    /// let cfg = ServerConfig::with_context(42).on_connect(|idx, ctx| {
    ///     assert_eq!(ctx, &42);
    /// });
    /// let server = Server::with_config(addr, protocol_id, private_key, cfg).unwrap();
    /// ```
    pub fn with_config(
        bind_addr: impl ToSocketAddrs,
        protocol_id: u64,
        private_key: Key,
        cfg: ServerConfig<Ctx>,
    ) -> Result<Self> {
        let server = Server {
            transceiver: NetcodeSocket::new(bind_addr, SEND_BUF_SIZE, RECV_BUF_SIZE)?,
            time: 0.0,
            private_key,
            protocol_id,
            sequence: 1 << 63,
            token_sequence: 0,
            challenge_sequence: 0,
            challenge_key: crypto::generate_key(),
            conn_cache: ConnectionCache::new(0.0),
            token_entries: TokenEntries::new(),
            cfg,
        };
        log::info!("server started on {}", server.addr());
        Ok(server)
    }
}

impl<T: Transceiver, S> Server<T, S> {
    const ALLOWED_PACKETS: u8 = 1 << Packet::REQUEST
        | 1 << Packet::RESPONSE
        | 1 << Packet::KEEP_ALIVE
        | 1 << Packet::PAYLOAD
        | 1 << Packet::DISCONNECT;
    fn on_connect(&mut self, client_idx: ClientIndex) {
        if let Some(cb) = self.cfg.on_connect.as_mut() {
            cb(client_idx, &mut self.cfg.context)
        }
    }
    fn on_disconnect(&mut self, client_idx: ClientIndex) {
        if let Some(cb) = self.cfg.on_disconnect.as_mut() {
            cb(client_idx, &mut self.cfg.context)
        }
    }
    fn touch_client(&mut self, client_idx: Option<ClientIndex>) -> Result<()> {
        let Some(idx) = client_idx else {
            return Ok(());
        };
        let Some(conn) = self.conn_cache.clients.get_mut(idx.0) else {
            return Ok(());
        };
        conn.last_receive_time = self.time;
        if !conn.is_confirmed() {
            log::debug!("server confirmed connection with client {idx}");
            conn.confirm();
        }
        Ok(())
    }
    fn process_packet(&mut self, addr: SocketAddr, packet: Packet) -> Result<()> {
        let client_idx = self.conn_cache.find_by_addr(&addr).map(|(idx, _)| idx);
        log::trace!(
            "server received {} from {}",
            packet.to_string(),
            client_idx
                .map(|idx| format!("client {idx}"))
                .unwrap_or_else(|| addr.to_string())
        );
        match packet {
            Packet::Request(packet) => self.process_connection_request(addr, packet),
            Packet::Response(packet) => self.process_connection_response(addr, packet),
            Packet::KeepAlive(_) => self.touch_client(client_idx),
            Packet::Payload(packet) => {
                self.touch_client(client_idx)?;
                if let Some(idx) = client_idx {
                    self.conn_cache
                        .packet_queue
                        .push_back((packet.buf.to_vec(), idx));
                }
                Ok(())
            }
            Packet::Disconnect(_) => {
                if let Some(idx) = client_idx {
                    log::debug!("server disconnected client {idx}");
                    self.on_disconnect(idx);
                    self.conn_cache.remove(idx);
                }
                Ok(())
            }
            _ => unreachable!("packet should have been filtered out by `ALLOWED_PACKETS`"),
        }
    }
    fn send_to_addr(&mut self, packet: Packet, addr: SocketAddr, key: Key) -> Result<()> {
        let mut buf = [0u8; MAX_PKT_BUF_SIZE];
        let size = packet.write(&mut buf, self.sequence, &key, self.protocol_id)?;
        self.transceiver
            .send(&buf[..size], addr)
            .map_err(|e| e.into())?;
        self.sequence += 1;
        Ok(())
    }
    fn send_to_client(&mut self, packet: Packet, idx: ClientIndex) -> Result<()> {
        let mut buf = [0u8; MAX_PKT_BUF_SIZE];
        let conn = &mut self.conn_cache.clients[idx.0];
        let size = packet.write(&mut buf, conn.sequence, &conn.send_key, self.protocol_id)?;
        self.transceiver
            .send(&buf[..size], conn.addr)
            .map_err(|e| e.into())?;
        conn.last_access_time = self.time;
        conn.last_send_time = self.time;
        conn.sequence += 1;
        Ok(())
    }
    fn process_connection_request(
        &mut self,
        from_addr: SocketAddr,
        mut packet: RequestPacket,
    ) -> Result<()> {
        let mut reader = std::io::Cursor::new(&mut packet.token_data[..]);
        let Ok(token) = ConnectTokenPrivate::read_from(&mut reader) else {
            log::debug!("server ignored connection request. failed to read connect token");
            return Ok(());
        };
        if !token
            .server_addresses
            .iter()
            .any(|(_, addr)| addr == self.transceiver.addr())
        {
            log::debug!(
                "server ignored connection request. server address not in connect token whitelist"
            );
            return Ok(());
        };
        if self
            .conn_cache
            .find_by_addr(&from_addr)
            .is_some_and(|(_, conn)| conn.is_connected())
        {
            log::debug!("server ignored connection request. a client with this address is already connected");
            return Ok(());
        };
        if self
            .conn_cache
            .find_by_id(token.client_id)
            .is_some_and(|(_, conn)| conn.is_connected())
        {
            log::debug!(
                "server ignored connection request. a client with this id is already connected"
            );
            return Ok(());
        };
        let entry = TokenEntry {
            time: self.time,
            addr: from_addr,
            mac: packet.token_data
                [ConnectTokenPrivate::SIZE - MAC_BYTES..ConnectTokenPrivate::SIZE]
                .try_into()
                .expect("valid MAC size"),
        };
        if !self.token_entries.find_or_insert(entry) {
            log::debug!("server ignored connection request. connect token has already been used");
            return Ok(());
        };
        if self.num_connected_clients() >= MAX_CLIENTS {
            log::debug!("server denied connection request. server is full");
            self.send_to_addr(
                DeniedPacket::create(),
                from_addr,
                token.server_to_client_key,
            )?;
            return Ok(());
        };
        self.conn_cache.add(
            token.client_id,
            from_addr,
            token.timeout_seconds,
            token.server_to_client_key,
            token.client_to_server_key,
        );
        let Ok(challenge_token_encrypted) = ChallengeToken {
            client_id: token.client_id,
            user_data: token.user_data,
        }
        .encrypt(self.challenge_sequence, &self.challenge_key) else {
            log::debug!("server ignored connection request. failed to encrypt challenge token");
            return Ok(());
        };
        self.send_to_addr(
            ChallengePacket::create(self.challenge_sequence, challenge_token_encrypted),
            from_addr,
            token.server_to_client_key,
        )?;
        log::debug!("server sent connection challenge packet");
        self.challenge_sequence += 1;
        Ok(())
    }
    fn process_connection_response(
        &mut self,
        from_addr: SocketAddr,
        mut packet: ResponsePacket,
    ) -> Result<()> {
        let Ok(challenge_token) =
            ChallengeToken::decrypt(&mut packet.token, packet.sequence, &self.challenge_key)
        else {
            log::debug!("server ignored connection response. failed to decrypt challenge token");
            return Ok(());
        };
        let Some((idx, conn)) = self.conn_cache.find_by_id(challenge_token.client_id) else {
            log::debug!("server ignored connection response. no packet send key");
            return Ok(());
        };
        if conn.is_connected() {
            log::debug!(
                "server ignored connection request. a client with this id is already connected"
            );
            return Ok(());
        };
        if self.num_connected_clients() >= MAX_CLIENTS {
            log::debug!("server denied connection response. server is full");
            self.send_to_addr(
                DeniedPacket::create(),
                from_addr,
                self.conn_cache.clients[idx.0].send_key,
            )?;
            return Ok(());
        };
        let client = &mut self.conn_cache.clients[idx.0];
        client.connect();
        client.last_send_time = self.time;
        client.last_receive_time = self.time;
        log::debug!(
            "server accepted client {} with id {}",
            idx,
            challenge_token.client_id
        );
        self.send_to_client(
            KeepAlivePacket::create(idx.0 as i32, MAX_CLIENTS as i32),
            idx,
        )?;
        self.on_connect(idx);
        Ok(())
    }
    fn check_for_timeouts(&mut self) {
        for idx in 0..MAX_CLIENTS {
            let Some(client) = self.conn_cache.clients.get_mut(idx) else {
                continue;
            };
            let idx = ClientIndex(idx);
            if !client.is_connected() {
                continue;
            }
            if client.timeout.is_positive()
                && client.last_receive_time + (client.timeout as f64) < self.time
            {
                log::debug!("server timed out client {idx}");
                self.on_disconnect(idx);
                self.conn_cache.remove(idx);
            }
        }
    }
    fn send_packets(&mut self) -> Result<()> {
        for idx in 0..MAX_CLIENTS {
            let Some(client) = self.conn_cache.clients.get_mut(idx) else {
                continue;
            };
            if !client.is_connected() {
                continue;
            }
            if client.last_send_time + self.cfg.keep_alive_send_rate >= self.time {
                continue;
            }

            self.send_to_client(
                KeepAlivePacket::create(idx as i32, MAX_CLIENTS as i32),
                ClientIndex(idx),
            )?;
            log::trace!("server sent connection keep-alive packet to client {idx}");
        }
        Ok(())
    }
    fn recv_packet(&mut self, buf: &mut [u8], now: u64, addr: SocketAddr) -> Result<()> {
        if buf.len() <= 1 {
            // Too small to be a packet
            return Ok(());
        }
        let (key, replay_protection) = match self.conn_cache.find_by_addr(&addr) {
            // Regardless of whether an entry in the connection cache exists for the client or not,
            // if the packet is a connection request we need to use the server's private key to decrypt it.
            _ if buf[0] == Packet::REQUEST => (self.private_key, None),
            Some((client_idx, _)) => (
                // If the packet is not a connection request, use the receive key to decrypt it.
                self.conn_cache.clients[client_idx.0].receive_key,
                self.conn_cache.replay_protection.get_mut(&client_idx),
            ),
            None => {
                // Not a connection request packet, and not a known client, so ignore
                log::debug!(
                    "server ignored non-connection-request packet from unknown address {addr}"
                );
                return Ok(());
            }
        };
        let packet = match Packet::read(
            buf,
            self.protocol_id,
            now,
            key,
            replay_protection,
            Self::ALLOWED_PACKETS,
        ) {
            Ok(packet) => packet,
            Err(Error::Crypto(_)) => {
                log::debug!("server ignored packet because it failed to decrypt");
                return Ok(());
            }
            Err(e) => {
                log::error!("server ignored packet: {e}");
                return Ok(());
            }
        };
        self.process_packet(addr, packet)
    }
    fn recv_packets(&mut self) -> Result<()> {
        let mut buf = [0u8; MAX_PACKET_SIZE];
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        while let Some((size, addr)) = self.transceiver.recv(&mut buf).map_err(|e| e.into())? {
            self.recv_packet(&mut buf[..size], now, addr)?;
        }
        Ok(())
    }
    pub fn with_config_and_transceiver(
        protocol_id: u64,
        private_key: Key,
        cfg: ServerConfig<S>,
        trx: T,
    ) -> Result<Self> {
        let server = Server {
            transceiver: trx,
            time: 0.0,
            private_key,
            protocol_id,
            sequence: 1 << 63,
            token_sequence: 0,
            challenge_sequence: 0,
            challenge_key: crypto::generate_key(),
            conn_cache: ConnectionCache::new(0.0),
            token_entries: TokenEntries::new(),
            cfg,
        };
        log::info!("server started on {}", server.addr());
        Ok(server)
    }
    /// Updates the server.
    ///
    /// * Updates the server's elapsed time.
    /// * Receives and processes packets from clients, any received payload packets will be queued.
    /// * Sends keep-alive packets to connected clients.
    /// * Checks for timed out clients and disconnects them.
    ///
    /// This method should be called regularly, probably at a fixed rate (e.g., 60Hz).
    ///
    /// # Panics
    /// Panics if the server can't send or receive packets.
    /// For a non-panicking version, use [`try_update`](Server::try_update).
    pub fn update(&mut self, time: f64) {
        self.try_update(time)
            .expect("send/recv error while updating server")
    }
    /// The fallible version of [`update`](Server::update).
    ///
    /// Returns an error if the server can't send or receive packets.
    pub fn try_update(&mut self, time: f64) -> Result<()> {
        self.time = time;
        self.conn_cache.update(self.time);
        self.recv_packets()?;
        self.send_packets()?;
        self.check_for_timeouts();
        Ok(())
    }
    /// Receives a packet from a client, if one is available in the queue.
    ///
    /// The packet will be returned as a `Vec<u8>` along with the client index of the sender.
    ///
    /// If no packet is available, `None` will be returned.
    ///
    /// # Example
    /// ```
    /// # use netcode::{Server, ServerConfig};
    /// # use std::net::{SocketAddr, Ipv4Addr};
    /// # use std::time::Instant;
    /// # let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 40003));
    /// # let protocol_id = 0x123456789ABCDEF0;
    /// # let private_key = [42u8; 32];
    /// # let mut server = Server::new(addr, protocol_id, private_key).unwrap();
    /// let start = Instant::now();
    /// loop {
    ///    let now = start.elapsed().as_secs_f64();
    ///    server.update(now);
    ///    let mut packet_buf = [0u8; netcode::MAX_PACKET_SIZE];
    ///    while let Some((packet, from)) = server.recv() {
    ///        // ...
    ///    }
    ///    # break;
    /// }
    pub fn recv(&mut self) -> Option<(Vec<u8>, ClientIndex)> {
        self.conn_cache.packet_queue.pop_front()
    }
    /// Sends a packet to a client.
    ///
    /// The provided buffer must be smaller than [`MAX_PACKET_SIZE`](crate::MAX_PACKET_SIZE).
    pub fn send(&mut self, buf: &[u8], client_idx: ClientIndex) -> Result<()> {
        if buf.len() > MAX_PACKET_SIZE {
            return Err(Error::SizeMismatch(MAX_PACKET_SIZE, buf.len()));
        }
        let Some(conn) = self.conn_cache.clients.get_mut(client_idx.0) else {
            return Err(Error::ClientNotFound);
        };
        if !conn.is_connected() {
            // since there is no way to obtain a client index of clients that are not connected,
            // there is no straight-forward way for a user to send a packet to a non-connected client.
            // still, in case a user somehow manages to obtain such index, we'll return an error.
            return Err(Error::ClientNotConnected);
        }
        if !conn.is_confirmed() {
            // send a keep-alive packet to the client to confirm the connection
            self.send_to_client(
                KeepAlivePacket::create(client_idx.0 as i32, MAX_CLIENTS as i32),
                client_idx,
            )?;
        }
        let packet = PayloadPacket::create(buf);
        self.send_to_client(packet, client_idx)
    }
    /// Sends a packet to all connected clients.
    ///
    /// The provided buffer must be smaller than [`MAX_PACKET_SIZE`](crate::MAX_PACKET_SIZE).
    pub fn send_all(&mut self, buf: &[u8]) -> Result<()> {
        for idx in 0..MAX_CLIENTS {
            match self.send(buf, ClientIndex(idx)) {
                Ok(_) | Err(Error::ClientNotConnected) | Err(Error::ClientNotFound) => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
    /// Creates a connect token builder for a given client ID.
    /// The builder can be used to configure the token with additional data before generating the final token.
    /// The `generate` method must be called on the builder to generate the final token.
    ///
    /// # Example
    ///
    /// ```
    /// # use netcode::{Server, ServerConfig};
    /// # use std::net::{SocketAddr, Ipv4Addr};
    ///  
    /// let private_key = netcode::generate_key();
    /// let protocol_id = 0x123456789ABCDEF0;
    /// let bind_addr = "0.0.0.0:0";
    /// let mut server = Server::new(bind_addr, protocol_id, private_key).unwrap();
    ///
    /// let client_id = 123u64;
    /// let token = server.token(client_id)
    ///     .expire_seconds(60)  // defaults to 30 seconds, negative for no expiry
    ///     .timeout_seconds(-1) // defaults to 15 seconds, negative for no timeout
    ///     .generate()
    ///     .unwrap();
    /// ```
    ///
    /// See [`ConnectTokenBuilder`](ConnectTokenBuilder) for more options.
    pub fn token(&mut self, client_id: ClientId) -> ConnectTokenBuilder<SocketAddr> {
        let token_builder = ConnectToken::build(
            self.transceiver.addr(),
            self.protocol_id,
            client_id,
            self.private_key,
        );
        self.token_sequence += 1;
        token_builder
    }
    /// Disconnects a client.
    ///
    /// The server will send a number of redundant disconnect packets to the client, and then remove its connection info.
    pub fn disconnect(&mut self, client_idx: ClientIndex) -> Result<()> {
        let Some(conn) = self.conn_cache.clients.get_mut(client_idx.0) else {
            return Ok(());
        };
        if !conn.is_connected() {
            return Ok(());
        }
        log::debug!("server disconnecting client {client_idx}");
        for _ in 0..self.cfg.num_disconnect_packets {
            self.send_to_client(DisconnectPacket::create(), client_idx)?;
        }
        self.on_disconnect(client_idx);
        self.conn_cache.remove(client_idx);
        Ok(())
    }
    /// Disconnects all clients.
    pub fn disconnect_all(&mut self) -> Result<()> {
        log::debug!("server disconnecting all clients");
        for idx in 0..MAX_CLIENTS {
            let Some(conn) = self.conn_cache.clients.get_mut(idx) else {
                continue;
            };
            if conn.is_connected() {
                self.disconnect(ClientIndex(idx))?;
            }
        }
        Ok(())
    }
    /// Gets the local `SocketAddr` this server is bound to.
    pub fn addr(&self) -> SocketAddr {
        self.transceiver.addr()
    }
    /// Gets the number of connected clients.
    pub fn num_connected_clients(&self) -> usize {
        self.conn_cache
            .clients
            .iter()
            .filter(|(_, c)| c.is_connected())
            .count()
    }
    /// Gets the [`ClientId`](ClientId) of a client.
    pub fn client_id(&self, client_idx: ClientIndex) -> Option<ClientId> {
        self.conn_cache
            .clients
            .get(client_idx.0)
            .map(|c| c.client_id)
    }
    /// Gets the address of a client.
    pub fn client_addr(&self, client_idx: ClientIndex) -> Option<SocketAddr> {
        self.conn_cache.clients.get(client_idx.0).map(|c| c.addr)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::simulator::NetworkSimulator;
    impl Server<NetworkSimulator> {
        pub(crate) fn with_simulator(
            sim: NetworkSimulator,
            private_key: Option<Key>,
        ) -> Result<Self> {
            let time = 0.0;
            log::info!("server started on {}", sim.addr());
            let server = Server {
                transceiver: sim,
                time,
                private_key: private_key.unwrap_or(crypto::generate_key()),
                protocol_id: 0,
                sequence: 1 << 63,
                token_sequence: 0,
                challenge_sequence: 0,
                challenge_key: crypto::generate_key(),
                conn_cache: ConnectionCache::new(time),
                token_entries: TokenEntries::new(),
                cfg: ServerConfig::default(),
            };
            Ok(server)
        }
        pub(crate) fn iter_clients(&self) -> impl Iterator<Item = ClientIndex> + '_ {
            self.conn_cache
                .clients
                .iter()
                .filter(|(_, c)| c.is_connected())
                .map(|(idx, _)| ClientIndex(idx))
        }
    }
}
