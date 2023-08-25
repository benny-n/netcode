use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::bytes::Bytes;
use crate::consts::{MAC_SIZE, MAX_CLIENTS, MAX_PAYLOAD_SIZE, MAX_PKT_BUF_SIZE, PACKET_SEND_RATE};
use crate::crypto::{self, Key};
use crate::error::NetcodeError;
use crate::free_list::FreeList;
use crate::packet::{
    ChallengePacket, DeniedPacket, DisconnectPacket, KeepAlivePacket, Packet, PayloadPacket,
    RequestPacket, ResponsePacket,
};
use crate::replay::ReplayProtection;
use crate::socket::NetcodeSocket;
use crate::token::{ChallengeToken, ConnectToken, ConnectTokenBuilder, ConnectTokenPrivate};
use crate::transceiver::Transceiver;

type Result<T> = std::result::Result<T, NetcodeError>;

#[derive(Clone, Copy)]
struct TokenEntry {
    time: f64,
    mac: [u8; 16],
    addr: SocketAddr,
}

struct TokenEntries {
    list: FreeList<TokenEntry, { MAX_CLIENTS * 8 }>,
}

impl TokenEntries {
    fn new() -> Self {
        Self {
            list: FreeList::new(),
        }
    }
    fn find_or_insert(&mut self, entry: TokenEntry) -> bool {
        let (mut oldest, mut matching) = (None, None);
        let mut oldest_time = f64::INFINITY;
        // Perform a linear search for the oldest and matching entries at the same time
        for (idx, saved_entry) in self.list.iter().enumerate() {
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
            self.list.insert(entry);
            return true;
        };
        if let Some(matching) = matching {
            // Allow reusing tokens only if the address matches
            self.list[matching].addr == entry.addr
        } else {
            // If there is no matching entry, replace the oldest one
            self.list.replace(oldest, entry);
            true
        }
    }
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

/// The client id from a connect token, must be unique for each client.
///
/// Note that this is not the same as the [`ClientIndex`](ClientIndex), which is used by the server to identify clients.
pub type ClientId = u64;

/// A thin wrapper around `usize` used by the server to identify clients.
///
/// This is used instead of `usize` to make it harder to accidentally use a client id as a client index, or mix between other `usize` values.
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
    // this somewhat mimics the original C implementation, but it's not exactly the same since `Connection` stores encryption mappings as well
    clients: FreeList<Connection, MAX_CLIENTS>,

    // we are not using a free-list here to not allocate memory up-front, since `ReplayProtection` is biggish (~2kb)
    replay_protection: HashMap<ClientIndex, ReplayProtection>,

    // corresponds to the server time
    time: f64,
}

impl ConnectionCache {
    fn new(server_time: f64) -> Self {
        Self {
            clients: FreeList::new(),
            replay_protection: HashMap::new(),
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
        if let Some(existing) = self
            .find_by_addr(&addr)
            .and_then(|idx| self.clients.get_mut(idx.0))
        {
            existing.client_id = client_id;
            existing.timeout = timeout;
            existing.expire_time = expire_time;
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
            expire_time,
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
    fn find_by_addr(&self, addr: &SocketAddr) -> Option<ClientIndex> {
        self.clients
            .iter()
            .enumerate()
            .find_map(|(idx, conn)| (conn.addr == *addr).then_some(ClientIndex(idx)))
    }
    fn find_by_id(&self, client_id: ClientId) -> Option<ClientIndex> {
        self.clients
            .iter()
            .enumerate()
            .find_map(|(idx, conn)| (conn.client_id == client_id).then_some(ClientIndex(idx)))
    }
    fn is_connection_expired(conn: &Connection, time: f64) -> bool {
        (0.0..time).contains(&conn.expire_time)
            || (0.0..time - conn.last_access_time).contains(&(conn.timeout as f64))
    }
    fn update(&mut self, time: f64) {
        self.time = time;
        for idx in 0..MAX_CLIENTS {
            let Some(conn) = self.clients.get_mut(idx) else {
                continue;
            };
            if Self::is_connection_expired(conn, time) {
                self.remove(ClientIndex(idx));
            }
        }
    }
}
type Callback<Ctx> = Box<dyn FnMut(ClientIndex, Option<&mut Ctx>) + Send + Sync + 'static>;
/// Configuration for a server.
///
/// * `num_disconnect_packets` - The number of redundant disconnect packets that will be sent to a client when the server is disconnecting it.
/// * `keep_alive_send_rate` - The rate at which keep alive packets will be sent to clients.
/// * `on_connect` - A callback that will be called when a client is connected to the server.
/// * `on_disconnect` - A callback that will be called when a client is disconnected from the server.
///
/// # Example
/// ```
/// # let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 40000));
/// # let protocol_id = 0x123456789ABCDEF0;
/// # let private_key = [42u8; 32];
/// use std::sync::{Arc, Mutex};
/// use netcode::server::{Server, ServerConfig};
///
/// let thread_safe_counter = Arc::new(Mutex::new(0));
/// let cfg = ServerConfig::with_context(thread_safe_counter).on_connect(|idx, ctx| {
///     if let Some(ctx) = ctx {
///         let mut counter = ctx.lock().unwrap();
///         *counter += 1;
///         println!("client {} connected, counter: {idx}", counter);
///     }
/// });
/// let server = Server::with_config(addr, protocol_id, Some(private_key), cfg).unwrap();
/// ```
pub struct ServerConfig<Ctx> {
    num_disconnect_packets: usize,
    keep_alive_send_rate: f64,
    context: Option<Box<Ctx>>,
    on_connect: Option<Callback<Ctx>>,
    on_disconnect: Option<Callback<Ctx>>,
}
impl<Ctx> Default for ServerConfig<Ctx> {
    fn default() -> Self {
        Self {
            num_disconnect_packets: 10,
            keep_alive_send_rate: PACKET_SEND_RATE,
            context: None,
            on_connect: None,
            on_disconnect: None,
        }
    }
}

impl<Ctx> ServerConfig<Ctx> {
    /// Create a new, default server configuration.
    pub fn new() -> ServerConfig<()> {
        ServerConfig::<()>::default()
    }
    /// Create a new server configuration with a state that will be passed to the callbacks.
    pub fn with_context(ctx: Ctx) -> Self {
        Self {
            context: Some(Box::new(ctx)),
            ..Self::default()
        }
    }
    /// Set the number of redundant disconnect packets that will be sent to a client when the server is disconnecting it. <br>
    /// The default is 10 packets.
    pub fn num_disconnect_packets(mut self, num: usize) -> Self {
        self.num_disconnect_packets = num;
        self
    }
    /// Set the rate at which keep alive packets will be sent to clients. <br>
    /// The default is 10 packets per second.
    pub fn keep_alive_send_rate(mut self, rate: f64) -> Self {
        self.keep_alive_send_rate = rate;
        self
    }
    /// Provide a callback that will be called when a client is connected to the server. <br>
    /// The callback will be called with the client index and the context that was provided (provide a `None` context if you don't need one).
    ///
    /// See [`ServerConfig`](ServerConfig) for an example.
    pub fn on_connect<F>(mut self, cb: F) -> Self
    where
        F: FnMut(ClientIndex, Option<&mut Ctx>) + Send + Sync + 'static,
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
        F: FnMut(ClientIndex, Option<&mut Ctx>) + Send + Sync + 'static,
    {
        self.on_disconnect = Some(Box::new(cb));
        self
    }
}
pub struct Server<T: Transceiver, Ctx = ()> {
    transceiver: T,
    time: f64,
    private_key: Key,
    max_clients: usize,
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
    /// Create a new, stateless server a default configuration.
    ///
    /// For a stateful server, use [`Server::with_config`](Server::with_config) and provide a state in the [`ServerConfig`](ServerConfig).
    ///
    /// # Example
    /// ```
    /// use netcode::server::Server;
    /// use std::net::{SocketAddr, Ipv4Addr};
    ///
    /// let private_key = [42u8; 32]; // TODO: generate a real private key
    /// let protocol_id = 0x123456789ABCDEF0;
    /// let addr = "127.0.0.1:41234";
    /// let server = Server::new(addr, protocol_id, Some(private_key)).unwrap();
    /// ```
    pub fn new(
        bind_addr: impl ToSocketAddrs,
        protocol_id: u64,
        private_key: Option<Key>,
    ) -> Result<Server<NetcodeSocket, ()>> {
        let server: Server<_, ()> = Server {
            transceiver: NetcodeSocket::new(bind_addr)?,
            time: 0.0,
            private_key: private_key.unwrap_or(crypto::generate_key()?),
            max_clients: MAX_CLIENTS,
            protocol_id,
            sequence: 1 << 63,
            token_sequence: 0,
            challenge_sequence: 0,
            challenge_key: crypto::generate_key()?,
            conn_cache: ConnectionCache::new(0.0),
            token_entries: TokenEntries::new(),
            cfg: ServerConfig::default(),
        };
        log::info!("server started on {}", server.transceiver.addr());
        Ok(server)
    }
}

impl<Ctx> Server<NetcodeSocket, Ctx> {
    /// Create a new with a custom configuration.
    ///
    /// State can be provided in the [`ServerConfig`](ServerConfig).
    ///
    /// # Example
    /// ```
    /// use netcode::server::{Server, ServerConfig};
    /// use std::net::{SocketAddr, Ipv4Addr};
    ///
    /// let private_key = [42u8; 32]; // TODO: generate a real private key
    /// let protocol_id = 0x123456789ABCDEF0;
    /// let addr = "127.0.0.1:40000".parse().unwrap();
    /// let cfg = ServerConfig::with_context(42).on_connect(|idx, ctx| {
    ///     if let Some(ctx) = ctx {
    ///         assert_eq!(*ctx, 42);
    ///     }
    /// });
    /// let server = Server::with_config(addr, protocol_id, Some(private_key), cfg).unwrap();
    /// ```
    pub fn with_config(
        bind_addr: SocketAddr,
        protocol_id: u64,
        private_key: Option<Key>,
        cfg: ServerConfig<Ctx>,
    ) -> Result<Self> {
        let server = Server {
            transceiver: NetcodeSocket::new(bind_addr)?,
            time: 0.0,
            private_key: private_key.unwrap_or(crypto::generate_key()?),
            max_clients: MAX_CLIENTS,
            protocol_id,
            sequence: 1 << 63,
            token_sequence: 0,
            challenge_sequence: 0,
            challenge_key: crypto::generate_key()?,
            conn_cache: ConnectionCache::new(0.0),
            token_entries: TokenEntries::new(),
            cfg,
        };
        log::info!("server started on {}", bind_addr);
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
            cb(client_idx, self.cfg.context.as_mut().map(|s| s.as_mut()))
        }
    }
    fn on_disconnect(&mut self, client_idx: ClientIndex) {
        if let Some(cb) = self.cfg.on_disconnect.as_mut() {
            cb(client_idx, self.cfg.context.as_mut().map(|s| s.as_mut()))
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
        let client_idx = self.conn_cache.find_by_addr(&addr);
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
            Packet::KeepAlive(_) | Packet::Payload(_) => self.touch_client(client_idx),
            Packet::Disconnect(_) => {
                if let Some(idx) = client_idx {
                    log::debug!("server disconnected client {idx}");
                    self.conn_cache.remove(idx);
                }
                Ok(())
            }
            _ => Err(NetcodeError::InvalidPacket)?,
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
    pub fn disconnect_client(&mut self, client_idx: ClientIndex) -> Result<()> {
        log::debug!("server disconnecting client {client_idx}");
        for _ in 0..self.cfg.num_disconnect_packets {
            self.send_to_client(DisconnectPacket::create(), client_idx)?;
        }
        self.on_disconnect(client_idx);
        self.conn_cache.remove(client_idx);
        Ok(())
    }
    pub fn disconnect_all(&mut self) -> Result<()> {
        log::debug!("server disconnecting all clients");
        for idx in 0..MAX_CLIENTS {
            let Some(conn) = self.conn_cache.clients.get_mut(idx) else {
                continue;
            };
            if conn.is_connected() {
                self.disconnect_client(ClientIndex(idx))?;
            }
        }
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
            .any(|addr| addr == self.transceiver.addr())
        {
            log::debug!(
                "server ignored connection request. server address not in connect token whitelist"
            );
            return Ok(());
        };
        if self
            .conn_cache
            .find_by_addr(&from_addr)
            .and_then(|idx| self.conn_cache.clients.get(idx.0))
            .is_some_and(|&conn| conn.is_connected())
        {
            log::debug!("server ignored connection request. a client with this address is already connected");
            return Ok(());
        };
        if self
            .conn_cache
            .find_by_id(token.client_id)
            .is_some_and(|idx| self.conn_cache.clients[idx.0].is_connected())
        {
            log::debug!(
                "server ignored connection request. a client with this id is already connected"
            );
            return Ok(());
        };
        let entry = TokenEntry {
            time: self.time,
            addr: from_addr,
            mac: packet.token_data[ConnectTokenPrivate::SIZE - MAC_SIZE..ConnectTokenPrivate::SIZE]
                .try_into()
                .map_err(|_| NetcodeError::InvalidPacket)?,
        };
        if !self.token_entries.find_or_insert(entry) {
            log::debug!("server ignored connection request. connect token has already been used");
            return Ok(());
        };
        if self.conn_cache.clients.len() >= self.max_clients {
            log::debug!("server denied connection request. server is full");
            self.send_to_addr(
                DeniedPacket::create(),
                from_addr,
                token.server_to_client_key,
            )?;
            return Ok(());
        };
        let expire_time = if token.timeout_seconds.is_positive() {
            self.time + token.timeout_seconds as f64
        } else {
            -1.0
        };
        self.conn_cache.add(
            token.client_id,
            from_addr,
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
        let num_clients = self.conn_cache.clients.len();
        let Some(idx) = self.conn_cache.find_by_id(challenge_token.client_id) else {
            log::debug!("server ignored connection response. no packet send key");
            return Ok(());
        };
        if num_clients >= self.max_clients {
            log::debug!("server denied connection request. server is full");
            self.send_to_addr(
                DeniedPacket::create(),
                from_addr,
                self.conn_cache.clients[idx.0].send_key,
            )?;
            return Ok(());
        };
        let client = &mut self.conn_cache.clients[idx.0];
        if client.is_connected() {
            log::debug!("server ignored connection response. client is already connected");
            return Ok(());
        };
        client.connect();
        client.expire_time = -1.0; // TODO: check if this is correct
        client.sequence = 0;
        client.last_send_time = self.time;
        client.last_receive_time = self.time;
        log::debug!(
            "server accepted client {} with id {}",
            idx,
            challenge_token.client_id
        );
        self.send_to_client(
            KeepAlivePacket::create(idx.0 as i32, self.max_clients as i32),
            idx,
        )?;
        self.on_connect(idx);
        Ok(())
    }
    fn check_for_timeouts(&mut self) -> Result<()> {
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
        Ok(())
    }
    fn send_keep_alive_packets(&mut self) -> Result<()> {
        for idx in 0..MAX_CLIENTS {
            let Some(client) = self.conn_cache.clients.get_mut(idx) else {
                continue;
            };
            if !client.is_connected() {
                continue;
            }
            if client.last_send_time + self.cfg.keep_alive_send_rate < self.time {
                log::trace!("server sent connection keep alive packet to client {idx}");
                self.send_to_client(
                    KeepAlivePacket::create(idx as i32, self.max_clients as i32),
                    ClientIndex(idx),
                )?;
            }
        }
        Ok(())
    }
    /// Gets the local `SocketAddr` this server is bound to.
    pub fn addr(&self) -> SocketAddr {
        self.transceiver.addr()
    }
    /// Creates a connect token builder for a given public server address and client ID.
    /// The builder can be used to configure the token with additional data before generating the final token.
    /// The `generate` method must be called on the builder to generate the final token.
    ///
    /// # Example
    ///
    /// ```
    /// # use netcode::server::{Server, ServerConfig};
    /// # use std::net::{SocketAddr, Ipv4Addr};
    ///  
    /// let private_key = Some([42u8; 32]); // TODO: generate a real private key
    /// let protocol_id = 0x123456789ABCDEF0;
    /// let bind_addr = "0.0.0.0:0";
    /// let mut server = Server::new(bind_addr, protocol_id, private_key).unwrap();
    ///
    /// let client_id = 123u64;
    /// let token = server.token(client_id)
    ///     .expire_seconds(60)  // optional - default is 30 seconds. negative values would make the token never expire.
    ///     .timeout_seconds(-1) // optional - default is 15 seconds. negative values would make the token never timeout.
    ///     .generate()
    ///     .unwrap();
    /// ```
    ///
    /// See [`ConnectTokenBuilder`](ConnectTokenBuilder) for more options.
    pub fn token(&mut self, client_id: u64) -> ConnectTokenBuilder<SocketAddr> {
        let token_builder = ConnectToken::build(
            self.transceiver.addr(),
            self.protocol_id,
            client_id,
            self.token_sequence,
        )
        .private_key(self.private_key);
        self.token_sequence += 1;
        token_builder
    }
    pub fn update(&mut self, time: f64) -> Result<()> {
        self.time = time;
        self.conn_cache.update(self.time);
        self.check_for_timeouts()?;
        self.send_keep_alive_packets()?;
        Ok(())
    }
    pub fn recv(&mut self, buf: &mut [u8]) -> Result<Option<(usize, ClientIndex)>> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let Some((size, addr)) = self.transceiver.recv(buf).map_err(|e| e.into())? else {
            // No packet received
            return Ok(None);
        };
        if size <= 1 {
            // Too small to be a packet
            return Ok(None);
        }
        let (key, replay_protection) = match self.conn_cache.find_by_addr(&addr) {
            // Regardless of whether an entry in the connection cache exists for the client or not,
            // if the packet is a connection request we need to use the server's private key to decrypt it.
            _ if Packet::is_connection_request(buf[0]) => (self.private_key, None),
            Some(client_idx) => (
                // If the packet is not a connection request, use the receive key to decrypt it.
                self.conn_cache.clients[client_idx.0].receive_key,
                self.conn_cache.replay_protection.get_mut(&client_idx),
            ),
            None => {
                // Not a connection request packet, and not a known client, so ignore
                log::debug!(
                    "server ignored non-connection-request packet from unknown address {addr}"
                );
                return Ok(None);
            }
        };
        let packet = match Packet::read(
            &mut buf[..size],
            self.protocol_id,
            now,
            key,
            replay_protection,
            Self::ALLOWED_PACKETS,
        ) {
            Ok(packet) => packet,
            Err(NetcodeError::Crypto(_)) => {
                log::debug!("server ignored packet because it failed to decrypt");
                return Ok(None);
            }
            Err(e) => {
                log::error!("server ignored packet: {e}");
                return Ok(None);
            }
        };
        let size = if let Packet::Payload(ref packet) = packet {
            packet.buf.len()
        } else {
            0
        };
        self.process_packet(addr, packet)?;
        Ok(self
            .conn_cache
            .find_by_addr(&addr)
            .and_then(|idx| (size > 0).then_some((size, idx))))
    }
    pub fn send(&mut self, buf: &[u8], client_idx: ClientIndex) -> Result<()> {
        if buf.len() > MAX_PAYLOAD_SIZE {
            return Err(NetcodeError::PacketSizeExceeded(buf.len()));
        }
        let Some(conn) = self.conn_cache.clients.get_mut(client_idx.0) else {
            return Err(NetcodeError::ClientNotFound);
        };
        if !conn.connected {
            // client is not yet connected, but this shouldn't be an error as the client may be sending a connection request
            log::debug!(
                "server ignored send to client {client_idx} because it is not yet connected",
            );
            return Ok(());
        }
        if !conn.confirmed {
            // send a keep alive packet to the client to confirm the connection
            self.send_to_client(
                KeepAlivePacket::create(client_idx.0 as i32, self.max_clients as i32),
                client_idx,
            )?;
        }
        let packet = PayloadPacket::create(buf);
        self.send_to_client(packet, client_idx)
    }
    pub fn iter_clients(&self) -> impl Iterator<Item = ClientIndex> + '_ {
        self.conn_cache
            .clients
            .iter()
            .filter(|c| c.is_connected())
            .enumerate()
            .map(|(idx, _)| ClientIndex(idx))
    }
    pub fn client_id(&self, client_idx: ClientIndex) -> Option<ClientId> {
        self.conn_cache
            .clients
            .get(client_idx.0)
            .map(|c| c.client_id)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::simulator::NetworkSimulator;
    impl Server<NetworkSimulator> {
        pub fn with_simulator(sim: NetworkSimulator, private_key: Option<Key>) -> Result<Self> {
            let time = 0.0;
            log::info!("server started on {}", sim.addr());
            let server = Server {
                transceiver: sim,
                time,
                private_key: private_key.unwrap_or(crypto::generate_key()?),
                max_clients: MAX_CLIENTS,
                protocol_id: 0,
                sequence: 1 << 63,
                token_sequence: 0,
                challenge_sequence: 0,
                challenge_key: crypto::generate_key()?,
                conn_cache: ConnectionCache::new(time),
                token_entries: TokenEntries::new(),
                cfg: ServerConfig::default(),
            };
            Ok(server)
        }
    }
}
