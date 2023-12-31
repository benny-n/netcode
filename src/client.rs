use std::{
    collections::VecDeque,
    net::{Ipv4Addr, SocketAddr},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    bytes::Bytes,
    error::{Error, Result},
    packet::{
        DisconnectPacket, KeepAlivePacket, Packet, PayloadPacket, RequestPacket, ResponsePacket,
    },
    replay::ReplayProtection,
    socket::NetcodeSocket,
    token::{ChallengeToken, ConnectToken},
    transceiver::Transceiver,
    MAX_PACKET_SIZE, MAX_PKT_BUF_SIZE, PACKET_SEND_RATE_SEC,
};

const RECV_BUF_SIZE: usize = 256 * 1024;
const SEND_BUF_SIZE: usize = 256 * 1024;

type Callback<Ctx> = Box<dyn FnMut(ClientState, ClientState, &mut Ctx) + Send + Sync + 'static>;
/// Configuration for a client.
///
/// * `num_disconnect_packets` - The number of redundant disconnect packets that will be sent to a server when the clients wants to disconnect.
/// * `packet_send_rate` - The rate at which periodic packets will be sent to the server.
/// * `on_state_change` - A callback that will be called when the client changes states.
///
/// # Example
/// ```
/// # struct MyContext;
/// # use netcode::Server;
/// # let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 40001));
/// # let private_key = netcode::generate_key();
/// # let token = Server::new(addr, 0x11223344, private_key).unwrap().token(123u64).generate().unwrap();
/// # let token_bytes = token.try_into_bytes().unwrap();
/// use netcode::{Client, ClientConfig, ClientState};
///
/// let cfg = ClientConfig::with_context(MyContext {})
///     .num_disconnect_packets(10)
///     .packet_send_rate(0.1)
///     .on_state_change(|from, to, _ctx| {
///     if let (ClientState::SendingChallengeResponse, ClientState::Connected) = (from, to) {
///        println!("client connected to server");
///     }
/// });
/// let mut client = Client::with_config(&token_bytes, cfg).unwrap();
/// client.connect();
/// ```
pub struct ClientConfig<Ctx> {
    num_disconnect_packets: usize,
    packet_send_rate: f64,
    context: Ctx,
    on_state_change: Option<Callback<Ctx>>,
}

impl Default for ClientConfig<()> {
    fn default() -> Self {
        Self {
            num_disconnect_packets: 10,
            packet_send_rate: PACKET_SEND_RATE_SEC,
            context: (),
            on_state_change: None,
        }
    }
}

impl<Ctx> ClientConfig<Ctx> {
    /// Create a new, default client configuration with no context.
    pub fn new() -> ClientConfig<()> {
        ClientConfig::<()>::default()
    }
    /// Create a new client configuration with context that will be passed to the callbacks.
    pub fn with_context(ctx: Ctx) -> Self {
        Self {
            num_disconnect_packets: 10,
            packet_send_rate: PACKET_SEND_RATE_SEC,
            context: ctx,
            on_state_change: None,
        }
    }
    /// Set the number of redundant disconnect packets that will be sent to a server when the clients wants to disconnect.
    /// The default is 10 packets.
    pub fn num_disconnect_packets(mut self, num_disconnect_packets: usize) -> Self {
        self.num_disconnect_packets = num_disconnect_packets;
        self
    }
    /// Set the rate at which periodic packets will be sent to the server.
    /// The default is 10 packets per second. (`0.1` seconds)
    pub fn packet_send_rate(mut self, rate_seconds: f64) -> Self {
        self.packet_send_rate = rate_seconds;
        self
    }
    /// Set a callback that will be called when the client changes states.
    pub fn on_state_change<F>(mut self, cb: F) -> Self
    where
        F: FnMut(ClientState, ClientState, &mut Ctx) + Send + Sync + 'static,
    {
        self.on_state_change = Some(Box::new(cb));
        self
    }
}

/// The states in the client state machine.
///
/// The initial state is `Disconnected`.
/// When a client wants to connect to a server, it requests a connect token from the web backend.
/// To begin this process, it transitions to `SendingConnectionRequest` with the first server address in the connect token.
/// After that the client can either transition to `SendingChallengeResponse` or one of the error states.
/// While in `SendingChallengeResponse`, when the client receives a connection keep-alive packet from the server,
/// it stores the client index and max clients in the packet, and transitions to `Connected`.
///
/// Any payload packets received prior to `Connected` are discarded.
///
/// `Connected` is the final stage in the connection process and represents a successful connection to the server.
///
/// While in this state:
///
///  - The client application may send payload packets to the server.
///  - In the absence of payload packets sent by the client application, the client generates and sends connection keep-alive packets
///    to the server at some rate (default is 10HZ, can be overridden in [`ClientConfig`](ClientConfig)).
///  - If no payload or keep-alive packets are received from the server within the timeout period specified in the connect token,
///    the client transitions to `ConnectionTimedOut`.
///  - While `Connected`, if the client receives a disconnect packet from the server, it transitions to `Disconnected`.
///    If the client wishes to disconnect from the server,
///    it sends a number of redundant connection disconnect packets (default is 10, can be overridden in [`ClientConfig`](ClientConfig))
///    before transitioning to `Disconnected`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ClientState {
    /// The connect token has expired.
    ConnectTokenExpired,
    /// The client has timed out while trying to connect to the server,
    /// or while connected to the server due to a lack of packets received/sent.
    ConnectionTimedOut,
    /// The client has timed out while waiting for a response from the server after sending a connection request packet.
    ConnectionRequestTimedOut,
    /// The client has timed out while waiting for a response from the server after sending a challenge response packet.
    ChallengeResponseTimedOut,
    /// The server has denied the client's connection request, most likely due to the server being full.
    ConnectionDenied,
    /// The client is disconnected from the server.
    Disconnected,
    /// The client is waiting for a response from the server after sending a connection request packet.
    SendingConnectionRequest,
    /// The client is waiting for a response from the server after sending a challenge response packet.
    SendingChallengeResponse,
    /// The client is connected to the server.
    Connected,
}

/// The `netcode` client.
///
/// To create a client one should obtain a connection token from a web backend (by REST API or other means). <br>
/// The client will use this token to connect to the dedicated `netcode` server.
///
/// While the client is connected, it can send and receive packets to and from the server. <br>
/// Similarly to the server, the client should be updated at a fixed rate (e.g., 60Hz) to process incoming packets and send outgoing packets. <br>
///
/// # Example
/// ```
/// # use netcode::{ConnectToken, Client, ClientConfig, ClientState};
/// # use std::time::{Instant, Duration};
/// # use std::thread;
/// # let mut server = netcode::Server::new("127.0.0.1:0", 0, [0; 32]).unwrap();
/// # let token_bytes = server.token(0).generate().unwrap().try_into_bytes().unwrap();
/// let mut client = Client::new(&token_bytes).unwrap();
/// client.connect();
///
/// let start = Instant::now();
/// let tick_rate = Duration::from_secs_f64(1.0 / 60.0);
/// loop {
///     client.update(start.elapsed().as_secs_f64());
///     if client.is_connected() {
///         client.send(b"Hello World!").unwrap();
///     }
///     if let Some(packet) = client.recv() {
///         println!("received packet: {:?}", packet);
///     }
///     thread::sleep(tick_rate);
///     # break;
/// }
/// ```
pub struct Client<T: Transceiver, Ctx = ()> {
    transceiver: T,
    state: ClientState,
    time: f64,
    start_time: f64,
    last_send_time: f64,
    last_receive_time: f64,
    server_addr_idx: usize,
    sequence: u64,
    challenge_token_sequence: u64,
    challenge_token_data: [u8; ChallengeToken::SIZE],
    client_index: i32,
    max_clients: i32,
    token: ConnectToken,
    replay_protection: ReplayProtection,
    should_disconnect: bool,
    should_disconnect_state: ClientState,
    packet_queue: VecDeque<Vec<u8>>,
    cfg: ClientConfig<Ctx>,
}

impl<Trx: Transceiver, Ctx> Client<Trx, Ctx> {
    fn from_token(token_bytes: &[u8], cfg: ClientConfig<Ctx>, trx: Trx) -> Result<Self> {
        if token_bytes.len() != ConnectToken::SIZE {
            return Err(Error::SizeMismatch(ConnectToken::SIZE, token_bytes.len()));
        }
        let mut buf = [0u8; ConnectToken::SIZE];
        buf.copy_from_slice(token_bytes);
        let mut cursor = std::io::Cursor::new(&mut buf[..]);
        let token = match ConnectToken::read_from(&mut cursor) {
            Ok(token) => token,
            Err(err) => {
                log::error!("invalid connect token: {err}");
                return Err(Error::InvalidToken(err));
            }
        };
        log::info!("client started on {}", trx.addr());
        Ok(Self {
            transceiver: trx,
            state: ClientState::Disconnected,
            time: 0.0,
            start_time: 0.0,
            last_send_time: f64::NEG_INFINITY,
            last_receive_time: f64::NEG_INFINITY,
            server_addr_idx: 0,
            sequence: 0,
            challenge_token_sequence: 0,
            challenge_token_data: [0u8; ChallengeToken::SIZE],
            client_index: 0,
            max_clients: 0,
            token,
            replay_protection: ReplayProtection::new(),
            should_disconnect: false,
            should_disconnect_state: ClientState::Disconnected,
            packet_queue: VecDeque::new(),
            cfg,
        })
    }
}

impl Client<NetcodeSocket> {
    /// Create a new client with a default configuration.
    ///
    /// # Example
    /// ```
    /// # use netcode::{ConnectToken, Client, ClientConfig, ClientState};
    /// // Generate a connection token for the client
    /// let private_key = netcode::generate_key();
    /// let token_bytes = ConnectToken::build("127.0.0.1:0", 0, 0, private_key)
    ///     .generate()
    ///     .unwrap()
    ///     .try_into_bytes()
    ///     .unwrap();
    ///
    /// let mut client = Client::new(&token_bytes).unwrap();
    /// ```
    pub fn new(token_bytes: &[u8]) -> Result<Self> {
        let netcode_sock =
            NetcodeSocket::new((Ipv4Addr::UNSPECIFIED, 0), SEND_BUF_SIZE, RECV_BUF_SIZE)?;
        Client::from_token(token_bytes, ClientConfig::default(), netcode_sock)
    }
}

impl<Ctx> Client<NetcodeSocket, Ctx> {
    /// Create a new client with a custom configuration. <br>
    /// Callbacks with context can be registered with the client to be notified when the client changes states. <br>
    /// See [`ClientConfig`](ClientConfig) for more details.
    ///
    /// # Example
    /// ```
    /// # use netcode::{ConnectToken, Client, ClientConfig, ClientState};
    /// # let private_key = netcode::generate_key();
    /// # let token_bytes = ConnectToken::build("127.0.0.1:0", 0, 0, private_key)
    /// #    .generate()
    /// #    .unwrap()
    /// #    .try_into_bytes()
    /// #    .unwrap();
    /// struct MyContext {};
    /// let cfg = ClientConfig::with_context(MyContext {}).on_state_change(|from, to, _ctx| {
    ///    assert_eq!(from, ClientState::Disconnected);
    ///    assert_eq!(to, ClientState::SendingConnectionRequest);
    /// });
    ///
    /// let mut client = Client::with_config(&token_bytes, cfg).unwrap();
    /// ```
    pub fn with_config(token_bytes: &[u8], cfg: ClientConfig<Ctx>) -> Result<Self> {
        let netcode_sock =
            NetcodeSocket::new((Ipv4Addr::UNSPECIFIED, 0), SEND_BUF_SIZE, RECV_BUF_SIZE)?;
        Client::from_token(token_bytes, cfg, netcode_sock)
    }
}

impl<T: Transceiver, Ctx> Client<T, Ctx> {
    const ALLOWED_PACKETS: u8 = 1 << Packet::DENIED
        | 1 << Packet::CHALLENGE
        | 1 << Packet::KEEP_ALIVE
        | 1 << Packet::PAYLOAD
        | 1 << Packet::DISCONNECT;

    fn set_state(&mut self, state: ClientState) {
        log::debug!("client state changing from {:?} to {:?}", self.state, state);
        if let Some(ref mut cb) = self.cfg.on_state_change {
            cb(self.state, state, &mut self.cfg.context)
        }
        self.state = state;
    }
    fn reset_connection(&mut self) {
        self.start_time = self.time;
        self.last_send_time = self.time - 1.0; // force a packet to be sent immediately
        self.last_receive_time = self.time;
        self.should_disconnect = false;
        self.should_disconnect_state = ClientState::Disconnected;
        self.challenge_token_sequence = 0;
        self.replay_protection = ReplayProtection::new();
    }
    fn reset(&mut self, new_state: ClientState) {
        self.sequence = 0;
        self.client_index = 0;
        self.max_clients = 0;
        self.start_time = 0.0;
        self.server_addr_idx = 0;
        self.set_state(new_state);
        self.reset_connection();
        log::debug!("client disconnected");
    }
    fn send_packets(&mut self) -> Result<()> {
        if self.last_send_time + self.cfg.packet_send_rate >= self.time {
            return Ok(());
        }
        let packet = match self.state {
            ClientState::SendingConnectionRequest => {
                log::debug!("client sending connection request packet to server");
                RequestPacket::create(
                    self.token.protocol_id,
                    self.token.expire_timestamp,
                    self.token.nonce,
                    self.token.private_data,
                )
            }
            ClientState::SendingChallengeResponse => {
                log::debug!("client sending connection response packet to server");
                ResponsePacket::create(self.challenge_token_sequence, self.challenge_token_data)
            }
            ClientState::Connected => {
                log::trace!("client sending connection keep-alive packet to server");
                KeepAlivePacket::create(0, 0)
            }
            _ => return Ok(()),
        };
        self.send_packet(packet)
    }
    fn connect_to_next_server(&mut self) -> std::result::Result<(), ()> {
        if self.server_addr_idx + 1 >= self.token.server_addresses.len() {
            log::debug!("no more servers to connect to");
            return Err(());
        }
        self.server_addr_idx += 1;
        self.connect();
        Ok(())
    }
    fn send_packet(&mut self, packet: Packet) -> Result<()> {
        let mut buf = [0u8; MAX_PKT_BUF_SIZE];
        let size = packet.write(
            &mut buf,
            self.sequence,
            &self.token.client_to_server_key,
            self.token.protocol_id,
        )?;
        let server_addr = self.token.server_addresses[self.server_addr_idx];
        self.transceiver
            .send(&buf[..size], server_addr)
            .map_err(|e| e.into())?;
        self.last_send_time = self.time;
        self.sequence += 1;
        Ok(())
    }
    fn process_packet(&mut self, addr: SocketAddr, packet: Packet) -> Result<()> {
        if addr != self.token.server_addresses[self.server_addr_idx] {
            return Ok(());
        }
        match (packet, self.state) {
            (
                Packet::Denied(_),
                ClientState::SendingConnectionRequest | ClientState::SendingChallengeResponse,
            ) => {
                self.should_disconnect = true;
                self.should_disconnect_state = ClientState::ConnectionDenied;
            }
            (Packet::Challenge(pkt), ClientState::SendingConnectionRequest) => {
                log::debug!("client received connection challenge packet from server");
                self.challenge_token_sequence = pkt.sequence;
                self.challenge_token_data = pkt.token;
                self.set_state(ClientState::SendingChallengeResponse);
            }
            (Packet::KeepAlive(_), ClientState::Connected) => {
                log::trace!("client received connection keep-alive packet from server");
            }
            (Packet::KeepAlive(pkt), ClientState::SendingChallengeResponse) => {
                log::debug!("client received connection keep-alive packet from server");
                self.client_index = pkt.client_index;
                self.max_clients = pkt.max_clients;
                self.set_state(ClientState::Connected);
                log::info!("client connected to server");
            }
            (Packet::Payload(pkt), ClientState::Connected) => {
                log::debug!("client received payload packet from server");
                self.packet_queue.push_back(pkt.buf.to_vec());
            }
            (Packet::Disconnect(_), ClientState::Connected) => {
                log::debug!("client received disconnect packet from server");
                self.should_disconnect = true;
                self.should_disconnect_state = ClientState::Disconnected;
            }
            _ => return Ok(()),
        }
        self.last_receive_time = self.time;
        Ok(())
    }
    fn update_state(&mut self) {
        let is_token_expired = self.time - self.start_time
            >= self.token.expire_timestamp as f64 - self.token.create_timestamp as f64;
        let is_connection_timed_out = self.token.timeout_seconds.is_positive()
            && (self.last_receive_time + (self.token.timeout_seconds as f64) < self.time);
        let new_state = match self.state {
            ClientState::SendingConnectionRequest | ClientState::SendingChallengeResponse
                if is_token_expired =>
            {
                log::info!("client connect failed. connect token expired");
                ClientState::ConnectTokenExpired
            }
            _ if self.should_disconnect => {
                log::debug!(
                    "client should disconnect -> {:?}",
                    self.should_disconnect_state
                );
                if self.connect_to_next_server().is_ok() {
                    return;
                };
                self.should_disconnect_state
            }
            ClientState::SendingConnectionRequest if is_connection_timed_out => {
                log::info!("client connect failed. connection request timed out");
                if self.connect_to_next_server().is_ok() {
                    return;
                };
                ClientState::ConnectionRequestTimedOut
            }
            ClientState::SendingChallengeResponse if is_connection_timed_out => {
                log::info!("client connect failed. connection response timed out");
                if self.connect_to_next_server().is_ok() {
                    return;
                };
                ClientState::ChallengeResponseTimedOut
            }
            ClientState::Connected if is_connection_timed_out => {
                log::info!("client connection timed out");
                ClientState::ConnectionTimedOut
            }
            _ => return,
        };
        self.reset(new_state);
    }
    fn recv_packet(&mut self, buf: &mut [u8], now: u64, addr: SocketAddr) -> Result<()> {
        if buf.len() <= 1 {
            // Too small to be a packet
            return Ok(());
        }
        let packet = match Packet::read(
            buf,
            self.token.protocol_id,
            now,
            self.token.server_to_client_key,
            Some(&mut self.replay_protection),
            Self::ALLOWED_PACKETS,
        ) {
            Ok(packet) => packet,
            Err(Error::Crypto(_)) => {
                log::debug!("client ignored packet because it failed to decrypt");
                return Ok(());
            }
            Err(e) => {
                log::error!("client ignored packet: {e}");
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
    /// Creates a new client instance with the given configuration and transceiver.
    ///
    /// This is useful if you want to use a custom transceiver implementation,
    /// in any other case you should use [`Client::new`](Client::new) or [`Client::with_config`](Client::with_config).
    ///
    /// # Examples
    ///
    /// ```
    /// use netcode::{Client, ClientConfig, ConnectToken, Transceiver};
    ///
    /// struct MyTransceiver {
    ///    // ...
    /// };
    ///
    /// impl Transceiver for MyTransceiver {
    ///    // ...
    ///    # type IntoError = std::io::Error;
    ///    # fn addr(&self) -> std::net::SocketAddr { unimplemented!() }
    ///    # fn send(&self, buf: &[u8], addr: std::net::SocketAddr) -> std::io::Result<usize> { unimplemented!() }
    ///    # fn recv(&self, buf: &mut [u8]) -> std::io::Result<Option<(usize, std::net::SocketAddr)>> { unimplemented!() }
    /// }
    ///
    /// # let private_key = netcode::generate_key();
    /// # let token_bytes = ConnectToken::build("127.0.0.1:0", 0, 0, private_key)
    /// #    .generate()
    /// #    .unwrap()
    /// #    .try_into_bytes()
    /// #    .unwrap();
    /// let cfg = ClientConfig::default();
    /// let trx = MyTransceiver { /* .. */ };
    ///
    /// let client = Client::with_config_and_transceiver(&token_bytes, cfg, trx).unwrap();
    /// ```
    pub fn with_config_and_transceiver(
        token_bytes: &[u8],
        cfg: ClientConfig<Ctx>,
        trx: T,
    ) -> Result<Self> {
        Client::from_token(token_bytes, cfg, trx)
    }
    /// Prepares the client to connect to the server.
    ///
    /// This function does not perform any IO, it only readies the client to send/receive packets on the next call to [`update`](Client::update). <br>
    pub fn connect(&mut self) {
        self.reset_connection();
        self.set_state(ClientState::SendingConnectionRequest);
        log::info!(
            "client connecting to server {} [{}/{}]",
            self.token.server_addresses[self.server_addr_idx],
            self.server_addr_idx + 1,
            self.token.server_addresses.len()
        );
    }
    /// Updates the client.
    ///
    /// * Updates the client's elapsed time.
    /// * Receives packets from the server, any received payload packets will be queued.
    /// * Sends keep-alive or request/response packets to the server to establish/maintain a connection.
    /// * Updates the client's state - checks for timeouts, errors and transitions to new states.
    ///
    /// This method should be called regularly, probably at a fixed rate (e.g., 60Hz).
    ///
    /// # Panics
    /// Panics if the client can't send or receive packets.
    /// For a non-panicking version, use [`try_update`](Client::try_update).
    pub fn update(&mut self, time: f64) {
        self.try_update(time)
            .expect("send/recv error while updating client")
    }
    /// The fallible version of [`update`](Client::update).
    ///
    /// Returns an error if the client can't send or receive packets.
    pub fn try_update(&mut self, time: f64) -> Result<()> {
        self.time = time;
        self.recv_packets()?;
        self.send_packets()?;
        self.update_state();
        Ok(())
    }
    /// Receives a packet from the server, if one is available in the queue.
    ///
    /// The packet will be returned as a `Vec<u8>`.
    ///
    /// If no packet is available, `None` will be returned.
    ///
    /// # Example
    /// ```
    /// # use netcode::{ConnectToken, Client, ClientConfig, ClientState};
    /// # use std::time::{Instant, Duration};
    /// # use std::thread;
    /// # let mut server = netcode::Server::new("127.0.0.1:0", 0, [0; 32]).unwrap();
    /// # let token_bytes = server.token(0).generate().unwrap().try_into_bytes().unwrap();
    /// let mut client = Client::new(&token_bytes).unwrap();
    /// client.connect();
    ///
    /// let start = Instant::now();
    /// let tick_rate = Duration::from_secs_f64(1.0 / 60.0);
    /// loop {
    ///     client.update(start.elapsed().as_secs_f64());
    ///     if let Some(packet) = client.recv() {
    ///         // ...
    ///     }
    ///     # break;
    ///     thread::sleep(tick_rate);
    /// }
    /// ```
    pub fn recv(&mut self) -> Option<Vec<u8>> {
        self.packet_queue.pop_front()
    }
    /// Sends a packet to the server.
    ///
    /// The provided buffer must be smaller than [`MAX_PACKET_SIZE`](crate::MAX_PACKET_SIZE).
    pub fn send(&mut self, buf: &[u8]) -> Result<()> {
        if self.state != ClientState::Connected {
            return Ok(());
        }
        if buf.len() > MAX_PACKET_SIZE {
            return Err(Error::SizeMismatch(MAX_PACKET_SIZE, buf.len()));
        }
        self.send_packet(PayloadPacket::create(buf))?;
        Ok(())
    }
    /// Disconnects the client from the server.
    ///
    /// The client will send a number of redundant disconnect packets to the server before transitioning to `Disconnected`.
    pub fn disconnect(&mut self) -> Result<()> {
        log::debug!(
            "client sending {} disconnect packets to server",
            self.cfg.num_disconnect_packets
        );
        for _ in 0..self.cfg.num_disconnect_packets {
            self.send_packet(DisconnectPacket::create())?;
        }
        self.reset(ClientState::Disconnected);
        Ok(())
    }
    /// Gets the local `SocketAddr` that the client is bound to.
    pub fn addr(&self) -> SocketAddr {
        self.transceiver.addr()
    }
    /// Gets the current state of the client.
    pub fn state(&self) -> ClientState {
        self.state
    }
    /// Returns true if the client is in an error state.
    pub fn is_error(&self) -> bool {
        self.state < ClientState::Disconnected
    }
    /// Returns true if the client is in a pending state.
    pub fn is_pending(&self) -> bool {
        self.state == ClientState::SendingConnectionRequest
            || self.state == ClientState::SendingChallengeResponse
    }
    /// Returns true if the client is connected to a server.
    pub fn is_connected(&self) -> bool {
        self.state == ClientState::Connected
    }
    /// Returns true if the client is disconnected from the server.
    pub fn is_disconnected(&self) -> bool {
        self.state == ClientState::Disconnected
    }
}

#[cfg(test)]
mod tests {
    use byteorder::{LittleEndian, WriteBytesExt};
    use chacha20poly1305::XNonce;

    use super::*;
    use crate::simulator::NetworkSimulator;
    use crate::token::ConnectTokenPrivate;
    use crate::{InvalidTokenError, NETCODE_VERSION};
    use std::io::Write;
    use std::mem::size_of;
    impl Client<NetworkSimulator> {
        pub(crate) fn with_simulator(token: ConnectToken, sim: NetworkSimulator) -> Result<Self> {
            Client::with_config_and_transceiver(
                &token.try_into_bytes()?,
                ClientConfig::default(),
                sim,
            )
        }
    }

    #[test]
    fn invalid_connect_token() {
        let mut token_bytes = [0u8; ConnectToken::SIZE];
        let mut cursor = std::io::Cursor::new(&mut token_bytes[..]);
        cursor.write_all(b"NETCODE VERSION 1.00\0").unwrap();
        let res = Client::new(&token_bytes);
        assert!(matches!(
            res,
            Err(Error::InvalidToken(InvalidTokenError::InvalidVersion))
        ));
        let mut token_bytes = [0u8; ConnectToken::SIZE];
        let mut cursor = std::io::Cursor::new(&mut token_bytes[..]);
        cursor.write_all(NETCODE_VERSION).unwrap();
        let res = Client::new(&token_bytes);
        assert!(matches!(
            res,
            Err(Error::InvalidToken(InvalidTokenError::AddressListLength(0)))
        ));
        let mut token_bytes = [0u8; ConnectToken::SIZE];
        let mut cursor = std::io::Cursor::new(&mut token_bytes[..]);
        cursor.write_all(NETCODE_VERSION).unwrap();
        cursor.write_u64::<LittleEndian>(0).unwrap(); // protocol id
        cursor.write_u64::<LittleEndian>(2).unwrap(); // create timestamp
        cursor.write_u64::<LittleEndian>(1).unwrap(); // expire timestamp, which is less than create timestamp -> invalid
        let res = Client::new(&token_bytes);
        assert!(matches!(
            res,
            Err(Error::InvalidToken(InvalidTokenError::InvalidTimestamp))
        ));
        let mut token_bytes = [0u8; ConnectToken::SIZE];
        let mut cursor = std::io::Cursor::new(&mut token_bytes[..]);
        cursor.write_all(NETCODE_VERSION).unwrap();
        cursor.write_u64::<LittleEndian>(0).unwrap(); // protocol id
        cursor.write_u64::<LittleEndian>(0).unwrap(); // create timestamp
        cursor.write_u64::<LittleEndian>(0).unwrap(); // expire timestamp
        cursor.write_all(&[0; size_of::<XNonce>()]).unwrap(); // nonce
        cursor.write_all(&[0; ConnectTokenPrivate::SIZE]).unwrap(); // private data
        cursor.write_i32::<LittleEndian>(0).unwrap(); // timeout
        cursor.write_u32::<LittleEndian>(1).unwrap(); // num server addresses
        cursor.write_u8(3).unwrap(); // INVALID server address type!
        let res = Client::new(&token_bytes);
        assert!(matches!(
            res,
            Err(Error::InvalidToken(
                InvalidTokenError::InvalidIpAddressType(3)
            ))
        ));
    }
}
