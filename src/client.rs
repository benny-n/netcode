use std::{
    net::SocketAddr,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    bytes::Bytes,
    consts::{MAX_PAYLOAD_SIZE, MAX_PKT_BUF_SIZE, PACKET_SEND_RATE},
    error::NetcodeError,
    packet::{
        DisconnectPacket, KeepAlivePacket, Packet, PayloadPacket, RequestPacket, ResponsePacket,
    },
    replay::ReplayProtection,
    socket::NetcodeSocket,
    token::{ChallengeToken, ConnectToken},
    transceiver::Transceiver,
};

type Result<T> = std::result::Result<T, NetcodeError>;

type Callback<Ctx> =
    Box<dyn FnMut(ClientState, ClientState, Option<&mut Ctx>) + Send + Sync + 'static>;
/// Configuration for a client
///
/// * `num_disconnect_packets` - The number of redundant disconnect packets that will be sent to a server when the clients wants to disconnect.
/// * `packet_send_rate` - The rate at which periodic packets will be sent to the server.
/// * `on_state_change` - A callback that will be called when the client changes states.
///
/// # Example
/// ```
/// # struct MyContext;
/// # let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 40000));
/// # let private_key = [42u8; 32];
/// # let token = netcode::server::Server::new(addr, 0x11223344, Some(private_key)).unwrap().token(123u64).generate().unwrap();
/// # let token_bytes = token.try_into_bytes().unwrap();
/// use netcode::client::{Client, ClientConfig, ClientState};
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
/// client.connect().unwrap();
/// ```
pub struct ClientConfig<Ctx> {
    ctx: Option<Box<Ctx>>,
    on_state_change: Option<Callback<Ctx>>,
    packet_send_rate: f64,
    num_disconnect_packets: usize,
}

impl<Ctx> Default for ClientConfig<Ctx> {
    fn default() -> Self {
        Self {
            num_disconnect_packets: 10,
            packet_send_rate: PACKET_SEND_RATE,
            ctx: None,
            on_state_change: None,
        }
    }
}

impl<Ctx> ClientConfig<Ctx> {
    /// Create a new, default client configuration.
    pub fn new() -> ClientConfig<()> {
        ClientConfig::<()>::default()
    }
    /// Create a new client configuration with a context.
    pub fn with_context(ctx: Ctx) -> Self {
        Self {
            ctx: Some(Box::new(ctx)),
            ..Self::default()
        }
    }
    /// Set the number of redundant disconnect packets that will be sent to a server when the clients wants to disconnect.
    pub fn num_disconnect_packets(mut self, num_disconnect_packets: usize) -> Self {
        self.num_disconnect_packets = num_disconnect_packets;
        self
    }
    /// Set the rate at which periodic packets will be sent to the server.
    pub fn packet_send_rate(mut self, packet_send_rate: f64) -> Self {
        self.packet_send_rate = packet_send_rate;
        self
    }
    /// Set a callback that will be called when the client changes states.
    pub fn on_state_change<F>(mut self, cb: F) -> Self
    where
        F: FnMut(ClientState, ClientState, Option<&mut Ctx>) + Send + Sync + 'static,
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
/// Any connection payload packets received prior to `Connected` are discarded.
///
/// `Connected` is the final stage in the connection process and represents a successful connection to the server.
///
/// While in this state:
///
///  - The client application may send connection payload packets to the server.
///  - In the absence of connection payload packets sent by the client application, the client generates and sends connection keep-alive packets
///    to the server at some rate (default is 10HZ, can be overridden in [`ClientConfig`](ClientConfig)).
///  - If no payload or keep-alive packets are received from the server within the timeout period specified in the connect token,
///    the client transitions to `ConnectionTimedOut`.
///  - While `Connected`, if the client receives a disconnect packet from the server, it transitions to `Disconnected`.
///    If the client wishes to disconnect from the server,
///    it sends a number of redundant connection disconnect packets (default is 10, can be overridden in [`ClientConfig`](ClientConfig))
///    before transitioning to `Disconnected`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ClientState {
    ConnectTokenExpired,
    ConnectionTimedOut,
    ConnectionRequestTimedOut,
    ChallengeResponseTimedOut,
    ConnectionDenied,
    Disconnected,
    SendingConnectionRequest,
    SendingChallengeResponse,
    Connected,
}

// TODO: document
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
    cfg: ClientConfig<Ctx>,
}

impl<Ctx> Client<NetcodeSocket, Ctx> {
    fn from_token(token_bytes: &[u8]) -> Result<Self> {
        if token_bytes.len() != ConnectToken::SIZE {
            return Err(NetcodeError::BufferSizeMismatch(
                ConnectToken::SIZE,
                token_bytes.len(),
            ));
        }
        let mut buf = [0u8; ConnectToken::SIZE];
        buf.copy_from_slice(token_bytes);
        let mut cursor = std::io::Cursor::new(&mut buf[..]);
        let token = match ConnectToken::read_from(&mut cursor) {
            Ok(token) => token,
            Err(err) => {
                return Err(NetcodeError::InvalidConnectToken(err));
            }
        };
        Ok(Self {
            transceiver: NetcodeSocket::default(),
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
            cfg: ClientConfig::default(),
        })
    }
}

impl Client<NetcodeSocket> {
    /// Create a new client with a default configuration.
    ///
    /// # Example
    /// ```
    /// # use netcode::client::{Client, ClientConfig, ClientState};
    /// # use netcode::token::ConnectToken;
    /// // Generate a connection token for the client
    /// let token_bytes = ConnectToken::build("127.0.0.1:0", 0, 0, 0).generate().unwrap().try_into_bytes().unwrap();
    ///
    /// // Start the client
    /// let mut client = Client::new(&token_bytes).unwrap();
    /// assert_eq!(client.state(), ClientState::Disconnected);
    ///
    /// // Connect to the server
    /// client.connect().unwrap();
    /// assert_eq!(client.state(), ClientState::SendingConnectionRequest);
    /// ```
    pub fn new(token_bytes: &[u8]) -> Result<Client<NetcodeSocket>> {
        let client = Client::from_token(token_bytes)?;
        log::info!("client started on {}", client.transceiver.addr());
        Ok(client)
    }
}

impl<Ctx> Client<NetcodeSocket, Ctx> {
    /// Create a new client with a custom configuration. <br>
    /// Callbacks with context can be registered with the client to be notified when the client changes states. <br>
    /// See [`ClientConfig`](ClientConfig) for more details.
    ///
    /// # Example
    /// ```
    /// # use netcode::client::{Client, ClientConfig, ClientState};
    /// # use netcode::token::ConnectToken;
    /// # struct MyContext;
    /// // Generate a connection token for the client
    /// let token_bytes = ConnectToken::build("127.0.0.1:0", 0, 0, 0).generate().unwrap().try_into_bytes().unwrap();
    ///
    /// // Create a client configuration with a context
    /// let cfg = ClientConfig::with_context(MyContext {}).on_state_change(|from, to, _ctx| {
    ///    assert_eq!(from, ClientState::Disconnected);
    ///    assert_eq!(to, ClientState::SendingConnectionRequest);
    /// });
    ///
    /// // Start the client
    /// let mut client = Client::with_config(&token_bytes, cfg).unwrap();
    /// assert_eq!(client.state(), ClientState::Disconnected);
    ///
    /// // Connect to the server
    /// client.connect().unwrap();
    /// assert_eq!(client.state(), ClientState::SendingConnectionRequest);
    /// ```
    pub fn with_config(
        token_bytes: &[u8],
        cfg: ClientConfig<Ctx>,
    ) -> Result<Client<NetcodeSocket, Ctx>> {
        let mut client = Client::from_token(token_bytes)?;
        client.cfg = cfg;
        log::info!("client started on {}", client.transceiver.addr());
        Ok(client)
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
            cb(
                self.state,
                state,
                self.cfg.ctx.as_mut().map(|ctx| ctx.as_mut()),
            )
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
        assert_ne!(self.state, new_state); // TODO: remove later
        self.sequence = 0;
        self.client_index = 0;
        self.max_clients = 0;
        self.start_time = 0.0;
        self.server_addr_idx = 0;
        self.set_state(new_state);
        self.reset_connection();
        log::debug!("client disconnected");
    }
    fn send_periodic_packets(&mut self) -> Result<()> {
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
                log::trace!("client sending connection keep alive packet to server");
                KeepAlivePacket::create(0, 0)
            }
            _ => return Ok(()),
        };
        self.send_packet(packet)?;
        Ok(())
    }
    fn connect_to_next_server(&mut self) -> Result<()> {
        if self.server_addr_idx + 1 >= self.token.server_addresses.len() {
            return Err(NetcodeError::NoMoreServers);
        }
        self.server_addr_idx += 1;
        self.connect()?;
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
                Packet::Disconnect(_),
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
                log::trace!("client received connection keep alive packet from server");
            }
            (Packet::KeepAlive(pkt), ClientState::SendingChallengeResponse) => {
                log::debug!("client received connection keep alive packet from server");
                self.client_index = pkt.client_index;
                self.max_clients = pkt.max_clients;
                self.set_state(ClientState::Connected);
                log::info!("client connected to server");
            }
            (Packet::Payload(_), ClientState::Connected) => {
                log::debug!("client received connection payload packet from server");
                // netcode_packet_queue_push( &client->packet_receive_queue, packet, sequence );
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
    // TODO: document
    pub fn disconnect(mut self) -> Result<()> {
        log::debug!(
            "client sending {} disconnect packets to server",
            self.cfg.num_disconnect_packets
        );
        for _ in 0..self.cfg.num_disconnect_packets {
            self.send_packet(DisconnectPacket::create())?;
        }
        Ok(())
    }
    // TODO: document
    pub fn connect(&mut self) -> Result<()> {
        self.reset_connection();
        self.set_state(ClientState::SendingConnectionRequest);
        log::info!(
            "client connecting to server {} [{}/{}]",
            self.token.server_addresses[self.server_addr_idx],
            self.server_addr_idx + 1,
            self.token.server_addresses.len()
        );
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
        matches!(
            self.state,
            ClientState::SendingConnectionRequest | ClientState::SendingChallengeResponse
        )
    }
    /// Returns true if the client is connected to a server.
    pub fn is_connected(&self) -> bool {
        matches!(self.state, ClientState::Connected)
    }
    // TODO: document
    pub fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let Some((size, addr)) = self.transceiver.recv(buf).map_err(|e| e.into())? else {
            // No packet received
            return Ok(0);
        };
        if size <= 1 {
            // Too small to be a packet
            return Ok(0);
        }
        let packet = match Packet::read(
            &mut buf[..size],
            self.token.protocol_id,
            now,
            self.token.server_to_client_key,
            Some(&mut self.replay_protection),
            Self::ALLOWED_PACKETS,
        ) {
            Ok(packet) => packet,
            Err(NetcodeError::Crypto(_)) => {
                log::debug!("client ignored packet because it failed to decrypt");
                return Ok(0);
            }
            Err(e) => {
                log::error!("client ignored packet: {e}");
                return Ok(0);
            }
        };
        let size = if let Packet::Payload(ref packet) = packet {
            packet.buf.len()
        } else {
            0
        };
        self.process_packet(addr, packet)?;
        Ok(size)
    }
    // TODO: document
    pub fn send(&mut self, buf: &[u8]) -> Result<()> {
        if self.state != ClientState::Connected {
            return Ok(());
        }
        if buf.len() > MAX_PAYLOAD_SIZE {
            return Err(NetcodeError::PacketSizeExceeded(buf.len()));
        }
        self.send_packet(PayloadPacket::create(buf))?;
        Ok(())
    }
    // TODO: document
    pub fn update(&mut self, time: f64) -> Result<()> {
        self.time = time;
        self.send_periodic_packets()?;
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
                    return Ok(());
                };
                self.should_disconnect_state
            }
            ClientState::SendingConnectionRequest if is_connection_timed_out => {
                log::info!("client connect failed. connection request timed out");
                if self.connect_to_next_server().is_ok() {
                    return Ok(());
                };
                ClientState::ConnectionRequestTimedOut
            }
            ClientState::SendingChallengeResponse if is_connection_timed_out => {
                log::info!("client connect failed. connection response timed out");
                if self.connect_to_next_server().is_ok() {
                    return Ok(());
                };
                ClientState::ChallengeResponseTimedOut
            }
            ClientState::Connected if is_connection_timed_out => {
                log::info!("client connection timed out");
                ClientState::ConnectionTimedOut
            }
            _ => return Ok(()),
        };
        self.reset(new_state);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::NETCODE_VERSION;
    use crate::simulator::NetworkSimulator;
    use std::io::Write;
    impl Client<NetworkSimulator> {
        pub fn with_simulator(token: ConnectToken, sim: NetworkSimulator) -> Result<Self> {
            Ok(Self {
                transceiver: sim,
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
                cfg: ClientConfig::default(),
            })
        }
    }

    #[test]
    fn invalid_connect_token() {
        let mut token_bytes = [0u8; ConnectToken::SIZE];
        let mut cursor = std::io::Cursor::new(&mut token_bytes[..]);
        cursor.write_all(b"NETCODE VERSION 1.00\0").unwrap();
        let Err(err) = Client::new(&token_bytes) else {
            panic!("expected error");
        };
        assert_eq!(
            "invalid connect token: invalid version info",
            err.to_string()
        );
        let mut token_bytes = [0u8; ConnectToken::SIZE];
        let mut cursor = std::io::Cursor::new(&mut token_bytes[..]);
        cursor.write_all(NETCODE_VERSION).unwrap();
        let Err(err) = Client::new(&token_bytes) else {
            panic!("expected error");
        };
        assert_eq!(
            "invalid connect token: invalid address list length 0",
            err.to_string()
        );
    }
}
