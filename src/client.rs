use std::net::{SocketAddr, ToSocketAddrs};

use crate::{
    bytes::Bytes,
    consts::{MAX_PAYLOAD_SIZE, MAX_PKT_BUF_SIZE},
    error::NetcodeError,
    packet::{
        DisconnectPacket, KeepAlivePacket, Packet, PayloadPacket, RequestPacket, ResponsePacket,
    },
    replay::ReplayProtection,
    socket::NetcodeSocket,
    token::{ChallengeToken, ConnectToken},
    transceiver::Transceiver,
    utils::{time_now_secs, time_now_secs_f64},
};

type Result<T> = std::result::Result<T, NetcodeError>;

type Callback<Ctx> = Box<dyn FnMut(ClientState, Option<&mut Ctx>) + Send + Sync + 'static>;
pub struct ClientConfig<Ctx> {
    ctx: Option<Box<Ctx>>,
    on_state_change: Option<Callback<Ctx>>,
    packet_send_rate: f64,
    num_disconnect_packets: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ClientState {
    ConnectTokenExpired,
    InvalidConnectToken,
    ConnectionTimedOut,
    ConnectionRequestTimedOut,
    ConnectionResponseTimedOut,
    ConnectionDenied,
    Disconnected,
    SendingConnectionRequest,
    SendingConnectionResponse,
    Connected,
}

pub struct Client<T: Transceiver, Token = (), Ctx = ()> {
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
    token: Token,
    replay_protection: ReplayProtection,
    should_disconnect: bool,
    should_disconnect_state: ClientState,
    cfg: ClientConfig<Ctx>,
}

impl Client<NetcodeSocket> {
    /// Create a new, stateless client with a default configuration.
    ///
    /// For a stateful client, use [`Client::with_context`](Client::with_context) and provide context in the [`ClientConfig`](ClientConfig).
    ///
    /// # Example
    /// ```
    /// // todo!()
    /// ```
    pub fn new(bind_addr: impl ToSocketAddrs) -> Result<Client<NetcodeSocket, (), ()>> {
        let time = time_now_secs_f64()?;
        let client: Client<_, _, ()> = Client {
            transceiver: NetcodeSocket::new(bind_addr)?,
            state: ClientState::Disconnected,
            time,
            start_time: 0.0,
            last_send_time: f64::NEG_INFINITY,
            last_receive_time: f64::NEG_INFINITY,
            server_addr_idx: 0,
            sequence: 0,
            challenge_token_sequence: 0,
            challenge_token_data: [0u8; ChallengeToken::SIZE],
            client_index: 0,
            max_clients: 0,
            token: (),
            replay_protection: ReplayProtection::new(),
            should_disconnect: false,
            should_disconnect_state: ClientState::Disconnected,
            cfg: ClientConfig {
                ctx: None,
                on_state_change: None,
                packet_send_rate: 20.0,
                num_disconnect_packets: 3,
            },
        };
        log::info!("client started on {}", client.transceiver.addr());
        Ok(client)
    }
}

impl<Ctx> Client<NetcodeSocket, (), Ctx> {
    pub fn connect(self, token_bytes: &[u8]) -> Result<Client<NetcodeSocket, ConnectToken, Ctx>> {
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
        let client = Client {
            transceiver: self.transceiver,
            state: ClientState::SendingConnectionRequest,
            time: self.time,
            start_time: self.time,
            last_send_time: self.time - 1.0, // force a packet to be sent immediately
            last_receive_time: self.time,
            server_addr_idx: 0,
            sequence: self.sequence,
            challenge_token_sequence: 0,
            challenge_token_data: self.challenge_token_data,
            client_index: self.client_index,
            max_clients: self.max_clients,
            token,
            replay_protection: ReplayProtection::new(),
            should_disconnect: false,
            should_disconnect_state: ClientState::Disconnected,
            cfg: self.cfg,
        };
        log::info!(
            "client connecting to server to server {} [{}/{}]",
            client.token.server_addresses[client.server_addr_idx],
            client.server_addr_idx + 1,
            client.token.server_addresses.len()
        );
        Ok(client)
    }
}

impl<T: Transceiver, Ctx> Client<T, ConnectToken, Ctx> {
    fn set_state(&mut self, state: ClientState) {
        log::debug!("client state changed from {:?} to {:?}", self.state, state);
        self.state = state;
        if let Some(ref mut cb) = self.cfg.on_state_change {
            cb(self.state, self.cfg.ctx.as_mut().map(|ctx| ctx.as_mut()))
        }
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

        // memset( &client->connect_token, 0, sizeof( struct netcode_connect_token_t ) );
        // memset( &client->context, 0, sizeof( struct netcode_context_t ) );
        // TODO: figure out if this needs to be done

        self.set_state(new_state);
        self.reset_connection();
        log::debug!("client disconnected");
    }
    // fn is_disconnected(&self) -> bool {
    //     self.state <= ClientState::Disconnected
    // }
    pub fn disconnect(mut self) -> Result<Client<T, (), Ctx>> {
        log::debug!(
            "client sending {} disconnect packets to server",
            self.cfg.num_disconnect_packets
        );
        for _ in 0..self.cfg.num_disconnect_packets {
            self.send_packet(DisconnectPacket::create())?;
        }
        let client = Client {
            // destructing '..' syntax will not work here because `self` type differs from `client` type
            transceiver: self.transceiver,
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
            token: (),
            replay_protection: ReplayProtection::new(),
            should_disconnect: false,
            should_disconnect_state: ClientState::Disconnected,
            cfg: self.cfg,
        };
        Ok(client)
    }
    fn send_periodic_packets(&mut self) -> Result<()> {
        if self.last_send_time + (1.0 / self.cfg.packet_send_rate) >= self.time {
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
            ClientState::SendingConnectionResponse => {
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
        self.reset_connection();
        log::info!(
            "client connecting to next server {} [{}/{}]",
            self.token.server_addresses[self.server_addr_idx],
            self.server_addr_idx + 1,
            self.token.server_addresses.len()
        );
        self.set_state(ClientState::SendingConnectionRequest);
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
                ClientState::SendingConnectionRequest | ClientState::SendingConnectionResponse,
            ) => {
                self.should_disconnect = true;
                self.should_disconnect_state = ClientState::ConnectionDenied;
            }
            (Packet::Challenge(pkt), ClientState::SendingConnectionRequest) => {
                log::debug!("client received connection challenge packet from server");
                self.challenge_token_sequence = pkt.sequence;
                self.challenge_token_data = pkt.token;
                self.set_state(ClientState::SendingConnectionResponse);
            }
            (Packet::KeepAlive(_), ClientState::Connected) => {
                log::trace!("client received connection keep alive packet from server");
            }
            (Packet::KeepAlive(pkt), ClientState::SendingConnectionResponse) => {
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
    pub fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        let now = time_now_secs()?;
        let (size, addr) = self.transceiver.recv(buf).map_err(|e| e.into())?;
        let Some(addr) = addr else {
            // No packet received
            return Ok(0);
        };
        if size <= 1 {
            // Too small to be a packet
            return Ok(0);
        }
        let packet = Packet::read(
            &mut buf[..size],
            self.token.protocol_id,
            now,
            self.token.server_to_client_key,
            Some(&mut self.replay_protection),
        )?;
        let size = if let Packet::Payload(ref packet) = packet {
            packet.buf.len()
        } else {
            0
        };
        self.process_packet(addr, packet)?;
        Ok(size)
    }
    pub fn state(&self) -> ClientState {
        self.state
    }
    pub fn is_connected(&self) -> bool {
        self.state == ClientState::Connected
    }
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
    pub fn update(&mut self, time: f64) -> Result<()> {
        self.time = time;
        self.send_periodic_packets()?;
        let is_token_expired = self.time - self.start_time
            >= self.token.expire_timestamp as f64 - self.token.create_timestamp as f64;
        let is_connection_timed_out = self.token.timeout_seconds.is_positive()
            && (self.last_receive_time + (self.token.timeout_seconds as f64) < self.time);
        let new_state = match self.state {
            ClientState::Disconnected | ClientState::Connected if is_token_expired => {
                log::info!("client connect failed. connect token expired");
                ClientState::ConnectTokenExpired
            }
            _ if self.should_disconnect => {
                log::debug!(
                    "client should disconnect -> {:?}",
                    self.should_disconnect_state
                );
                self.connect_to_next_server()?;
                self.should_disconnect_state
            }
            ClientState::SendingConnectionRequest if is_connection_timed_out => {
                log::info!("client connect failed. connection request timed out");
                self.connect_to_next_server()?;
                ClientState::ConnectionRequestTimedOut
            }
            ClientState::SendingConnectionResponse if is_connection_timed_out => {
                log::info!("client connect failed. connection response timed out");
                self.connect_to_next_server()?;
                ClientState::ConnectionResponseTimedOut
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

#[test]
fn client_type_state() {
    let disconnected_client = Client::new("127.0.0.1:40000").unwrap();
    let token = ConnectToken::build("127.0.0.1:40000", 0, 0, 0)
        .generate()
        .unwrap();
    let mut token_bytes = [0u8; ConnectToken::SIZE];
    let mut cursor = std::io::Cursor::new(&mut token_bytes[..]);
    token.write_to(&mut cursor).unwrap();
    let client = disconnected_client.connect(&token_bytes).unwrap();
    assert_eq!(client.state, ClientState::SendingConnectionRequest);
    let disconnected_client = client.disconnect().unwrap();
    assert_eq!(disconnected_client.state, ClientState::Disconnected);
}
