use std::net::SocketAddr;

use crate::{
    consts::MAX_PKT_BUF_SIZE,
    crypto::Key,
    error::NetcodeError,
    packet::Packet,
    replay::ReplayProtection,
    socket::NetcodeSocket,
    token::{ChallengeToken, ConnectToken},
    transceiver::Transceiver,
    utils::time_now_secs,
};

type Result<T> = std::result::Result<T, NetcodeError>;

type Callback<Ctx> = Box<dyn FnMut(ClientState, Option<&mut Ctx>) + Send + Sync + 'static>;
pub struct ClientConfig<Ctx> {
    ctx: Option<Box<Ctx>>,
    on_state_change: Option<Callback<Ctx>>,
}

#[derive(Debug, Clone, Copy)]
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

pub struct Client<T: Transceiver, Ctx = ()> {
    transceiver: T,
    state: ClientState,
    time: f64,
    start_time: f64,
    last_send_time: f64,
    last_receive_time: f64,
    bind_addr: SocketAddr,
    server_addr: SocketAddr,
    sequence: u64,
    challenge_token_sequence: u64,
    challenge_token_data: [u8; ChallengeToken::SIZE],
    client_index: i32,
    max_clients: i32,
    send_key: Key,
    receive_key: Key,
    token: ConnectToken,
    replay_protection: ReplayProtection,
    should_disconnect: bool,
    should_disconnect_state: ClientState,
    cfg: ClientConfig<Ctx>,
}

impl<T: Transceiver, Ctx> Client<T, Ctx> {
    fn set_state(&mut self, state: ClientState) {
        log::debug!("client state changed from {:?} to {:?}", self.state, state);
        self.state = state;
        if let Some(ref mut cb) = self.cfg.on_state_change {
            cb(self.state, self.cfg.ctx.as_mut().map(|ctx| ctx.as_mut()))
        }
    }
    fn send_packet(&mut self, packet: Packet) -> Result<()> {
        let mut buf = [0u8; MAX_PKT_BUF_SIZE];
        let size = packet.write(
            &mut buf,
            self.sequence,
            &self.send_key,
            self.token.protocol_id,
        )?;
        self.transceiver
            .send(&buf[..size], self.server_addr)
            .map_err(|e| e.into())?;
        self.last_send_time = self.time;
        self.sequence += 1;
        Ok(())
    }
    fn process_packet(&mut self, addr: SocketAddr, packet: Packet) -> Result<()> {
        if addr != self.server_addr {
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
                log::debug!("client received connection keep alive packet from server");
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
            self.receive_key,
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
}
