use std::{
    cell::RefCell,
    collections::VecDeque,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use crate::{
    consts::MAX_CLIENTS, crypto, error::NetcodeError, server::Server, time::time_now_secs_f64,
    transceiver::Transceiver,
};

const MAX_RECEIVE_PACKETS: usize = 64;
const NUM_PACKET_ENTRIES: usize = 256 * MAX_CLIENTS;
const NUM_PENDING_RECEIVE_PACKETS: usize = MAX_RECEIVE_PACKETS * MAX_CLIENTS;

#[derive(Debug, Clone)]
pub struct PacketEntry {
    pub from: SocketAddr,
    pub to: SocketAddr,
    pub delivery_time: f64,
    pub packet: Vec<u8>,
}

pub struct NetworkSimulator {
    pub latency_ms: f64,
    pub jitter_ms: f64,
    pub packet_loss_percent: f64,
    pub duplicate_packet_percent: f64,
    pub time: f64,
    pub current_sender: Option<SocketAddr>,
    pub current_receiver: Option<SocketAddr>,
    pub packet_entries: RefCell<VecDeque<PacketEntry>>,
    pub pending_receive_packets: RefCell<VecDeque<PacketEntry>>,
    pub packet_buffers: RefCell<[Vec<u8>; MAX_RECEIVE_PACKETS]>,
}

impl NetworkSimulator {
    pub fn new(
        latency_ms: f64,
        jitter_ms: f64,
        packet_loss_percent: f64,
        duplicate_packet_percent: f64,
    ) -> Self {
        const EMPTY_VEC: Vec<u8> = Vec::new();
        Self {
            latency_ms,
            jitter_ms,
            packet_loss_percent,
            duplicate_packet_percent,
            time: 0.0,
            current_sender: None,
            current_receiver: None,
            packet_entries: RefCell::new(VecDeque::with_capacity(NUM_PACKET_ENTRIES)),
            pending_receive_packets: RefCell::new(VecDeque::with_capacity(
                NUM_PENDING_RECEIVE_PACKETS,
            )),
            packet_buffers: RefCell::new([EMPTY_VEC; MAX_RECEIVE_PACKETS]),
        }
    }

    pub fn update(&mut self, time: f64, (sender, receiver): (SocketAddr, SocketAddr)) {
        self.time = time;
        self.current_sender = Some(sender);
        self.current_receiver = Some(receiver);
        self.pending_receive_packets.borrow_mut().clear();
        let mut packet_entries = self.packet_entries.borrow_mut();
        while let Some(entry) = packet_entries.pop_front() {
            if entry.delivery_time <= time {
                self.pending_receive_packets.borrow_mut().push_back(entry);
            }
        }
    }
}

fn rand_float(range: std::ops::Range<f64>) -> f64 {
    use chacha20poly1305::aead::{rand_core::RngCore, OsRng};
    let rand = OsRng.next_u32() as f64 / u32::MAX as f64;
    range.start + rand * (range.end - range.start)
}

impl Transceiver for NetworkSimulator {
    type Error = std::io::Error;

    fn addr(&self) -> SocketAddr {
        // Network simulator is always on localhost
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40000)
    }

    fn recv(&self, _buf: &mut [u8]) -> Result<(usize, Option<SocketAddr>), Self::Error> {
        let Some(to) = self.current_receiver else {
            return Ok((0, None));
        };
        let mut num_packets = 0;
        while let Some(entry) = self.pending_receive_packets.borrow_mut().pop_front() {
            if num_packets >= MAX_RECEIVE_PACKETS {
                break;
            }
            if entry.to != to {
                continue;
            }
            self.packet_buffers.borrow_mut()[num_packets] = entry.packet;
            num_packets += 1;
        }
        Ok((num_packets, None))
    }
    fn send(&self, buf: &[u8], addr: SocketAddr) -> Result<usize, Self::Error> {
        let Some(from) = self.current_sender else {
            return Ok(buf.len());
        };
        if rand_float(0.0..100.) < self.packet_loss_percent {
            return Ok(buf.len());
        }
        let mut delay = self.latency_ms / 1000.0;
        if self.jitter_ms > 0.0 {
            delay += rand_float(-self.jitter_ms..self.jitter_ms) / 1000.0;
        }
        let mut entry = PacketEntry {
            from,
            to: addr,
            delivery_time: self.time + delay,
            packet: buf.to_vec(),
        };
        self.packet_entries.borrow_mut().push_back(entry.clone());
        if rand_float(0.0..100.) < self.duplicate_packet_percent {
            entry.delivery_time += rand_float(0.0..1.);
            self.packet_entries.borrow_mut().push_back(entry);
        }
        Ok(buf.len())
    }
}

mod tests {
    use std::rc::Rc;

    use env_logger::Builder;
    use log::LevelFilter;

    use crate::{
        client::{Client, ClientState},
        token::ConnectToken,
    };

    use super::*;

    #[test]
    fn client_connect_server() {
        Builder::new().filter(None, LevelFilter::Trace).init();
        let simulator = NetworkSimulator::new(250.0, 250.0, 5.0, 10.0);
        let simulator = Rc::new(RefCell::new(simulator));

        let mut time = time_now_secs_f64();
        let delta = 1. / 10.;

        let addr = simulator.addr();
        let token = ConnectToken::build(addr, 0, 0, 0)
            .timeout_seconds(-1)
            .expire_seconds(-1)
            .generate()
            .unwrap();

        let mut server = Server::with_simulator(simulator.clone()).unwrap();
        let mut client = Client::with_simulator(token, simulator.clone()).unwrap();

        client.connect().unwrap();

        loop {
            simulator.borrow_mut().update(time, (addr, addr));
            client.update(time).unwrap();
            simulator.borrow_mut().update(time, (addr, addr));
            server.recv(&mut [0; 1175]).unwrap();
            server.update(time).unwrap();
            client.recv(&mut [0; 1175]).unwrap();

            if client.state() == ClientState::Connected {
                break;
            }

            time += delta;
        }
    }
}
