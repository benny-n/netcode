use std::{
    cell::RefCell,
    collections::HashMap,
    io::{self, ErrorKind},
    net::{Ipv4Addr, SocketAddr},
    rc::Rc,
    sync::mpsc::{self, Receiver, Sender},
};

use crate::{server::Server, transceiver::Transceiver};

#[derive(Debug, Clone)]
pub struct PacketEntry {
    pub from: SocketAddr,
    pub to: SocketAddr,
    pub delivery_time: f64,
    pub packet: Vec<u8>,
}

pub struct Channel {
    pub tx: Sender<PacketEntry>,
    pub rx: Receiver<PacketEntry>,
}

#[derive(Clone, Copy)]
pub struct SimulationConfig {
    pub latency_ms: f64,
    pub jitter_ms: f64,
    pub packet_loss_percent: f64,
    pub duplicate_packet_percent: f64,
}

impl Default for SimulationConfig {
    fn default() -> Self {
        Self {
            latency_ms: 250.0,
            jitter_ms: 250.0,
            packet_loss_percent: 5.0,
            duplicate_packet_percent: 10.0,
        }
    }
}

pub struct NetworkSimulator {
    pub port: u16,
    pub time: f64,
    pub cfg: SimulationConfig,
    pub routing_table: Rc<RefCell<HashMap<u16, Channel>>>,
}

impl NetworkSimulator {
    pub fn new(port: u16, table: Rc<RefCell<HashMap<u16, Channel>>>) -> Self {
        let (tx, rx) = mpsc::channel::<PacketEntry>();
        table.borrow_mut().insert(port, Channel { tx, rx });
        Self {
            port,
            time: 0.0,
            cfg: SimulationConfig::default(),
            routing_table: table,
        }
    }
}

fn rand_float(range: std::ops::Range<f64>) -> f64 {
    use chacha20poly1305::aead::{rand_core::RngCore, OsRng};
    let rand = OsRng.next_u32() as f64 / u32::MAX as f64;
    range.start + rand * (range.end - range.start)
}

impl Transceiver for NetworkSimulator {
    type Error = io::Error;

    fn addr(&self) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, self.port))
    }

    fn recv(&self, buf: &mut [u8]) -> Result<Option<(usize, SocketAddr)>, Self::Error> {
        // routing table -> given an addr of self, look through the table for the receiving endpoint
        // if no entry is found, return early
        let table = self.routing_table.borrow();
        let Some(rx) = table.get(&self.port).map(|c| &c.rx) else {
            return Ok(None);
        };
        if let Ok(entry) = rx.try_recv() {
            if entry.to != self.addr() {
                return Err(io::Error::new(
                    ErrorKind::Other,
                    "received packet for wrong address",
                ));
            }
            let len = entry.packet.len();
            buf[..len].copy_from_slice(&entry.packet[..len]);
            return Ok(Some((len, entry.from)));
        }
        Ok(None)
    }
    fn send(&self, buf: &[u8], addr: SocketAddr) -> Result<usize, Self::Error> {
        // routing table -> given an addr, look through the table for the sending endpoint
        // if no entry is found, return early
        let table = self.routing_table.borrow();
        let Some(tx) = table.get(&addr.port()).map(|c| &c.tx) else {
            return Ok(0);
        };
        if rand_float(0.0..100.) < self.cfg.packet_loss_percent {
            log::error!("packet lost {}", buf[0] & 0xF);
            return Ok(0);
        }
        let mut delay = self.cfg.latency_ms / 1000.0;
        if self.cfg.jitter_ms > 0.0 {
            delay += rand_float(-self.cfg.jitter_ms..self.cfg.jitter_ms) / 1000.0;
        }
        let mut entry = PacketEntry {
            from: self.addr(),
            to: addr,
            delivery_time: self.time + delay,
            packet: buf.to_vec(),
        };
        tx.send(entry.clone()).ok();
        if rand_float(0.0..100.) < self.cfg.duplicate_packet_percent {
            log::error!("duplicating packet");
            entry.delivery_time += rand_float(0.0..1.);
            tx.send(entry).ok();
        }
        Ok(buf.len())
    }
}

mod tests {
    use crate::{
        client::{Client, ClientState},
        token::ConnectToken,
        CONNECTION_TIMEOUT_SEC,
    };

    use super::*;

    fn enable_logging() {
        // Uncomment this to enable logging

        // static LOGGER_CELL: std::sync::OnceLock<()> = std::sync::OnceLock::new();
        // LOGGER_CELL.get_or_init(|| {
        //     env_logger::Builder::new()
        //         .filter(None, log::LevelFilter::Trace)
        //         .init();
        // });
    }

    #[test]
    fn client_server_connect_send_recv() {
        enable_logging();

        let routing_table = Rc::new(RefCell::new(HashMap::new()));
        let client_sim = NetworkSimulator::new(40000, routing_table.clone());
        let server_sim = NetworkSimulator::new(50000, routing_table.clone());

        let mut time = 0.0;
        let delta = 1. / 10.;

        let mut server = Server::with_simulator(server_sim, None).unwrap();

        let token = server
            .token(123u64)
            .expire_seconds(-1)
            .timeout_seconds(-1)
            .generate()
            .unwrap();

        let mut client = Client::with_simulator(token, client_sim).unwrap();

        client.connect();

        loop {
            client.update(time).unwrap();
            client.recv(&mut [0; 1175]).unwrap();
            server.update(time).unwrap();
            server.recv(&mut [0; 1175]).unwrap();

            if client.state() == ClientState::Connected {
                break;
            }

            time += delta;
        }
        assert_eq!(server.iter_clients().count(), 1);
        assert_eq!(server.iter_clients().last().unwrap().0, 0);
        assert!(client.is_connected());

        let mut payload = vec![b'a'];
        loop {
            client.update(time).unwrap();
            client.send(&payload).unwrap();
            let mut buf = [0; 1175];
            let size = client.recv(&mut buf).unwrap();
            if size > 0 {
                payload = buf[..size].to_vec();
                payload.push(payload.last().unwrap() + 1);
            }

            server.update(time).unwrap();
            let mut buf = [0; 1175];
            if let Ok(Some((size, client_idx))) = server.recv(&mut buf) {
                payload = buf[..size].to_vec();
                payload.push(payload.last().unwrap() + 1);
                server.send(&payload, client_idx).unwrap();
            }

            if payload.contains(&(b'z')) {
                break;
            }

            time += delta;
        }
        assert_eq!(payload, b"abcdefghijklmnopqrstuvwxyz");
    }

    #[test]
    fn client_server_timeout() {
        enable_logging();

        let routing_table = Rc::new(RefCell::new(HashMap::new()));
        let client_sim = NetworkSimulator::new(40000, routing_table.clone());
        let server_sim = NetworkSimulator::new(50000, routing_table.clone());

        let mut time = 0.0;
        let delta = 1. / 10.;

        let mut server = Server::with_simulator(server_sim, None).unwrap();

        let token = server.token(123u64).generate().unwrap();

        let mut client = Client::with_simulator(token, client_sim).unwrap();

        client.connect();

        // connect client
        loop {
            client.update(time).unwrap();
            client.recv(&mut [0; 1175]).unwrap();
            server.update(time).unwrap();
            server.recv(&mut [0; 1175]).unwrap();

            if client.is_connected() || client.is_error() {
                break;
            }

            time += delta;
        }
        assert_eq!(server.iter_clients().count(), 1);
        assert_eq!(server.iter_clients().last().unwrap().0, 0);
        assert!(client.is_connected());

        // now don't update server for a while and ensure client times out
        let num_iterations = (1.5 * CONNECTION_TIMEOUT_SEC as f64 / delta).ceil() as usize;
        for _ in 0..num_iterations {
            client.update(time).unwrap();
            client.recv(&mut [0; 1175]).unwrap();

            time += delta;
        }
        assert!(client.is_error());
        assert!(client.state() == ClientState::ConnectionTimedOut);
    }

    #[test]
    fn client_server_keep_alive() {
        enable_logging();

        let routing_table = Rc::new(RefCell::new(HashMap::new()));
        let client_sim = NetworkSimulator::new(40000, routing_table.clone());
        let server_sim = NetworkSimulator::new(50000, routing_table.clone());

        let mut time = 0.0;
        let delta = 1. / 10.;

        let mut server = Server::with_simulator(server_sim, None).unwrap();

        let token = server.token(123u64).generate().unwrap();

        let mut client = Client::with_simulator(token, client_sim).unwrap();

        client.connect();

        let num_iterations = (1.5 * CONNECTION_TIMEOUT_SEC as f64 / delta).ceil() as usize;
        let mut iterations_done = 0;
        for i in 0..num_iterations {
            client.update(time).unwrap();
            client.recv(&mut [0; 1175]).unwrap();
            server.update(time).unwrap();
            server.recv(&mut [0; 1175]).unwrap();

            if client.is_connected() || client.is_error() {
                break;
            }

            time += delta;
            iterations_done = i;
        }
        assert_eq!(server.iter_clients().count(), 1);
        assert_eq!(server.iter_clients().last().unwrap().0, 0);
        assert!(client.is_connected());
        assert!(iterations_done < num_iterations);
    }

    #[test]
    fn multiple_clients() {
        enable_logging();

        let routing_table = Rc::new(RefCell::new(HashMap::new()));
        let client1_sim = NetworkSimulator::new(40000, routing_table.clone());
        let client2_sim = NetworkSimulator::new(40001, routing_table.clone());
        let client3_sim = NetworkSimulator::new(40002, routing_table.clone());
        let server_sim = NetworkSimulator::new(50000, routing_table.clone());

        let mut time = 0.0;
        let delta = 1. / 10.;

        let mut server = Server::with_simulator(server_sim, None).unwrap();

        let token1 = server.token(1).generate().unwrap();
        let token2 = server.token(2).generate().unwrap();
        let token3 = server.token(3).generate().unwrap();

        let mut clients = vec![
            Client::with_simulator(token1, client1_sim).unwrap(),
            Client::with_simulator(token2, client2_sim).unwrap(),
            Client::with_simulator(token3, client3_sim).unwrap(),
        ];

        for client in clients.iter_mut() {
            client.connect();
        }

        loop {
            for client in clients.iter_mut() {
                client.update(time).unwrap();
                client.recv(&mut [0; 1175]).unwrap();
            }
            server.update(time).unwrap();
            server.recv(&mut [0; 1175]).unwrap();

            if clients.iter().all(|c| c.is_connected()) || clients.iter().any(|c| c.is_error()) {
                break;
            }

            time += delta;
        }
        assert_eq!(server.iter_clients().count(), 3);
        for client in clients.iter() {
            assert!(client.is_connected());
        }

        // exchange some messages
        let mut client_num_packets_received = [false, false, false];
        let mut server_num_packets_received = [false, false, false];
        let payload = b"hello";
        loop {
            for (i, client) in clients.iter_mut().enumerate() {
                client.update(time).unwrap();
                let mut buf = [0; 1175];
                let size = client.recv(&mut buf).unwrap();
                if size > 0 {
                    client_num_packets_received[i] = true;
                    assert_eq!(size, payload.len());
                    assert_eq!(&buf[..size], payload);
                }
                if client.is_connected() {
                    client.send(payload).unwrap();
                }
            }
            server.update(time).unwrap();
            let mut buf = [0; 1175];
            if let Ok(Some((size, client_idx))) = server.recv(&mut buf) {
                server_num_packets_received[client_idx] = true;
                assert_eq!(size, payload.len());
                assert_eq!(&buf[..size], payload);
                server.send(payload, client_idx).unwrap();
            }

            if clients.iter().any(|c| c.is_error()) {
                break;
            }

            if client_num_packets_received.iter().all(|&b| b)
                && server_num_packets_received.iter().all(|&b| b)
            {
                break;
            }

            time += delta;
        }

        assert!(client_num_packets_received.iter().all(|&b| b));
        assert!(server_num_packets_received.iter().all(|&b| b));

        // now disconnect one client (by the client's initiative) and ensure the server disconnects it
        clients.pop().unwrap().disconnect().unwrap();
        loop {
            for client in clients.iter_mut() {
                client.update(time).unwrap();
                client.recv(&mut [0; 1175]).unwrap();
            }
            server.update(time).unwrap();
            server.recv(&mut [0; 1175]).unwrap();

            if clients.iter().any(|c| c.is_error()) {
                break;
            }

            if server.iter_clients().count() <= 2 {
                break;
            }

            time += delta;
        }
        assert_eq!(server.iter_clients().count(), 2);

        // disconnect the remaining clients (by the server's initiative) and ensure they disconnect
        server.disconnect_all().unwrap();
        loop {
            for client in clients.iter_mut() {
                client.update(time).unwrap();
                client.recv(&mut [0; 1175]).unwrap();
            }
            server.update(time).unwrap();
            server.recv(&mut [0; 1175]).unwrap();

            if clients.iter().any(|c| c.is_error()) {
                break;
            }

            if server.iter_clients().count() == 0 {
                break;
            }

            time += delta;
        }
        assert_eq!(server.iter_clients().count(), 0);
    }

    #[test]
    fn multiple_servers() {
        enable_logging();

        let routing_table = Rc::new(RefCell::new(HashMap::new()));
        let client_sim = NetworkSimulator::new(40000, routing_table.clone());
        let server1_sim = NetworkSimulator::new(50000, routing_table.clone());
        let server2_sim = NetworkSimulator::new(50001, routing_table.clone());

        let mut time = 0.0;
        let delta = 1. / 10.;

        let private_key = [42u8; 32];
        let mut server1 = Server::with_simulator(server1_sim, Some(private_key)).unwrap();
        let mut server2 = Server::with_simulator(server2_sim, Some(private_key)).unwrap();

        let token = ConnectToken::build(&[server1.addr(), server2.addr()][..], 0, 0, 0)
            .private_key(private_key)
            .generate()
            .unwrap();

        let mut client = Client::with_simulator(token, client_sim).unwrap();
        client.connect();

        // connect to 1st server
        loop {
            client.update(time).unwrap();
            client.recv(&mut [0; 1175]).unwrap();
            server1.update(time).unwrap();
            server1.recv(&mut [0; 1175]).unwrap();

            if client.is_connected() || client.is_error() {
                break;
            }

            time += delta;
        }
        assert_eq!(server1.iter_clients().count(), 1);
        assert_eq!(server1.iter_clients().last().unwrap().0, 0);
        assert!(client.is_connected());
        assert_eq!(server2.iter_clients().count(), 0);

        // disconnect client from 1st server
        server1.disconnect_all().unwrap();
        loop {
            client.update(time).unwrap();
            client.recv(&mut [0; 1175]).unwrap();
            server1.update(time).unwrap();
            server1.recv(&mut [0; 1175]).unwrap();
            server2.update(time).unwrap();
            server2.recv(&mut [0; 1175]).unwrap();

            if client.is_error() {
                break;
            }

            if server2.iter_clients().count() == 1 && client.is_connected() {
                break;
            }

            time += delta;
        }
        assert_eq!(server1.iter_clients().count(), 0);
        assert_eq!(server2.iter_clients().count(), 1);
        assert_eq!(server2.iter_clients().last().unwrap().0, 0);
        assert!(client.is_connected());
    }
}
