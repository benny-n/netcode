use std::{
    cell::RefCell,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket},
    sync::mpsc::{Receiver, Sender},
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

pub struct NetworkSimulator {
    pub latency_ms: f64,
    pub jitter_ms: f64,
    pub packet_loss_percent: f64,
    pub duplicate_packet_percent: f64,
    pub time: f64,
    pub addr: SocketAddr,
    pub current_sender: Option<SocketAddr>,
    pub current_receiver: Option<SocketAddr>,
    pub channel: Option<Channel>,
}

impl NetworkSimulator {
    pub fn new(
        latency_ms: f64,
        jitter_ms: f64,
        packet_loss_percent: f64,
        duplicate_packet_percent: f64,
    ) -> Self {
        let addr = UdpSocket::bind("0.0.0.0:0")
            .expect("couldn't bind to address")
            .local_addr()
            .expect("couldn't get local address");
        Self {
            latency_ms,
            jitter_ms,
            packet_loss_percent,
            duplicate_packet_percent,
            time: 0.0,
            addr,
            current_sender: None,
            current_receiver: None,
            channel: None,
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
        self.addr
    }

    fn recv(&self, buf: &mut [u8]) -> Result<(usize, Option<SocketAddr>), Self::Error> {
        let Some(to) = self.current_receiver else {
            return Ok((0, None));
        };
        if let Some(entry) = self.channel.as_ref().and_then(|c| c.rx.try_recv().ok()) {
            if entry.to != to {
                return Ok((0, None));
            }
            let len = entry.packet.len();
            buf[..len].copy_from_slice(&entry.packet[..len]);
            return Ok((len, Some(entry.from)));
        }
        Ok((0, None))
    }
    fn send(&self, buf: &[u8], addr: SocketAddr) -> Result<usize, Self::Error> {
        let Some(from) = self.current_sender else {
            return Ok(0);
        };
        if rand_float(0.0..100.) < self.packet_loss_percent {
            return Ok(0);
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
        self.channel.as_ref().map(|c| c.tx.send(entry.clone()));
        if rand_float(0.0..100.) < self.duplicate_packet_percent {
            log::error!("duplicating packet");
            entry.delivery_time += rand_float(0.0..1.);
            self.channel.as_ref().map(|c| c.tx.send(entry));
        }
        Ok(buf.len())
    }
}

mod tests {
    use std::{rc::Rc, sync::mpsc};

    use crate::client::{Client, ClientState};

    use super::*;

    #[test]
    fn client_server_connect() {
        env_logger::Builder::new()
            .filter(None, log::LevelFilter::Trace)
            .init();

        let mut simulator = NetworkSimulator::new(250.0, 250.0, 5.0, 0.0);
        let (tx, rx) = mpsc::channel::<PacketEntry>();
        simulator.channel = Some(Channel { tx, rx });
        let simulator = Rc::new(RefCell::new(simulator));

        let mut time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        let delta = 1. / 10.;

        let mut server = Server::with_simulator(simulator.clone()).unwrap();

        let token = server
            .token(123u64)
            .expire_seconds(-1)
            .timeout_seconds(-1)
            .generate()
            .unwrap();

        let mut client = Client::with_simulator(token, simulator.clone()).unwrap();

        simulator.borrow_mut().current_sender = Some(client.addr());
        simulator.borrow_mut().current_receiver = Some(server.addr());

        client.connect().unwrap();

        loop {
            client.recv(&mut [0; 1175]).unwrap();
            client.update(time).unwrap();
            server.recv(&mut [0; 1175]).unwrap();
            server.update(time).unwrap();

            if client.state() == ClientState::Connected {
                break;
            }

            time += delta;
            std::thread::sleep(std::time::Duration::from_secs_f64(delta));
        }

        // let mut payload = vec![b'a'];
        // loop {
        //     println!(
        //         "payload: {}",
        //         std::str::from_utf8(payload.as_slice()).unwrap()
        //     );
        //     client.send(&payload).unwrap();
        //     let mut buf = [0; 1175];
        //     let size = client.recv(&mut buf).unwrap();
        //     if size > 0 {
        //         payload = buf[..size].to_vec();
        //         payload.push(payload.last().unwrap() + 1);
        //     }
        //     client.update(time).unwrap();

        //     let mut buf = [0; 1175];
        //     let size = server.recv(&mut buf).unwrap();
        //     if size > 0 {
        //         payload = buf[..size].to_vec();
        //         payload.push(payload.last().unwrap() + 1);
        //     }
        //     server.send(&payload, 0).unwrap();
        //     server.update(time).unwrap();

        //     if payload.contains(&(b'z')) {
        //         break;
        //     }

        //     time += delta;
        // }
        // assert_eq!(
        //     std::str::from_utf8(&payload).unwrap(),
        //     "abcdefghijklmnopqrstuvwxyz"
        // );
    }
}
