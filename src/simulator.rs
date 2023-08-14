// use std::{collections::VecDeque, net::SocketAddr};

// use crate::{
//     consts::{MAX_CLIENTS, MAX_PKT_BUF_SIZE},
//     transceiver::Transceiver,
// };

// const NUM_PACKET_ENTRIES: usize = 256 * MAX_CLIENTS;
// const NUM_PENDING_RECEIVE_PACKETS: usize = 64 * MAX_CLIENTS;

// #[derive(Debug)]
// pub(crate) struct PacketEntry {
//     pub(crate) from: SocketAddr,
//     pub(crate) to: SocketAddr,
//     pub(crate) delivery_time: f64,
//     pub(crate) packet: Vec<u8>,
// }

// #[derive(Default)]
// pub(crate) struct NetworkSimulator {
//     pub(crate) latency_ms: f32,
//     pub(crate) jitter_ms: f32,
//     pub(crate) packet_loss_percent: f32,
//     pub(crate) duplicate_packet_percent: f32,
//     pub(crate) time: f64,
//     pub(crate) packet_entries: VecDeque<PacketEntry>,
//     pub(crate) pending_receive_packets: Vec<PacketEntry>,
// }

// impl NetworkSimulator {
//     pub fn new(
//         lattecy_ms: f32,
//         jitter_ms: f32,
//         packet_loss_percent: f32,
//         duplicate_packet_percent: f32,
//     ) -> Self {
//         Self {
//             latency_ms: lattecy_ms,
//             jitter_ms,
//             packet_loss_percent,
//             duplicate_packet_percent,
//             ..Default::default()
//         }
//     }
// }

// fn rand_float(range: std::ops::Range<f32>) -> f32 {
//     use chacha20poly1305::aead::{rand_core::RngCore, OsRng};
//     let rand = OsRng.next_u32() as f32 / u32::MAX as f32;
//     range.start + rand * (range.end - range.start)
// }

// impl Transceiver for NetworkSimulator {
//     type Error = std::io::Error;

//     fn recv(
//         &mut self,
//         from: SocketAddr,
//         to: SocketAddr,
//         buf: &mut [u8],
//     ) -> Result<(usize, Option<SocketAddr>), Self::Error> {
//         for (idx, mut packet) in self.pending_receive_packets.iter_mut().enumerate() {
//             if packet.to != to {
//                 continue;
//             }
//             packet.from = from;
//             self.pending_receive_packets.push(packet);
//         }
//         Ok((0, None))
//     }
//     fn send(&mut self, from: SocketAddr, to: SocketAddr, buf: &[u8]) -> Result<usize, Self::Error> {
//         if rand_float(0f32..100.) < self.packet_loss_percent {
//             return Ok(buf.len());
//         }
//         let mut delay = self.latency_ms / 1000.0;
//         if self.jitter_ms > 0.0 {
//             delay += rand_float(-self.jitter_ms..self.jitter_ms) / 1000.0;
//         }
//         let entry = PacketEntry {
//             from,
//             to,
//             delivery_time: self.time + delay as f64 + rand_float(0f32..1.0) as f64,
//             packet: buf.to_vec(),
//         };
//         self.packet_entries.push_back(entry);
//         Ok(buf.len())
//     }
// }
