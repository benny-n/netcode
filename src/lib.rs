//! # netcode
//!
//! The `netcode` crate implements the [netcode](https://github.com/networkprotocol/netcode)
//! network protocol created by [Glenn Fiedler](https://gafferongames.com) for multiplayer games.
//!
//! ~~Being a thin wrapper over UDP sockets, `netcode` is offering a seemingly general purpose connection-based secure data transfer.~~
//! ~~However, its core design and feature set are tailored specifically to meet the demands of multiplayer games networking.~~
//!
//! ## Server
//!
//! The netcode server is responsible for managing the state of the clients and sending/receiving packets.
//!
//! The game server typically runs in a loop, processing incoming packets and sending game updates.
//! It's common to run the server at a fixed tick rate (e.g., 60Hz) to maintain consistency across clients.
//!
//! To create a server:
//!  * Provide the address you intend to bind to.
//!  * Provide the protocol id - a `u64` that uniquely identifies your app.
//!  * Provide a private key - a `u8` array of length 32. If you don't have one, you can generate one with `netcode::generate_key()`.
//!     If you will pass `None` as the private key, the server will generate one for you.
//!  * Optionally provide a [`ServerConfig`](ServerConfig) - a struct that allows you to customize the server's behavior.
//!
//! ```
//! # use std::{thread, time::{Instant, Duration, SystemTime, UNIX_EPOCH}};
//! use netcode::{Server, MAX_PACKET_SIZE};
//!
//! // Create a server
//! let protocol_id = 0x11223344;
//! let private_key = netcode::generate_key(); // you can also provide your own key
//! let mut server = Server::new("127.0.0.1:12345", protocol_id, private_key).unwrap();
//!
//!
//! // Run the server at 60Hz
//! let start = Instant::now();
//! loop {
//!     thread::sleep(Duration::from_secs_f64(1.0 / 60.0));
//!     let now = start.elapsed().as_secs_f64();
//!     server.update(now).unwrap();
//!     let mut packet = [0; MAX_PACKET_SIZE];
//!     if let Ok(Some((received, _))) = server.recv(&mut packet) {
//!        let payload = &packet[..received];
//!        // ...
//!     }
//! #   else { break;}
//! }
//! ```
//!
//! ## Client
//!
//! The netcode client connects to the server and communicates using the same protocol.
//!
//! Like the server, the game client should run in a loop to process incoming data,
//! send updates to the server, and maintain a stable connection.
//!
//! To create a client:
//!  * Provide a **connect token** - a `u8` array of length 2048 serialized from a [`ConnectToken`](ConnectToken).
//!  * Optionally provide a [`ClientConfig`](ClientConfig) - a struct that allows you to customize the client's behavior.
//!
//! ```
//! use netcode::{ConnectToken, Client, MAX_PACKET_SIZE};
//!
//! // Generate a connection token for the client
//! let protocol_id = 0x11223344;
//! let private_key = netcode::generate_key(); // you can also provide your own key
//! let client_id = 123u64; // globally unique identifier for an authenticated client
//! let server_address = "127.0.0.1:12345"; // the server's public address (can also be multiple addresses)
//!
//! let connect_token = ConnectToken::build("127.0.0.1:12345", protocol_id, client_id, private_key)
//!     .generate()
//!     .unwrap();
//!
//! // Start the client
//! let token_bytes = connect_token.try_into_bytes().unwrap();
//! let mut client = Client::new(&token_bytes).unwrap();
//! client.connect();
//! ```

mod bytes;
mod crypto;
mod free_list;
mod packet;
mod replay;
mod socket;
mod transceiver;

#[cfg(test)]
mod simulator;

mod client;
mod error;
mod server;
mod token;

pub(crate) const MAC_SIZE: usize = 16;
pub(crate) const MAX_PKT_BUF_SIZE: usize = 1300;
pub(crate) const CONNECTION_TIMEOUT_SEC: i32 = 15;
pub(crate) const PACKET_SEND_RATE_SEC: f64 = 1.0 / 10.0;
pub(crate) const PRIVATE_KEY_SIZE: usize = 32;

// Re-exports
pub use crate::client::{Client, ClientConfig, ClientState};
pub use crate::crypto::{generate_key, try_generate_key, Key};
pub use crate::error::{Error, Result};
pub use crate::server::{Server, ServerConfig};
pub use crate::token::{ConnectToken, ConnectTokenBuilder, InvalidTokenError};

// Public constants

/// The size of the user data in a connect token.
pub const USER_DATA_SIZE: usize = 256;
/// The maximum size of a packet in bytes.
pub const MAX_PACKET_SIZE: usize = 1200;
/// The version of the netcode protocol implemented by this crate.
pub const NETCODE_VERSION: &[u8; 13] = b"NETCODE 1.01\0";
