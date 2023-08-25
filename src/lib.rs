//! # netcode
//!
//! The `netcode` crate implements the [netcode](https://github.com/networkprotocol/netcode)
//! network protocol for multiplayer games created by [Glenn Fiedler](https://gafferongames.com).
//!
//! > “ _**netcode** is a simple connection based client/server protocol built on top of UDP_ ”
//!
//! `netcode` is a thin wrapper over UDP sockets, offering a connection-based secure data transfer.
//!  Its core design and feature set are tailored specifically to meet the demands of multiplayer games.
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
//! use netcode::{Server, MAX_PAYLOAD_SIZE};
//!
//! // Create a server
//! let protocol_id = 0x11223344;
//! let private_key = [0u8; 32]; // TODO: generate a real private key with 'netcode::generate_key()'
//! let mut server = Server::new("127.0.0.1:12345", protocol_id, Some(private_key)).unwrap();
//!
//!
//! // Run the server at 60Hz
//! let start = Instant::now();
//! loop {
//!     thread::sleep(Duration::from_secs_f64(1.0 / 60.0));
//!     let now = start.elapsed().as_secs_f64();
//!     server.update(now).unwrap();
//!     let mut payload = [0; MAX_PAYLOAD_SIZE];
//!     if let Ok(Some((received, _))) = server.recv(&mut payload) {
//!        let payload = &payload[..received];
//!        // ...
//!     }
//! #   else { break;}
//! }
//! ```
//!
//! ## Client
//!
//! The game client connects to the server and communicates using the same protocol.
//!
//! Like the server, the game client should run in a loop to process incoming data,
//! send updates to the server, and maintain a stable connection.
//!
//! To create a client:
//!  * Provide a **connect token** - a `u8` array of length 2048 serialized from a [`ConnectToken`](ConnectToken).
//!  * Optionally provide a [`ClientConfig`](ClientConfig) - a struct that allows you to customize the client's behavior.
//!
//! ```
//! use netcode::{ConnectToken, Client, MAX_PAYLOAD_SIZE};
//!
//! // Generate a connection token for the client
//! let protocol_id = 0x11223344;
//! let private_key = [0u8; 32]; // TODO: generate a real private key with 'netcode::generate_key()'
//! let nonce = 0; // starts at zero and should increase with each connect token generated
//! let client_id = 123u64; // globally unique identifier for an authenticated client
//! let server_address = "127.0.0.1:12345"; // the server's public address (can also be multiple addresses)
//!
//! let connect_token = ConnectToken::build("127.0.0.1:12345", protocol_id, client_id, nonce)
//!     .private_key(private_key) // If not provided, a random key will be generated for you
//!     .generate()
//!     .unwrap();
//!
//! // Start the client
//! let token_bytes = connect_token.try_into_bytes().unwrap();
//! let mut client = Client::new(&token_bytes).unwrap();
//! client.connect();
//! ```

mod bytes;
mod consts;
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

pub use crate::client::{Client, ClientConfig, ClientState};
pub use crate::crypto::generate_key;
pub use crate::server::{Server, ServerConfig};
pub use crate::token::{ConnectToken, ConnectTokenBuilder};
pub use consts::*;
