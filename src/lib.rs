//! # netcode
//!
//! The `netcode` crate implements the [netcode](https://github.com/networkprotocol/netcode)
//! network protocol created by [Glenn Fiedler](https://gafferongames.com).
//!
//! `netcode` is a UDP-based protocol that provides secure, connection-based data transfer.
//!
//! Since the protocol is meant to be used to implement multiplayer games, its API is designed
//! to be used in a game loop, where the server and client are updated at a fixed rate (e.g., 60Hz).
//!
//! ## Protocol
//!
//! The three main components of the netcode protocol are:
//! * Dedicated [`Servers`](Server).
//! * [`Clients`](Client).
//! * The web backend - a service that authenticates clients and generates [`ConnectTokens`](ConnectToken).
//!   
//! The protocol does not specify how the web backend should be implemented, but it should probably be a typical HTTPS server
//! that provides a means for clients to authenticate and request connection tokens.
//!
//! The sequence of operations for a client to connect to a server is as follows:
//!
//! 1. The `Client` authenticates with the web backend service. (e.g., by OAuth or some other means)
//! 2. The authenticated `Client` requests a connection token from the web backend.
//! 3. The web backend generates a [`ConnectToken`](ConnectToken) and sends it to the `Client`. (e.g., as a JSON response)
//! 4. The `Client` uses the token to connect to a dedicated `Server`.
//! 5. The `Server` makes sure the token is valid and allows the `Client` to connect.
//! 6. The `Client` and `Server` can now exchange encrypted and signed UDP packets.
//!
//! To learn more about the netcode protocol, see the upstream [specification](https://github.com/networkprotocol/netcode/blob/master/STANDARD.md).
//!
//! ## Server
//!
//! The netcode server is responsible for managing the state of the clients and sending/receiving packets.
//!
//! The server should run as a part of the game loop, process incoming packets and send updates to the clients.
//!
//! To create a server:
//!  * Provide the address you intend to bind to.
//!  * Provide the protocol id - a `u64` that uniquely identifies your app.
//!  * Provide a private key - a `u8` array of length 32. If you don't have one, you can generate one with `netcode::generate_key()`.
//!  * Optionally provide a [`ServerConfig`](ServerConfig) - a struct that allows you to customize the server's behavior.
//!
//! ```
//! use std::{thread, time::{Instant, Duration}};
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
//!     server.update(now);
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
//! use std::{thread, time::{Instant, Duration}};
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
//!
//! // Run the client at 60Hz
//! let start = Instant::now();
//! loop {
//!     thread::sleep(Duration::from_secs_f64(1.0 / 60.0));
//!     let now = start.elapsed().as_secs_f64();
//!     client.update(now);
//!     let mut packet = [0; MAX_PACKET_SIZE];
//!     if let Ok(received) = client.recv(&mut packet) {
//!         let payload = &packet[..received];
//!         // ...
//!     }
//!     # break;
//! }
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
pub use crate::server::{ClientId, ClientIndex, Server, ServerConfig};
pub use crate::token::{ConnectToken, ConnectTokenBuilder, InvalidTokenError};

// Public constants

/// The size of the user data in a connect token.
pub const USER_DATA_SIZE: usize = 256;
/// The maximum size of a packet in bytes.
pub const MAX_PACKET_SIZE: usize = 1200;
/// The version of the netcode protocol implemented by this crate.
pub const NETCODE_VERSION: &[u8; 13] = b"NETCODE 1.01\0";
