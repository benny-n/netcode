pub const NETCODE_VERSION: &[u8; 13] = b"NETCODE 1.01\0";
pub const USER_DATA_SIZE: usize = 256;
pub const MAC_SIZE: usize = 16;
pub const PRIVATE_KEY_SIZE: usize = 32;
pub const MAX_PKT_BUF_SIZE: usize = 1200;
pub const MAX_PAYLOAD_SIZE: usize = MAX_PKT_BUF_SIZE - MAC_SIZE - 8 - 1; // 8 bytes for sequence number, 1 byte for packet type
pub const MAX_CLIENTS: usize = 256;
pub const DEFAULT_TOKEN_EXPIRE_SECONDS: i32 = 30;
pub const DEFAULT_CONNECTION_TIMEOUT_SECONDS: i32 = 15;
pub const PACKET_SEND_RATE: f64 = 1.0 / 10.0;

pub(crate) const SERVER_SOCKET_RECV_BUF_SIZE: usize = 4 * 1024 * 1024;
pub(crate) const SERVER_SOCKET_SEND_BUF_SIZE: usize = 4 * 1024 * 1024;
