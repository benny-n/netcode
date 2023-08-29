use byteorder::{LittleEndian, WriteBytesExt};
use chacha20poly1305::{
    aead::{rand_core::RngCore, OsRng},
    AeadInPlace, ChaCha20Poly1305, KeyInit, Tag,
};
use std::io;

use crate::{MAC_BYTES, PRIVATE_KEY_BYTES};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("buffer size mismatch")]
    BufferSizeMismatch,
    #[error("failed to encrypt: {0}")]
    Failed(#[from] chacha20poly1305::aead::Error),
    #[error("failed to generate key: {0}")]
    GenerateKey(chacha20poly1305::aead::rand_core::Error),
}
/// A 32-byte array, used as a key for encrypting and decrypting packets and connect tokens.
pub type Key = [u8; crate::PRIVATE_KEY_BYTES];
pub type Result<T> = std::result::Result<T, Error>;

/// Generates a random key for encrypting and decrypting packets and connect tokens.
///
/// Panics if the underlying RNG fails (highly unlikely). <br>
/// For a non-panicking version, see [`try_generate_key`](fn.try_generate_key.html).
///
/// # Example
/// ```
/// use netcode::generate_key;
///
/// let key = generate_key();
/// assert_eq!(key.len(), 32);
/// ```
pub fn generate_key() -> Key {
    let mut key: Key = [0; PRIVATE_KEY_BYTES];
    OsRng.fill_bytes(&mut key);
    key
}
/// The fallible version of [`generate_key`](fn.generate_key.html).
///
/// Returns an error if the underlying RNG fails (highly unlikely).
///
/// # Example
/// ```
/// use netcode::try_generate_key;
///
/// let key = try_generate_key().unwrap();
/// assert_eq!(key.len(), 32);
/// ```
pub fn try_generate_key() -> Result<Key> {
    let mut key: Key = [0; PRIVATE_KEY_BYTES];
    OsRng.try_fill_bytes(&mut key).map_err(Error::GenerateKey)?;
    Ok(key)
}

pub fn encrypt(
    buffer: &mut [u8],
    associated_data: Option<&[u8]>,
    nonce: u64,
    key: &Key,
) -> Result<()> {
    let size = buffer.len();
    if size < MAC_BYTES {
        // Should have 16 bytes of extra space for the MAC
        return Err(Error::BufferSizeMismatch);
    }
    let mut final_nonce = [0; 12];
    io::Cursor::new(&mut final_nonce[4..]).write_u64::<LittleEndian>(nonce)?;
    let mac = ChaCha20Poly1305::new(key.into()).encrypt_in_place_detached(
        &final_nonce.into(),
        associated_data.unwrap_or_default(),
        &mut buffer[..size - MAC_BYTES],
    )?;
    buffer[size - MAC_BYTES..].copy_from_slice(mac.as_ref());
    Ok(())
}

pub fn decrypt(
    buffer: &mut [u8],
    associated_data: Option<&[u8]>,
    nonce: u64,
    key: &Key,
) -> Result<()> {
    if buffer.len() < MAC_BYTES {
        // Should already include the MAC
        return Err(Error::BufferSizeMismatch);
    }
    let mut final_nonce = [0; 12];
    io::Cursor::new(&mut final_nonce[4..]).write_u64::<LittleEndian>(nonce)?;
    let (buffer, mac) = buffer.split_at_mut(buffer.len() - MAC_BYTES);
    ChaCha20Poly1305::new(key.into()).decrypt_in_place_detached(
        &final_nonce.into(),
        associated_data.unwrap_or_default(),
        buffer,
        Tag::from_slice(mac),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buf_too_small() {
        let mut buffer = [0; 0];
        let nonce = 0;
        let key = generate_key();
        let result = encrypt(&mut buffer, None, nonce, &key);
        assert!(result.is_err());
    }

    #[test]
    fn encrypt_decrypt_zero_sized_buffer() {
        let mut buffer = [0u8; MAC_BYTES]; // 16 bytes is the minimum size, which our actual buffer is empty
        let nonce = 0;
        let key = generate_key();
        encrypt(&mut buffer, None, nonce, &key).unwrap();

        // The buffer should have been modified
        assert_ne!(buffer, [0u8; MAC_BYTES]);

        decrypt(&mut buffer, None, nonce, &key).unwrap();
    }
}
