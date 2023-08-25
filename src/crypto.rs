use byteorder::{LittleEndian, WriteBytesExt};
use chacha20poly1305::{
    aead::{rand_core::RngCore, OsRng},
    AeadInPlace, ChaCha20Poly1305, KeyInit, Tag,
};
use std::io;

use crate::{MAC_SIZE, PRIVATE_KEY_SIZE};

#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
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
pub type Key = [u8; crate::PRIVATE_KEY_SIZE];
pub type Result<T> = std::result::Result<T, Error>;

/// Generates a random key for use with the netcode protocol.
///
/// Returns an error if the underlying RNG fails (highly unlikely).
///
/// # Examples
/// ```
/// use netcode::generate_key;
///
/// let key = generate_key().unwrap();
/// assert_eq!(key.len(), 32);
/// ```
pub fn generate_key() -> Result<Key> {
    let mut key: Key = [0; PRIVATE_KEY_SIZE];
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
    if size < MAC_SIZE {
        // Should have 16 bytes of extra space for the MAC
        return Err(Error::BufferSizeMismatch);
    }
    let mut final_nonce = [0; 12];
    io::Cursor::new(&mut final_nonce[4..]).write_u64::<LittleEndian>(nonce)?;
    let mac = ChaCha20Poly1305::new(key.into()).encrypt_in_place_detached(
        &final_nonce.into(),
        associated_data.unwrap_or_default(),
        &mut buffer[..size - MAC_SIZE],
    )?;
    buffer[size - MAC_SIZE..].copy_from_slice(mac.as_ref());
    Ok(())
}

pub fn decrypt(
    buffer: &mut [u8],
    associated_data: Option<&[u8]>,
    nonce: u64,
    key: &Key,
) -> Result<()> {
    if buffer.len() < MAC_SIZE {
        // Should already include the MAC
        return Err(Error::BufferSizeMismatch);
    }
    let mut final_nonce = [0; 12];
    io::Cursor::new(&mut final_nonce[4..]).write_u64::<LittleEndian>(nonce)?;
    let (buffer, mac) = buffer.split_at_mut(buffer.len() - MAC_SIZE);
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
        let key = generate_key().unwrap();
        let result = encrypt(&mut buffer, None, nonce, &key);
        assert!(result.is_err());
    }

    #[test]
    fn encrypt_decrypt_zero_sized_buffer() {
        let mut buffer = [0u8; MAC_SIZE]; // 16 bytes is the minimum size, which our actual buffer is empty
        let nonce = 0;
        let key = generate_key().unwrap();
        encrypt(&mut buffer, None, nonce, &key).unwrap();

        // The buffer should have been modified
        assert_ne!(buffer, [0u8; MAC_SIZE]);

        decrypt(&mut buffer, None, nonce, &key).unwrap();
    }
}
