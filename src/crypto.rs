use byteorder::{LittleEndian, WriteBytesExt};
use chacha20poly1305::{
    aead::{heapless::Vec, rand_core::RngCore, Aead, OsRng, Payload},
    AeadInPlace, ChaCha20Poly1305, KeyInit, Tag,
};
use std::io;

use crate::{
    consts::PRIVATE_KEY_BYTES,
    error::{CryptoError, NetcodeError},
};

pub const AUTH_TAG_BYTES: usize = 16;

pub fn generate_key() -> Result<[u8; PRIVATE_KEY_BYTES], NetcodeError> {
    let mut key: [u8; PRIVATE_KEY_BYTES] = [0; PRIVATE_KEY_BYTES];
    OsRng
        .try_fill_bytes(&mut key)
        .map_err(CryptoError::GenerateKey)?;
    Ok(key)
}

pub fn encrypt<const N: usize>(
    buffer: &mut [u8],
    associated_data: Option<&[u8]>,
    nonce: u64,
    key: &[u8; PRIVATE_KEY_BYTES],
) -> Result<[u8; N], CryptoError> {
    let mut final_nonce = [0; 12];
    io::Cursor::new(&mut final_nonce[4..]).write_u64::<LittleEndian>(nonce)?;
    let mut out: Vec<u8, N> = Vec::new();
    out.extend_from_slice(&buffer[..N - AUTH_TAG_BYTES])
        .map_err(|_| CryptoError::BufferSizeMismatch)?;
    ChaCha20Poly1305::new(key.into()).encrypt_in_place(
        &final_nonce.into(),
        associated_data.unwrap_or_default(),
        &mut out,
    )?;
    Ok(out.into_array().unwrap())
}

pub fn decrypt<const N: usize>(
    buffer: &mut [u8],
    associated_data: Option<&[u8]>,
    nonce: u64,
    key: &[u8; PRIVATE_KEY_BYTES],
) -> Result<(), CryptoError> {
    let mut final_nonce = [0; 12];
    io::Cursor::new(&mut final_nonce[4..]).write_u64::<LittleEndian>(nonce)?;
    let mut out: Vec<u8, N> = Vec::new();
    out.extend_from_slice(buffer)
        .map_err(|_| CryptoError::BufferSizeMismatch)?;
    ChaCha20Poly1305::new(key.into()).decrypt_in_place(
        &final_nonce.into(),
        associated_data.unwrap_or_default(),
        &mut out,
    )?;
    buffer[..N - AUTH_TAG_BYTES].copy_from_slice(&out);
    Ok(())
}
