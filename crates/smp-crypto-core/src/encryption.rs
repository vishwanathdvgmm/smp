use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::RngCore;

use crate::error::CryptoError;

pub fn encrypt(
    key_bytes: &[u8; 32],
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<(Vec<u8>, [u8; 12]), CryptoError> {
    let key = Key::from_slice(key_bytes);
    let cipher = ChaCha20Poly1305::new(key);

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, chacha20poly1305::aead::Payload {
            msg: plaintext,
            aad: associated_data,
        })
        .map_err(|_| CryptoError::EncryptionFailed)?;

    Ok((ciphertext, nonce_bytes))
}

pub fn decrypt(
    key_bytes: &[u8; 32],
    ciphertext: &[u8],
    nonce_bytes: &[u8; 12],
    associated_data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let key = Key::from_slice(key_bytes);
    let cipher = ChaCha20Poly1305::new(key);

    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, chacha20poly1305::aead::Payload {
            msg: ciphertext,
            aad: associated_data,
        })
        .map_err(|_| CryptoError::DecryptionFailed)
}
