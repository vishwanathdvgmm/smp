use smp_crypto_core::{
    encryption::{decrypt, encrypt},
    identity::Identity,
    ratchet::DoubleRatchet,
};

use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

use crate::storage::storage_dir;

fn session_dir(user: &str) -> String {
    format!("{}/sessions", storage_dir(user))
}

fn session_path(user: &str, peer_hex: &str) -> String {
    format!("{}/{}.bin", session_dir(user), peer_hex)
}

fn derive_storage_key(identity: &Identity) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(identity.encryption_secret.to_bytes());
    hasher.update(b"smp-session-storage");
    hasher.finalize().into()
}

pub fn save_session(user: &str, peer_hex: &str, identity: &Identity, ratchet: &DoubleRatchet) {
    let _ = fs::create_dir_all(session_dir(user));

    let serialized = serde_json::to_vec(ratchet).unwrap();
    let key = derive_storage_key(identity);

    let (ciphertext, nonce) = encrypt(&key, &serialized, b"session-store").unwrap();

    let mut stored = nonce.to_vec();
    stored.extend_from_slice(&ciphertext);

    let _ = fs::write(session_path(user, peer_hex), stored);
}

pub fn load_session(user: &str, peer_hex: &str, identity: &Identity) -> Option<DoubleRatchet> {
    let path = session_path(user, peer_hex);

    if !Path::new(&path).exists() {
        return None;
    }

    let data = fs::read(path).ok()?;
    if data.len() < 12 {
        return None;
    }

    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&data[..12]);

    let ciphertext = &data[12..];

    let key = derive_storage_key(identity);

    let decrypted = decrypt(&key, ciphertext, &nonce, b"session-store").ok()?;

    serde_json::from_slice(&decrypted).ok()
}
