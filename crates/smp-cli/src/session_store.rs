use crate::storage::STORAGE_DIR;
use smp_crypto_core::ratchet::DoubleRatchet;
use std::fs;
use std::path::Path;

pub fn session_dir() -> String {
    format!("{}/sessions", STORAGE_DIR)
}

pub fn session_path(peer_hex: &str) -> String {
    format!("{}/{}.json", session_dir(), peer_hex)
}

pub fn save_session(peer_hex: &str, ratchet: &DoubleRatchet) {
    fs::create_dir_all(session_dir()).unwrap();

    let data = serde_json::to_string_pretty(ratchet).unwrap();
    fs::write(session_path(peer_hex), data).unwrap();
}

pub fn load_session(peer_hex: &str) -> Option<DoubleRatchet> {
    let path = session_path(peer_hex);

    if Path::new(&path).exists() {
        let data = fs::read_to_string(path).unwrap();
        Some(serde_json::from_str(&data).unwrap())
    } else {
        None
    }
}