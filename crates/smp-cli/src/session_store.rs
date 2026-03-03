use smp_crypto_core::{
    encryption::{decrypt, encrypt},
    identity::Identity,
    ratchet::DoubleRatchet,
};

use hkdf::Hkdf;
use sha2::Sha256;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

use crate::storage::storage_dir;

const SESSION_VERSION: u8 = 1;

fn session_dir(user: &str) -> String {
    format!("{}/sessions", storage_dir(user))
}

fn session_path(user: &str, peer_hex: &str) -> String {
    format!("{}/{}.bin", session_dir(user), peer_hex)
}

fn derive_storage_key(identity: &Identity, peer_hex: &str) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, &identity.encryption_secret.to_bytes());
    let mut key = [0u8; 32];
    let info = format!("smp-session-storage-v1:{}", peer_hex);
    hk.expand(info.as_bytes(), &mut key)
        .expect("HKDF expand should not fail for 32 bytes");
    key
}

pub fn save_session(user: &str, peer_hex: &str, identity: &Identity, ratchet: &DoubleRatchet) {
    let _ = fs::create_dir_all(session_dir(user));

    // Serialize ratchet directly, prepend version byte — avoids clone
    let ratchet_bytes = match serde_json::to_vec(ratchet) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[SESSION] Serialize failed: {:?}", e);
            return;
        }
    };

    let mut serialized = vec![SESSION_VERSION];
    serialized.extend_from_slice(&ratchet_bytes);

    let key = derive_storage_key(identity, peer_hex);

    let (ciphertext, nonce) = match encrypt(&key, &serialized, b"session-store") {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[SESSION] Encrypt failed: {:?}", e);
            return;
        }
    };

    let mut stored = nonce.to_vec();
    stored.extend_from_slice(&ciphertext);

    // Durable atomic write: write → fsync → rename
    let path = session_path(user, peer_hex);
    let tmp_path = format!("{}.tmp", path);

    let write_result = (|| -> std::io::Result<()> {
        let mut file = File::create(&tmp_path)?;
        file.write_all(&stored)?;
        file.sync_all()?;
        Ok(())
    })();

    if let Err(e) = write_result {
        eprintln!("[SESSION] Write temp file failed: {:?}", e);
        return;
    }

    if let Err(e) = fs::rename(&tmp_path, &path) {
        eprintln!("[SESSION] Atomic rename failed: {:?}", e);
        let _ = fs::remove_file(&tmp_path);
    } else {
        // Fsync the directory for crash-consistent durability (mainly needed on Unix)
        #[cfg(unix)]
        {
            if let Ok(dir_file) = File::open(session_dir(user)) {
                let _ = dir_file.sync_all();
            }
        }
    }
}

pub fn load_session(user: &str, peer_hex: &str, identity: &Identity) -> Option<DoubleRatchet> {
    let path = session_path(user, peer_hex);

    if !Path::new(&path).exists() {
        return None;
    }

    let data = fs::read(&path).ok()?;
    if data.len() < 12 {
        eprintln!("[SESSION] Corrupt session file (too short)");
        return None;
    }

    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&data[..12]);

    let ciphertext = &data[12..];

    let key = derive_storage_key(identity, peer_hex);

    let decrypted = match decrypt(&key, ciphertext, &nonce, b"session-store") {
        Ok(d) => d,
        Err(_) => {
            eprintln!("[SESSION] Decryption failed — key mismatch or corruption");
            return None;
        }
    };

    if decrypted.is_empty() {
        eprintln!("[SESSION] Empty decrypted payload");
        return None;
    }

    let version = decrypted[0];
    if version != SESSION_VERSION {
        eprintln!(
            "[SESSION] Version mismatch: expected {}, got {}",
            SESSION_VERSION, version
        );
        return None;
    }

    match serde_json::from_slice(&decrypted[1..]) {
        Ok(r) => Some(r),
        Err(e) => {
            eprintln!("[SESSION] Deserialize failed: {:?}", e);
            None
        }
    }
}
