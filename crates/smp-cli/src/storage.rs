use serde::{Deserialize, Serialize};
use smp_crypto_core::{
    encryption::{decrypt, encrypt},
    identity::Identity,
    prekey::generate_one_time_prekey,
};
use std::{
    fs::{self, File},
    io::Write,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::{Signer, SigningKey};
use rand_core::{OsRng, RngCore};
use x25519_dalek::{PublicKey, StaticSecret};

const PREKEY_POOL_SIZE: usize = 20;
const REFILL_THRESHOLD: usize = 5;
const REFILL_BATCH: usize = 10;
const SIGNED_PREKEY_TTL: u64 = 60 * 60 * 24; // 24 hours
const MASTER_KEY_FILE: &str = "master.key";

/* ================= PATH HELPERS ================= */

pub fn storage_dir(user: &str) -> String {
    format!(".smp/{}", user)
}

fn identity_path(user: &str) -> String {
    format!("{}/identity.bin", storage_dir(user))
}

fn prekey_path(user: &str) -> String {
    format!("{}/prekeys.bin", storage_dir(user))
}

fn signed_prekey_path(user: &str) -> String {
    format!("{}/signed_prekey.bin", storage_dir(user))
}

fn master_key_path(user: &str) -> String {
    format!("{}/{}", storage_dir(user), MASTER_KEY_FILE)
}

/* ================= MASTER KEY ================= */

fn load_or_create_master_key(user: &str) -> Option<[u8; 32]> {
    let dir = storage_dir(user);
    if fs::create_dir_all(&dir).is_err() {
        return None;
    }

    let path = master_key_path(user);

    if Path::new(&path).exists() {
        let data = fs::read(&path).ok()?;
        if data.len() != 32 {
            return None;
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&data);
        return Some(key);
    }

    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);

    if fs::write(&path, &key).is_err() {
        return None;
    }

    Some(key)
}

/* ================= ENCRYPTED FILE HELPERS ================= */

fn encrypted_write(user: &str, path: String, plaintext: &[u8]) -> bool {
    let key = match load_or_create_master_key(user) {
        Some(k) => k,
        None => return false,
    };

    let (ciphertext, nonce) = match encrypt(&key, plaintext, b"storage-file") {
        Ok(v) => v,
        Err(_) => return false,
    };

    let mut stored = nonce.to_vec();
    stored.extend_from_slice(&ciphertext);

    let tmp_path = format!("{}.tmp", path);

    let write_result = (|| -> std::io::Result<()> {
        let mut file = File::create(&tmp_path)?;
        file.write_all(&stored)?;
        file.sync_all()?;
        Ok(())
    })();

    if write_result.is_err() {
        return false;
    }

    if fs::rename(&tmp_path, &path).is_err() {
        let _ = fs::remove_file(&tmp_path);
        return false;
    }

    true
}

fn encrypted_read(user: &str, path: String) -> Option<Vec<u8>> {
    let key = load_or_create_master_key(user)?;
    let data = fs::read(&path).ok()?;

    if data.len() < 12 {
        return None;
    }

    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&data[..12]);

    decrypt(&key, &data[12..], &nonce, b"storage-file").ok()
}

/* ================= DATA STRUCTS ================= */

#[derive(Serialize, Deserialize)]
struct StoredIdentity {
    signing_key: [u8; 32],
    encryption_secret: [u8; 32],
}

#[derive(Serialize, Deserialize, Clone)]
pub struct StoredPreKey {
    pub id: u32,
    pub secret: [u8; 32],
    pub public: [u8; 32],
}

#[derive(Serialize, Deserialize)]
pub struct PreKeyPool {
    pub unused: Vec<StoredPreKey>,
    pub used: Vec<StoredPreKey>,
}

#[derive(Serialize, Deserialize)]
pub struct SignedPreKey {
    pub id: u32,
    pub secret: [u8; 32],
    pub public: [u8; 32],
    pub signature: Vec<u8>,
    pub created_at: u64,
    pub expires_at: u64,
}

/* ================= IDENTITY ================= */

pub fn load_or_create_identity(user: &str) -> Identity {
    let dir = storage_dir(user);
    let _ = fs::create_dir_all(&dir);

    let path = identity_path(user);

    if Path::new(&path).exists() {
        if let Some(decrypted) = encrypted_read(user, path.clone()) {
            if let Ok(stored) = serde_json::from_slice::<StoredIdentity>(&decrypted) {
                let signing_key = SigningKey::from_bytes(&stored.signing_key);
                let verifying_key = signing_key.verifying_key();
                let encryption_secret = StaticSecret::from(stored.encryption_secret);
                let encryption_public = PublicKey::from(&encryption_secret);

                return Identity {
                    signing_key,
                    verifying_key,
                    encryption_secret,
                    encryption_public,
                };
            }
        }
    }

    let identity = Identity::generate();

    let stored = StoredIdentity {
        signing_key: identity.signing_key.to_bytes(),
        encryption_secret: identity.encryption_secret.to_bytes(),
    };

    if let Ok(json) = serde_json::to_vec(&stored) {
        let _ = encrypted_write(user, path, &json);
    }

    identity
}

/* ================= PREKEY POOL ================= */

pub fn load_or_create_prekey_pool(user: &str) -> PreKeyPool {
    let _ = fs::create_dir_all(storage_dir(user));
    let path = prekey_path(user);

    if Path::new(&path).exists() {
        if let Some(decrypted) = encrypted_read(user, path.clone()) {
            if let Ok(pool) = serde_json::from_slice::<PreKeyPool>(&decrypted) {
                return pool;
            }
        }
    }

    let mut pool = PreKeyPool {
        unused: Vec::new(),
        used: Vec::new(),
    };

    for _ in 0..PREKEY_POOL_SIZE {
        let pk = generate_one_time_prekey();
        pool.unused.push(StoredPreKey {
            id: pk.id,
            secret: pk.secret.to_bytes(),
            public: *pk.public.as_bytes(),
        });
    }

    persist_pool(user, &pool);
    pool
}

pub fn take_prekey(user: &str, pool: &mut PreKeyPool) -> StoredPreKey {
    auto_refill(pool);
    let pk = pool.unused.remove(0);
    pool.used.push(pk.clone());
    persist_pool(user, pool);
    pk
}

fn auto_refill(pool: &mut PreKeyPool) {
    if pool.unused.len() < REFILL_THRESHOLD {
        for _ in 0..REFILL_BATCH {
            let pk = generate_one_time_prekey();
            pool.unused.push(StoredPreKey {
                id: pk.id,
                secret: pk.secret.to_bytes(),
                public: *pk.public.as_bytes(),
            });
        }
    }
}

fn persist_pool(user: &str, pool: &PreKeyPool) {
    if let Ok(json) = serde_json::to_vec(pool) {
        let _ = encrypted_write(user, prekey_path(user), &json);
    }
}

/* ================= SIGNED PREKEY ================= */

pub fn load_or_rotate_signed_prekey(user: &str, identity: &Identity) -> SignedPreKey {
    let _ = fs::create_dir_all(storage_dir(user));
    let path = signed_prekey_path(user);
    let now = current_time();

    if Path::new(&path).exists() {
        if let Some(decrypted) = encrypted_read(user, path.clone()) {
            if let Ok(stored) = serde_json::from_slice::<SignedPreKey>(&decrypted) {
                if stored.expires_at > now {
                    return stored;
                }
            }
        }
    }

    let new_pk = generate_one_time_prekey();

    let mut message = Vec::new();
    message.extend_from_slice(&new_pk.id.to_be_bytes());
    message.extend_from_slice(new_pk.public.as_bytes());

    let signature = identity.signing_key.sign(&message);

    let spk = SignedPreKey {
        id: new_pk.id,
        secret: new_pk.secret.to_bytes(),
        public: *new_pk.public.as_bytes(),
        signature: signature.to_bytes().to_vec(),
        created_at: now,
        expires_at: now + SIGNED_PREKEY_TTL,
    };

    if let Ok(json) = serde_json::to_vec(&spk) {
        let _ = encrypted_write(user, path, &json);
    }

    spk
}

fn current_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/* ================= PEERS (PUBLIC ONLY) ================= */

#[derive(Serialize, Deserialize)]
pub struct KnownPeer {
    pub verifying_key: [u8; 32],
}

pub(crate) fn peer_dir(user: &str) -> String {
    format!("{}/peers", storage_dir(user))
}

pub(crate) fn peer_path(user: &str, identity_hex: &str) -> String {
    format!("{}/{}.json", peer_dir(user), identity_hex)
}

pub fn load_peer(user: &str, identity_hex: &str) -> Option<KnownPeer> {
    let path = peer_path(user, identity_hex);
    if Path::new(&path).exists() {
        let data = fs::read_to_string(path).ok()?;
        serde_json::from_str(&data).ok()
    } else {
        None
    }
}

pub fn save_peer(user: &str, identity_hex: &str, verifying_key: [u8; 32]) {
    let _ = fs::create_dir_all(peer_dir(user));
    let peer = KnownPeer { verifying_key };
    if let Ok(json) = serde_json::to_string_pretty(&peer) {
        let _ = fs::write(peer_path(user, identity_hex), json);
    }
}
