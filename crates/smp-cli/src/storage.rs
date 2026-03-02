use serde::{Deserialize, Serialize};
use smp_crypto_core::{identity::Identity, prekey::generate_one_time_prekey};
use std::{
    fs,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::{Signer, SigningKey};
use x25519_dalek::{PublicKey, StaticSecret};

const PREKEY_POOL_SIZE: usize = 20;
const REFILL_THRESHOLD: usize = 5;
const REFILL_BATCH: usize = 10;
const SIGNED_PREKEY_TTL: u64 = 60;

/* ================= PATH HELPERS ================= */

pub fn storage_dir(user: &str) -> String {
    format!(".smp/{}", user)
}

fn identity_path(user: &str) -> String {
    format!("{}/identity.json", storage_dir(user))
}

fn prekey_path(user: &str) -> String {
    format!("{}/prekeys.json", storage_dir(user))
}

fn signed_prekey_path(user: &str) -> String {
    format!("{}/signed_prekey.json", storage_dir(user))
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
    fs::create_dir_all(&dir).unwrap();

    let path = identity_path(user);

    if Path::new(&path).exists() {
        let data = fs::read_to_string(path).unwrap();
        let stored: StoredIdentity = serde_json::from_str(&data).unwrap();

        let signing_key = SigningKey::from_bytes(&stored.signing_key);
        let verifying_key = signing_key.verifying_key();

        let encryption_secret = StaticSecret::from(stored.encryption_secret);
        let encryption_public = PublicKey::from(&encryption_secret);

        Identity {
            signing_key,
            verifying_key,
            encryption_secret,
            encryption_public,
        }
    } else {
        let identity = Identity::generate();

        let stored = StoredIdentity {
            signing_key: identity.signing_key.to_bytes(),
            encryption_secret: identity.encryption_secret.to_bytes(),
        };

        fs::write(&path, serde_json::to_string_pretty(&stored).unwrap()).unwrap();

        identity
    }
}

/* ================= PREKEY POOL ================= */

pub fn load_or_create_prekey_pool(user: &str) -> PreKeyPool {
    let dir = storage_dir(user);
    fs::create_dir_all(&dir).unwrap();

    let path = prekey_path(user);

    if Path::new(&path).exists() {
        let data = fs::read_to_string(path).unwrap();
        serde_json::from_str(&data).unwrap()
    } else {
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
    fs::write(
        prekey_path(user),
        serde_json::to_string_pretty(pool).unwrap(),
    )
    .unwrap();
}

/* ================= SIGNED PREKEY ================= */

pub fn load_or_rotate_signed_prekey(user: &str, identity: &Identity) -> SignedPreKey {
    let dir = storage_dir(user);
    fs::create_dir_all(&dir).unwrap();

    let path = signed_prekey_path(user);
    let now = current_time();

    if Path::new(&path).exists() {
        let data = fs::read_to_string(&path).unwrap();
        let stored: SignedPreKey = serde_json::from_str(&data).unwrap();

        if stored.expires_at > now {
            return stored;
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

    fs::write(&path, serde_json::to_string_pretty(&spk).unwrap()).unwrap();

    spk
}

fn current_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[allow(dead_code)]
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

#[allow(dead_code)]
pub fn load_peer(user: &str, identity_hex: &str) -> Option<KnownPeer> {
    let path = peer_path(user, identity_hex);

    if Path::new(&path).exists() {
        let data = fs::read_to_string(path).ok()?;
        serde_json::from_str(&data).ok()
    } else {
        None
    }
}

#[allow(dead_code)]
pub fn save_peer(user: &str, identity_hex: &str, verifying_key: [u8; 32]) {
    let dir = peer_dir(user);
    let _ = fs::create_dir_all(&dir);

    let peer = KnownPeer { verifying_key };

    fs::write(
        peer_path(user, identity_hex),
        serde_json::to_string_pretty(&peer).unwrap(),
    )
    .ok();
}
