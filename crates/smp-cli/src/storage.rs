use serde::{Deserialize, Serialize};
use smp_crypto_core::{identity::Identity, prekey::generate_one_time_prekey};
use std::{
    fs,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::{Signer, SigningKey};
use x25519_dalek::{PublicKey, StaticSecret};

pub const STORAGE_DIR: &str = ".smp";
const IDENTITY_FILE: &str = ".smp/identity.json";
const PREKEY_FILE: &str = ".smp/prekeys.json";
const SIGNED_PREKEY_FILE: &str = ".smp/signed_prekey.json";

const PREKEY_POOL_SIZE: usize = 20;
const REFILL_THRESHOLD: usize = 5;
const REFILL_BATCH: usize = 10;

// 60 seconds for testing rotation
const SIGNED_PREKEY_TTL: u64 = 60;

#[derive(Serialize, Deserialize)]
pub struct StoredIdentity {
    pub signing_key: [u8; 32],
    pub encryption_secret: [u8; 32],
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

/* ---------------- Identity ---------------- */

pub fn load_or_create_identity() -> Identity {
    fs::create_dir_all(STORAGE_DIR).unwrap();

    if Path::new(IDENTITY_FILE).exists() {
        let data = fs::read_to_string(IDENTITY_FILE).unwrap();
        let stored: StoredIdentity = serde_json::from_str(&data).unwrap();

        let signing_key = SigningKey::from_bytes(&stored.signing_key);
        let encryption_secret = StaticSecret::from(stored.encryption_secret);
        let verifying_key = signing_key.verifying_key();
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

        fs::write(
            IDENTITY_FILE,
            serde_json::to_string_pretty(&stored).unwrap(),
        )
        .unwrap();

        identity
    }
}

/* ---------------- One-Time PreKey Pool ---------------- */

pub fn load_or_create_prekey_pool() -> PreKeyPool {
    fs::create_dir_all(STORAGE_DIR).unwrap();

    if Path::new(PREKEY_FILE).exists() {
        let data = fs::read_to_string(PREKEY_FILE).unwrap();
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

        persist_pool(&pool);
        pool
    }
}

pub fn take_prekey(pool: &mut PreKeyPool) -> StoredPreKey {
    auto_refill(pool);

    let pk = pool.unused.remove(0);
    pool.used.push(pk.clone());

    persist_pool(pool);
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

fn persist_pool(pool: &PreKeyPool) {
    fs::write(PREKEY_FILE, serde_json::to_string_pretty(pool).unwrap()).unwrap();
}

/* ---------------- Signed PreKey ---------------- */

pub fn load_or_rotate_signed_prekey(identity: &Identity) -> SignedPreKey {
    fs::create_dir_all(STORAGE_DIR).unwrap();

    let now = current_time();

    if Path::new(SIGNED_PREKEY_FILE).exists() {
        let data = fs::read_to_string(SIGNED_PREKEY_FILE).unwrap();
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

    fs::write(
        SIGNED_PREKEY_FILE,
        serde_json::to_string_pretty(&spk).unwrap(),
    )
    .unwrap();

    spk
}

fn current_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
