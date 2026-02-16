use serde::{Deserialize, Serialize};
use smp_crypto_core::{identity::Identity, prekey::generate_one_time_prekey};
use std::{fs, path::Path};

use ed25519_dalek::SigningKey;
use x25519_dalek::{PublicKey, StaticSecret};

const STORAGE_DIR: &str = ".smp";
const IDENTITY_FILE: &str = ".smp/identity.json";
const PREKEY_FILE: &str = ".smp/prekeys.json";

const PREKEY_POOL_SIZE: usize = 20;
const REFILL_THRESHOLD: usize = 5;
const REFILL_BATCH: usize = 10;

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
    pub consumed: Vec<u32>,
}

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

pub fn load_or_create_prekey_pool() -> PreKeyPool {
    fs::create_dir_all(STORAGE_DIR).unwrap();

    if Path::new(PREKEY_FILE).exists() {
        let data = fs::read_to_string(PREKEY_FILE).unwrap();
        serde_json::from_str(&data).unwrap()
    } else {
        let mut pool = PreKeyPool {
            unused: Vec::new(),
            consumed: Vec::new(),
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
    pool.consumed.push(pk.id);

    persist_pool(pool);

    pk
}

fn auto_refill(pool: &mut PreKeyPool) {
    if pool.unused.len() < REFILL_THRESHOLD {
        println!(
            "PreKey pool low ({} remaining). Refilling...",
            pool.unused.len()
        );

        for _ in 0..REFILL_BATCH {
            let pk = generate_one_time_prekey();

            pool.unused.push(StoredPreKey {
                id: pk.id,
                secret: pk.secret.to_bytes(),
                public: *pk.public.as_bytes(),
            });
        }

        println!("PreKey pool refilled.");
    }
}

fn persist_pool(pool: &PreKeyPool) {
    fs::write(PREKEY_FILE, serde_json::to_string_pretty(pool).unwrap()).unwrap();
}
