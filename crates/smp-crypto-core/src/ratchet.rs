use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;

const MAX_SKIP: u32 = 1000;

#[derive(Serialize, Deserialize, Clone)]
pub struct DoubleRatchet {
    // Root key from X3DH / initial handshake
    pub root_key: [u8; 32],

    // Sending & receiving chain keys
    pub chain_key_send: Option<[u8; 32]>,
    pub chain_key_recv: Option<[u8; 32]>,

    // Message counters
    pub ns: u32, // number sent
    pub nr: u32, // number received

    // Skipped message keys (for out-of-order delivery)
    pub skipped_keys: HashMap<u32, [u8; 32]>,
}

impl DoubleRatchet {
    // =============================
    // Initialization
    // =============================

    pub fn new(shared_secret: [u8; 32]) -> Self {
        // Derive initial send & receive chains from shared secret
        let (initial_chain, _) = Self::kdf_chain(&shared_secret);

        Self {
            root_key: shared_secret,
            chain_key_send: Some(initial_chain),
            chain_key_recv: Some(initial_chain),
            ns: 0,
            nr: 0,
            skipped_keys: HashMap::new(),
        }
    }

    // =============================
    // HKDF Root Derivation
    // =============================

    #[allow(dead_code)]
    fn kdf_root(root_key: &[u8; 32], dh_output: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
        let hk = Hkdf::<Sha256>::new(Some(root_key), dh_output);

        let mut new_root = [0u8; 32];
        let mut new_chain = [0u8; 32];

        hk.expand(b"SMP_ROOT", &mut new_root)
            .expect("HKDF root expand failed");
        hk.expand(b"SMP_CHAIN", &mut new_chain)
            .expect("HKDF chain expand failed");

        (new_root, new_chain)
    }

    // =============================
    // HKDF Chain Derivation
    // =============================

    fn kdf_chain(chain_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
        let hk = Hkdf::<Sha256>::new(None, chain_key);

        let mut new_chain = [0u8; 32];
        let mut message_key = [0u8; 32];

        hk.expand(b"SMP_CHAIN_NEXT", &mut new_chain)
            .expect("HKDF chain next failed");
        hk.expand(b"SMP_MESSAGE_KEY", &mut message_key)
            .expect("HKDF message key failed");

        (new_chain, message_key)
    }

    // =============================
    // Sending Key
    // =============================

    pub fn next_sending_key(&mut self) -> Result<([u8; 32], u32), String> {
        let ck = self.chain_key_send.ok_or("Send chain not initialized")?;

        let (new_ck, mk) = Self::kdf_chain(&ck);

        self.chain_key_send = Some(new_ck);
        let msg_number = self.ns;
        self.ns += 1;

        Ok((mk, msg_number))
    }

    // =============================
    // Receiving Key
    // =============================

    pub fn receive_key(&mut self, message_number: u32) -> Result<[u8; 32], String> {
        // Replay protection
        if message_number < self.nr {
            if let Some(key) = self.skipped_keys.remove(&message_number) {
                return Ok(key);
            }
            return Err("Replay detected".into());
        }

        // Skip window protection
        if message_number - self.nr > MAX_SKIP {
            return Err("Ratchet window exceeded".into());
        }

        // Advance chain to target message
        while self.nr < message_number {
            let ck = self.chain_key_recv.ok_or("Recv chain not initialized")?;

            let (new_ck, mk) = Self::kdf_chain(&ck);

            self.chain_key_recv = Some(new_ck);
            self.skipped_keys.insert(self.nr + 1, mk);

            self.nr += 1;
        }

        // Derive actual message key
        let ck = self.chain_key_recv.ok_or("Recv chain not initialized")?;

        let (new_ck, mk) = Self::kdf_chain(&ck);

        self.chain_key_recv = Some(new_ck);
        self.nr += 1;

        Ok(mk)
    }
}
