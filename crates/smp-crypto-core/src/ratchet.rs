use hkdf::Hkdf;
use sha2::Sha256;
use std::collections::HashMap;

pub struct RatchetState {
    pub root_key: [u8; 32],
    pub chain_key: [u8; 32],
    pub send_count: u32,
    pub recv_count: u32,
    pub skipped_keys: HashMap<u32, [u8; 32]>,
}

impl RatchetState {
    pub fn initialize(shared_secret: &[u8]) -> Self {
        let hk = Hkdf::<Sha256>::new(None, shared_secret);

        let mut root = [0u8; 32];
        hk.expand(b"root_key", &mut root).unwrap();

        let mut chain = [0u8; 32];
        hk.expand(b"chain_key", &mut chain).unwrap();

        Self {
            root_key: root,
            chain_key: chain,
            send_count: 0,
            recv_count: 0,
            skipped_keys: HashMap::new(),
        }
    }

    pub fn next_sending_key(&mut self) -> ([u8; 32], u32) {
        let hk = Hkdf::<Sha256>::new(None, &self.chain_key);

        let mut message_key = [0u8; 32];
        hk.expand(b"message_key", &mut message_key).unwrap();

        let mut new_chain = [0u8; 32];
        hk.expand(b"chain_step", &mut new_chain).unwrap();

        self.chain_key = new_chain;

        let number = self.send_count;
        self.send_count += 1;

        (message_key, number)
    }

    pub fn receive_key(&mut self, msg_number: u32) -> [u8; 32] {
        if let Some(key) = self.skipped_keys.remove(&msg_number) {
            return key;
        }

        while self.recv_count < msg_number {
            let skipped = self.derive_next_key();
            self.skipped_keys.insert(self.recv_count, skipped);
            self.recv_count += 1;
        }

        let key = self.derive_next_key();
        self.recv_count += 1;

        key
    }

    fn derive_next_key(&mut self) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(None, &self.chain_key);

        let mut message_key = [0u8; 32];
        hk.expand(b"message_key", &mut message_key).unwrap();

        let mut new_chain = [0u8; 32];
        hk.expand(b"chain_step", &mut new_chain).unwrap();

        self.chain_key = new_chain;

        message_key
    }
}
