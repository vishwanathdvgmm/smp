use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::{HashMap, VecDeque};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CryptoError;

const MAX_SKIP: u32 = 1000;
const MAX_STORED_SKIPPED: usize = 200;

#[derive(Serialize, Deserialize, Clone, Zeroize, ZeroizeOnDrop)]
pub struct DoubleRatchet {
    pub root_key: [u8; 32],

    pub dh_self_secret: [u8; 32],
    pub dh_self_public: [u8; 32],
    pub dh_remote_public: Option<[u8; 32]>,

    pub chain_key_send: Option<[u8; 32]>,
    pub chain_key_recv: Option<[u8; 32]>,

    pub ns: u32,
    pub nr: u32,
    pub pn: u32,

    #[zeroize(skip)]
    pub skipped_keys: HashMap<String, [u8; 32]>,

    #[zeroize(skip)]
    pub skipped_order: VecDeque<String>,
}

impl DoubleRatchet {
    /* ================= INITIALIZATION ================= */

    pub fn new(shared_secret: [u8; 32]) -> Self {
        let dh_secret = StaticSecret::random();
        let dh_public = PublicKey::from(&dh_secret);

        Self {
            root_key: shared_secret,
            dh_self_secret: dh_secret.to_bytes(),
            dh_self_public: dh_public.to_bytes(),
            dh_remote_public: None,
            chain_key_send: None,
            chain_key_recv: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped_keys: HashMap::new(),
            skipped_order: VecDeque::new(),
        }
    }

    /* ================= KDF ================= */

    fn kdf_root(
        root_key: &[u8; 32],
        dh_output: &[u8; 32],
    ) -> Result<([u8; 32], [u8; 32]), CryptoError> {
        let hk = Hkdf::<Sha256>::new(Some(root_key), dh_output);

        let mut new_root = [0u8; 32];
        let mut new_chain = [0u8; 32];

        hk.expand(b"SMP_ROOT", &mut new_root)
            .map_err(|_| CryptoError::InvalidKey)?;
        hk.expand(b"SMP_CHAIN", &mut new_chain)
            .map_err(|_| CryptoError::InvalidKey)?;

        Ok((new_root, new_chain))
    }

    fn kdf_chain(chain_key: &[u8; 32]) -> Result<([u8; 32], [u8; 32]), CryptoError> {
        let hk = Hkdf::<Sha256>::new(None, chain_key);

        let mut new_chain = [0u8; 32];
        let mut message_key = [0u8; 32];

        hk.expand(b"SMP_CHAIN_NEXT", &mut new_chain)
            .map_err(|_| CryptoError::InvalidKey)?;
        hk.expand(b"SMP_MESSAGE_KEY", &mut message_key)
            .map_err(|_| CryptoError::InvalidKey)?;

        Ok((new_chain, message_key))
    }

    /* ================= SKIPPED KEY STORAGE ================= */

    fn store_skipped(&mut self, msg: u32, key: [u8; 32]) {
        if let Some(remote) = self.dh_remote_public {
            let index = (remote, msg);

            if self.skipped_keys.len() >= MAX_STORED_SKIPPED {
                if let Some(old) = self.skipped_order.pop_front() {
                    self.skipped_keys.remove(&old);
                }
            }

            self.skipped_keys.insert(index, key);
            self.skipped_order.push_back(index);
        }
    }

    fn take_skipped(&mut self, msg: u32) -> Option<[u8; 32]> {
        if let Some(remote) = self.dh_remote_public {
            let index = (remote, msg);
            if let Some(k) = self.skipped_keys.remove(&index) {
                return Some(k);
            }
        }
        None
    }

    /* ================= DH RATCHET STEP ================= */

    pub fn dh_ratchet_step(&mut self, remote_pub: [u8; 32]) -> Result<(), CryptoError> {
        let remote = PublicKey::from(remote_pub);
        let self_secret = StaticSecret::from(self.dh_self_secret);

        let dh1 = self_secret.diffie_hellman(&remote).to_bytes();
        let (new_root, new_recv_chain) = Self::kdf_root(&self.root_key, &dh1)?;

        self.root_key = new_root;
        self.chain_key_recv = Some(new_recv_chain);

        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;

        self.dh_remote_public = Some(remote_pub);

        let new_secret = StaticSecret::random();
        let new_public = PublicKey::from(&new_secret);

        self.dh_self_secret = new_secret.to_bytes();
        self.dh_self_public = new_public.to_bytes();

        let dh2 = new_secret.diffie_hellman(&remote).to_bytes();
        let (new_root2, new_send_chain) = Self::kdf_root(&self.root_key, &dh2)?;

        self.root_key = new_root2;
        self.chain_key_send = Some(new_send_chain);

        Ok(())
    }

    pub fn init_sender(&mut self, remote_pub: [u8; 32]) -> Result<(), CryptoError> {
        let remote = PublicKey::from(remote_pub);
        let self_secret = StaticSecret::from(self.dh_self_secret);

        let dh = self_secret.diffie_hellman(&remote).to_bytes();
        let (new_root, send_chain) = Self::kdf_root(&self.root_key, &dh)?;

        self.root_key = new_root;
        self.chain_key_send = Some(send_chain);
        self.dh_remote_public = Some(remote_pub);

        Ok(())
    }

    pub fn advance_send_chain(&mut self, remote_pub: [u8; 32]) -> Result<(), CryptoError> {
        let remote = PublicKey::from(remote_pub);

        let new_secret = StaticSecret::random();
        let new_public = PublicKey::from(&new_secret);

        self.dh_self_secret = new_secret.to_bytes();
        self.dh_self_public = new_public.to_bytes();

        let dh = new_secret.diffie_hellman(&remote).to_bytes();
        let (new_root, send_chain) = Self::kdf_root(&self.root_key, &dh)?;

        self.root_key = new_root;
        self.chain_key_send = Some(send_chain);
        self.ns = 0;

        Ok(())
    }

    pub fn bootstrap_as_receiver(
        &mut self,
        self_secret_bytes: [u8; 32],
        remote_pub: [u8; 32],
    ) -> Result<(), CryptoError> {
        let self_secret = StaticSecret::from(self_secret_bytes);
        let remote = PublicKey::from(remote_pub);

        self.dh_self_secret = self_secret_bytes;
        self.dh_self_public = PublicKey::from(&self_secret).to_bytes();

        let dh = self_secret.diffie_hellman(&remote).to_bytes();
        let (new_root, recv_chain) = Self::kdf_root(&self.root_key, &dh)?;

        self.root_key = new_root;
        self.chain_key_recv = Some(recv_chain);
        self.dh_remote_public = Some(remote_pub);

        Ok(())
    }

    /* ================= SENDING ================= */

    pub fn next_sending_key(&mut self) -> Result<([u8; 32], u32), CryptoError> {
        let ck = self.chain_key_send.ok_or(CryptoError::InvalidKey)?;

        let (new_ck, mk) = Self::kdf_chain(&ck)?;

        self.chain_key_send = Some(new_ck);

        let msg_number = self.ns;
        self.ns += 1;

        Ok((mk, msg_number))
    }

    /* ================= RECEIVING ================= */

    pub fn receive_key(&mut self, message_number: u32) -> Result<[u8; 32], CryptoError> {
        if let Some(k) = self.take_skipped(message_number) {
            return Ok(k);
        }

        if message_number < self.nr {
            return Err(CryptoError::InvalidKey);
        }

        if message_number.saturating_sub(self.nr) > MAX_SKIP {
            return Err(CryptoError::InvalidKey);
        }

        while self.nr < message_number {
            let ck = self.chain_key_recv.ok_or(CryptoError::InvalidKey)?;

            let (new_ck, mk) = Self::kdf_chain(&ck)?;

            self.chain_key_recv = Some(new_ck);

            self.store_skipped(self.nr, mk);

            self.nr += 1;
        }

        let ck = self.chain_key_recv.ok_or(CryptoError::InvalidKey)?;

        let (new_ck, mk) = Self::kdf_chain(&ck)?;

        self.chain_key_recv = Some(new_ck);
        self.nr += 1;

        Ok(mk)
    }
}
