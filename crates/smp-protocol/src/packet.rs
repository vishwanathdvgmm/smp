use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::ProtocolError;

const MAX_CLOCK_SKEW_SECS: u64 = 5 * 60;
const MAX_PACKET_AGE_SECS: u64 = 24 * 60 * 60;

pub const SMP_VERSION: u8 = 1;

pub fn identity_hash(pubkey_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(pubkey_bytes);
    hasher.finalize().into()
}

pub fn compute_message_id(
    ephemeral_pubkey: &[u8; 32],
    timestamp: u64,
    ciphertext: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ephemeral_pubkey);
    hasher.update(timestamp.to_be_bytes());
    hasher.update(ciphertext);
    hasher.finalize().into()
}

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

#[derive(Clone, Serialize, Deserialize)]
pub struct SmpPacket {
    pub version: u8,
    pub flags: u8,

    pub message_id: [u8; 32],

    pub prekey_id: u32,

    pub sender_identity_hash: [u8; 32],
    pub recipient_identity_hash: [u8; 32],

    pub ephemeral_pubkey: [u8; 32],
    pub timestamp: u64,

    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,

    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

impl SmpPacket {
    pub fn serialize_without_signature(&self) -> Vec<u8> {
        let mut out = Vec::new();

        out.push(self.version);
        out.push(self.flags);

        out.extend_from_slice(&self.message_id);
        out.extend_from_slice(&self.prekey_id.to_be_bytes());

        out.extend_from_slice(&self.sender_identity_hash);
        out.extend_from_slice(&self.recipient_identity_hash);
        out.extend_from_slice(&self.ephemeral_pubkey);

        out.extend_from_slice(&self.timestamp.to_be_bytes());

        out.extend_from_slice(&self.nonce);

        let ct_len = (self.ciphertext.len() as u32).to_be_bytes();
        out.extend_from_slice(&ct_len);
        out.extend_from_slice(&self.ciphertext);

        out
    }

    pub fn serialize_aad(&self) -> Vec<u8> {
        let mut out = Vec::new();

        out.push(self.version);
        out.push(self.flags);

        out.extend_from_slice(&self.sender_identity_hash);
        out.extend_from_slice(&self.recipient_identity_hash);
        out.extend_from_slice(&self.ephemeral_pubkey);

        out.extend_from_slice(&self.timestamp.to_be_bytes());

        // Note: Nonce and ciphertext are NOT included in AAD
        // as they are generated/finalized during/after encryption.

        out
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = self.serialize_without_signature();
        out.extend_from_slice(&self.signature);
        out
    }
}

impl SmpPacket {
    pub fn sign(&mut self, signing_key: &ed25519_dalek::SigningKey) {
        let message = self.serialize_without_signature();
        let sig: Signature = signing_key.sign(&message);
        self.signature = sig.to_bytes();
    }

    pub fn verify(&self, verifying_key: &VerifyingKey) -> Result<(), ProtocolError> {
        let message = self.serialize_without_signature();
        let sig = Signature::from_bytes(&self.signature);

        verifying_key
            .verify(&message, &sig)
            .map_err(|_| ProtocolError::SignatureInvalid)
    }
}

impl SmpPacket {
    pub fn validate_timestamp(&self) -> Result<(), crate::error::ProtocolError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| crate::error::ProtocolError::InvalidFormat)?
            .as_secs();

        // Reject if timestamp too far in future
        if self.timestamp > now + MAX_CLOCK_SKEW_SECS {
            return Err(crate::error::ProtocolError::InvalidFormat);
        }

        // Reject if packet too old
        if now > self.timestamp + MAX_PACKET_AGE_SECS {
            return Err(crate::error::ProtocolError::InvalidFormat);
        }

        Ok(())
    }
}

impl SmpPacket {
    pub fn validate(
        &self,
        verifying_key: &ed25519_dalek::VerifyingKey,
    ) -> Result<(), crate::error::ProtocolError> {
        // 1. Version check
        if self.version != SMP_VERSION {
            return Err(crate::error::ProtocolError::UnsupportedVersion);
        }

        // 2. Signature check
        self.verify(verifying_key)?;

        // 3. Timestamp check
        self.validate_timestamp()?;

        // 4. Basic structural sanity
        if self.ciphertext.is_empty() {
            return Err(crate::error::ProtocolError::InvalidFormat);
        }

        Ok(())
    }
}
