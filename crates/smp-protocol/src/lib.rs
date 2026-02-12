pub mod error;
pub mod packet;

#[cfg(test)]
mod tests {
    use super::packet::*;
    use smp_crypto_core::identity::Identity;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_packet_sign_verify() {
        let alice = Identity::generate();

        let mut packet = SmpPacket {
            version: SMP_VERSION,
            flags: 0,

            sender_identity_hash: identity_hash(alice.verifying_key.as_bytes()),
            recipient_identity_hash: [0u8; 32],

            ephemeral_pubkey: [1u8; 32],
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),

            nonce: [2u8; 12],
            ciphertext: b"encrypted data".to_vec(),

            signature: [0u8; 64],
        };

        packet.sign(&alice.signing_key);

        assert!(packet.verify(&alice.verifying_key).is_ok());
    }
}

#[cfg(test)]
mod integration_tests {
    use smp_crypto_core::{
        encryption::{decrypt, encrypt},
        handshake::derive_shared_secret,
        identity::Identity,
    };

    use super::packet::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_full_async_message_flow() {
        // Generate identities
        let alice = Identity::generate();
        let bob = Identity::generate();

        // Alice derives shared session key
        let alice_session_key =
            derive_shared_secret(&alice.encryption_secret, &bob.encryption_public);

        // Bob derives same session key
        let bob_session_key =
            derive_shared_secret(&bob.encryption_secret, &alice.encryption_public);

        assert_eq!(alice_session_key, bob_session_key);

        // Alice encrypts message
        let plaintext = b"Hello Bob, this is SMP.";
        let (ciphertext, nonce) =
            encrypt(&alice_session_key, plaintext).expect("Encryption failed");

        // Construct packet
        let mut packet = SmpPacket {
            version: SMP_VERSION,
            flags: 0,

            sender_identity_hash: identity_hash(alice.verifying_key.as_bytes()),
            recipient_identity_hash: identity_hash(bob.verifying_key.as_bytes()),

            ephemeral_pubkey: alice.encryption_public.to_bytes(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),

            nonce,
            ciphertext,

            signature: [0u8; 64],
        };

        // Alice signs packet
        packet.sign(&alice.signing_key);

        // Bob verifies signature
        packet
            .verify(&alice.verifying_key)
            .expect("Signature verification failed");

        // Bob decrypts
        let decrypted = decrypt(&bob_session_key, &packet.ciphertext, &packet.nonce)
            .expect("Decryption failed");

        assert_eq!(plaintext.to_vec(), decrypted);
    }
}
