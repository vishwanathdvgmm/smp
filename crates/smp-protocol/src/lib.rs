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

            message_id: [0u8; 32],

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
    use super::packet::*;
    use smp_crypto_core::{
        encryption::{decrypt, encrypt},
        handshake::{derive_session_key, generate_ephemeral},
        identity::Identity,
    };
    use std::time::{SystemTime, UNIX_EPOCH};
    use x25519_dalek::PublicKey;

    #[test]
    fn test_full_async_message_flow() {
        // Generate identities
        let alice = Identity::generate();
        let bob = Identity::generate();

        // Alice generates ephemeral key
        let eph = generate_ephemeral();

        // Alice derives session key
        let alice_session_key = derive_session_key(&eph.secret, &bob.encryption_public);

        // Alice encrypts message
        let plaintext = b"Hello Bob, this is SMP.";

        // Construct packet FIRST (without ciphertext & signature)
        let mut packet = SmpPacket {
            version: SMP_VERSION,
            flags: 0,

            message_id: [0u8; 32],

            sender_identity_hash: identity_hash(alice.verifying_key.as_bytes()),
            recipient_identity_hash: identity_hash(bob.verifying_key.as_bytes()),

            ephemeral_pubkey: eph.public.to_bytes(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),

            nonce: [0u8; 12],   // temporary placeholder
            ciphertext: vec![], // temporary placeholder
            signature: [0u8; 64],
        };

        // Associated Data = header (without signature)
        let associated_data = packet.serialize_aad();

        // Encrypt using AAD
        let (ciphertext, nonce) =
            encrypt(&alice_session_key, plaintext, &associated_data).expect("Encryption failed");

        let message_id =
            compute_message_id(&packet.ephemeral_pubkey, packet.timestamp, &ciphertext);

        packet.message_id = message_id;

        packet.nonce = nonce;
        packet.ciphertext = ciphertext;

        // Alice signs packet
        packet.sign(&alice.signing_key);

        // Bob verifies signature
        packet
            .validate(&alice.verifying_key)
            .expect("Packet validation failed");

        // Bob reconstructs ephemeral public key
        let alice_ephemeral_pub = PublicKey::from(packet.ephemeral_pubkey);

        // Bob derives session key
        let bob_session_key = derive_session_key(&bob.encryption_secret, &alice_ephemeral_pub);

        // Bob decrypts
        // Recompute associated data on Bob side
        let associated_data = packet.serialize_aad();

        let decrypted = decrypt(
            &bob_session_key,
            &packet.ciphertext,
            &packet.nonce,
            &associated_data,
        )
        .expect("Decryption failed");

        assert_eq!(plaintext.to_vec(), decrypted);
    }
}
