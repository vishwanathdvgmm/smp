pub mod encryption;
pub mod error;
pub mod handshake;
pub mod identity;

#[cfg(test)]
mod tests {
    use crate::identity::Identity;
    use crate::handshake::derive_shared_secret;
    use crate::encryption::{encrypt, decrypt};

    #[test]
    fn test_secure_message_flow() {
        let alice = Identity::generate();
        let bob = Identity::generate();

        let alice_key =
            derive_shared_secret(&alice.encryption_secret, &bob.encryption_public);

        let bob_key =
            derive_shared_secret(&bob.encryption_secret, &alice.encryption_public);

        assert_eq!(alice_key, bob_key);

        let message = b"Hello SMP";

        let (ciphertext, nonce) = encrypt(&alice_key, message).unwrap();

        let decrypted = decrypt(&bob_key, &ciphertext, &nonce).unwrap();

        assert_eq!(message.to_vec(), decrypted);
    }
}
