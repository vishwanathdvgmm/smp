pub mod encryption;
pub mod error;
pub mod handshake;
pub mod identity;
pub mod prekey;

#[cfg(test)]
mod tests {
    use crate::encryption::{decrypt, encrypt};
    use crate::handshake::derive_session_key;
    use crate::identity::Identity;

    #[test]
    fn test_secure_message_flow() {
        let alice = Identity::generate();
        let bob = Identity::generate();

        let alice_key = derive_session_key(&alice.encryption_secret, &bob.encryption_public);

        let bob_key = derive_session_key(&bob.encryption_secret, &alice.encryption_public);

        assert_eq!(alice_key, bob_key);

        let message = b"Hello SMP";

        let (ciphertext, nonce) = encrypt(&alice_key, message, &[]).unwrap();

        let decrypted = decrypt(&bob_key, &ciphertext, &nonce, &[]).unwrap();

        assert_eq!(message.to_vec(), decrypted);
    }
}

#[cfg(test)]
mod prekey_tests {
    use crate::identity::Identity;
    use crate::prekey::*;

    #[test]
    fn test_prekey_bundle_sign_verify() {
        let bob = Identity::generate();

        let one_time = generate_one_time_prekey();

        let bundle = create_prekey_bundle(&bob.signing_key, bob.verifying_key, &one_time);

        assert!(verify_prekey_bundle(&bundle).is_ok());
    }
}
