use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use rand::Rng;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::CryptoError;

pub struct OneTimePreKey {
    pub id: u32,
    pub secret: StaticSecret,
    pub public: PublicKey,
}

pub struct PreKeyBundle {
    pub identity_public_key: VerifyingKey,
    pub prekey_id: u32,
    pub prekey_public: PublicKey,
    pub signature: [u8; 64],
}

pub fn generate_one_time_prekey() -> OneTimePreKey {
    let mut rng = OsRng;
    let secret = StaticSecret::random_from_rng(&mut rng);
    let public = PublicKey::from(&secret);
    let id = rand::thread_rng().gen::<u32>();

    OneTimePreKey { id, secret, public }
}

pub fn create_prekey_bundle(
    signing_key: &SigningKey,
    identity_public: VerifyingKey,
    one_time: &OneTimePreKey,
) -> PreKeyBundle {
    let mut message = Vec::new();
    message.extend_from_slice(&one_time.id.to_be_bytes());
    message.extend_from_slice(one_time.public.as_bytes());

    let signature: Signature = signing_key.sign(&message);

    PreKeyBundle {
        identity_public_key: identity_public,
        prekey_id: one_time.id,
        prekey_public: one_time.public,
        signature: signature.to_bytes(),
    }
}

pub fn verify_prekey_bundle(bundle: &PreKeyBundle) -> Result<(), CryptoError> {
    let mut message = Vec::new();

    message.extend_from_slice(&bundle.prekey_id.to_be_bytes());
    message.extend_from_slice(bundle.prekey_public.as_bytes());

    let signature = Signature::from_bytes(&bundle.signature);

    bundle
        .identity_public_key
        .verify(&message, &signature)
        .map_err(|_| CryptoError::InvalidKey)
}
