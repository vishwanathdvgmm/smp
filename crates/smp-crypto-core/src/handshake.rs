use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use rand::rngs::OsRng;

pub struct EphemeralKeyPair {
    pub secret: StaticSecret,
    pub public: PublicKey,
}

pub fn generate_ephemeral() -> EphemeralKeyPair {
    let mut rng = OsRng;
    let secret = StaticSecret::random_from_rng(&mut rng);
    let public = PublicKey::from(&secret);

    EphemeralKeyPair { secret, public }
}

pub fn derive_session_key(
    my_secret: &StaticSecret,
    their_public: &PublicKey,
) -> [u8; 32] {
    let shared = my_secret.diffie_hellman(their_public);

    let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(b"smp-session-key", &mut okm)
        .expect("HKDF expand failed");

    okm
}
