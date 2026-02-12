use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

pub fn derive_shared_secret(
    my_secret: &StaticSecret,
    their_public: &PublicKey,
) -> [u8; 32] {
    let shared = my_secret.diffie_hellman(their_public);

    let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(b"smp-session-key", &mut okm)
        .expect("HKDF expand should not fail");

    okm
}
