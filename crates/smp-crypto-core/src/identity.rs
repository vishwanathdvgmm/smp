use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

pub struct Identity {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
    pub encryption_secret: StaticSecret,
    pub encryption_public: PublicKey,
}

impl Identity {
    pub fn generate() -> Self {
        let mut rng = OsRng;

        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();

        let encryption_secret = StaticSecret::random_from_rng(&mut rng);
        let encryption_public = PublicKey::from(&encryption_secret);

        Self {
            signing_key,
            verifying_key,
            encryption_secret,
            encryption_public,
        }
    }
}
