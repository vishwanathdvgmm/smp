use smp_crypto_core::{
    encryption::{decrypt, encrypt},
    handshake::{derive_session_key, generate_ephemeral},
    identity::Identity,
    prekey::{create_prekey_bundle, generate_one_time_prekey, verify_prekey_bundle},
};

use smp_protocol::packet::{SMP_VERSION, SmpPacket, compute_message_id, identity_hash};

use reqwest::Client;
use std::time::{SystemTime, UNIX_EPOCH};
use x25519_dalek::PublicKey;

#[tokio::main]
async fn main() {
    let client = Client::new();

    // -------------------------
    // Bob Setup
    // -------------------------
    let bob = Identity::generate();
    let one_time = generate_one_time_prekey();

    let bundle = create_prekey_bundle(&bob.signing_key, bob.verifying_key, &one_time);

    verify_prekey_bundle(&bundle).unwrap();

    println!("Bob ready.");
    println!(
        "Bob recipient hash: {}",
        hex::encode(identity_hash(bob.verifying_key.as_bytes()))
    );

    // -------------------------
    // Alice Sends Message
    // -------------------------
    let alice = Identity::generate();

    let eph = generate_ephemeral();

    let alice_session_key = derive_session_key(&eph.secret, &bundle.prekey_public);

    let plaintext = b"Hello Bob over network!";

    let mut packet = SmpPacket {
        version: SMP_VERSION,
        flags: 0,
        message_id: [0u8; 32],
        prekey_id: bundle.prekey_id,
        sender_identity_hash: identity_hash(alice.verifying_key.as_bytes()),
        recipient_identity_hash: identity_hash(bob.verifying_key.as_bytes()),
        ephemeral_pubkey: eph.public.to_bytes(),
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        nonce: [0u8; 12],
        ciphertext: vec![],
        signature: [0u8; 64],
    };

    let associated_data = packet.serialize_header_for_aad();

    let (ciphertext, nonce) = encrypt(&alice_session_key, plaintext, &associated_data).unwrap();

    packet.nonce = nonce;
    packet.ciphertext = ciphertext;

    packet.message_id = compute_message_id(
        &packet.ephemeral_pubkey,
        packet.timestamp,
        &packet.ciphertext,
    );

    packet.sign(&alice.signing_key);

    // Send to relay
    let res = client
        .post("http://127.0.0.1:3000/send")
        .json(&packet)
        .send()
        .await
        .unwrap();

    println!("Relay response: {:?}", res.text().await.unwrap());

    // -------------------------
    // Bob Fetches
    // -------------------------
    let recipient_hex = hex::encode(identity_hash(bob.verifying_key.as_bytes()));

    let messages: Vec<Vec<u8>> = client
        .get(format!("http://127.0.0.1:3000/inbox/{}", recipient_hex))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    println!("Bob received {} message(s)", messages.len());

    if let Some(raw) = messages.first() {
        let packet: SmpPacket = serde_json::from_slice(raw).unwrap();

        packet.validate(&alice.verifying_key).unwrap();

        let alice_ephemeral_pub = PublicKey::from(packet.ephemeral_pubkey);

        let bob_session_key = derive_session_key(&one_time.secret, &alice_ephemeral_pub);

        let associated_data = packet.serialize_header_for_aad();

        let decrypted = decrypt(
            &bob_session_key,
            &packet.ciphertext,
            &packet.nonce,
            &associated_data,
        )
        .unwrap();

        println!("Bob decrypted: {}", String::from_utf8(decrypted).unwrap());
    }
}
