use smp_crypto_core::{
    encryption::{decrypt, encrypt},
    handshake::{derive_session_key, generate_ephemeral},
    identity::Identity,
    prekey::{create_prekey_bundle, verify_prekey_bundle, PreKeyBundle},
    ratchet::DoubleRatchet,
};

mod storage;
use storage::*;

mod session_store;
use session_store::*;

use smp_protocol::packet::{
    compute_message_id, identity_hash, SmpPacket, FLAG_USE_SIGNED_PREKEY, SMP_VERSION,
};

use reqwest::Client;
use std::time::{SystemTime, UNIX_EPOCH};
use x25519_dalek::{PublicKey, StaticSecret};

#[tokio::main]
async fn main() {
    let client = Client::new();

    /* ---------------- Bob Setup ---------------- */

    let bob = load_or_create_identity();
    let mut pool = load_or_create_prekey_pool();

    let recipient_hash = identity_hash(bob.verifying_key.as_bytes());
    let recipient_hex = hex::encode(recipient_hash);

    // Session keys MUST be separated per role
    let alice_session_key = format!("alice_{}", recipient_hex);
    let bob_session_key = format!("bob_{}", recipient_hex);

    let spk = load_or_rotate_signed_prekey(&bob);

    client
        .post("http://127.0.0.1:3000/signed_prekey")
        .json(&serde_json::json!({
            "identity_public_key": bob.verifying_key.as_bytes(),
            "prekey_id": spk.id,
            "public": spk.public,
            "signature": spk.signature,
            "created_at": spk.created_at,
            "expires_at": spk.expires_at,
        }))
        .send()
        .await
        .unwrap();

    println!("Bob uploaded signed prekey.");

    // Upload OPKs
    for _ in 0..5 {
        let stored_pk = take_prekey(&mut pool);

        let one_time = smp_crypto_core::prekey::OneTimePreKey {
            id: stored_pk.id,
            secret: StaticSecret::from(stored_pk.secret),
            public: PublicKey::from(stored_pk.public),
        };

        let bundle = create_prekey_bundle(&bob.signing_key, bob.verifying_key, &one_time);

        client
            .post("http://127.0.0.1:3000/prekey")
            .json(&bundle)
            .send()
            .await
            .unwrap();
    }

    println!("Bob uploaded OPKs.");

    /* ---------------- Alice Fetch ---------------- */

    let fetched_opk: Option<Vec<u8>> = client
        .get(format!("http://127.0.0.1:3000/prekey/{}", recipient_hex))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let mut using_spk = false;
    let prekey_id;
    let peer_public;

    if let Some(bytes) = fetched_opk {
        let bundle: PreKeyBundle = serde_json::from_slice(&bytes).unwrap();
        verify_prekey_bundle(&bundle).unwrap();

        println!("Alice using OPK.");

        prekey_id = bundle.prekey_id;
        peer_public = bundle.prekey_public;
    } else {
        let fetched_spk: Option<Vec<u8>> = client
            .get(format!(
                "http://127.0.0.1:3000/signed_prekey/{}",
                recipient_hex
            ))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        let spk_json = fetched_spk.expect("No Signed PreKey found");
        let spk_value: serde_json::Value = serde_json::from_slice(&spk_json).unwrap();

        prekey_id = spk_value["prekey_id"].as_u64().unwrap() as u32;

        let public_vec: Vec<u8> = spk_value["public"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap() as u8)
            .collect();

        peer_public = PublicKey::from(<[u8; 32]>::try_from(public_vec).unwrap());
        using_spk = true;

        println!("Alice using Signed PreKey fallback.");
    }

    /* ---------------- Alice Sends ---------------- */

    let alice = Identity::generate();
    let eph = generate_ephemeral();

    let shared_secret = derive_session_key(&eph.secret, &peer_public);
    println!("Alice shared: {}", hex::encode(shared_secret));

    let mut alice_ratchet =
        load_session(&alice_session_key).unwrap_or_else(|| DoubleRatchet::new(shared_secret));

    let (message_key, msg_number) = alice_ratchet.next_sending_key().unwrap();

    let plaintext = b"Hello Bob over network!";

    let mut packet = SmpPacket {
        version: SMP_VERSION,
        flags: if using_spk { FLAG_USE_SIGNED_PREKEY } else { 0 },
        message_id: [0u8; 32],
        prekey_id,
        message_number: msg_number,
        dh_ratchet_pub: None,
        sender_identity_hash: identity_hash(alice.verifying_key.as_bytes()),
        recipient_identity_hash: recipient_hash,
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

    let (ciphertext, nonce) = encrypt(&message_key, plaintext, &associated_data).unwrap();

    packet.nonce = nonce;
    packet.ciphertext = ciphertext;

    packet.message_id = compute_message_id(
        &packet.ephemeral_pubkey,
        packet.timestamp,
        &packet.ciphertext,
    );

    packet.sign(&alice.signing_key);

    client
        .post("http://127.0.0.1:3000/send")
        .json(&packet)
        .send()
        .await
        .unwrap();

    save_session(&alice_session_key, &alice_ratchet);

    println!("Alice sent encrypted message.");

    /* ---------------- Bob Fetch ---------------- */

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

        let bob_secret = if packet.flags & FLAG_USE_SIGNED_PREKEY != 0 {
            println!("Bob decrypting via Signed PreKey.");
            StaticSecret::from(spk.secret)
        } else {
            println!("Bob decrypting via OPK.");

            let pool = load_or_create_prekey_pool();
            let matching = pool
                .used
                .iter()
                .find(|p| p.id == packet.prekey_id)
                .expect("Matching OPK not found");

            StaticSecret::from(matching.secret)
        };

        let shared_secret = derive_session_key(&bob_secret, &alice_ephemeral_pub);
        println!("Bob shared: {}", hex::encode(shared_secret));

        let mut bob_ratchet =
            load_session(&bob_session_key).unwrap_or_else(|| DoubleRatchet::new(shared_secret));

        let message_key = bob_ratchet.receive_key(packet.message_number).unwrap();

        let associated_data = packet.serialize_header_for_aad();

        let decrypted = decrypt(
            &message_key,
            &packet.ciphertext,
            &packet.nonce,
            &associated_data,
        )
        .unwrap();

        save_session(&bob_session_key, &bob_ratchet);

        println!("Bob decrypted: {}", String::from_utf8(decrypted).unwrap());
    }
}
