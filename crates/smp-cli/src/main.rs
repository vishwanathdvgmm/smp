use smp_crypto_core::{
    encryption::{decrypt, encrypt},
    handshake::{derive_session_key, generate_ephemeral},
    prekey::{create_prekey_bundle, PreKeyBundle},
    ratchet::DoubleRatchet,
};

mod storage;
use storage::*;

mod session_store;
use session_store::*;

mod reliability;
use reliability::*;

use smp_protocol::packet::{identity_hash, SmpPacket, SMP_VERSION};

use ed25519_dalek::VerifyingKey;
use reqwest::Client;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{self, AsyncBufReadExt};
use tokio::time::{sleep, Duration};
use x25519_dalek::{PublicKey, StaticSecret};

const ROTATION_INTERVAL: u32 = 3;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        println!("Usage: smp-cli <alice|bob>");
        return;
    }

    let user = args[1].as_str();
    let client = Client::new();

    match user {
        "bob" => run_bob("bob", client).await,
        "alice" => run_alice("alice", client).await,
        _ => println!("Invalid user. Use alice or bob."),
    }
}

/* ========================= BOB ========================= */

async fn run_bob(user: &str, client: Client) {
    println!("Running as Bob");

    // 1️⃣ Load identity
    let identity = load_or_create_identity(user);

    // 2️⃣ Load prekey pool
    let mut pool = load_or_create_prekey_pool(user);

    // 3️⃣ Compute identity hash
    let bob_hash = identity_hash(identity.verifying_key.as_bytes());
    let bob_hex = hex::encode(bob_hash);

    println!("Bob identity hash:\n{}", bob_hex);

    // ======================================================
    // 🔐 ADD PREKEY PUBLISHING CODE RIGHT HERE
    // ======================================================

    let spk = load_or_rotate_signed_prekey(user, &identity);

    let _ = client
        .post("http://127.0.0.1:3000/signed_prekey")
        .json(&serde_json::json!({
            "identity_public_key": identity.verifying_key.as_bytes(),
            "prekey_id": spk.id,
            "public": spk.public,
            "signature": spk.signature,
            "created_at": spk.created_at,
            "expires_at": spk.expires_at,
        }))
        .send()
        .await;

    for _ in 0..5 {
        let stored_pk = take_prekey(user, &mut pool);

        let one_time = smp_crypto_core::prekey::OneTimePreKey {
            id: stored_pk.id,
            secret: StaticSecret::from(stored_pk.secret),
            public: PublicKey::from(stored_pk.public),
        };

        let bundle = create_prekey_bundle(&identity.signing_key, identity.verifying_key, &one_time);

        let _ = client
            .post("http://127.0.0.1:3000/prekey")
            .json(&bundle)
            .send()
            .await;
    }

    println!("Bob ready. Press ENTER to poll inbox.");

    // 4️⃣ Inbox polling loop
    let mut input = String::new();
    loop {
        input.clear();
        std::io::stdin().read_line(&mut input).unwrap();

        if let Ok(resp) = client
            .get(format!("http://127.0.0.1:3000/inbox/{}", bob_hex))
            .send()
            .await
        {
            if let Ok(messages) = resp.json::<Vec<Vec<u8>>>().await {
                for raw in messages {
                    if let Ok(packet) = serde_json::from_slice::<SmpPacket>(&raw) {
                        handle_incoming_packet(user, &identity, &mut pool, packet, &client).await;
                    }
                }
            }
        }
    }
}

/* ========================= ALICE ========================= */

async fn run_alice(user: &str, client: Client) {
    println!("Running as Alice");

    let identity = load_or_create_identity(user);
    let alice_hash = identity_hash(identity.verifying_key.as_bytes());
    let alice_hex = hex::encode(alice_hash);

    println!("Enter Bob's identity hash:");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
    let bob_hex = input.trim().to_string();
    let session_key = bob_hex.clone();

    let resend_user = user.to_string();
    let resend_client = client.clone();

    // Reliability resend worker
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;

            let unacked = load_unacked(&resend_user);

            for msg in unacked {
                if should_retry(&msg, 10) {
                    println!(
                        "[RETRY] Resending {} (attempt {})",
                        hex::encode(msg.message_id),
                        msg.retry_count + 1
                    );

                    let _ = resend_client
                        .post("http://127.0.0.1:3000/send")
                        .body(msg.packet_bytes.clone())
                        .send()
                        .await;

                    increment_retry(&resend_user, msg.message_id);
                }
            }
        }
    });

    let stdin = io::BufReader::new(io::stdin());
    let mut lines = stdin.lines();

    println!("Type messages:");

    loop {
        tokio::select! {
            Ok(Some(line)) = lines.next_line() => {
                send_alice_message(
                    user,
                    &identity,
                    &client,
                    &alice_hash,
                    &bob_hex,
                    &session_key,
                    line
                ).await;
            }

            _ = sleep(Duration::from_secs(2)) => {
                poll_alice_inbox(user, &client, &identity, &alice_hex).await;
            }
        }
    }
}

/* ========================= SENDING ========================= */

async fn send_alice_message(
    user: &str,
    identity: &smp_crypto_core::identity::Identity,
    client: &Client,
    alice_hash: &[u8; 32],
    bob_hex: &str,
    session_key: &str,
    message: String,
) {
    let mut prekey_id_for_packet = 0u32;
    let mut ephemeral_pubkey = [0u8; 32];

    let mut ratchet = if let Some(r) = load_session(user, session_key, identity) {
        r
    } else {
        let eph = generate_ephemeral();

        let resp = client
            .get(format!("http://127.0.0.1:3000/prekey/{}", bob_hex))
            .send()
            .await
            .unwrap();

        let bytes: Vec<u8> = resp.json().await.unwrap();
        let bundle: PreKeyBundle = serde_json::from_slice(&bytes).unwrap();

        prekey_id_for_packet = bundle.prekey_id;
        ephemeral_pubkey = eph.public.to_bytes();

        let shared_secret = match derive_session_key(&eph.secret, &bundle.prekey_public) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("[SECURITY] Session key derivation failed: {:?}", e);
                return;
            }
        };

        let mut r = DoubleRatchet::new(shared_secret);

        if let Err(e) = r.init_sender(bundle.prekey_public.to_bytes()) {
            eprintln!("[SECURITY] Ratchet init failed: {:?}", e);
            return;
        }

        r
    };

    // PCS rotation BEFORE deriving next key
    if ratchet.ns >= ROTATION_INTERVAL {
        if let Some(remote_pub) = ratchet.dh_remote_public {
            if let Err(e) = ratchet.dh_ratchet_step(remote_pub) {
                eprintln!("[SECURITY] PCS rotation failed: {:?}", e);
                return;
            }
        }
    }

    let (message_key, msg_number) = match ratchet.next_sending_key() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[SECURITY] Send key derivation failed: {:?}", e);
            return;
        }
    };

    let recipient_identity_hash = match hex::decode(bob_hex) {
        Ok(bytes) => match bytes.try_into() {
            Ok(arr) => arr,
            Err(_) => {
                eprintln!("[SECURITY] Invalid recipient hash length");
                return;
            }
        },
        Err(_) => {
            eprintln!("[SECURITY] Invalid recipient hash encoding");
            return;
        }
    };

    let mut packet = SmpPacket {
        version: SMP_VERSION,
        flags: 0,
        message_id: [0u8; 32],
        prekey_id: prekey_id_for_packet,
        message_number: msg_number,
        dh_ratchet_pub: Some(ratchet.dh_self_public),
        sender_identity_hash: *alice_hash,
        sender_verifying_key: identity.verifying_key.to_bytes(),
        recipient_identity_hash: recipient_identity_hash,
        ephemeral_pubkey,
        timestamp: now(),
        nonce: [0u8; 12],
        ciphertext: vec![],
        signature: [0u8; 64],
    };

    let aad = packet.serialize_header_for_aad();
    let (ciphertext, nonce) = match encrypt(&message_key, message.as_bytes(), &aad) {
        Ok(v) => v,
        Err(_) => {
            eprintln!("[SECURITY] Encryption failed");
            return;
        }
    };

    packet.nonce = nonce;
    packet.ciphertext = ciphertext;

    let mut hasher = Sha256::new();
    hasher.update(packet.sender_identity_hash);
    hasher.update(packet.message_number.to_be_bytes());
    hasher.update(&packet.nonce);
    hasher.update(&packet.ciphertext);
    packet.message_id = hasher.finalize().into();

    packet.sign(&identity.signing_key);

    client
        .post("http://127.0.0.1:3000/send")
        .json(&packet)
        .send()
        .await
        .ok();

    let packet_bytes = serde_json::to_vec(&packet).unwrap();

    store_outgoing(
        user,
        OutgoingMessage {
            message_id: packet.message_id,
            recipient_hex: bob_hex.to_string(),
            packet_bytes,
            timestamp: now(),
            acked: false,
            retry_count: 0,
        },
    );

    save_session(user, session_key, identity, &ratchet);
}

/* ========================= RECEIVING ========================= */

async fn handle_incoming_packet(
    user: &str,
    identity: &smp_crypto_core::identity::Identity,
    pool: &mut storage::PreKeyPool,
    packet: SmpPacket,
    _client: &Client,
) {
    let sender_hex = hex::encode(packet.sender_identity_hash);
    let session_key = sender_hex.clone();

    let my_hash = identity_hash(identity.verifying_key.as_bytes());

    if packet.recipient_identity_hash != my_hash {
        eprintln!("[SECURITY] Packet not intended for this identity.");
        return;
    }

    // TOFU enforcement
    match load_peer(user, &sender_hex) {
        Some(peer) => {
            if peer.verifying_key != packet.sender_verifying_key {
                eprintln!("[SECURITY] Identity changed. Possible MITM.");
                return;
            }
        }
        None => {
            println!("New peer detected. Saving identity (TOFU).");
            save_peer(user, &sender_hex, packet.sender_verifying_key);
        }
    }

    // Signature validation
    let verifying_key = match VerifyingKey::from_bytes(&packet.sender_verifying_key) {
        Ok(vk) => vk,
        Err(_) => {
            eprintln!("[SECURITY] Invalid verifying key");
            return;
        }
    };

    if packet.validate(&verifying_key).is_err() {
        eprintln!("[SECURITY] Packet signature invalid");
        return;
    }

    let mut ratchet = if let Some(r) = load_session(user, &session_key, identity) {
        r
    } else {
        let matching = match pool.used.iter().find(|p| p.id == packet.prekey_id) {
            Some(m) => m,
            None => {
                eprintln!("[SECURITY] Invalid prekey id");
                return;
            }
        };

        let bob_secret = StaticSecret::from(matching.secret);
        let alice_ephemeral = PublicKey::from(packet.ephemeral_pubkey);

        let shared_secret = match derive_session_key(&bob_secret, &alice_ephemeral) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("[SECURITY] Session key derivation failed: {:?}", e);
                return;
            }
        };

        let mut r = DoubleRatchet::new(shared_secret);

        if let Err(e) = r.bootstrap_as_receiver(matching.secret, packet.dh_ratchet_pub.unwrap()) {
            eprintln!("[SECURITY] Bootstrap failed: {:?}", e);
            return;
        }

        r
    };

    /* ================= STATE INVARIANT CHECK ================= */

    if ratchet.chain_key_recv.is_none() && packet.prekey_id == 0 {
        eprintln!("[SECURITY] Invalid state: no recv chain and no prekey");
        return;
    }

    if let Some(remote_pub) = packet.dh_ratchet_pub {
        if ratchet.dh_remote_public != Some(remote_pub) {
            if let Err(e) = ratchet.dh_ratchet_step(remote_pub) {
                eprintln!("[SECURITY] DH step failed: {:?}", e);
                return;
            }
        }
    }

    let message_key = match ratchet.receive_key(packet.message_number) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("[SECURITY] Receive error: {:?}", e);
            return;
        }
    };

    let aad = packet.serialize_header_for_aad();

    let decrypted: Vec<u8> = match decrypt(&message_key, &packet.ciphertext, &packet.nonce, &aad) {
        Ok(d) => d,
        Err(_) => {
            eprintln!("[SECURITY] Decryption failed");
            return;
        }
    };

    /* ================= ACK HANDLING ================= */

    if packet.flags & smp_protocol::packet::FLAG_ACK != 0 {
        if decrypted.len() != 32 {
            eprintln!("[SECURITY] Invalid ACK payload length");
            return;
        }

        let id: [u8; 32] = decrypted.try_into().unwrap();

        if mark_acked(user, id) {
            println!("Delivery confirmed for message {}", hex::encode(id));
        } else {
            eprintln!("[SECURITY] ACK for unknown message");
        }

        save_session(user, &session_key, identity, &ratchet);
        return;
    }

    /* ================= NORMAL MESSAGE ================= */

    println!("\n[{}] {}", sender_hex, String::from_utf8_lossy(&decrypted));

    save_session(user, &session_key, identity, &ratchet);
}

async fn poll_alice_inbox(
    user: &str,
    client: &Client,
    identity: &smp_crypto_core::identity::Identity,
    alice_hex: &str,
) {
    if let Ok(resp) = client
        .get(format!("http://127.0.0.1:3000/inbox/{}", alice_hex))
        .send()
        .await
    {
        if let Ok(messages) = resp.json::<Vec<Vec<u8>>>().await {
            let mut pool = load_or_create_prekey_pool(user);

            for raw in messages {
                if let Ok(packet) = serde_json::from_slice::<SmpPacket>(&raw) {
                    handle_incoming_packet(user, identity, &mut pool, packet, client).await;
                }
            }
        }
    }
}

/* ========================= UTIL ========================= */

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
