use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

fn outgoing_path(user: &str) -> String {
    format!(".smp/{}/outgoing.json", user)
}

#[derive(Serialize, Deserialize, Clone)]
pub struct OutgoingMessage {
    pub message_id: [u8; 32],
    pub recipient_hex: String,
    pub packet_bytes: Vec<u8>,
    pub timestamp: u64,
    pub acked: bool,
    pub retry_count: u32,
}

const MAX_RETRIES: u32 = 5;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn load_all(user: &str) -> Vec<OutgoingMessage> {
    let path = outgoing_path(user);
    if !Path::new(&path).exists() {
        return Vec::new();
    }

    let data = fs::read_to_string(path).unwrap_or_default();
    serde_json::from_str(&data).unwrap_or_default()
}

fn save_all(user: &str, msgs: &[OutgoingMessage]) {
    let path = outgoing_path(user);
    let dir = format!(".smp/{}", user);
    let _ = fs::create_dir_all(dir);
    let _ = fs::write(path, serde_json::to_string_pretty(msgs).unwrap());
}

pub fn store_outgoing(user: &str, msg: OutgoingMessage) {
    let mut all = load_all(user);
    all.push(msg);
    save_all(user, &all);
}

/// Returns true if ACK was valid and message existed
pub fn mark_acked(user: &str, message_id: [u8; 32]) -> bool {
    let mut all = load_all(user);
    let mut found = false;

    for m in &mut all {
        if m.message_id == message_id {
            if !m.acked {
                m.acked = true;
                found = true;
            }
        }
    }

    if found {
        save_all(user, &all);
    }

    found
}

pub fn load_unacked(user: &str) -> Vec<OutgoingMessage> {
    load_all(user)
        .into_iter()
        .filter(|m| {
            if m.retry_count >= MAX_RETRIES {
                println!(
                    "[RELIABILITY] Max retries exceeded for {}",
                    hex::encode(m.message_id)
                );
                false
            } else {
                !m.acked
            }
        })
        .collect()
}

pub fn increment_retry(user: &str, message_id: [u8; 32]) {
    let mut all = load_all(user);

    for m in &mut all {
        if m.message_id == message_id {
            m.retry_count += 1;
            m.timestamp = now();
        }
    }

    save_all(user, &all);
}

pub fn should_retry(msg: &OutgoingMessage, timeout_secs: u64) -> bool {
    if msg.acked {
        return false;
    }

    if msg.retry_count >= MAX_RETRIES {
        return false;
    }

    now() > msg.timestamp + timeout_secs
}
