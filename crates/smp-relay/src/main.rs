use axum::{
    routing::{get, post},
    Router,
    extract::{Path, State},
    Json,
};
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use smp_protocol::packet::SmpPacket;

#[derive(Clone)]
struct AppState {
    // recipient_hash -> Vec<packet_bytes>
    inboxes: Arc<Mutex<HashMap<[u8; 32], Vec<Vec<u8>>>>>,
    seen_message_ids: Arc<Mutex<HashSet<[u8; 32]>>>,
}

#[tokio::main]
async fn main() {
    let state = AppState {
        inboxes: Arc::new(Mutex::new(HashMap::new())),
        seen_message_ids: Arc::new(Mutex::new(HashSet::new())),
    };

    let app = Router::new()
        .route("/send", post(send))
        .route("/inbox/:recipient", get(get_inbox))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("Relay running on http://{}", addr);

    axum::serve(tokio::net::TcpListener::bind(addr).await.unwrap(), app)
        .await
        .unwrap();
}

async fn send(
    State(state): State<AppState>,
    Json(packet): Json<SmpPacket>,
) -> String {
    // Basic replay protection (relay-level)
    {
        let mut seen = state.seen_message_ids.lock().unwrap();
        if seen.contains(&packet.message_id) {
            return "Duplicate message_id rejected".into();
        }
        seen.insert(packet.message_id);
    }

    {
        let mut inboxes = state.inboxes.lock().unwrap();
        inboxes
            .entry(packet.recipient_identity_hash)
            .or_default()
            .push(packet.serialize());
    }

    "Message accepted".into()
}

async fn get_inbox(
    State(state): State<AppState>,
    Path(recipient): Path<String>,
) -> Json<Vec<Vec<u8>>> {
    let recipient_bytes = hex::decode(recipient).unwrap();
    let mut key = [0u8; 32];
    key.copy_from_slice(&recipient_bytes);

    let inboxes = state.inboxes.lock().unwrap();
    let messages = inboxes.get(&key).cloned().unwrap_or_default();

    Json(messages)
}
