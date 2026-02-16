use axum::{
    routing::{get, post},
    Router,
    extract::{Path, State},
    Json,
};
use serde_json::json;
use smp_protocol::packet::SmpPacket;
use smp_crypto_core::prekey::PreKeyBundle;
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::net::SocketAddr;

#[derive(Clone)]
struct AppState {
    db: PgPool,
}

#[tokio::main]
async fn main() {
    let db = PgPoolOptions::new()
        .max_connections(5)
        .connect("postgres://smp_user:smp_pass@127.0.0.1:5433/smp_db")
        .await
        .expect("DB connection failed");

    let state = AppState { db };

    let app = Router::new()
        .route("/send", post(send))
        .route("/inbox/:recipient", get(get_inbox))
        .route("/prekey", post(upload_prekey))
        .route("/prekey/:recipient", get(fetch_prekey))
        .route("/signed_prekey", post(upload_signed_prekey))
        .route("/signed_prekey/:recipient", get(fetch_signed_prekey))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("Relay running on http://{}", addr);

    axum::serve(tokio::net::TcpListener::bind(addr).await.unwrap(), app)
        .await
        .unwrap();
}

/* -------------------- Messages -------------------- */

async fn send(
    State(state): State<AppState>,
    Json(packet): Json<SmpPacket>,
) -> Json<serde_json::Value> {
    let serialized = serde_json::to_vec(&packet).unwrap();

    let res = sqlx::query!(
        "INSERT INTO messages (message_id, recipient_hash, packet_json, created_at)
         VALUES ($1, $2, $3, $4)",
        packet.message_id.as_slice(),
        packet.recipient_identity_hash.as_slice(),
        serialized,
        packet.timestamp as i64
    )
    .execute(&state.db)
    .await;

    match res {
        Ok(_) => Json(json!({"status": "accepted"})),
        Err(_) => Json(json!({"status": "duplicate_or_error"})),
    }
}

async fn get_inbox(
    State(state): State<AppState>,
    Path(recipient): Path<String>,
) -> Json<Vec<Vec<u8>>> {
    let recipient_bytes = hex::decode(recipient).unwrap();

    let rows = sqlx::query!(
        "SELECT packet_json FROM messages
         WHERE recipient_hash = $1",
        recipient_bytes
    )
    .fetch_all(&state.db)
    .await
    .unwrap();

    let mut messages = Vec::new();
    for row in &rows {
        messages.push(row.packet_json.clone());
    }

    sqlx::query!(
        "DELETE FROM messages WHERE recipient_hash = $1",
        recipient_bytes
    )
    .execute(&state.db)
    .await
    .unwrap();

    Json(messages)
}

/* -------------------- One-Time PreKeys -------------------- */

async fn upload_prekey(
    State(state): State<AppState>,
    Json(bundle): Json<PreKeyBundle>,
) -> Json<serde_json::Value> {
    let recipient_hash =
        smp_protocol::packet::identity_hash(bundle.identity_public_key.as_bytes());

    let serialized = serde_json::to_vec(&bundle).unwrap();

    sqlx::query!(
        "INSERT INTO prekeys (recipient_hash, prekey_id, bundle_json, created_at)
         VALUES ($1, $2, $3, EXTRACT(EPOCH FROM NOW())::BIGINT)
         ON CONFLICT DO NOTHING",
        recipient_hash.as_slice(),
        bundle.prekey_id as i32,
        serialized
    )
    .execute(&state.db)
    .await
    .unwrap();

    Json(json!({"status": "prekey_uploaded"}))
}

async fn fetch_prekey(
    State(state): State<AppState>,
    Path(recipient): Path<String>,
) -> Json<Option<Vec<u8>>> {
    let recipient_bytes = hex::decode(recipient).unwrap();

    let row = sqlx::query!(
        "SELECT prekey_id, bundle_json
         FROM prekeys
         WHERE recipient_hash = $1
         ORDER BY created_at ASC
         LIMIT 1",
        recipient_bytes
    )
    .fetch_optional(&state.db)
    .await
    .unwrap();

    if let Some(r) = row {
        sqlx::query!(
            "DELETE FROM prekeys
             WHERE recipient_hash = $1 AND prekey_id = $2",
            recipient_bytes,
            r.prekey_id
        )
        .execute(&state.db)
        .await
        .unwrap();

        Json(Some(r.bundle_json))
    } else {
        Json(None)
    }
}

/* -------------------- Signed PreKey -------------------- */

async fn upload_signed_prekey(
    State(state): State<AppState>,
    Json(spk): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let identity_public =
        spk["identity_public_key"].as_array().unwrap();

    let identity_bytes: Vec<u8> =
        identity_public.iter().map(|v| v.as_u64().unwrap() as u8).collect();

    let recipient_hash =
        smp_protocol::packet::identity_hash(&identity_bytes);

    let serialized = serde_json::to_vec(&spk).unwrap();

    sqlx::query!(
        "INSERT INTO signed_prekeys (recipient_hash, bundle_json, created_at, expires_at)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (recipient_hash)
         DO UPDATE SET bundle_json = $2, created_at = $3, expires_at = $4",
        recipient_hash.as_slice(),
        serialized,
        spk["created_at"].as_u64().unwrap() as i64,
        spk["expires_at"].as_u64().unwrap() as i64,
    )
    .execute(&state.db)
    .await
    .unwrap();

    Json(json!({"status": "signed_prekey_uploaded"}))
}

async fn fetch_signed_prekey(
    State(state): State<AppState>,
    Path(recipient): Path<String>,
) -> Json<Option<Vec<u8>>> {
    let recipient_bytes = hex::decode(recipient).unwrap();

    let row = sqlx::query!(
        "SELECT bundle_json FROM signed_prekeys
         WHERE recipient_hash = $1",
        recipient_bytes
    )
    .fetch_optional(&state.db)
    .await
    .unwrap();

    match row {
        Some(r) => Json(Some(r.bundle_json)),
        None => Json(None),
    }
}
