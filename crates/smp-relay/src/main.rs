use axum::{
    extract::{Path, State},
    routing::{get, post},
    Json, Router,
};
use serde_json::json;
use smp_protocol::packet::SmpPacket;
use sqlx::{postgres::PgPoolOptions, PgPool};
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
        "SELECT message_id, packet_json FROM messages
         WHERE recipient_hash = $1::bytea",
        recipient_bytes
    )
    .fetch_all(&state.db)
    .await
    .unwrap();

    let mut messages = Vec::new();

    for row in &rows {
        messages.push(row.packet_json.clone());
    }

    // Pull-and-delete
    sqlx::query!(
        "DELETE FROM messages WHERE recipient_hash = $1::bytea",
        recipient_bytes
    )
    .execute(&state.db)
    .await
    .unwrap();

    Json(messages)
}
