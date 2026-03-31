use crate::api::AppState;
use axum::extract::State;
use axum::Json;
use serde_json::{json, Value};

pub async fn health_check(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "status": "healthy",
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_seconds": state.start_time.elapsed().as_secs()
    }))
}
