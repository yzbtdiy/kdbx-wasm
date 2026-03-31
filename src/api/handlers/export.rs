use crate::api::AppState;
use crate::error::KdbxError;
use axum::extract::{Path, Query, State};
use axum::http::header;
use axum::response::{AppendHeaders, IntoResponse};
use serde::Deserialize;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct ExportQuery {
    pub encryption: Option<String>,
    pub compression: Option<String>,
}

pub async fn export_kdbx(
    State(state): State<AppState>,
    Path(session_id): Path<Uuid>,
    Query(query): Query<ExportQuery>,
) -> Result<impl IntoResponse, KdbxError> {
    let encryption = query.encryption.as_deref().and_then(|e| match e.to_lowercase().as_str() {
        "aes256" => Some(crate::core::types::EncryptionAlgorithm::Aes256),
        "chacha20" => Some(crate::core::types::EncryptionAlgorithm::ChaCha20),
        _ => None,
    });
    let compression = query.compression.as_deref().and_then(|c| match c.to_lowercase().as_str() {
        "true" | "1" | "gzip" => Some(crate::core::types::CompressionAlgorithm::Gzip),
        "false" | "0" | "none" => Some(crate::core::types::CompressionAlgorithm::None),
        _ => None,
    });

    let data = state.file_service.export_kdbx(&session_id, encryption, compression).await?;

    let headers = AppendHeaders([
        (header::CONTENT_TYPE, "application/octet-stream".to_string()),
        (header::CONTENT_DISPOSITION, "attachment; filename=\"database.kdbx\"".to_string()),
    ]);
    Ok((headers, data))
}
