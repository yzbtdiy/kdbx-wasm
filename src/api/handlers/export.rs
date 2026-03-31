use crate::api::dto::response::ErrorResponse;
use crate::api::state::AppState;
use axum::{
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::{AppendHeaders, IntoResponse},
    Json,
};
use serde::Deserialize;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct ExportQuery {
    pub encryption: Option<String>,
    pub compression: Option<String>,
}

/// 导出KDBX文件
pub async fn export_kdbx(
    State(app_state): State<AppState>,
    Path(session_id): Path<Uuid>,
    Query(query): Query<ExportQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    // 解析加密算法
    let encryption = query.encryption.as_ref().and_then(|e| match e.to_lowercase().as_str() {
        "aes256" => Some(crate::core::types::EncryptionAlgorithm::Aes256),
        "chacha20" => Some(crate::core::types::EncryptionAlgorithm::ChaCha20),
        _ => None,
    });

    // 解析压缩选项
    let compression = query.compression.as_ref().and_then(|c| match c.to_lowercase().as_str() {
        "true" | "1" | "gzip" => Some(crate::core::types::CompressionAlgorithm::Gzip),
        "false" | "0" | "none" => Some(crate::core::types::CompressionAlgorithm::None),
        _ => None,
    });

    // 导出文件
    let kdbx_data = app_state
        .file_service
        .export_kdbx(&session_id, encryption, compression)
        .await
        .map_err(|e| {
            let status = match e {
                crate::error::KdbxError::SessionNotFound(_) => StatusCode::NOT_FOUND,
                crate::error::KdbxError::SessionExpired(_) => StatusCode::GONE,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };

            (
                status,
                axum::Json(ErrorResponse {
                    error: crate::api::dto::response::ErrorDetail {
                        code: "EXPORT_FAILED".to_string(),
                        message: e.to_string(),
                        details: None,
                    },
                }),
            )
        })?;

    // 设置响应头
    let headers = AppendHeaders([
        (header::CONTENT_TYPE, "application/octet-stream".to_string()),
        (
            header::CONTENT_DISPOSITION,
            "attachment; filename=\"database.kdbx\"".to_string(),
        ),
    ]);

    Ok((headers, kdbx_data))
}
