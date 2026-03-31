use crate::api::dto::response::{ErrorResponse, SessionMetadata, SessionResponse};
use crate::api::state::AppState;
use axum::{
    extract::{Multipart, Path, State},
    http::StatusCode,
    Json,
};
use uuid::Uuid;

/// 创建会话
pub async fn create_session(
    State(app_state): State<AppState>,
    mut multipart: Multipart,
) -> Result<Json<SessionResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mut kdbx_data: Option<Vec<u8>> = None;
    let mut master_password: Option<String> = None;
    let mut key_file_data: Option<Vec<u8>> = None;

    // 解析multipart表单
    while let Some(field) = multipart.next_field().await.map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: crate::api::dto::response::ErrorDetail {
                    code: "INVALID_REQUEST".to_string(),
                    message: format!("Failed to parse multipart: {}", e),
                    details: None,
                },
            }),
        )
    })? {
        let name = field.name().unwrap_or("").to_string();

        match name.as_str() {
            "file" => {
                kdbx_data = Some(field.bytes().await.map_err(|e| {
                    (
                        StatusCode::BAD_REQUEST,
                        Json(ErrorResponse {
                            error: crate::api::dto::response::ErrorDetail {
                                code: "INVALID_FILE".to_string(),
                                message: format!("Failed to read file: {}", e),
                                details: None,
                            },
                        }),
                    )
                })?.to_vec());
            }
            "master_password" => {
                let text = field.text().await.map_err(|e| {
                    (
                        StatusCode::BAD_REQUEST,
                        Json(ErrorResponse {
                            error: crate::api::dto::response::ErrorDetail {
                                code: "INVALID_PASSWORD".to_string(),
                                message: format!("Failed to read password: {}", e),
                                details: None,
                            },
                        }),
                    )
                })?;
                master_password = Some(text);
            }
            "key_file" => {
                key_file_data = Some(field.bytes().await.map_err(|e| {
                    (
                        StatusCode::BAD_REQUEST,
                        Json(ErrorResponse {
                            error: crate::api::dto::response::ErrorDetail {
                                code: "INVALID_KEY_FILE".to_string(),
                                message: format!("Failed to read key file: {}", e),
                                details: None,
                            },
                        }),
                    )
                })?.to_vec());
            }
            _ => {}
        }
    }

    let kdbx_data = kdbx_data.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: crate::api::dto::response::ErrorDetail {
                    code: "MISSING_FILE".to_string(),
                    message: "KDBX file is required".to_string(),
                    details: None,
                },
            }),
        )
    })?;

    // 创建会话
    let session = app_state
        .session_store
        .create_session(&kdbx_data, master_password, key_file_data)
        .await
        .map_err(|e| {
            let status = match e {
                crate::error::KdbxError::InvalidSignature => StatusCode::BAD_REQUEST,
                crate::error::KdbxError::UnsupportedVersion(_, _) => StatusCode::BAD_REQUEST,
                crate::error::KdbxError::InvalidMasterKey => StatusCode::UNAUTHORIZED,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };

            (
                status,
                Json(ErrorResponse {
                    error: crate::api::dto::response::ErrorDetail {
                        code: "SESSION_CREATE_FAILED".to_string(),
                        message: e.to_string(),
                        details: None,
                    },
                }),
            )
        })?;

    Ok(Json(SessionResponse {
        session_id: session.id,
        metadata: SessionMetadata {
            version: format!(
                "{}.{}",
                session.kdbx_session.header.version.major,
                session.kdbx_session.header.version.minor
            ),
            encryption_algorithm: format!("{:?}", session.kdbx_session.header.encryption),
            kdf: format!("{:?}", session.kdbx_session.header.kdf),
            entry_count: session.kdbx_session.entries.len(),
            group_count: session.kdbx_session.groups.len(),
        },
        created_at: session.created_at,
    }))
}

/// 获取会话信息
pub async fn get_session(
    State(app_state): State<AppState>,
    Path(session_id): Path<Uuid>,
) -> Result<Json<SessionResponse>, (StatusCode, Json<ErrorResponse>)> {
    let session = app_state
        .session_store
        .get_session(&session_id)
        .await
        .map_err(|e| {
            let status = match e {
                crate::error::KdbxError::SessionNotFound(_) => StatusCode::NOT_FOUND,
                crate::error::KdbxError::SessionExpired(_) => StatusCode::GONE,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };

            (
                status,
                Json(ErrorResponse {
                    error: crate::api::dto::response::ErrorDetail {
                        code: "SESSION_NOT_FOUND".to_string(),
                        message: e.to_string(),
                        details: None,
                    },
                }),
            )
        })?;

    Ok(Json(SessionResponse {
        session_id: session.id,
        metadata: SessionMetadata {
            version: format!(
                "{}.{}",
                session.kdbx_session.header.version.major,
                session.kdbx_session.header.version.minor
            ),
            encryption_algorithm: format!("{:?}", session.kdbx_session.header.encryption),
            kdf: format!("{:?}", session.kdbx_session.header.kdf),
            entry_count: session.kdbx_session.entries.len(),
            group_count: session.kdbx_session.groups.len(),
        },
        created_at: session.created_at,
    }))
}

/// 关闭会话
pub async fn close_session(
    State(app_state): State<AppState>,
    Path(session_id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    app_state
        .session_store
        .close_session(&session_id)
        .await
        .map_err(|e| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: crate::api::dto::response::ErrorDetail {
                        code: "SESSION_NOT_FOUND".to_string(),
                        message: e.to_string(),
                        details: None,
                    },
                }),
            )
        })?;

    Ok(StatusCode::NO_CONTENT)
}
