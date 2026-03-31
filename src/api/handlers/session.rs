use crate::api::dto::{SessionMetadata, SessionResponse};
use crate::api::AppState;
use crate::error::KdbxError;
use axum::extract::{Multipart, Path, State};
use axum::http::StatusCode;
use axum::Json;
use uuid::Uuid;

pub async fn create_session(
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> Result<Json<SessionResponse>, KdbxError> {
    let mut kdbx_data: Option<Vec<u8>> = None;
    let mut master_password: Option<String> = None;
    let mut key_file_data: Option<Vec<u8>> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| KdbxError::ValidationError(format!("Failed to parse multipart: {e}")))?
    {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "file" => {
                kdbx_data = Some(
                    field.bytes().await
                        .map_err(|e| KdbxError::ValidationError(format!("Failed to read file: {e}")))?
                        .to_vec(),
                );
            }
            "master_password" => {
                master_password = Some(
                    field.text().await
                        .map_err(|e| KdbxError::ValidationError(format!("Failed to read password: {e}")))?,
                );
            }
            "key_file" => {
                key_file_data = Some(
                    field.bytes().await
                        .map_err(|e| KdbxError::ValidationError(format!("Failed to read key file: {e}")))?
                        .to_vec(),
                );
            }
            _ => {}
        }
    }

    let kdbx_data = kdbx_data
        .ok_or_else(|| KdbxError::ValidationError("KDBX file is required".into()))?;

    let session = state.session_store.create_session(&kdbx_data, master_password, key_file_data).await?;

    Ok(Json(SessionResponse {
        session_id: session.id,
        metadata: SessionMetadata::from_session(&session),
        created_at: session.created_at,
    }))
}

pub async fn get_session(
    State(state): State<AppState>,
    Path(session_id): Path<Uuid>,
) -> Result<Json<SessionResponse>, KdbxError> {
    let session = state.session_store.get_session(&session_id).await?;
    Ok(Json(SessionResponse {
        session_id: session.id,
        metadata: SessionMetadata::from_session(&session),
        created_at: session.created_at,
    }))
}

pub async fn close_session(
    State(state): State<AppState>,
    Path(session_id): Path<Uuid>,
) -> Result<StatusCode, KdbxError> {
    state.session_store.close_session(&session_id).await?;
    Ok(StatusCode::NO_CONTENT)
}
