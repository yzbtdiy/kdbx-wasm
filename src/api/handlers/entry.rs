use crate::api::dto::request::{CreateEntryRequest, UpdateEntryRequest};
use crate::api::dto::response::{
    EntryListResponse, EntryResponse, ErrorResponse, Pagination,
};
use crate::api::state::AppState;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use uuid::Uuid;

fn to_entry_response(entry: crate::core::types::Entry) -> EntryResponse {
    EntryResponse {
        id: entry.id,
        title: entry.title,
        username: entry.username,
        password: entry
            .password
            .map(|p| p.as_str().to_string())
            .unwrap_or_default(),
        url: entry.url,
        notes: entry.notes,
        tags: entry.tags,
        custom_fields: entry.custom_fields,
        icon_id: entry.icon_id,
        group_id: entry.group_id,
        created_at: entry.created_at,
        updated_at: entry.updated_at,
        accessed_at: entry.accessed_at,
        expires_at: entry.expires_at,
    }
}

#[derive(Debug, Deserialize)]
pub struct ListEntriesQuery {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
    pub search: Option<String>,
    pub group_id: Option<Uuid>,
}

/// 创建条目
pub async fn create_entry(
    State(app_state): State<AppState>,
    Path(session_id): Path<Uuid>,
    Json(request): Json<CreateEntryRequest>,
) -> Result<Json<EntryResponse>, (StatusCode, Json<ErrorResponse>)> {
    let entry = app_state
        .entry_service
        .create_entry(
            &session_id,
            request.group_id.unwrap_or(Uuid::nil()),
            request.title,
            request.username,
            request.password,
            request.url,
            request.notes,
            request.tags,
            request.custom_fields,
            request.icon_id,
            request.expires_at,
        )
        .await
        .map_err(|e| {
            let status = match e {
                crate::error::KdbxError::SessionNotFound(_) => StatusCode::NOT_FOUND,
                crate::error::KdbxError::SessionExpired(_) => StatusCode::GONE,
                crate::error::KdbxError::ValidationError(_) => StatusCode::BAD_REQUEST,
                crate::error::KdbxError::GroupNotFound(_) => StatusCode::NOT_FOUND,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };

            (
                status,
                Json(ErrorResponse {
                    error: crate::api::dto::response::ErrorDetail {
                        code: "ENTRY_CREATE_FAILED".to_string(),
                        message: e.to_string(),
                        details: None,
                    },
                }),
            )
        })?;

    Ok(Json(to_entry_response(entry)))
}

/// 列出条目
pub async fn list_entries(
    State(app_state): State<AppState>,
    Path(session_id): Path<Uuid>,
    Query(query): Query<ListEntriesQuery>,
) -> Result<Json<EntryListResponse>, (StatusCode, Json<ErrorResponse>)> {
    let page = query.page.unwrap_or(1);
    let per_page = query.per_page.unwrap_or(20).min(100);

    let (entries, total) = app_state
        .entry_service
        .list_entries(
            &session_id,
            query.group_id,
            query.search.as_deref(),
            page,
            per_page,
        )
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
                        code: "ENTRY_LIST_FAILED".to_string(),
                        message: e.to_string(),
                        details: None,
                    },
                }),
            )
        })?;

    let total_pages = ((total as f64) / (per_page as f64)).ceil() as u32;

    Ok(Json(EntryListResponse {
        entries: entries.into_iter().map(to_entry_response).collect(),
        pagination: Pagination {
            page,
            per_page,
            total,
            total_pages,
        },
    }))
}

/// 获取条目
pub async fn get_entry(
    State(app_state): State<AppState>,
    Path((session_id, entry_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<EntryResponse>, (StatusCode, Json<ErrorResponse>)> {
    let entry = app_state
        .entry_service
        .get_entry(&session_id, &entry_id)
        .await
        .map_err(|e| {
            let status = match e {
                crate::error::KdbxError::SessionNotFound(_) => StatusCode::NOT_FOUND,
                crate::error::KdbxError::SessionExpired(_) => StatusCode::GONE,
                crate::error::KdbxError::EntryNotFound(_) => StatusCode::NOT_FOUND,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };

            (
                status,
                Json(ErrorResponse {
                    error: crate::api::dto::response::ErrorDetail {
                        code: "ENTRY_NOT_FOUND".to_string(),
                        message: e.to_string(),
                        details: None,
                    },
                }),
            )
        })?;

    Ok(Json(to_entry_response(entry)))
}

/// 更新条目
pub async fn update_entry(
    State(app_state): State<AppState>,
    Path((session_id, entry_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<UpdateEntryRequest>,
) -> Result<Json<EntryResponse>, (StatusCode, Json<ErrorResponse>)> {
    let entry = app_state
        .entry_service
        .update_entry(
            &session_id,
            &entry_id,
            request.title,
            request.username,
            request.password,
            request.url,
            request.notes,
            request.tags,
            request.custom_fields,
            request.icon_id,
            request.group_id,
            request.expires_at,
        )
        .await
        .map_err(|e| {
            let status = match e {
                crate::error::KdbxError::SessionNotFound(_) => StatusCode::NOT_FOUND,
                crate::error::KdbxError::SessionExpired(_) => StatusCode::GONE,
                crate::error::KdbxError::EntryNotFound(_) => StatusCode::NOT_FOUND,
                crate::error::KdbxError::ValidationError(_) => StatusCode::BAD_REQUEST,
                crate::error::KdbxError::GroupNotFound(_) => StatusCode::NOT_FOUND,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };

            (
                status,
                Json(ErrorResponse {
                    error: crate::api::dto::response::ErrorDetail {
                        code: "ENTRY_UPDATE_FAILED".to_string(),
                        message: e.to_string(),
                        details: None,
                    },
                }),
            )
        })?;

    Ok(Json(to_entry_response(entry)))
}

/// 删除条目
pub async fn delete_entry(
    State(app_state): State<AppState>,
    Path((session_id, entry_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    app_state
        .entry_service
        .delete_entry(&session_id, &entry_id, false)
        .await
        .map_err(|e| {
            let status = match e {
                crate::error::KdbxError::SessionNotFound(_) => StatusCode::NOT_FOUND,
                crate::error::KdbxError::SessionExpired(_) => StatusCode::GONE,
                crate::error::KdbxError::EntryNotFound(_) => StatusCode::NOT_FOUND,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };

            (
                status,
                Json(ErrorResponse {
                    error: crate::api::dto::response::ErrorDetail {
                        code: "ENTRY_DELETE_FAILED".to_string(),
                        message: e.to_string(),
                        details: None,
                    },
                }),
            )
        })?;

    Ok(StatusCode::NO_CONTENT)
}
