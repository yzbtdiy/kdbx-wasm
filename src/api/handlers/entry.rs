use crate::api::dto::*;
use crate::api::AppState;
use crate::error::KdbxError;
use crate::service::entry::{CreateEntryParams, UpdateEntryParams};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct ListEntriesQuery {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
    pub search: Option<String>,
    pub group_id: Option<Uuid>,
}

pub async fn create_entry(
    State(state): State<AppState>,
    Path(session_id): Path<Uuid>,
    Json(req): Json<CreateEntryRequest>,
) -> Result<Json<EntryResponse>, KdbxError> {
    let params = CreateEntryParams {
        group_id: req.group_id.unwrap_or(Uuid::nil()),
        title: req.title,
        username: req.username,
        password: req.password,
        url: req.url,
        notes: req.notes,
        tags: req.tags,
        custom_fields: req.custom_fields,
        icon_id: req.icon_id,
        expires_at: req.expires_at,
    };
    let entry = state.entry_service.create_entry(&session_id, params).await?;
    Ok(Json(EntryResponse::from_entry(entry)))
}

pub async fn list_entries(
    State(state): State<AppState>,
    Path(session_id): Path<Uuid>,
    Query(query): Query<ListEntriesQuery>,
) -> Result<Json<EntryListResponse>, KdbxError> {
    let page = query.page.unwrap_or(1);
    let per_page = query.per_page.unwrap_or(20).min(100);

    let (entries, total) = state.entry_service
        .list_entries(&session_id, query.group_id, query.search.as_deref(), page, per_page)
        .await?;

    let total_pages = ((total as f64) / (per_page as f64)).ceil() as u32;
    Ok(Json(EntryListResponse {
        entries: entries.into_iter().map(EntryResponse::from_entry).collect(),
        pagination: Pagination { page, per_page, total, total_pages },
    }))
}

pub async fn get_entry(
    State(state): State<AppState>,
    Path((session_id, entry_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<EntryResponse>, KdbxError> {
    let entry = state.entry_service.get_entry(&session_id, &entry_id).await?;
    Ok(Json(EntryResponse::from_entry(entry)))
}

pub async fn update_entry(
    State(state): State<AppState>,
    Path((session_id, entry_id)): Path<(Uuid, Uuid)>,
    Json(req): Json<UpdateEntryRequest>,
) -> Result<Json<EntryResponse>, KdbxError> {
    let params = UpdateEntryParams {
        title: req.title,
        username: req.username,
        password: req.password,
        url: req.url,
        notes: req.notes,
        tags: req.tags,
        custom_fields: req.custom_fields,
        icon_id: req.icon_id,
        group_id: req.group_id,
        expires_at: req.expires_at,
    };
    let entry = state.entry_service.update_entry(&session_id, &entry_id, params).await?;
    Ok(Json(EntryResponse::from_entry(entry)))
}

pub async fn delete_entry(
    State(state): State<AppState>,
    Path((session_id, entry_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, KdbxError> {
    state.entry_service.delete_entry(&session_id, &entry_id, false).await?;
    Ok(StatusCode::NO_CONTENT)
}
