use crate::api::dto::*;
use crate::api::AppState;
use crate::error::KdbxError;
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
    let entry = state.entry_service.create_entry(
        &session_id,
        req.group_id.unwrap_or(Uuid::nil()),
        req.title, req.username, req.password,
        req.url, req.notes, req.tags, req.custom_fields,
        req.icon_id, req.expires_at,
    ).await?;
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
    let entry = state.entry_service.update_entry(
        &session_id, &entry_id,
        req.title, req.username, req.password,
        req.url, req.notes, req.tags, req.custom_fields,
        req.icon_id, req.group_id, req.expires_at,
    ).await?;
    Ok(Json(EntryResponse::from_entry(entry)))
}

pub async fn delete_entry(
    State(state): State<AppState>,
    Path((session_id, entry_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, KdbxError> {
    state.entry_service.delete_entry(&session_id, &entry_id, false).await?;
    Ok(StatusCode::NO_CONTENT)
}
