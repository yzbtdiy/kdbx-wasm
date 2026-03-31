use crate::api::dto::*;
use crate::api::AppState;
use crate::error::KdbxError;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use uuid::Uuid;

pub async fn create_group(
    State(state): State<AppState>,
    Path(session_id): Path<Uuid>,
    Json(req): Json<CreateGroupRequest>,
) -> Result<Json<GroupResponse>, KdbxError> {
    let group = state.group_service
        .create_group(&session_id, req.name, req.parent_id, req.icon_id)
        .await?;
    Ok(Json(GroupResponse::from_group(group)))
}

pub async fn get_group_tree(
    State(state): State<AppState>,
    Path(session_id): Path<Uuid>,
) -> Result<Json<GroupTreeResponse>, KdbxError> {
    let tree = state.group_service.get_group_tree(&session_id).await?;
    Ok(Json(GroupTreeResponse {
        groups: tree.into_iter().map(GroupNode::from_service).collect(),
    }))
}

pub async fn update_group(
    State(state): State<AppState>,
    Path((session_id, group_id)): Path<(Uuid, Uuid)>,
    Json(req): Json<UpdateGroupRequest>,
) -> Result<Json<GroupResponse>, KdbxError> {
    let group = state.group_service
        .update_group(&session_id, &group_id, req.name, req.parent_id, req.icon_id)
        .await?;
    Ok(Json(GroupResponse::from_group(group)))
}

pub async fn delete_group(
    State(state): State<AppState>,
    Path((session_id, group_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, KdbxError> {
    state.group_service.delete_group(&session_id, &group_id, false).await?;
    Ok(StatusCode::NO_CONTENT)
}
