use crate::api::dto::request::{CreateGroupRequest, UpdateGroupRequest};
use crate::api::dto::response::{ErrorResponse, GroupNode, GroupResponse, GroupTreeResponse};
use crate::api::state::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use uuid::Uuid;

/// 创建分组
pub async fn create_group(
    State(app_state): State<AppState>,
    Path(session_id): Path<Uuid>,
    Json(request): Json<CreateGroupRequest>,
) -> Result<Json<GroupResponse>, (StatusCode, Json<ErrorResponse>)> {
    let group = app_state
        .group_service
        .create_group(&session_id, request.name, request.parent_id, request.icon_id)
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
                        code: "GROUP_CREATE_FAILED".to_string(),
                        message: e.to_string(),
                        details: None,
                    },
                }),
            )
        })?;

    Ok(Json(GroupResponse {
        id: group.id,
        name: group.name,
        parent_id: group.parent_id,
        icon_id: group.icon_id,
        created_at: group.created_at,
        updated_at: group.updated_at,
    }))
}

/// 获取分组树
pub async fn get_group_tree(
    State(app_state): State<AppState>,
    Path(session_id): Path<Uuid>,
) -> Result<Json<GroupTreeResponse>, (StatusCode, Json<ErrorResponse>)> {
    let tree = app_state
        .group_service
        .get_group_tree(&session_id)
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
                        code: "GROUP_TREE_FAILED".to_string(),
                        message: e.to_string(),
                        details: None,
                    },
                }),
            )
        })?;

    // 转换GroupNode类型
    let converted_tree: Vec<GroupNode> = tree
        .into_iter()
        .map(|n| convert_group_node(n))
        .collect();

    Ok(Json(GroupTreeResponse {
        groups: converted_tree,
    }))
}

/// 转换GroupNode类型
fn convert_group_node(node: crate::service::GroupNode) -> GroupNode {
    GroupNode {
        id: node.id,
        name: node.name,
        icon_id: node.icon_id,
        children: node.children.into_iter().map(convert_group_node).collect(),
    }
}

/// 更新分组
pub async fn update_group(
    State(app_state): State<AppState>,
    Path((session_id, group_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<UpdateGroupRequest>,
) -> Result<Json<GroupResponse>, (StatusCode, Json<ErrorResponse>)> {
    let group = app_state
        .group_service
        .update_group(
            &session_id,
            &group_id,
            request.name,
            request.parent_id,
            request.icon_id,
        )
        .await
        .map_err(|e| {
            let status = match e {
                crate::error::KdbxError::SessionNotFound(_) => StatusCode::NOT_FOUND,
                crate::error::KdbxError::SessionExpired(_) => StatusCode::GONE,
                crate::error::KdbxError::GroupNotFound(_) => StatusCode::NOT_FOUND,
                crate::error::KdbxError::ValidationError(_) => StatusCode::BAD_REQUEST,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };

            (
                status,
                Json(ErrorResponse {
                    error: crate::api::dto::response::ErrorDetail {
                        code: "GROUP_UPDATE_FAILED".to_string(),
                        message: e.to_string(),
                        details: None,
                    },
                }),
            )
        })?;

    Ok(Json(GroupResponse {
        id: group.id,
        name: group.name,
        parent_id: group.parent_id,
        icon_id: group.icon_id,
        created_at: group.created_at,
        updated_at: group.updated_at,
    }))
}

/// 删除分组
pub async fn delete_group(
    State(app_state): State<AppState>,
    Path((session_id, group_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    app_state
        .group_service
        .delete_group(&session_id, &group_id, false)
        .await
        .map_err(|e| {
            let status = match e {
                crate::error::KdbxError::SessionNotFound(_) => StatusCode::NOT_FOUND,
                crate::error::KdbxError::SessionExpired(_) => StatusCode::GONE,
                crate::error::KdbxError::GroupNotFound(_) => StatusCode::NOT_FOUND,
                crate::error::KdbxError::ValidationError(_) => StatusCode::BAD_REQUEST,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };

            (
                status,
                Json(ErrorResponse {
                    error: crate::api::dto::response::ErrorDetail {
                        code: "GROUP_DELETE_FAILED".to_string(),
                        message: e.to_string(),
                        details: None,
                    },
                }),
            )
        })?;

    Ok(StatusCode::NO_CONTENT)
}
