use crate::api::handlers::{
    close_session, create_entry, create_group, create_session, delete_entry, delete_group,
    export_kdbx, get_entry, get_group_tree, get_session, health_check, list_entries, update_entry,
    update_group,
};
use crate::api::state::AppState;
use axum::{
    routing::{delete, get, patch, post},
    Router,
};

pub fn create_router(state: AppState) -> Router {
    Router::new()
        // 健康检查
        .route("/health", get(health_check))
        // API v1路由
        .nest("/api/v1", api_v1_routes())
        .with_state(state)
}

fn api_v1_routes() -> Router<AppState> {
    Router::new()
        // 会话管理
        .route("/sessions", post(create_session))
        .route("/sessions/{id}", get(get_session))
        .route("/sessions/{id}", delete(close_session))
        // 条目管理
        .route("/sessions/{sid}/entries", post(create_entry))
        .route("/sessions/{sid}/entries", get(list_entries))
        .route("/sessions/{sid}/entries/{eid}", get(get_entry))
        .route("/sessions/{sid}/entries/{eid}", patch(update_entry))
        .route("/sessions/{sid}/entries/{eid}", delete(delete_entry))
        // 分组管理
        .route("/sessions/{sid}/groups", post(create_group))
        .route("/sessions/{sid}/groups/tree", get(get_group_tree))
        .route("/sessions/{sid}/groups/{gid}", patch(update_group))
        .route("/sessions/{sid}/groups/{gid}", delete(delete_group))
        // 文件导出
        .route("/sessions/{id}/export", get(export_kdbx))
}
