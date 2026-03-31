pub mod dto;
pub mod handlers;

use crate::service::{EntryService, FileService, GroupService, SessionStore};
use axum::{
    routing::{delete, get, patch, post},
    Router,
};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct AppState {
    pub start_time: Instant,
    pub session_store: Arc<SessionStore>,
    pub entry_service: Arc<EntryService>,
    pub group_service: Arc<GroupService>,
    pub file_service: Arc<FileService>,
}

impl AppState {
    pub fn new(session_timeout: Duration) -> Self {
        let session_store = Arc::new(SessionStore::new(session_timeout));
        Self {
            start_time: Instant::now(),
            session_store: session_store.clone(),
            entry_service: Arc::new(EntryService::new((*session_store).clone())),
            group_service: Arc::new(GroupService::new((*session_store).clone())),
            file_service: Arc::new(FileService::new((*session_store).clone())),
        }
    }
}

pub fn create_router(state: AppState) -> Router {
    use handlers::*;

    let api = Router::new()
        // Sessions
        .route("/sessions", post(create_session))
        .route("/sessions/{id}", get(get_session))
        .route("/sessions/{id}", delete(close_session))
        // Entries
        .route("/sessions/{sid}/entries", post(create_entry))
        .route("/sessions/{sid}/entries", get(list_entries))
        .route("/sessions/{sid}/entries/{eid}", get(get_entry))
        .route("/sessions/{sid}/entries/{eid}", patch(update_entry))
        .route("/sessions/{sid}/entries/{eid}", delete(delete_entry))
        // Groups
        .route("/sessions/{sid}/groups", post(create_group))
        .route("/sessions/{sid}/groups/tree", get(get_group_tree))
        .route("/sessions/{sid}/groups/{gid}", patch(update_group))
        .route("/sessions/{sid}/groups/{gid}", delete(delete_group))
        // Export
        .route("/sessions/{id}/export", get(export_kdbx));

    Router::new()
        .route("/health", get(health_check))
        .nest("/api/v1", api)
        .with_state(state)
}
