use crate::service::{EntryService, FileService, GroupService, SessionStore};
use std::sync::Arc;
use std::time::Instant;

#[derive(Clone)]
pub struct AppState {
    pub start_time: Instant,
    pub session_store: Arc<SessionStore>,
    pub entry_service: Arc<EntryService>,
    pub group_service: Arc<GroupService>,
    pub file_service: Arc<FileService>,
}

impl AppState {
    pub fn new(session_timeout: std::time::Duration) -> Self {
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
