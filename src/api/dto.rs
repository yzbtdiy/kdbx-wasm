use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

// ── Requests ──

#[derive(Debug, Deserialize)]
pub struct CreateEntryRequest {
    pub title: String,
    pub username: Option<String>,
    pub password: String,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub tags: Option<Vec<String>>,
    pub custom_fields: Option<HashMap<String, String>>,
    pub icon_id: Option<u32>,
    pub group_id: Option<Uuid>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateEntryRequest {
    pub title: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub tags: Option<Vec<String>>,
    pub custom_fields: Option<HashMap<String, String>>,
    pub icon_id: Option<u32>,
    pub group_id: Option<Uuid>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
pub struct CreateGroupRequest {
    pub name: String,
    pub parent_id: Option<Uuid>,
    pub icon_id: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateGroupRequest {
    pub name: Option<String>,
    pub parent_id: Option<Uuid>,
    pub icon_id: Option<u32>,
}

// ── Responses ──

#[derive(Debug, Serialize)]
pub struct EntryResponse {
    pub id: Uuid,
    pub title: String,
    pub username: Option<String>,
    pub password: String,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub tags: Vec<String>,
    pub custom_fields: HashMap<String, String>,
    pub icon_id: u32,
    pub group_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub accessed_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct EntryListResponse {
    pub entries: Vec<EntryResponse>,
    pub pagination: Pagination,
}

#[derive(Debug, Serialize)]
pub struct Pagination {
    pub page: u32,
    pub per_page: u32,
    pub total: u64,
    pub total_pages: u32,
}

#[derive(Debug, Serialize)]
pub struct GroupResponse {
    pub id: Uuid,
    pub name: String,
    pub parent_id: Option<Uuid>,
    pub icon_id: u32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct GroupTreeResponse {
    pub groups: Vec<GroupNode>,
}

#[derive(Debug, Serialize)]
pub struct GroupNode {
    pub id: Uuid,
    pub name: String,
    pub icon_id: u32,
    pub children: Vec<GroupNode>,
}

#[derive(Debug, Serialize)]
pub struct SessionResponse {
    pub session_id: Uuid,
    pub metadata: SessionMetadata,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct SessionMetadata {
    pub version: String,
    pub encryption_algorithm: String,
    pub kdf: String,
    pub entry_count: usize,
    pub group_count: usize,
}

impl EntryResponse {
    pub fn from_entry(e: crate::core::types::Entry) -> Self {
        Self {
            id: e.id,
            title: e.title,
            username: e.username,
            password: e.password.map(|p| p.as_str().to_string()).unwrap_or_default(),
            url: e.url,
            notes: e.notes,
            tags: e.tags,
            custom_fields: e.custom_fields,
            icon_id: e.icon_id,
            group_id: e.group_id,
            created_at: e.created_at,
            updated_at: e.updated_at,
            accessed_at: e.accessed_at,
            expires_at: e.expires_at,
        }
    }
}

impl SessionMetadata {
    pub fn from_session(s: &crate::service::Session) -> Self {
        Self {
            version: format!("{}.{}", s.kdbx_session.header.version.major, s.kdbx_session.header.version.minor),
            encryption_algorithm: format!("{:?}", s.kdbx_session.header.encryption),
            kdf: format!("{:?}", s.kdbx_session.header.kdf),
            entry_count: s.kdbx_session.entries.len(),
            group_count: s.kdbx_session.groups.len(),
        }
    }
}

impl GroupResponse {
    pub fn from_group(g: crate::core::types::Group) -> Self {
        Self {
            id: g.id,
            name: g.name,
            parent_id: g.parent_id,
            icon_id: g.icon_id,
            created_at: g.created_at,
            updated_at: g.updated_at,
        }
    }
}

impl GroupNode {
    pub fn from_service(n: crate::service::GroupNode) -> Self {
        Self {
            id: n.id,
            name: n.name,
            icon_id: n.icon_id,
            children: n.children.into_iter().map(Self::from_service).collect(),
        }
    }
}
