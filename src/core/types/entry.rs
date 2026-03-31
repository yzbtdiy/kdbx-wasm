use crate::core::types::secure::SecString;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// 密码条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub id: Uuid,
    pub group_id: Uuid,
    pub title: String,
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<SecString>,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub icon_id: u32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub accessed_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub tags: Vec<String>,
    pub custom_fields: HashMap<String, String>,
}

impl Entry {
    pub fn new(group_id: Uuid, title: String, password: SecString) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            group_id,
            title,
            username: None,
            password: Some(password),
            url: None,
            notes: None,
            icon_id: 0,
            created_at: now,
            updated_at: now,
            accessed_at: now,
            expires_at: None,
            tags: Vec::new(),
            custom_fields: HashMap::new(),
        }
    }

    pub fn touch(&mut self) {
        self.accessed_at = Utc::now();
    }

    pub fn update(&mut self) {
        self.updated_at = Utc::now();
    }
}

/// 分组
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub id: Uuid,
    pub name: String,
    pub parent_id: Option<Uuid>,
    pub icon_id: u32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub notes: Option<String>,
}

impl Group {
    pub fn new(name: String, parent_id: Option<Uuid>) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            name,
            parent_id,
            icon_id: 0,
            created_at: now,
            updated_at: now,
            notes: None,
        }
    }

    pub fn update(&mut self) {
        self.updated_at = Utc::now();
    }
}

/// 删除对象
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeletedObject {
    pub id: Uuid,
    pub deletion_time: DateTime<Utc>,
}

impl DeletedObject {
    pub fn new(id: Uuid) -> Self {
        Self {
            id,
            deletion_time: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entry_creation() {
        let group_id = Uuid::new_v4();
        let password = SecString::from_str("test_password");
        let entry = Entry::new(group_id, "Test Entry".to_string(), password);

        assert_eq!(entry.title, "Test Entry");
        assert_eq!(entry.group_id, group_id);
        assert!(entry.password.is_some());
    }

    #[test]
    fn test_group_creation() {
        let parent_id = Uuid::new_v4();
        let group = Group::new("Test Group".to_string(), Some(parent_id));

        assert_eq!(group.name, "Test Group");
        assert_eq!(group.parent_id, Some(parent_id));
    }
}
