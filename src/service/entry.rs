use crate::core::types::{Entry, SecString};
use crate::error::KdbxError;
use crate::service::session::SessionStore;
use std::collections::HashMap;
use uuid::Uuid;

/// 创建条目参数
pub struct CreateEntryParams {
    pub group_id: Uuid,
    pub title: String,
    pub username: Option<String>,
    pub password: String,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub tags: Option<Vec<String>>,
    pub custom_fields: Option<HashMap<String, String>>,
    pub icon_id: Option<u32>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// 更新条目参数
pub struct UpdateEntryParams {
    pub title: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub tags: Option<Vec<String>>,
    pub custom_fields: Option<HashMap<String, String>>,
    pub icon_id: Option<u32>,
    pub group_id: Option<Uuid>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// 条目服务
pub struct EntryService {
    session_store: SessionStore,
}

impl EntryService {
    pub fn new(session_store: SessionStore) -> Self {
        Self { session_store }
    }

    /// 创建条目
    pub async fn create_entry(
        &self,
        session_id: &Uuid,
        params: CreateEntryParams,
    ) -> Result<Entry, KdbxError> {
        let CreateEntryParams {
            group_id,
            title,
            username,
            password,
            url,
            notes,
            tags,
            custom_fields,
            icon_id,
            expires_at,
        } = params;
        // 验证必填字段
        if title.trim().is_empty() {
            return Err(KdbxError::ValidationError("Title is required".to_string()));
        }
        if password.is_empty() {
            return Err(KdbxError::ValidationError("Password is required".to_string()));
        }

        // 验证字段长度
        if title.len() > 500 {
            return Err(KdbxError::ValidationError("Title too long (max 500 chars)".to_string()));
        }
        if password.len() > 10000 {
            return Err(KdbxError::ValidationError("Password too long (max 10000 chars)".to_string()));
        }

        // 获取会话
        let mut session = self.session_store.get_session(session_id).await?;

        // 验证分组存在
        if !session.kdbx_session.groups.contains_key(&group_id) {
            return Err(KdbxError::GroupNotFound(group_id));
        }

        // 创建条目
        let mut entry = Entry::new(group_id, title, SecString::from_plain(&password));
        entry.username = username;
        entry.url = url;
        entry.notes = notes;
        entry.tags = tags.unwrap_or_default();
        entry.custom_fields = custom_fields.unwrap_or_default();
        entry.icon_id = icon_id.unwrap_or(0);
        entry.expires_at = expires_at;

        let entry_id = entry.id;

        // 添加到会话
        session.kdbx_session.entries.insert(entry_id, entry.clone());

        // 更新会话
        self.session_store.update_session(session).await?;

        Ok(entry)
    }

    /// 获取条目
    pub async fn get_entry(&self, session_id: &Uuid, entry_id: &Uuid) -> Result<Entry, KdbxError> {
        let session = self.session_store.get_session(session_id).await?;

        session
            .kdbx_session
            .entries
            .get(entry_id)
            .cloned()
            .ok_or(KdbxError::EntryNotFound(*entry_id))
    }

    /// 列出条目
    pub async fn list_entries(
        &self,
        session_id: &Uuid,
        group_id: Option<Uuid>,
        search: Option<&str>,
        page: u32,
        per_page: u32,
    ) -> Result<(Vec<Entry>, u64), KdbxError> {
        let session = self.session_store.get_session(session_id).await?;

        let mut entries: Vec<Entry> = session
            .kdbx_session
            .entries
            .values()
            .filter(|entry| {
                // 过滤分组
                if let Some(gid) = group_id
                    && entry.group_id != gid
                {
                    return false;
                }

                // 搜索过滤
                if let Some(query) = search {
                    let query_lower = query.to_lowercase();
                    let title_match = entry.title.to_lowercase().contains(&query_lower);
                    let username_match = entry
                        .username
                        .as_ref()
                        .map(|u| u.to_lowercase().contains(&query_lower))
                        .unwrap_or(false);
                    let url_match = entry
                        .url
                        .as_ref()
                        .map(|u| u.to_lowercase().contains(&query_lower))
                        .unwrap_or(false);

                    return title_match || username_match || url_match;
                }

                true
            })
            .cloned()
            .collect();

        // 排序（按标题）
        entries.sort_by(|a, b| a.title.cmp(&b.title));

        let total = entries.len() as u64;

        // 分页
        let start = ((page - 1) * per_page) as usize;
        let _end = (start + per_page as usize).min(entries.len());

        let page_entries: Vec<Entry> = entries.into_iter().skip(start).take(per_page as usize).collect();

        Ok((page_entries, total))
    }

    /// 更新条目
    pub async fn update_entry(
        &self,
        session_id: &Uuid,
        entry_id: &Uuid,
        params: UpdateEntryParams,
    ) -> Result<Entry, KdbxError> {
        let UpdateEntryParams {
            title,
            username,
            password,
            url,
            notes,
            tags,
            custom_fields,
            icon_id,
            group_id,
            expires_at,
        } = params;
        // 获取会话
        let mut session = self.session_store.get_session(session_id).await?;

        // 获取条目
        let entry = session
            .kdbx_session
            .entries
            .get_mut(entry_id)
            .ok_or(KdbxError::EntryNotFound(*entry_id))?;

        // 更新字段
        if let Some(t) = title {
            if t.trim().is_empty() {
                return Err(KdbxError::ValidationError("Title cannot be empty".to_string()));
            }
            entry.title = t;
        }

        if let Some(u) = username {
            entry.username = Some(u);
        }

        if let Some(p) = password {
            entry.password = Some(SecString::from_plain(&p));
        }

        if let Some(u) = url {
            entry.url = Some(u);
        }

        if let Some(n) = notes {
            entry.notes = Some(n);
        }

        if let Some(tags) = tags {
            entry.tags = tags;
        }

        if let Some(custom_fields) = custom_fields {
            entry.custom_fields = custom_fields;
        }

        if let Some(i) = icon_id {
            entry.icon_id = i;
        }

        if let Some(gid) = group_id {
            if !session.kdbx_session.groups.contains_key(&gid) {
                return Err(KdbxError::GroupNotFound(gid));
            }
            entry.group_id = gid;
        }

        if let Some(exp) = expires_at {
            entry.expires_at = Some(exp);
        }

        entry.update();

        let updated_entry = entry.clone();

        // 更新会话
        self.session_store.update_session(session).await?;

        Ok(updated_entry)
    }

    /// 删除条目
    pub async fn delete_entry(
        &self,
        session_id: &Uuid,
        entry_id: &Uuid,
        permanent: bool,
    ) -> Result<(), KdbxError> {
        let mut session = self.session_store.get_session(session_id).await?;

        if permanent {
            // 永久删除
            session
                .kdbx_session
                .entries
                .remove(entry_id)
                .ok_or(KdbxError::EntryNotFound(*entry_id))?;
        } else {
            // 软删除（添加到删除对象列表）
            let entry = session
                .kdbx_session
                .entries
                .remove(entry_id)
                .ok_or(KdbxError::EntryNotFound(*entry_id))?;

            let deleted_obj = crate::core::types::DeletedObject::new(entry.id);
            session.kdbx_session.deleted_objects.push(deleted_obj);
        }

        // 更新会话
        self.session_store.update_session(session).await?;

        Ok(())
    }
}
