use crate::core::types::Group;
use crate::error::KdbxError;
use crate::service::session::{Session, SessionStore};
use uuid::Uuid;

/// 分组服务
pub struct GroupService {
    session_store: SessionStore,
}

impl GroupService {
    pub fn new(session_store: SessionStore) -> Self {
        Self { session_store }
    }

    /// 创建分组
    pub async fn create_group(
        &self,
        session_id: &Uuid,
        name: String,
        parent_id: Option<Uuid>,
        icon_id: Option<u32>,
    ) -> Result<Group, KdbxError> {
        // 验证名称
        if name.trim().is_empty() {
            return Err(KdbxError::ValidationError("Group name is required".to_string()));
        }
        if name.len() > 500 {
            return Err(KdbxError::ValidationError("Group name too long (max 500 chars)".to_string()));
        }

        // 获取会话
        let mut session = self.session_store.get_session(session_id).await?;

        // 验证父分组存在
        if let Some(pid) = parent_id
            && !session.kdbx_session.groups.contains_key(&pid)
        {
            return Err(KdbxError::GroupNotFound(pid));
        }

        // 创建分组
        let mut group = Group::new(name, parent_id);
        group.icon_id = icon_id.unwrap_or(0);

        let group_id = group.id;

        // 添加到会话
        session.kdbx_session.groups.insert(group_id, group.clone());

        // 更新会话
        self.session_store.update_session(session).await?;

        Ok(group)
    }

    /// 获取分组
    pub async fn get_group(&self, session_id: &Uuid, group_id: &Uuid) -> Result<Group, KdbxError> {
        let session = self.session_store.get_session(session_id).await?;

        session
            .kdbx_session
            .groups
            .get(group_id)
            .cloned()
            .ok_or(KdbxError::GroupNotFound(*group_id))
    }

    /// 获取分组树
    pub async fn get_group_tree(&self, session_id: &Uuid) -> Result<Vec<GroupNode>, KdbxError> {
        let session = self.session_store.get_session(session_id).await?;

        // 找出所有根分组（没有父分组的）
        let root_groups: Vec<Group> = session
            .kdbx_session
            .groups
            .values()
            .filter(|g| g.parent_id.is_none())
            .cloned()
            .collect();

        // 构建树
        let tree: Vec<GroupNode> = root_groups
            .into_iter()
            .map(|g| self.build_group_tree(&session, g))
            .collect();

        Ok(tree)
    }

    /// 递归构建分组树
    fn build_group_tree(&self, session: &Session, group: Group) -> GroupNode {
        let children: Vec<GroupNode> = session
            .kdbx_session
            .groups
            .values()
            .filter(|g| g.parent_id == Some(group.id))
            .cloned()
            .map(|g| self.build_group_tree(session, g))
            .collect();

        GroupNode {
            id: group.id,
            name: group.name,
            icon_id: group.icon_id,
            children,
        }
    }

    /// 更新分组
    pub async fn update_group(
        &self,
        session_id: &Uuid,
        group_id: &Uuid,
        name: Option<String>,
        parent_id: Option<Uuid>,
        icon_id: Option<u32>,
    ) -> Result<Group, KdbxError> {
        // 获取会话
        let mut session = self.session_store.get_session(session_id).await?;

        // 验证分组存在
        if !session.kdbx_session.groups.contains_key(group_id) {
            return Err(KdbxError::GroupNotFound(*group_id));
        }

        // 验证父分组存在
        if let Some(pid) = parent_id {
            if !session.kdbx_session.groups.contains_key(&pid) {
                return Err(KdbxError::GroupNotFound(pid));
            }

            // 防止循环引用
            if self.would_create_cycle(&session, *group_id, pid) {
                return Err(KdbxError::ValidationError(
                    "Cannot create circular reference".to_string(),
                ));
            }
        }

        // 获取分组并更新
        let group = session
            .kdbx_session
            .groups
            .get_mut(group_id)
            .ok_or(KdbxError::GroupNotFound(*group_id))?;

        // 更新字段
        if let Some(n) = name {
            if n.trim().is_empty() {
                return Err(KdbxError::ValidationError("Group name cannot be empty".to_string()));
            }
            group.name = n;
        }

        if let Some(pid) = parent_id {
            group.parent_id = Some(pid);
        }

        if let Some(i) = icon_id {
            group.icon_id = i;
        }

        group.update();

        let updated_group = group.clone();

        // 更新会话
        self.session_store.update_session(session).await?;

        Ok(updated_group)
    }

    /// 检查是否会创建循环引用
    fn would_create_cycle(&self, session: &Session, group_id: Uuid, new_parent_id: Uuid) -> bool {
        if group_id == new_parent_id {
            return true;
        }

        let mut current_id = new_parent_id;
        while let Some(current_group) = session.kdbx_session.groups.get(&current_id) {
            if let Some(parent_id) = current_group.parent_id {
                if parent_id == group_id {
                    return true;
                }
                current_id = parent_id;
            } else {
                break;
            }
        }

        false
    }

    /// 删除分组
    pub async fn delete_group(
        &self,
        session_id: &Uuid,
        group_id: &Uuid,
        force: bool,
    ) -> Result<(), KdbxError> {
        let mut session = self.session_store.get_session(session_id).await?;

        // 检查分组是否存在
        if !session.kdbx_session.groups.contains_key(group_id) {
            return Err(KdbxError::GroupNotFound(*group_id));
        }

        // 检查是否有子分组
        let has_children = session
            .kdbx_session
            .groups
            .values()
            .any(|g| g.parent_id == Some(*group_id));

        // 检查是否有条目
        let has_entries = session
            .kdbx_session
            .entries
            .values()
            .any(|e| e.group_id == *group_id);

        if (has_children || has_entries) && !force {
            return Err(KdbxError::ValidationError(
                "Group has children or entries. Use force=true to delete.".to_string(),
            ));
        }

        if force {
            // 递归删除所有子分组和条目
            self.delete_group_recursive(&mut session, *group_id)?;
        } else {
            // 只删除空分组
            session.kdbx_session.groups.remove(group_id);
        }

        // 更新会话
        self.session_store.update_session(session).await?;

        Ok(())
    }

    /// 递归删除分组
    fn delete_group_recursive(&self, session: &mut Session, group_id: Uuid) -> Result<(), KdbxError> {
        // 删除所有子分组
        let child_ids: Vec<Uuid> = session
            .kdbx_session
            .groups
            .values()
            .filter(|g| g.parent_id == Some(group_id))
            .map(|g| g.id)
            .collect();

        for child_id in child_ids {
            self.delete_group_recursive(session, child_id)?;
        }

        // 删除该分组下的所有条目
        let entry_ids: Vec<Uuid> = session
            .kdbx_session
            .entries
            .values()
            .filter(|e| e.group_id == group_id)
            .map(|e| e.id)
            .collect();

        for entry_id in entry_ids {
            session.kdbx_session.entries.remove(&entry_id);
        }

        // 删除分组
        session.kdbx_session.groups.remove(&group_id);

        Ok(())
    }
}

/// 分组树节点
#[derive(Debug, Clone, serde::Serialize)]
pub struct GroupNode {
    pub id: Uuid,
    pub name: String,
    pub icon_id: u32,
    pub children: Vec<GroupNode>,
}
