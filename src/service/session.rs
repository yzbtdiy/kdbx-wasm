use crate::core::{parser::{parse_kdbx, generate_kdbx}, KdbxSession, SecString, SecVec};
use crate::error::KdbxError;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use uuid::Uuid;

/// 会话信息
#[derive(Debug, Clone)]
pub struct Session {
    pub id: Uuid,
    pub kdbx_session: KdbxSession,
    pub created_at: DateTime<Utc>,
    pub last_accessed_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub master_password: Option<SecString>,
    pub key_file_data: Option<SecVec<u8>>,
}

impl Session {
    pub fn new(
        kdbx_session: KdbxSession,
        master_password: Option<SecString>,
        key_file_data: Option<SecVec<u8>>,
        timeout: Duration,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            kdbx_session,
            created_at: now,
            last_accessed_at: now,
            expires_at: now + chrono::Duration::from_std(timeout).unwrap(),
            master_password,
            key_file_data,
        }
    }

    pub fn touch(&mut self) {
        self.last_accessed_at = Utc::now();
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }
}

/// 会话存储
#[derive(Clone)]
pub struct SessionStore {
    sessions: Arc<RwLock<HashMap<Uuid, Session>>>,
    timeout: Duration,
}

impl SessionStore {
    pub fn new(timeout: Duration) -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            timeout,
        }
    }

    /// 创建新会话
    pub async fn create_session(
        &self,
        kdbx_data: &[u8],
        master_password: Option<String>,
        key_file_data: Option<Vec<u8>>,
    ) -> Result<Session, KdbxError> {
        let mp = master_password.map(|s| SecString::from_plain(&s));
        let kf = key_file_data.map(SecVec::new);

        // 解析KDBX文件
        let kdbx_session = parse_kdbx(
            kdbx_data,
            mp.as_ref().map(|s| s.as_str()),
            kf.as_deref().map(|v| v.as_slice()),
        )?;

        // 创建会话
        let session = Session::new(kdbx_session, mp, kf, self.timeout);
        let session_id = session.id;

        // 存储会话
        let mut sessions = self.sessions.write().await;
        sessions.insert(session_id, session.clone());

        Ok(session)
    }

    /// 获取会话
    pub async fn get_session(&self, session_id: &Uuid) -> Result<Session, KdbxError> {
        // Fast path: read lock for non-expired sessions
        {
            let sessions = self.sessions.read().await;
            if let Some(session) = sessions.get(session_id) {
                if !session.is_expired() {
                    return Ok(session.clone());
                }
            } else {
                return Err(KdbxError::SessionNotFound(*session_id));
            }
        }

        // Slow path: write lock to clean up expired session or touch
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(session_id) {
            if session.is_expired() {
                sessions.remove(session_id);
                return Err(KdbxError::SessionExpired(*session_id));
            }
            session.touch();
            Ok(session.clone())
        } else {
            Err(KdbxError::SessionNotFound(*session_id))
        }
    }

    /// 更新会话
    pub async fn update_session(&self, session: Session) -> Result<(), KdbxError> {
        let mut sessions = self.sessions.write().await;

        match sessions.entry(session.id) {
            std::collections::hash_map::Entry::Occupied(mut e) => {
                e.insert(session);
                Ok(())
            }
            std::collections::hash_map::Entry::Vacant(_) => {
                Err(KdbxError::SessionNotFound(session.id))
            }
        }
    }

    /// 关闭会话
    pub async fn close_session(&self, session_id: &Uuid) -> Result<(), KdbxError> {
        let mut sessions = self.sessions.write().await;

        if sessions.remove(session_id).is_some() {
            // 清零敏感数据（Session的Drop会自动处理）
            Ok(())
        } else {
            Err(KdbxError::SessionNotFound(*session_id))
        }
    }

    /// 导出KDBX文件
    pub async fn export_kdbx(&self, session_id: &Uuid) -> Result<Vec<u8>, KdbxError> {
        let session = self.get_session(session_id).await?;

        generate_kdbx(
            &session.kdbx_session,
            session.master_password.as_ref().map(|s| s.as_str()),
            session.key_file_data.as_deref().map(|v| v.as_slice()),
        )
    }

    /// 清理过期会话
    pub async fn cleanup_expired(&self) {
        let mut sessions = self.sessions.write().await;
        let expired_ids: Vec<Uuid> = sessions
            .iter()
            .filter(|(_, session)| session.is_expired())
            .map(|(id, _)| *id)
            .collect();

        for id in expired_ids {
            sessions.remove(&id);
            tracing::info!("Session {} expired and removed", id);
        }
    }

    /// 获取会话数量
    pub async fn session_count(&self) -> usize {
        self.sessions.read().await.len()
    }
}

/// 启动会话清理任务
pub fn start_cleanup_task(store: Arc<SessionStore>, interval: Duration) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut timer = tokio::time::interval(interval);
        loop {
            timer.tick().await;
            store.cleanup_expired().await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_session_store() {
        let store = SessionStore::new(Duration::from_secs(1800));

        // 测试创建会话
        // 注意：需要有效的KDBX文件数据
        // let session = store.create_session(&kdbx_data, Some("password".to_string()), None).await;
        // assert!(session.is_ok());

        assert_eq!(store.session_count().await, 0);
    }
}
