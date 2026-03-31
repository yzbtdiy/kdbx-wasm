use crate::core::crypto::generate_random_bytes;
use crate::core::types::{CompressionAlgorithm, EncryptionAlgorithm, FileVersion, KdbxHeader};
use crate::error::KdbxError;
use crate::service::session::SessionStore;
use uuid::Uuid;

/// 文件服务
pub struct FileService {
    session_store: SessionStore,
}

impl FileService {
    pub fn new(session_store: SessionStore) -> Self {
        Self { session_store }
    }

    /// 导出KDBX文件
    pub async fn export_kdbx(
        &self,
        session_id: &Uuid,
        encryption: Option<EncryptionAlgorithm>,
        compression: Option<CompressionAlgorithm>,
    ) -> Result<Vec<u8>, KdbxError> {
        let mut session = self.session_store.get_session(session_id).await?;

        let new_encryption = encryption.unwrap_or(session.kdbx_session.header.encryption);
        let new_compression = compression.unwrap_or(session.kdbx_session.header.compression);
        let iv_len = match new_encryption {
            EncryptionAlgorithm::Aes256 => 16,
            EncryptionAlgorithm::ChaCha20 => 12,
        };

        session.kdbx_session.header = KdbxHeader {
            version: FileVersion::new(4, 0),
            encryption: new_encryption,
            compression: new_compression,
            kdf: session.kdbx_session.header.kdf.clone(),
            master_seed: generate_random_bytes(32),
            encryption_iv: generate_random_bytes(iv_len),
            // KDBX 3.1 兼容字段 (KDBX 4中可选)
            transform_seed: None,
            transform_rounds: None,
            stream_start_bytes: None,
            inner_random_stream_key: Some(generate_random_bytes(64)),
        };

        self.session_store.update_session(session.clone()).await?;

        // 导出
        self.session_store.export_kdbx(session_id).await
    }

    /// 获取会话元数据
    pub async fn get_metadata(&self, session_id: &Uuid) -> Result<SessionMetadata, KdbxError> {
        let session = self.session_store.get_session(session_id).await?;

        Ok(SessionMetadata {
            version: format!(
                "{}.{}",
                session.kdbx_session.header.version.major,
                session.kdbx_session.header.version.minor
            ),
            encryption_algorithm: format!("{:?}", session.kdbx_session.header.encryption),
            kdf: format!("{:?}", session.kdbx_session.header.kdf),
            entry_count: session.kdbx_session.entries.len(),
            group_count: session.kdbx_session.groups.len(),
        })
    }
}

/// Session metadata
#[derive(Debug, Clone, serde::Serialize)]
pub struct SessionMetadata {
    pub version: String,
    pub encryption_algorithm: String,
    pub kdf: String,
    pub entry_count: usize,
    pub group_count: usize,
}
