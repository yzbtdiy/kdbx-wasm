use thiserror::Error;

#[derive(Error, Debug)]
pub enum KdbxError {
    #[error("Invalid file signature")]
    InvalidSignature,

    #[error("Unsupported KDBX version: {0}.{1}")]
    UnsupportedVersion(u16, u16),

    #[error("Invalid master key")]
    InvalidMasterKey,

    #[error("Decryption failed")]
    DecryptionFailed,

    #[error("HMAC verification failed")]
    HmacVerificationFailed,

    #[error("Compression error: {0}")]
    CompressionError(String),

    #[error("Invalid file format")]
    InvalidFileFormat,

    #[error("Entry not found: {0}")]
    EntryNotFound(uuid::Uuid),

    #[error("Group not found: {0}")]
    GroupNotFound(uuid::Uuid),

    #[error("Session not found: {0}")]
    SessionNotFound(uuid::Uuid),

    #[error("Session expired: {0}")]
    SessionExpired(uuid::Uuid),

    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Unsupported encryption algorithm")]
    UnsupportedEncryptionAlgorithm,

    #[error("Unsupported KDF algorithm")]
    UnsupportedKdfAlgorithm,

    #[error("Missing required field: {0}")]
    MissingField(String),

    #[error("Invalid field value: {0}")]
    InvalidFieldValue(String),
}

// 实现从其他错误类型到KdbxError的转换
impl From<serde_json::Error> for KdbxError {
    fn from(err: serde_json::Error) -> Self {
        KdbxError::SerializationError(err.to_string())
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl From<config::ConfigError> for KdbxError {
    fn from(err: config::ConfigError) -> Self {
        KdbxError::ValidationError(err.to_string())
    }
}
