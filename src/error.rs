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

#[cfg(not(target_arch = "wasm32"))]
impl axum::response::IntoResponse for KdbxError {
    fn into_response(self) -> axum::response::Response {
        use axum::http::StatusCode;

        let (status, code) = match &self {
            KdbxError::InvalidSignature
            | KdbxError::UnsupportedVersion(_, _)
            | KdbxError::InvalidFileFormat
            | KdbxError::ValidationError(_)
            | KdbxError::MissingField(_)
            | KdbxError::InvalidFieldValue(_)
            | KdbxError::UnsupportedEncryptionAlgorithm
            | KdbxError::UnsupportedKdfAlgorithm
            | KdbxError::CompressionError(_) => (StatusCode::BAD_REQUEST, "BAD_REQUEST"),

            KdbxError::InvalidMasterKey
            | KdbxError::DecryptionFailed
            | KdbxError::HmacVerificationFailed => (StatusCode::UNAUTHORIZED, "UNAUTHORIZED"),

            KdbxError::EntryNotFound(_)
            | KdbxError::GroupNotFound(_)
            | KdbxError::SessionNotFound(_) => (StatusCode::NOT_FOUND, "NOT_FOUND"),

            KdbxError::SessionExpired(_) => (StatusCode::GONE, "SESSION_EXPIRED"),

            KdbxError::IoError(_) | KdbxError::SerializationError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR")
            }
        };

        let body = serde_json::json!({
            "error": {
                "code": code,
                "message": self.to_string()
            }
        });

        (status, axum::Json(body)).into_response()
    }
}
