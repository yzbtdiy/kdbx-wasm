use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;
use std::ops::{Deref, DerefMut};
use uuid::Uuid;

// ── File Signatures ──

pub const SIGNATURE1: u32 = 0x9AA2D903;
pub const SIGNATURE2: u32 = 0xB54BFB67;

// ── File Version ──

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileVersion {
    pub major: u16,
    pub minor: u16,
}

impl FileVersion {
    pub fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }

    pub fn is_kdbx4(&self) -> bool {
        self.major == 4
    }
}

// ── Encryption Algorithm ──

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EncryptionAlgorithm {
    Aes256,
    ChaCha20,
}

impl EncryptionAlgorithm {
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Aes256),
            2 => Some(Self::ChaCha20),
            _ => None,
        }
    }

    pub fn to_u32(&self) -> u32 {
        match self {
            Self::Aes256 => 0,
            Self::ChaCha20 => 2,
        }
    }
}

// ── Compression Algorithm ──

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CompressionAlgorithm {
    None,
    Gzip,
}

impl CompressionAlgorithm {
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::None),
            1 => Some(Self::Gzip),
            _ => None,
        }
    }

    pub fn to_u32(&self) -> u32 {
        match self {
            Self::None => 0,
            Self::Gzip => 1,
        }
    }
}

// ── KDF Algorithm ──

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum KdfAlgorithm {
    Argon2d {
        memory: u64,
        iterations: u64,
        parallelism: u32,
        salt: Vec<u8>,
    },
    Argon2id {
        memory: u64,
        iterations: u64,
        parallelism: u32,
        salt: Vec<u8>,
    },
    AesKdf {
        rounds: u64,
        salt: Vec<u8>,
    },
}

// ── KDBX Header ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdbxHeader {
    pub version: FileVersion,
    pub encryption: EncryptionAlgorithm,
    pub compression: CompressionAlgorithm,
    pub kdf: KdfAlgorithm,
    pub master_seed: Vec<u8>,
    pub encryption_iv: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transform_seed: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transform_rounds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream_start_bytes: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inner_random_stream_key: Option<Vec<u8>>,
}

// ── Entry ──

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

// ── Group ──

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

// ── Deleted Object ──

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

// ── Metadata ──

#[derive(Debug, Clone, Default)]
pub struct Metadata {
    pub database_name: Option<String>,
    pub database_description: Option<String>,
    pub default_username: Option<String>,
    pub maintenance_history_days: u32,
    pub color: Option<String>,
}

// ── KDBX Session ──

#[derive(Debug, Clone)]
pub struct KdbxSession {
    pub header: KdbxHeader,
    pub groups: HashMap<Uuid, Group>,
    pub entries: HashMap<Uuid, Entry>,
    pub deleted_objects: Vec<DeletedObject>,
    pub metadata: Metadata,
}

// ── Secure Memory Types ──

pub struct SecVec<T> {
    data: Vec<T>,
}

impl<T> SecVec<T> {
    pub fn new(data: Vec<T>) -> Self {
        Self { data }
    }

    pub fn into_vec(mut self) -> Vec<T> {
        let data = std::mem::take(&mut self.data);
        std::mem::forget(self);
        data
    }
}

impl<T> Drop for SecVec<T> {
    fn drop(&mut self) {
        unsafe {
            for byte in self.data.iter_mut() {
                std::ptr::write_volatile(byte, std::mem::zeroed());
            }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

impl<T> Deref for SecVec<T> {
    type Target = Vec<T>;
    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<T> DerefMut for SecVec<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl<T: Clone> Clone for SecVec<T> {
    fn clone(&self) -> Self {
        Self { data: self.data.clone() }
    }
}

pub struct SecString(SecVec<u8>);

impl std::fmt::Debug for SecString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecString([REDACTED])")
    }
}

impl SecString {
    pub fn from_str(s: &str) -> Self {
        Self(SecVec::new(s.as_bytes().to_vec()))
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(SecVec::new(bytes))
    }

    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).unwrap_or("")
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0.into_vec()
    }
}

impl Clone for SecString {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl Serialize for SecString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &**self);
        serializer.serialize_str(&encoded)
    }
}

impl<'de> Deserialize<'de> for SecString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &s)
            .map_err(serde::de::Error::custom)?;
        Ok(SecString::from_bytes(bytes))
    }
}

impl Deref for SecString {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_version() {
        assert!(FileVersion::new(4, 0).is_kdbx4());
        assert!(!FileVersion::new(3, 5).is_kdbx4());
    }

    #[test]
    fn test_encryption_algorithm() {
        assert_eq!(EncryptionAlgorithm::from_u32(0), Some(EncryptionAlgorithm::Aes256));
        assert_eq!(EncryptionAlgorithm::from_u32(2), Some(EncryptionAlgorithm::ChaCha20));
        assert_eq!(EncryptionAlgorithm::from_u32(1), None);
    }

    #[test]
    fn test_compression_algorithm() {
        assert_eq!(CompressionAlgorithm::from_u32(0), Some(CompressionAlgorithm::None));
        assert_eq!(CompressionAlgorithm::from_u32(1), Some(CompressionAlgorithm::Gzip));
    }

    #[test]
    fn test_entry_creation() {
        let group_id = Uuid::new_v4();
        let entry = Entry::new(group_id, "Test".to_string(), SecString::from_str("pass"));
        assert_eq!(entry.title, "Test");
        assert_eq!(entry.group_id, group_id);
    }

    #[test]
    fn test_group_creation() {
        let pid = Uuid::new_v4();
        let group = Group::new("Test Group".to_string(), Some(pid));
        assert_eq!(group.name, "Test Group");
        assert_eq!(group.parent_id, Some(pid));
    }

    #[test]
    fn test_sec_string() {
        let password = SecString::from_str("my_secret_password");
        assert_eq!(password.as_str(), "my_secret_password");
    }
}
