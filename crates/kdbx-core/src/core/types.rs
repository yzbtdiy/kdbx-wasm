use crate::error::KdbxError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;
use std::ops::{Deref, DerefMut};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

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
    pub root_group: Option<Uuid>,
    pub group_children: HashMap<Uuid, Vec<Uuid>>,
    pub group_entries: HashMap<Uuid, Vec<Uuid>>,
}

impl KdbxSession {
    pub fn rebuild_indexes(&mut self) {
        self.root_group = self
            .groups
            .values()
            .find(|g| g.parent_id.is_none())
            .map(|g| g.id);

        self.group_children.clear();
        for group in self.groups.values() {
            if let Some(pid) = group.parent_id {
                self.group_children.entry(pid).or_default().push(group.id);
            }
        }

        self.group_entries.clear();
        for entry in self.entries.values() {
            self.group_entries
                .entry(entry.group_id)
                .or_default()
                .push(entry.id);
        }
    }

    pub fn create_entry(
        &mut self,
        group_id: Uuid,
        title: String,
        password: SecString,
    ) -> Result<Uuid, KdbxError> {
        if !self.groups.contains_key(&group_id) {
            return Err(KdbxError::GroupNotFound(group_id));
        }
        let entry = Entry::new(group_id, title, password);
        let id = entry.id;
        self.group_entries.entry(group_id).or_default().push(id);
        self.entries.insert(id, entry);
        Ok(id)
    }

    pub fn delete_entry(&mut self, id: Uuid) -> Result<(), KdbxError> {
        let entry = self
            .entries
            .remove(&id)
            .ok_or(KdbxError::EntryNotFound(id))?;
        self.deleted_objects.push(DeletedObject::new(id));
        if let Some(list) = self.group_entries.get_mut(&entry.group_id) {
            list.retain(|&eid| eid != id);
        }
        Ok(())
    }

    pub fn move_entry(&mut self, entry_id: Uuid, target_group_id: Uuid) -> Result<(), KdbxError> {
        if !self.groups.contains_key(&target_group_id) {
            return Err(KdbxError::GroupNotFound(target_group_id));
        }
        let entry = self
            .entries
            .get_mut(&entry_id)
            .ok_or(KdbxError::EntryNotFound(entry_id))?;
        let old_group_id = entry.group_id;
        entry.group_id = target_group_id;
        entry.update();
        if let Some(list) = self.group_entries.get_mut(&old_group_id) {
            list.retain(|&eid| eid != entry_id);
        }
        self.group_entries
            .entry(target_group_id)
            .or_default()
            .push(entry_id);
        Ok(())
    }

    pub fn create_group(
        &mut self,
        name: String,
        parent_id: Option<Uuid>,
    ) -> Result<Uuid, KdbxError> {
        if let Some(pid) = parent_id && !self.groups.contains_key(&pid) {
            return Err(KdbxError::GroupNotFound(pid));
        }
        let group = Group::new(name, parent_id);
        let id = group.id;
        if parent_id.is_none() && self.root_group.is_some() {
            return Err(KdbxError::ValidationError(
                "Root group already exists".into(),
            ));
        }
        if let Some(pid) = parent_id {
            self.group_children.entry(pid).or_default().push(id);
        } else {
            self.root_group = Some(id);
        }
        self.groups.insert(id, group);
        Ok(id)
    }

    pub fn delete_group(&mut self, id: Uuid) -> Result<(), KdbxError> {
        if !self.groups.contains_key(&id) {
            return Err(KdbxError::GroupNotFound(id));
        }
        // Prevent deletion if group has children or entries
        if let Some(children) = self.group_children.get(&id) && !children.is_empty() {
            return Err(KdbxError::ValidationError(
                "Group contains sub-groups".into(),
            ));
        }
        if let Some(entries) = self.group_entries.get(&id) && !entries.is_empty() {
            return Err(KdbxError::ValidationError("Group contains entries".into()));
        }
        let group = self.groups.remove(&id).unwrap();
        self.deleted_objects.push(DeletedObject::new(id));
        if let Some(pid) = group.parent_id {
            if let Some(list) = self.group_children.get_mut(&pid) {
                list.retain(|&gid| gid != id);
            }
        } else {
            self.root_group = None;
        }
        Ok(())
    }

    pub fn update_metadata<F>(&mut self, f: F)
    where
        F: FnOnce(&mut Metadata),
    {
        f(&mut self.metadata);
    }
}

// ── Search Query ──

#[derive(Debug, Clone, Default)]
pub struct SearchQuery<'a> {
    pub text: Option<&'a str>,
    pub group_id: Option<Uuid>,
    pub tags: Vec<&'a str>,
    pub exclude_expired: bool,
}

impl<'a> SearchQuery<'a> {
    pub fn matches(&self, entry: &Entry, now: DateTime<Utc>) -> bool {
        if let Some(gid) = self.group_id && entry.group_id != gid {
            return false;
        }
        if self.exclude_expired && let Some(expires) = entry.expires_at && expires <= now {
            return false;
        }
        if !self.tags.is_empty() {
            let has_all_tags = self
                .tags
                .iter()
                .all(|tag| entry.tags.iter().any(|t| t.eq_ignore_ascii_case(tag)));
            if !has_all_tags {
                return false;
            }
        }
        if let Some(query) = self.text {
            let q = query.to_lowercase();
            if !entry.title.to_lowercase().contains(&q)
                && !entry
                    .username
                    .as_deref()
                    .unwrap_or("")
                    .to_lowercase()
                    .contains(&q)
                && !entry
                    .url
                    .as_deref()
                    .unwrap_or("")
                    .to_lowercase()
                    .contains(&q)
                && !entry
                    .notes
                    .as_deref()
                    .unwrap_or("")
                    .to_lowercase()
                    .contains(&q)
                && !entry.tags.iter().any(|t| t.to_lowercase().contains(&q))
                && !entry
                    .custom_fields
                    .values()
                    .any(|v| v.to_lowercase().contains(&q))
            {
                return false;
            }
        }
        true
    }
}

// ── Secure Memory Types ──

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecVec<T: Zeroize> {
    data: Vec<T>,
}

impl<T: Zeroize> std::fmt::Debug for SecVec<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecVec([REDACTED])")
    }
}

impl<T: Zeroize> SecVec<T> {
    pub fn new(data: Vec<T>) -> Self {
        Self { data }
    }

    pub fn into_vec(mut self) -> Vec<T> {
        std::mem::take(&mut self.data)
    }
}

impl<T: Zeroize> Deref for SecVec<T> {
    type Target = Vec<T>;
    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<T: Zeroize> DerefMut for SecVec<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl<T: Zeroize> AsRef<[T]> for SecVec<T> {
    fn as_ref(&self) -> &[T] {
        &self.data
    }
}

impl<T: Zeroize> AsMut<[T]> for SecVec<T> {
    fn as_mut(&mut self) -> &mut [T] {
        &mut self.data
    }
}

impl<T: Zeroize + Clone> Clone for SecVec<T> {
    fn clone(&self) -> Self {
        Self {
            data: self.data.clone(),
        }
    }
}

impl<T: Zeroize + PartialEq> PartialEq for SecVec<T> {
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data
    }
}

impl<T: Zeroize + PartialEq> Eq for SecVec<T> {}

impl<T: Zeroize + PartialEq> PartialEq<Vec<T>> for SecVec<T> {
    fn eq(&self, other: &Vec<T>) -> bool {
        &self.data == other
    }
}

impl<T: Zeroize + PartialEq> PartialEq<SecVec<T>> for Vec<T> {
    fn eq(&self, other: &SecVec<T>) -> bool {
        self == &other.data
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecString {
    #[zeroize(skip)]
    _marker: (),
    data: Vec<u8>,
}

impl std::fmt::Debug for SecString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecString([REDACTED])")
    }
}

impl SecString {
    pub fn from_plain(s: &str) -> Self {
        Self {
            _marker: (),
            data: s.as_bytes().to_vec(),
        }
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self {
            _marker: (),
            data: bytes,
        }
    }

    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.data).unwrap_or("")
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn into_bytes(mut self) -> Vec<u8> {
        std::mem::take(&mut self.data)
    }
}

impl Clone for SecString {
    fn clone(&self) -> Self {
        Self {
            _marker: (),
            data: self.data.clone(),
        }
    }
}

impl Serialize for SecString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &self.data);
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
        &self.data
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
        assert_eq!(
            EncryptionAlgorithm::from_u32(0),
            Some(EncryptionAlgorithm::Aes256)
        );
        assert_eq!(
            EncryptionAlgorithm::from_u32(2),
            Some(EncryptionAlgorithm::ChaCha20)
        );
        assert_eq!(EncryptionAlgorithm::from_u32(1), None);
    }

    #[test]
    fn test_compression_algorithm() {
        assert_eq!(
            CompressionAlgorithm::from_u32(0),
            Some(CompressionAlgorithm::None)
        );
        assert_eq!(
            CompressionAlgorithm::from_u32(1),
            Some(CompressionAlgorithm::Gzip)
        );
    }

    #[test]
    fn test_entry_creation() {
        let group_id = Uuid::new_v4();
        let entry = Entry::new(group_id, "Test".to_string(), SecString::from_plain("pass"));
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
        let password = SecString::from_plain("my_secret_password");
        assert_eq!(password.as_str(), "my_secret_password");
    }
}
