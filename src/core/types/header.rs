use serde::{Deserialize, Serialize};

/// 文件签名
pub const SIGNATURE1: u32 = 0x9AA2D903;
pub const SIGNATURE2: u32 = 0xB54BFB67;

/// 文件版本
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

/// 加密算法
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EncryptionAlgorithm {
    Aes256,
    ChaCha20,
}

impl EncryptionAlgorithm {
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(EncryptionAlgorithm::Aes256),
            2 => Some(EncryptionAlgorithm::ChaCha20),
            _ => None,
        }
    }

    pub fn to_u32(&self) -> u32 {
        match self {
            EncryptionAlgorithm::Aes256 => 0,
            EncryptionAlgorithm::ChaCha20 => 2,
        }
    }
}

/// 压缩算法
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CompressionAlgorithm {
    None,
    Gzip,
}

impl CompressionAlgorithm {
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(CompressionAlgorithm::None),
            1 => Some(CompressionAlgorithm::Gzip),
            _ => None,
        }
    }

    pub fn to_u32(&self) -> u32 {
        match self {
            CompressionAlgorithm::None => 0,
            CompressionAlgorithm::Gzip => 1,
        }
    }
}

/// 密钥派生函数
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

/// KDBX文件头部
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdbxHeader {
    pub version: FileVersion,
    pub encryption: EncryptionAlgorithm,
    pub compression: CompressionAlgorithm,
    pub kdf: KdfAlgorithm,
    pub master_seed: Vec<u8>,
    pub encryption_iv: Vec<u8>,
    // KDBX 3.1 兼容字段 (KDBX 4中这些字段在KDF参数中)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transform_seed: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transform_rounds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream_start_bytes: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inner_random_stream_key: Option<Vec<u8>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_version() {
        let version = FileVersion::new(4, 0);
        assert!(version.is_kdbx4());

        let old_version = FileVersion::new(3, 5);
        assert!(!old_version.is_kdbx4());
    }

    #[test]
    fn test_encryption_algorithm() {
        assert_eq!(EncryptionAlgorithm::from_u32(0), Some(EncryptionAlgorithm::Aes256));
        assert_eq!(EncryptionAlgorithm::from_u32(2), Some(EncryptionAlgorithm::ChaCha20));
        assert_eq!(EncryptionAlgorithm::from_u32(1), None);

        assert_eq!(EncryptionAlgorithm::Aes256.to_u32(), 0);
        assert_eq!(EncryptionAlgorithm::ChaCha20.to_u32(), 2);
    }

    #[test]
    fn test_compression_algorithm() {
        assert_eq!(CompressionAlgorithm::from_u32(0), Some(CompressionAlgorithm::None));
        assert_eq!(CompressionAlgorithm::from_u32(1), Some(CompressionAlgorithm::Gzip));

        assert_eq!(CompressionAlgorithm::None.to_u32(), 0);
        assert_eq!(CompressionAlgorithm::Gzip.to_u32(), 1);
    }
}
