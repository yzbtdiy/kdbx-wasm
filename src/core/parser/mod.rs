pub mod header;
pub mod data_stream;
pub mod xml;

use crate::core::crypto::{
    compute_hmac_sha256, decrypt_aes256_cbc, decrypt_chacha20, derive_key_aes_kdf,
    derive_key_argon2d, derive_key_argon2id, encrypt_aes256_cbc, encrypt_chacha20,
};
use crate::core::types::{
    CompressionAlgorithm, DeletedObject, EncryptionAlgorithm, Entry, Group, KdbxHeader,
    KdfAlgorithm,
};
use crate::error::KdbxError;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use rand::RngCore;
use sha2::{Digest, Sha256, Sha512};
use std::collections::HashMap;
use std::io::{Read, Write};
use uuid::Uuid;

/// 组合主密钥（主密码 + 密钥文件）
/// 根据 KeePass 规范：
/// - 如果只有密码：composite_key = SHA256(password)
/// - 如果有密码和密钥文件：composite_key = SHA256(SHA256(password) || key_file_hash)
pub fn combine_master_key(
    master_password: Option<&str>,
    key_file_data: Option<&[u8]>,
) -> Result<Vec<u8>, KdbxError> {
    let mut combined = Vec::new();

    if let Some(password) = master_password {
        let password_hash = Sha256::digest(password.as_bytes());
        combined.extend_from_slice(&password_hash);
    }

    if let Some(key_file) = key_file_data {
        if key_file.len() == 32 {
            combined.extend_from_slice(key_file);
        } else {
            let key_hash = Sha256::digest(key_file);
            combined.extend_from_slice(&key_hash);
        }
    }

    if combined.is_empty() {
        return Err(KdbxError::InvalidMasterKey);
    }

    // 计算最终组合密钥
    let final_hash = Sha256::digest(&combined);
    Ok(final_hash.to_vec())
}

/// 派生加密密钥
pub fn derive_encryption_key(
    master_key: &[u8],
    header: &KdbxHeader,
) -> Result<Vec<u8>, KdbxError> {
    let transformed_key = derive_transformed_key(master_key, header)?;

    tracing::debug!("Transformed key: {:02x?}", transformed_key);

    // 组合master_seed和transformed_key生成最终密钥
    let mut final_key_input = Vec::new();
    final_key_input.extend_from_slice(&header.master_seed);
    final_key_input.extend_from_slice(&transformed_key);

    tracing::debug!("Final key input: {:02x?}", final_key_input);

    let final_key = Sha256::digest(&final_key_input);
    tracing::debug!("Final encryption key: {:02x?}", final_key);

    Ok(final_key.to_vec())
}

fn derive_transformed_key(master_key: &[u8], header: &KdbxHeader) -> Result<Vec<u8>, KdbxError> {
    tracing::debug!("Deriving encryption key...");
    tracing::debug!("Master key: {:02x?}", master_key);

    match &header.kdf {
        KdfAlgorithm::Argon2d {
            memory,
            iterations,
            parallelism,
            salt,
        } => {
            tracing::debug!("Using Argon2d: memory={}, iterations={}, parallelism={}", memory, iterations, parallelism);
            tracing::debug!("Salt: {:02x?}", salt);
            derive_key_argon2d(
                master_key,
                salt,
                *memory,
                *iterations,
                *parallelism,
                32,
            )
        }
        KdfAlgorithm::Argon2id {
            memory,
            iterations,
            parallelism,
            salt,
        } => {
            tracing::debug!("Using Argon2id: memory={}, iterations={}, parallelism={}", memory, iterations, parallelism);
            tracing::debug!("Salt: {:02x?}", salt);
            derive_key_argon2id(
                master_key,
                salt,
                *memory,
                *iterations,
                *parallelism,
                32,
            )
        }
        KdfAlgorithm::AesKdf { rounds, salt } => {
            tracing::debug!("Using AES-KDF: rounds={}", rounds);
            tracing::debug!("Salt (seed): {:02x?}", salt);
            derive_key_aes_kdf(master_key, salt, *rounds, 32)
        }
    }
}

fn derive_hmac_base_key(master_key: &[u8], header: &KdbxHeader) -> Result<Vec<u8>, KdbxError> {
    let transformed_key = derive_transformed_key(master_key, header)?;
    let mut hmac_key_input = Vec::with_capacity(header.master_seed.len() + transformed_key.len() + 1);
    hmac_key_input.extend_from_slice(&header.master_seed);
    hmac_key_input.extend_from_slice(&transformed_key);
    hmac_key_input.push(0x01);
    Ok(Sha512::digest(&hmac_key_input).to_vec())
}

fn derive_hmac_block_key(hmac_base_key: &[u8], block_index: u64) -> Vec<u8> {
    let mut input = Vec::with_capacity(8 + hmac_base_key.len());
    input.extend_from_slice(&block_index.to_le_bytes());
    input.extend_from_slice(hmac_base_key);
    Sha512::digest(&input).to_vec()
}

/// 解密数据块
pub fn decrypt_block(
    encrypted_data: &[u8],
    key: &[u8],
    header: &KdbxHeader,
) -> Result<Vec<u8>, KdbxError> {
    match header.encryption {
        EncryptionAlgorithm::Aes256 => {
            decrypt_aes256_cbc(encrypted_data, key, &header.encryption_iv)
        }
        EncryptionAlgorithm::ChaCha20 => {
            decrypt_chacha20(encrypted_data, key, &header.encryption_iv)
        }
    }
}

/// 加密数据块
pub fn encrypt_block(
    plaintext: &[u8],
    key: &[u8],
    header: &KdbxHeader,
) -> Result<Vec<u8>, KdbxError> {
    match header.encryption {
        EncryptionAlgorithm::Aes256 => {
            encrypt_aes256_cbc(plaintext, key, &header.encryption_iv)
        }
        EncryptionAlgorithm::ChaCha20 => {
            encrypt_chacha20(plaintext, key, &header.encryption_iv)
        }
    }
}

/// 解压缩数据
pub fn decompress_data(data: &[u8], compression: CompressionAlgorithm) -> Result<Vec<u8>, KdbxError> {
    match compression {
        CompressionAlgorithm::None => Ok(data.to_vec()),
        CompressionAlgorithm::Gzip => {
            let mut decoder = GzDecoder::new(data);
            let mut decompressed = Vec::new();
            decoder
                .read_to_end(&mut decompressed)
                .map_err(|e| KdbxError::CompressionError(e.to_string()))?;
            Ok(decompressed)
        }
    }
}

/// 压缩数据
pub fn compress_data(data: &[u8], compression: CompressionAlgorithm) -> Result<Vec<u8>, KdbxError> {
    match compression {
        CompressionAlgorithm::None => Ok(data.to_vec()),
        CompressionAlgorithm::Gzip => {
            let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
            encoder
                .write_all(data)
                .map_err(|e| KdbxError::CompressionError(e.to_string()))?;
            encoder
                .finish()
                .map_err(|e| KdbxError::CompressionError(e.to_string()))
        }
    }
}

/// KDBX会话数据
#[derive(Debug, Clone)]
pub struct KdbxSession {
    pub header: KdbxHeader,
    pub groups: HashMap<Uuid, Group>,
    pub entries: HashMap<Uuid, Entry>,
    pub deleted_objects: Vec<DeletedObject>,
    pub metadata: Metadata,
}

/// 元数据
#[derive(Debug, Clone, Default)]
pub struct Metadata {
    pub database_name: Option<String>,
    pub database_description: Option<String>,
    pub default_username: Option<String>,
    pub maintenance_history_days: u32,
    pub color: Option<String>,
}

/// 解析完整的KDBX文件
pub fn parse_kdbx(
    data: &[u8],
    master_password: Option<&str>,
    key_file_data: Option<&[u8]>,
) -> Result<KdbxSession, KdbxError> {
    // 1. 解析头部
    let header = header::parse_header(data)?;

    // 2. 计算头部大小
    let header_end = find_header_end(data)?;

    if data.len() < header_end + 64 {
        return Err(KdbxError::InvalidFileFormat);
    }

    // KDBX 4 文件结构:
    // [Header] [SHA-256(Header)] [HMAC-SHA-256(Header)] [HMAC Block Stream]
    // KDBX 3.1 文件结构:
    // [Header] [SHA-256(Header)] [Encrypted Data]

    // 3. 读取SHA-256 hash (32 bytes)
    let sha256_offset = header_end;
    let stored_sha256 = &data[sha256_offset..sha256_offset + 32];
    let computed_sha256 = Sha256::digest(&data[..header_end]);
    if stored_sha256 != computed_sha256.as_slice() {
        return Err(KdbxError::ValidationError("Header SHA-256 mismatch".to_string()));
    }

    // 4. 读取HMAC (32 bytes) - KDBX 4 only
    let hmac_offset = sha256_offset + 32;
    let stored_hmac = &data[hmac_offset..hmac_offset + 32];

    // 5. 读取加密数据 (HMAC Block Stream)
    let encrypted_data = &data[hmac_offset + 32..];

    // 6. 组合主密钥
    let master_key = combine_master_key(master_password, key_file_data)?;
    tracing::debug!("Master key: {:02x?}", master_key);

    let hmac_base_key = derive_hmac_base_key(&master_key, &header)?;
    let header_hmac_key = derive_hmac_block_key(&hmac_base_key, u64::MAX);
    let expected_header_hmac = compute_hmac_sha256(&header_hmac_key, &data[..header_end])?;
    if stored_hmac != expected_header_hmac.as_slice() {
        return Err(KdbxError::HmacVerificationFailed);
    }

    // 7. 派生加密密钥
    let encryption_key = derive_encryption_key(&master_key, &header)?;
    tracing::debug!("Encryption key: {:02x?}", encryption_key);
    tracing::debug!("Encryption IV: {:02x?}", header.encryption_iv);
    tracing::debug!("Master seed: {:02x?}", header.master_seed);

    // 8. 解析HMAC Block Stream并解密
    // HMAC Block格式: [HMAC(32)] [Size(4)] [Encrypted Data]
    let decrypted_data = parse_and_decrypt_hmac_block_stream(
        encrypted_data,
        &hmac_base_key,
        &encryption_key,
        &header.encryption_iv,
        &header.encryption,
    )?;

    // 9. 解压缩
    let decompressed_data = decompress_data(&decrypted_data, header.compression)?;

    // 10. 解析内部数据流
    let (groups, entries, deleted_objects, metadata) =
        data_stream::parse_data_stream(&decompressed_data)?;

    Ok(KdbxSession {
        header,
        groups,
        entries,
        deleted_objects,
        metadata,
    })
}

/// 解析并解密HMAC Block Stream
fn parse_and_decrypt_hmac_block_stream(
    data: &[u8],
    hmac_base_key: &[u8],
    key: &[u8],
    iv: &[u8],
    encryption: &EncryptionAlgorithm,
) -> Result<Vec<u8>, KdbxError> {
    tracing::debug!("Parsing HMAC block stream, data length: {}", data.len());
    tracing::debug!("Encryption key: {:02x?}", key);
    tracing::debug!("IV: {:02x?}", iv);

    let mut cursor = std::io::Cursor::new(data);
    let mut encrypted_data = Vec::new();
    let mut block_count = 0;

    loop {
        // 读取HMAC (32 bytes)
        let mut hmac = [0u8; 32];
        if cursor.read_exact(&mut hmac).is_err() {
            tracing::debug!("Failed to read HMAC, end of stream");
            break; // 数据结束
        }

        // 读取块大小 (4 bytes, little-endian)
        use byteorder::ReadBytesExt;
        let block_size = match cursor.read_u32::<byteorder::LittleEndian>() {
            Ok(size) => size as usize,
            Err(_) => {
                tracing::debug!("Failed to read block size");
                break;
            }
        };

        tracing::debug!("Block {}: HMAC={:02x?}, size={}", block_count, &hmac[..8], block_size);

        // 读取加密数据
        let mut encrypted_block = vec![0u8; block_size];
        cursor.read_exact(&mut encrypted_block)?;

        let block_hmac_key = derive_hmac_block_key(hmac_base_key, block_count as u64);
        let mut block_payload = Vec::with_capacity(8 + 4 + encrypted_block.len());
        block_payload.extend_from_slice(&(block_count as u64).to_le_bytes());
        block_payload.extend_from_slice(&(block_size as u32).to_le_bytes());
        block_payload.extend_from_slice(&encrypted_block);
        let expected_hmac = compute_hmac_sha256(&block_hmac_key, &block_payload)?;
        if hmac != expected_hmac.as_slice() {
            return Err(KdbxError::HmacVerificationFailed);
        }

        // 块大小为0表示结束
        if block_size == 0 {
            tracing::debug!("Block size is 0, end of stream");
            break;
        }

        tracing::debug!("Block {} encrypted data (first 16 bytes): {:02x?}", block_count, &encrypted_block[..16.min(encrypted_block.len())]);

        // 合并加密数据
        encrypted_data.extend_from_slice(&encrypted_block);
        block_count += 1;
    }

    tracing::debug!("Total encrypted data length: {}", encrypted_data.len());
    tracing::debug!("Total blocks: {}", block_count);

    // 整体解密
    tracing::debug!("Decrypting with {:?}...", encryption);
    let decrypted = match encryption {
        EncryptionAlgorithm::Aes256 => {
            decrypt_aes256_cbc(&encrypted_data, key, iv)?
        }
        EncryptionAlgorithm::ChaCha20 => {
            decrypt_chacha20(&encrypted_data, key, iv)?
        }
    };

    tracing::debug!("Decrypted data length: {}", decrypted.len());
    tracing::debug!("Decrypted data (first 32 bytes): {:02x?}", &decrypted[..32.min(decrypted.len())]);

    Ok(decrypted)
}

/// 查找头部结束位置
fn find_header_end(data: &[u8]) -> Result<usize, KdbxError> {
    let mut cursor = std::io::Cursor::new(data);

    // 跳过签名和版本（8 + 4 = 12字节）
    use byteorder::ReadBytesExt;
    cursor.read_u32::<byteorder::LittleEndian>()?;
    cursor.read_u32::<byteorder::LittleEndian>()?;
    cursor.read_u16::<byteorder::LittleEndian>()?;
    cursor.read_u16::<byteorder::LittleEndian>()?;

    // 查找结束标记
    loop {
        let field_id = cursor.read_u8()?;
        // KDBX 4: 字段大小是4字节 (Int32)
        let field_size = cursor.read_u32::<byteorder::LittleEndian>()? as usize;

        // 跳过字段数据（包括End字段的值）
        if field_size > 0 {
            cursor.read_exact(&mut vec![0u8; field_size])?;
        }

        if field_id == 0 {
            // 结束标记
            break;
        }
    }

    Ok(cursor.position() as usize)
}

/// 生成KDBX文件
pub fn generate_kdbx(
    session: &KdbxSession,
    master_password: Option<&str>,
    key_file_data: Option<&[u8]>,
) -> Result<Vec<u8>, KdbxError> {
    let inner_random_stream_key = session
        .header
        .inner_random_stream_key
        .clone()
        .unwrap_or_else(|| generate_random_bytes(64));

    // 1. 序列化内部数据流
    let data_stream = data_stream::generate_data_stream(
        &session.groups,
        &session.entries,
        &session.deleted_objects,
        &session.metadata,
        &inner_random_stream_key,
    )?;

    // 2. 压缩数据
    let compressed_data = compress_data(&data_stream, session.header.compression)?;

    // 3. 组合主密钥
    let master_key = combine_master_key(master_password, key_file_data)?;

    // 4. 派生加密密钥和HMAC基钥
    let encryption_key = derive_encryption_key(&master_key, &session.header)?;
    let hmac_base_key = derive_hmac_base_key(&master_key, &session.header)?;

    // 5. 加密数据
    let encrypted_data = encrypt_block(&compressed_data, &encryption_key, &session.header)?;

    // 6. 生成头部及其校验
    let header_data = header::generate_header(&session.header)?;
    let header_sha = Sha256::digest(&header_data);
    let header_hmac_key = derive_hmac_block_key(&hmac_base_key, u64::MAX);
    let header_hmac = compute_hmac_sha256(&header_hmac_key, &header_data)?;
    let hmac_block_stream = generate_hmac_block_stream(&encrypted_data, &hmac_base_key)?;

    // 7. 组装完整文件
    let mut file_data = Vec::new();
    file_data.extend_from_slice(&header_data);
    file_data.extend_from_slice(&header_sha);
    file_data.extend_from_slice(&header_hmac);
    file_data.extend_from_slice(&hmac_block_stream);

    Ok(file_data)
}

fn generate_hmac_block_stream(encrypted_data: &[u8], hmac_base_key: &[u8]) -> Result<Vec<u8>, KdbxError> {
    let mut output = Vec::new();

    for (block_index, block_data) in [encrypted_data, &[]].into_iter().enumerate() {
        let block_size = block_data.len() as u32;
        let block_hmac_key = derive_hmac_block_key(hmac_base_key, block_index as u64);
        let mut block_payload = Vec::with_capacity(8 + 4 + block_data.len());
        block_payload.extend_from_slice(&(block_index as u64).to_le_bytes());
        block_payload.extend_from_slice(&block_size.to_le_bytes());
        block_payload.extend_from_slice(block_data);
        let block_hmac = compute_hmac_sha256(&block_hmac_key, &block_payload)?;

        output.extend_from_slice(&block_hmac);
        output.extend_from_slice(&block_size.to_le_bytes());
        output.extend_from_slice(block_data);
    }

    Ok(output)
}

fn generate_random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    rand::rng().fill_bytes(&mut bytes);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_combine_master_key() {
        let key = combine_master_key(Some("password"), None).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_combine_master_key_with_keyfile() {
        let key_file = b"test_key_file_content";
        let key = combine_master_key(Some("password"), Some(key_file)).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_aes_kdf_full_flow() {
        // 测试完整的AES-KDF密钥派生流程
        // 使用与Python测试相同的参数

        // 密码 'redhat'
        let password = "redhat";

        // 组合主密钥
        let composite_key = combine_master_key(Some(password), None).unwrap();
        println!("Composite key: {:02x?}", composite_key);

        // 预期的composite key
        let expected_composite = hex::decode("f7bbe6812e0fefadf10358d9d947c392fd35605191c7ad8d839c32a6a63bdce7").unwrap();
        assert_eq!(composite_key, expected_composite, "Composite key mismatch");

        // Salt (seed) from file
        let salt = hex::decode("35e2f8638d230481e7268c51738330e6022c3f4f8d8b60b812d7b9b88489921d").unwrap();

        // Rounds
        let rounds = 600000;

        // AES-KDF
        let transformed_key = derive_key_aes_kdf(&composite_key, &salt, rounds, 32).unwrap();
        println!("Transformed key: {:02x?}", transformed_key);

        // 预期的transformed key
        let expected_transformed = hex::decode("fab896ca4366e7adbc101f5800da8bd91e735f07b23df1b566f4e9d64dac7990").unwrap();
        assert_eq!(transformed_key, expected_transformed, "Transformed key mismatch");

        // Master seed from file
        let master_seed = hex::decode("01fbd84c41214a48a006908a05a034cf3742935f19d2c083f8d8a4698bded6d0").unwrap();

        // 最终密钥 = SHA256(master_seed + transformed_key)
        let mut final_key_input = Vec::new();
        final_key_input.extend_from_slice(&master_seed);
        final_key_input.extend_from_slice(&transformed_key);
        let final_key = Sha256::digest(&final_key_input).to_vec();
        println!("Final encryption key: {:02x?}", final_key);

        // 预期的最终密钥
        let expected_final = hex::decode("6ab1ecd4dc2fe8877aa100c75b54005d59fbb12320f3b079a207d4d22b48925b").unwrap();
        assert_eq!(final_key, expected_final, "Final key mismatch");
    }

    #[test]
    fn test_parse_pass_kdbx_sample() {
        let data = std::fs::read(format!("{}\\pass.kdbx", env!("CARGO_MANIFEST_DIR"))).unwrap();
        let header = header::parse_header(&data).unwrap();
        let header_end = find_header_end(&data).unwrap();
        let stored_header_sha = &data[header_end..header_end + 32];
        let computed_header_sha = Sha256::digest(&data[..header_end]);

        assert_eq!(stored_header_sha, computed_header_sha.as_slice(), "Header SHA mismatch");

        let composite_key = combine_master_key(Some("redhat"), None).unwrap();
        let encryption_key = derive_encryption_key(&composite_key, &header).unwrap();
        let encrypted_data = &data[header_end + 64..];

        let decrypted = parse_and_decrypt_hmac_block_stream(
            encrypted_data,
            &derive_hmac_base_key(&composite_key, &header).unwrap(),
            &encryption_key,
            &header.encryption_iv,
            &header.encryption,
        )
        .unwrap();

        assert!(!decrypted.is_empty());
    }

    #[test]
    fn test_generate_and_parse_roundtrip_kdbx4() {
        let data = std::fs::read(format!("{}\\pass.kdbx", env!("CARGO_MANIFEST_DIR"))).unwrap();
        let session = parse_kdbx(&data, Some("redhat"), None).unwrap();

        let exported = generate_kdbx(&session, Some("redhat"), None).unwrap();
        let reparsed = parse_kdbx(&exported, Some("redhat"), None).unwrap();

        assert_eq!(reparsed.entries.len(), session.entries.len());
        assert_eq!(reparsed.groups.len(), session.groups.len());
    }

    #[test]
    fn test_hmac_verification_rejects_tampering() {
        let data = std::fs::read(format!("{}\\pass.kdbx", env!("CARGO_MANIFEST_DIR"))).unwrap();
        let mut tampered = data.clone();
        let header_end = find_header_end(&tampered).unwrap();
        let payload_offset = header_end + 64 + 36;
        tampered[payload_offset] ^= 0x01;

        let result = parse_kdbx(&tampered, Some("redhat"), None);
        assert!(matches!(result, Err(KdbxError::HmacVerificationFailed)));
    }
}
