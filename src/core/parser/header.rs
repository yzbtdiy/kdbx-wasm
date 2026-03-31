use crate::core::types::{
    CompressionAlgorithm, EncryptionAlgorithm, FileVersion, KdbxHeader, KdfAlgorithm,
    SIGNATURE1, SIGNATURE2,
};
use crate::error::KdbxError;
use byteorder::{LittleEndian, ReadBytesExt};
use std::io::{Cursor, Read};

/// 头部字段ID
#[repr(u8)]
enum HeaderFieldId {
    End = 0,
    _Comment = 1,
    CipherId = 2,
    CompressionFlags = 3,
    MasterSeed = 4,
    TransformSeed = 5,
    TransformRounds = 6,
    EncryptionIv = 7,
    StreamStartBytes = 9,
    InnerRandomStreamKey = 10,
    KdfParameters = 11,
}

/// 解析KDBX文件头部
pub fn parse_header(data: &[u8]) -> Result<KdbxHeader, KdbxError> {
    let mut cursor = Cursor::new(data);

    // 1. 验证文件签名
    let signature1 = cursor.read_u32::<LittleEndian>()?;
    if signature1 != SIGNATURE1 {
        return Err(KdbxError::InvalidSignature);
    }

    let signature2 = cursor.read_u32::<LittleEndian>()?;
    if signature2 != SIGNATURE2 {
        return Err(KdbxError::InvalidSignature);
    }

    // 2. 读取文件版本
    let version_minor = cursor.read_u16::<LittleEndian>()?;
    let version_major = cursor.read_u16::<LittleEndian>()?;
    let version = FileVersion::new(version_major, version_minor);

    if !version.is_kdbx4() {
        return Err(KdbxError::UnsupportedVersion(version_major, version_minor));
    }

    // 3. 解析头部字段
    let mut encryption = None;
    let mut compression = None;
    let mut master_seed = None;
    let mut transform_seed = None;
    let mut transform_rounds = None;
    let mut encryption_iv = None;
    let mut stream_start_bytes = None;
    let mut inner_random_stream_key = None;
    let mut kdf = None;

    loop {
        let field_id = cursor.read_u8()?;
        // KDBX 4: 字段大小是4字节 (Int32)
        let field_size = cursor.read_u32::<LittleEndian>()? as usize;

        let mut field_data = vec![0u8; field_size];
        if field_size > 0 {
            cursor.read_exact(&mut field_data)?;
        }

        if field_id == HeaderFieldId::End as u8 {
            break;
        }

        match field_id {
            id if id == HeaderFieldId::CipherId as u8 => {
                // UUID格式的加密算法标识
                encryption = parse_encryption_uuid(&field_data)?;
            }
            id if id == HeaderFieldId::CompressionFlags as u8 => {
                let flags = u32::from_le_bytes([
                    field_data[0],
                    field_data[1],
                    field_data[2],
                    field_data[3],
                ]);
                compression = CompressionAlgorithm::from_u32(flags);
            }
            id if id == HeaderFieldId::MasterSeed as u8 => {
                master_seed = Some(field_data);
            }
            id if id == HeaderFieldId::TransformSeed as u8 => {
                transform_seed = Some(field_data);
            }
            id if id == HeaderFieldId::TransformRounds as u8 => {
                let rounds = u64::from_le_bytes([
                    field_data[0], field_data[1], field_data[2], field_data[3],
                    field_data[4], field_data[5], field_data[6], field_data[7],
                ]);
                transform_rounds = Some(rounds);
            }
            id if id == HeaderFieldId::EncryptionIv as u8 => {
                encryption_iv = Some(field_data);
            }
            id if id == HeaderFieldId::StreamStartBytes as u8 => {
                stream_start_bytes = Some(field_data);
            }
            id if id == HeaderFieldId::InnerRandomStreamKey as u8 => {
                inner_random_stream_key = Some(field_data);
            }
            id if id == HeaderFieldId::KdfParameters as u8 => {
                kdf = parse_kdf_parameters(&field_data)?;
            }
            _ => {
                // 忽略未知字段
            }
        }
    }

    // 构建头部
    Ok(KdbxHeader {
        version,
        encryption: encryption.ok_or_else(|| KdbxError::MissingField("encryption".to_string()))?,
        compression: compression.ok_or_else(|| KdbxError::MissingField("compression".to_string()))?,
        kdf: kdf.ok_or_else(|| KdbxError::MissingField("kdf".to_string()))?,
        master_seed: master_seed.ok_or_else(|| KdbxError::MissingField("master_seed".to_string()))?,
        encryption_iv: encryption_iv.ok_or_else(|| KdbxError::MissingField("encryption_iv".to_string()))?,
        // KDBX 3.1 兼容字段 (KDBX 4中可选)
        transform_seed,
        transform_rounds,
        stream_start_bytes,
        inner_random_stream_key,
    })
}

/// 解析加密算法UUID
fn parse_encryption_uuid(uuid: &[u8]) -> Result<Option<EncryptionAlgorithm>, KdbxError> {
    // 打印实际接收到的UUID用于调试
    tracing::debug!("Received encryption UUID: {:02x?}", uuid);

    // AES-256 UUID: 31C1F2E6BF714350BE5805216AFC5AFF
    let aes_uuid = [
        0x31, 0xc1, 0xf2, 0xe6, 0xbf, 0x71, 0x43, 0x50, 0xbe, 0x58, 0x05, 0x21, 0x6a, 0xfc, 0x5a, 0xff,
    ];
    // ChaCha20 UUID: D6038A2B8B6F4CB5A524339A31DBB59A
    let chacha_uuid = [
        0xd6, 0x03, 0x8a, 0x2b, 0x8b, 0x6f, 0x4c, 0xb5, 0xa5, 0x24, 0x33, 0x9a, 0x31, 0xdb, 0xb5, 0x9a,
    ];

    if uuid == aes_uuid {
        Ok(Some(EncryptionAlgorithm::Aes256))
    } else if uuid == chacha_uuid {
        Ok(Some(EncryptionAlgorithm::ChaCha20))
    } else {
        tracing::error!("Unsupported encryption UUID: {:02x?}", uuid);
        tracing::error!("Expected AES UUID: {:02x?}", aes_uuid);
        tracing::error!("Expected ChaCha20 UUID: {:02x?}", chacha_uuid);
        Err(KdbxError::UnsupportedEncryptionAlgorithm)
    }
}

/// 解析KDF参数（使用字典格式）
fn parse_kdf_parameters(data: &[u8]) -> Result<Option<KdfAlgorithm>, KdbxError> {
    // KDBX 4使用Variant Dictionary格式存储KDF参数
    // 格式: [2字节版本] [n个条目] [1字节空终止符]
    // 每个条目: [1字节类型] [4字节键名长度] [键名] [4字节值长度] [值]

    let mut cursor = Cursor::new(data);

    // 读取字典版本 (0x0100)
    let _version = cursor.read_u16::<LittleEndian>()?;

    // Argon2d UUID: EF636DDF8C29444B91F7A9A403E30A0C
    let argon2d_uuid: [u8; 16] = [
        0xef, 0x63, 0x6d, 0xdf, 0x8c, 0x29, 0x44, 0x4b, 0x91, 0xf7, 0xa9, 0xa4, 0x03, 0xe3, 0x0a, 0x0c,
    ];
    // Argon2id UUID: 9E298B1956DB4773B23DFC3EC6F0A1E6
    let argon2id_uuid: [u8; 16] = [
        0x9e, 0x29, 0x8b, 0x19, 0x56, 0xdb, 0x47, 0x73, 0xb2, 0x3d, 0xfc, 0x3e, 0xc6, 0xf0, 0xa1, 0xe6,
    ];
    // AES-KDF UUID: C9D9F39A628A4460BF740D08C18A4FEA
    let aes_kdf_uuid: [u8; 16] = [
        0xc9, 0xd9, 0xf3, 0x9a, 0x62, 0x8a, 0x44, 0x60, 0xbf, 0x74, 0x0d, 0x08, 0xc1, 0x8a, 0x4f, 0xea,
    ];

    // 解析参数字典
    let mut kdf_uuid: Option<[u8; 16]> = None;
    let mut memory = None;
    let mut iterations = None;
    let mut parallelism = None;
    let mut rounds = None;
    let mut salt = None;

    // 读取字典条目
    loop {
        let entry_type = cursor.read_u8()?;
        if entry_type == 0 {
            break; // 结束标记
        }

        let key_len = cursor.read_u32::<LittleEndian>()? as usize;
        let mut key = vec![0u8; key_len];
        cursor.read_exact(&mut key)?;
        let key_str = String::from_utf8_lossy(&key);

        let value_len = cursor.read_u32::<LittleEndian>()? as usize;
        let mut value = vec![0u8; value_len];
        cursor.read_exact(&mut value)?;

        match key_str.as_ref() {
            "$UUID" => {
                // KDF UUID (16字节)
                if value.len() == 16 {
                    let mut uuid_arr = [0u8; 16];
                    uuid_arr.copy_from_slice(&value);
                    kdf_uuid = Some(uuid_arr);
                }
            }
            "M" | "Memory" => {
                memory = Some(u64::from_le_bytes([
                    value[0], value[1], value[2], value[3],
                    value[4], value[5], value[6], value[7],
                ]));
            }
            "I" | "Iterations" => {
                iterations = Some(u64::from_le_bytes([
                    value[0], value[1], value[2], value[3],
                    value[4], value[5], value[6], value[7],
                ]));
            }
            "P" | "Parallelism" => {
                parallelism = Some(u32::from_le_bytes([
                    value[0], value[1], value[2], value[3],
                ]));
            }
            "R" | "Rounds" => {
                rounds = Some(u64::from_le_bytes([
                    value[0], value[1], value[2], value[3],
                    value[4], value[5], value[6], value[7],
                ]));
            }
            "S" => {
                // Salt (用于Argon2或AES-KDF)
                salt = Some(value);
            }
            _ => {
                tracing::debug!("Unknown KDF parameter: {} = {:02x?}", key_str, value);
            }
        }
    }

    let kdf_uuid = kdf_uuid.ok_or_else(|| KdbxError::MissingField("kdf_uuid".to_string()))?;

    tracing::debug!("Parsed KDF UUID: {:02x?}", kdf_uuid);

    // 默认salt (32字节全零)
    let default_salt = vec![0u8; 32];
    let salt = salt.unwrap_or(default_salt);

    if kdf_uuid == argon2d_uuid {
        Ok(Some(KdfAlgorithm::Argon2d {
            memory: memory.unwrap_or(65536),
            iterations: iterations.unwrap_or(3),
            parallelism: parallelism.unwrap_or(4),
            salt,
        }))
    } else if kdf_uuid == argon2id_uuid {
        Ok(Some(KdfAlgorithm::Argon2id {
            memory: memory.unwrap_or(65536),
            iterations: iterations.unwrap_or(3),
            parallelism: parallelism.unwrap_or(4),
            salt,
        }))
    } else if kdf_uuid == aes_kdf_uuid {
        Ok(Some(KdfAlgorithm::AesKdf {
            rounds: rounds.unwrap_or(100000),
            salt,
        }))
    } else {
        tracing::error!("Unsupported KDF UUID: {:02x?}", kdf_uuid);
        Err(KdbxError::UnsupportedKdfAlgorithm)
    }
}

/// 生成KDBX文件头部
pub fn generate_header(header: &KdbxHeader) -> Result<Vec<u8>, KdbxError> {
    let mut data = Vec::new();

    // 写入签名
    data.extend_from_slice(&SIGNATURE1.to_le_bytes());
    data.extend_from_slice(&SIGNATURE2.to_le_bytes());

    // 写入版本
    data.extend_from_slice(&header.version.minor.to_le_bytes());
    data.extend_from_slice(&header.version.major.to_le_bytes());

    // 写入加密算法UUID
    data.push(HeaderFieldId::CipherId as u8);
    let cipher_uuid = get_encryption_uuid(&header.encryption);
    data.extend_from_slice(&(cipher_uuid.len() as u32).to_le_bytes());
    data.extend_from_slice(&cipher_uuid);

    // 写入压缩标志
    data.push(HeaderFieldId::CompressionFlags as u8);
    let compression_flags = header.compression.to_u32();
    data.extend_from_slice(&4u32.to_le_bytes());
    data.extend_from_slice(&compression_flags.to_le_bytes());

    // 写入master_seed
    data.push(HeaderFieldId::MasterSeed as u8);
    data.extend_from_slice(&(header.master_seed.len() as u32).to_le_bytes());
    data.extend_from_slice(&header.master_seed);

    // 写入encryption_iv
    data.push(HeaderFieldId::EncryptionIv as u8);
    data.extend_from_slice(&(header.encryption_iv.len() as u32).to_le_bytes());
    data.extend_from_slice(&header.encryption_iv);

    // KDBX 3.1 兼容字段 (可选)
    if let Some(ref transform_seed) = header.transform_seed {
        data.push(HeaderFieldId::TransformSeed as u8);
        data.extend_from_slice(&(transform_seed.len() as u32).to_le_bytes());
        data.extend_from_slice(transform_seed);
    }

    if let Some(transform_rounds) = header.transform_rounds {
        data.push(HeaderFieldId::TransformRounds as u8);
        data.extend_from_slice(&8u32.to_le_bytes());
        data.extend_from_slice(&transform_rounds.to_le_bytes());
    }

    if let Some(ref stream_start_bytes) = header.stream_start_bytes {
        data.push(HeaderFieldId::StreamStartBytes as u8);
        data.extend_from_slice(&(stream_start_bytes.len() as u32).to_le_bytes());
        data.extend_from_slice(stream_start_bytes);
    }

    if let Some(ref inner_random_stream_key) = header.inner_random_stream_key {
        data.push(HeaderFieldId::InnerRandomStreamKey as u8);
        data.extend_from_slice(&(inner_random_stream_key.len() as u32).to_le_bytes());
        data.extend_from_slice(inner_random_stream_key);
    }

    // 写入KDF参数
    data.push(HeaderFieldId::KdfParameters as u8);
    let kdf_params = generate_kdf_parameters(&header.kdf)?;
    data.extend_from_slice(&(kdf_params.len() as u32).to_le_bytes());
    data.extend_from_slice(&kdf_params);

    // 写入结束标记
    data.push(HeaderFieldId::End as u8);
    data.extend_from_slice(&4u32.to_le_bytes());
    data.extend_from_slice(&[0x0D, 0x0A, 0x0D, 0x0A]);

    Ok(data)
}

/// 获取加密算法UUID
fn get_encryption_uuid(encryption: &EncryptionAlgorithm) -> Vec<u8> {
    match encryption {
        // AES-256 UUID: 31C1F2E6BF714350BE5805216AFC5AFF
        EncryptionAlgorithm::Aes256 => vec![
            0x31, 0xc1, 0xf2, 0xe6, 0xbf, 0x71, 0x43, 0x50,
            0xbe, 0x58, 0x05, 0x21, 0x6a, 0xfc, 0x5a, 0xff,
        ],
        // ChaCha20 UUID: D6038A2B8B6F4CB5A524339A31DBB59A
        EncryptionAlgorithm::ChaCha20 => vec![
            0xd6, 0x03, 0x8a, 0x2b, 0x8b, 0x6f, 0x4c, 0xb5,
            0xa5, 0x24, 0x33, 0x9a, 0x31, 0xdb, 0xb5, 0x9a,
        ],
    }
}

/// 生成KDF参数
fn generate_kdf_parameters(kdf: &KdfAlgorithm) -> Result<Vec<u8>, KdbxError> {
    let mut data = Vec::new();

    // 写入版本 (0x0100)
    data.extend_from_slice(&0x0100u16.to_le_bytes());

    // 获取KDF UUID
    let kdf_uuid: Vec<u8> = match kdf {
        // Argon2d UUID: EF636DDF8C29444B91F7A9A403E30A0C
        KdfAlgorithm::Argon2d { .. } => vec![
            0xef, 0x63, 0x6d, 0xdf, 0x8c, 0x29, 0x44, 0x4b,
            0x91, 0xf7, 0xa9, 0xa4, 0x03, 0xe3, 0x0a, 0x0c,
        ],
        // Argon2id UUID: 9E298B1956DB4773B23DFC3EC6F0A1E6
        KdfAlgorithm::Argon2id { .. } => vec![
            0x9e, 0x29, 0x8b, 0x19, 0x56, 0xdb, 0x47, 0x73,
            0xb2, 0x3d, 0xfc, 0x3e, 0xc6, 0xf0, 0xa1, 0xe6,
        ],
        // AES-KDF UUID: C9D9F39A628A4460BF740D08C18A4FEA
        KdfAlgorithm::AesKdf { .. } => vec![
            0xc9, 0xd9, 0xf3, 0x9a, 0x62, 0x8a, 0x44, 0x60,
            0xbf, 0x74, 0x0d, 0x08, 0xc1, 0x8a, 0x4f, 0xea,
        ],
    };

    // 写入 $UUID 条目
    // 格式: [类型(1字节)] [键名长度(4字节)] [键名] [值长度(4字节)] [值]
    data.push(0x42); // Byte[] 类型
    let uuid_key = b"$UUID";
    data.extend_from_slice(&(uuid_key.len() as u32).to_le_bytes());
    data.extend_from_slice(uuid_key);
    data.extend_from_slice(&(kdf_uuid.len() as u32).to_le_bytes());
    data.extend_from_slice(&kdf_uuid);

    // 写入其他参数
    match kdf {
        KdfAlgorithm::Argon2d { memory, iterations, parallelism, salt } |
        KdfAlgorithm::Argon2id { memory, iterations, parallelism, salt } => {
            // Salt (S)
            data.push(0x42); // Byte[]
            data.extend_from_slice(&1u32.to_le_bytes());
            data.extend_from_slice(b"S");
            data.extend_from_slice(&(salt.len() as u32).to_le_bytes());
            data.extend_from_slice(salt);

            // Memory (M)
            data.push(0x05); // UInt64
            data.extend_from_slice(&1u32.to_le_bytes());
            data.extend_from_slice(b"M");
            data.extend_from_slice(&8u32.to_le_bytes());
            data.extend_from_slice(&memory.to_le_bytes());

            // Iterations (I)
            data.push(0x05);
            data.extend_from_slice(&1u32.to_le_bytes());
            data.extend_from_slice(b"I");
            data.extend_from_slice(&8u32.to_le_bytes());
            data.extend_from_slice(&iterations.to_le_bytes());

            // Parallelism (P)
            data.push(0x04); // UInt32
            data.extend_from_slice(&1u32.to_le_bytes());
            data.extend_from_slice(b"P");
            data.extend_from_slice(&4u32.to_le_bytes());
            data.extend_from_slice(&parallelism.to_le_bytes());
        }
        KdfAlgorithm::AesKdf { rounds, salt } => {
            // Salt (S)
            data.push(0x42); // Byte[]
            data.extend_from_slice(&1u32.to_le_bytes());
            data.extend_from_slice(b"S");
            data.extend_from_slice(&(salt.len() as u32).to_le_bytes());
            data.extend_from_slice(salt);

            // Rounds (R)
            data.push(0x05);
            data.extend_from_slice(&1u32.to_le_bytes());
            data.extend_from_slice(b"R");
            data.extend_from_slice(&8u32.to_le_bytes());
            data.extend_from_slice(&rounds.to_le_bytes());
        }
    }

    // 写入结束标记
    data.push(0x00);

    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_signature() {
        let mut data = Vec::new();
        data.extend_from_slice(&SIGNATURE1.to_le_bytes());
        data.extend_from_slice(&SIGNATURE2.to_le_bytes());
        data.extend_from_slice(&4u16.to_le_bytes()); // minor version
        data.extend_from_slice(&4u16.to_le_bytes()); // major version
        data.push(0); // End header

        let result = parse_header(&data);
        assert!(result.is_err()); // 缺少必需字段
    }
}
