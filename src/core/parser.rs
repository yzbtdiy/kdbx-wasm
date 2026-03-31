use crate::core::crypto::*;
use crate::core::header;
use crate::core::types::*;
use crate::core::xml;
use crate::error::KdbxError;
use byteorder::{LittleEndian, ReadBytesExt};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use rand::RngCore;
use sha2::{Digest, Sha256, Sha512};
use std::collections::HashMap;
use std::io::{Cursor, Read, Write};
use uuid::Uuid;

const INNER_STREAM_CHACHA20: u32 = 3;

// ── Key Derivation ──

pub fn combine_master_key(
    password: Option<&str>,
    key_file: Option<&[u8]>,
) -> Result<Vec<u8>, KdbxError> {
    let mut combined = Vec::new();

    if let Some(pw) = password {
        combined.extend_from_slice(&Sha256::digest(pw.as_bytes()));
    }
    if let Some(kf) = key_file {
        if kf.len() == 32 {
            combined.extend_from_slice(kf);
        } else {
            combined.extend_from_slice(&Sha256::digest(kf));
        }
    }
    if combined.is_empty() {
        return Err(KdbxError::InvalidMasterKey);
    }

    Ok(Sha256::digest(&combined).to_vec())
}

fn derive_transformed_key(master_key: &[u8], header: &KdbxHeader) -> Result<Vec<u8>, KdbxError> {
    match &header.kdf {
        KdfAlgorithm::Argon2d { memory, iterations, parallelism, salt } => {
            derive_key_argon2d(master_key, salt, *memory, *iterations, *parallelism, 32)
        }
        KdfAlgorithm::Argon2id { memory, iterations, parallelism, salt } => {
            derive_key_argon2id(master_key, salt, *memory, *iterations, *parallelism, 32)
        }
        KdfAlgorithm::AesKdf { rounds, salt } => {
            derive_key_aes_kdf(master_key, salt, *rounds, 32)
        }
    }
}

fn derive_encryption_key(master_key: &[u8], header: &KdbxHeader) -> Result<Vec<u8>, KdbxError> {
    let transformed = derive_transformed_key(master_key, header)?;
    let mut input = Vec::with_capacity(header.master_seed.len() + transformed.len());
    input.extend_from_slice(&header.master_seed);
    input.extend_from_slice(&transformed);
    Ok(Sha256::digest(&input).to_vec())
}

fn derive_hmac_base_key(master_key: &[u8], header: &KdbxHeader) -> Result<Vec<u8>, KdbxError> {
    let transformed = derive_transformed_key(master_key, header)?;
    let mut input = Vec::with_capacity(header.master_seed.len() + transformed.len() + 1);
    input.extend_from_slice(&header.master_seed);
    input.extend_from_slice(&transformed);
    input.push(0x01);
    Ok(Sha512::digest(&input).to_vec())
}

fn derive_hmac_block_key(base_key: &[u8], block_index: u64) -> Vec<u8> {
    let mut input = Vec::with_capacity(8 + base_key.len());
    input.extend_from_slice(&block_index.to_le_bytes());
    input.extend_from_slice(base_key);
    Sha512::digest(&input).to_vec()
}

// ── Encrypt / Decrypt Dispatch ──



fn encrypt_block(data: &[u8], key: &[u8], header: &KdbxHeader) -> Result<Vec<u8>, KdbxError> {
    match header.encryption {
        EncryptionAlgorithm::Aes256 => encrypt_aes256_cbc(data, key, &header.encryption_iv),
        EncryptionAlgorithm::ChaCha20 => encrypt_chacha20(data, key, &header.encryption_iv),
    }
}

// ── Compression ──

fn decompress(data: &[u8], algo: CompressionAlgorithm) -> Result<Vec<u8>, KdbxError> {
    match algo {
        CompressionAlgorithm::None => Ok(data.to_vec()),
        CompressionAlgorithm::Gzip => {
            let mut out = Vec::new();
            GzDecoder::new(data)
                .read_to_end(&mut out)
                .map_err(|e| KdbxError::CompressionError(e.to_string()))?;
            Ok(out)
        }
    }
}

fn compress(data: &[u8], algo: CompressionAlgorithm) -> Result<Vec<u8>, KdbxError> {
    match algo {
        CompressionAlgorithm::None => Ok(data.to_vec()),
        CompressionAlgorithm::Gzip => {
            let mut enc = GzEncoder::new(Vec::new(), Compression::default());
            enc.write_all(data).map_err(|e| KdbxError::CompressionError(e.to_string()))?;
            enc.finish().map_err(|e| KdbxError::CompressionError(e.to_string()))
        }
    }
}

// ── Inner Data Stream ──

fn parse_data_stream(
    data: &[u8],
) -> Result<(HashMap<Uuid, Group>, HashMap<Uuid, Entry>, Vec<DeletedObject>, Metadata), KdbxError> {
    let mut cursor = Cursor::new(data);
    let mut stream_id: Option<u32> = None;
    let mut stream_key: Option<Vec<u8>> = None;

    loop {
        let field_id = cursor.read_u8()?;
        let field_size = cursor.read_u32::<LittleEndian>()? as usize;
        let mut field_data = vec![0u8; field_size];
        if field_size > 0 {
            cursor.read_exact(&mut field_data)?;
        }
        match field_id {
            0 => break,
            1 if field_data.len() == 4 => {
                stream_id = Some(u32::from_le_bytes(field_data[..4].try_into().unwrap()));
            }
            2 => stream_key = Some(field_data),
            3 => {} // Binary attachments - consume to skip
            _ => return Err(KdbxError::InvalidFileFormat),
        }
    }

    let xml_data = &data[cursor.position() as usize..];
    let mut protected_stream = match (stream_id, stream_key) {
        (Some(id), Some(key)) => Some(xml::ProtectedStream::new(id, &key)?),
        (None, None) => None,
        _ => return Err(KdbxError::InvalidFileFormat),
    };

    xml::parse_xml(xml_data, protected_stream.as_mut())
}

fn generate_data_stream(
    groups: &HashMap<Uuid, Group>,
    entries: &HashMap<Uuid, Entry>,
    deleted: &[DeletedObject],
    metadata: &Metadata,
    stream_key: &[u8],
) -> Result<Vec<u8>, KdbxError> {
    let mut stream = xml::ProtectedStream::new(INNER_STREAM_CHACHA20, stream_key)?;
    let xml_data = xml::generate_xml(groups, entries, deleted, metadata, Some(&mut stream))?;

    let mut out = Vec::new();
    // Inner stream ID field
    out.push(1);
    out.extend_from_slice(&4u32.to_le_bytes());
    out.extend_from_slice(&INNER_STREAM_CHACHA20.to_le_bytes());
    // Inner stream key field
    out.push(2);
    out.extend_from_slice(&(stream_key.len() as u32).to_le_bytes());
    out.extend_from_slice(stream_key);
    // End field
    out.push(0);
    out.extend_from_slice(&0u32.to_le_bytes());
    // XML payload
    out.extend_from_slice(&xml_data);
    Ok(out)
}

// ── HMAC Block Stream ──

fn parse_hmac_block_stream(
    data: &[u8],
    hmac_base_key: &[u8],
    key: &[u8],
    iv: &[u8],
    encryption: &EncryptionAlgorithm,
) -> Result<Vec<u8>, KdbxError> {
    let mut cursor = Cursor::new(data);
    let mut encrypted_data = Vec::new();
    let mut block_idx: u64 = 0;

    loop {
        let mut hmac = [0u8; 32];
        if cursor.read_exact(&mut hmac).is_err() {
            break;
        }
        let block_size = match cursor.read_u32::<LittleEndian>() {
            Ok(s) => s as usize,
            Err(_) => break,
        };

        let mut block = vec![0u8; block_size];
        cursor.read_exact(&mut block)?;

        // Verify HMAC
        let block_hmac_key = derive_hmac_block_key(hmac_base_key, block_idx);
        let mut payload = Vec::with_capacity(12 + block.len());
        payload.extend_from_slice(&block_idx.to_le_bytes());
        payload.extend_from_slice(&(block_size as u32).to_le_bytes());
        payload.extend_from_slice(&block);
        let expected = compute_hmac_sha256(&block_hmac_key, &payload)?;
        if hmac != expected.as_slice() {
            return Err(KdbxError::HmacVerificationFailed);
        }

        if block_size == 0 {
            break;
        }
        encrypted_data.extend_from_slice(&block);
        block_idx += 1;
    }

    match encryption {
        EncryptionAlgorithm::Aes256 => decrypt_aes256_cbc(&encrypted_data, key, iv),
        EncryptionAlgorithm::ChaCha20 => decrypt_chacha20(&encrypted_data, key, iv),
    }
}

fn generate_hmac_block_stream(encrypted: &[u8], hmac_base_key: &[u8]) -> Result<Vec<u8>, KdbxError> {
    let mut output = Vec::new();
    for (idx, block_data) in [encrypted, &[] as &[u8]].into_iter().enumerate() {
        let size = block_data.len() as u32;
        let block_key = derive_hmac_block_key(hmac_base_key, idx as u64);
        let mut payload = Vec::with_capacity(12 + block_data.len());
        payload.extend_from_slice(&(idx as u64).to_le_bytes());
        payload.extend_from_slice(&size.to_le_bytes());
        payload.extend_from_slice(block_data);
        let hmac = compute_hmac_sha256(&block_key, &payload)?;
        output.extend_from_slice(&hmac);
        output.extend_from_slice(&size.to_le_bytes());
        output.extend_from_slice(block_data);
    }
    Ok(output)
}

// ── Header End Position ──

fn find_header_end(data: &[u8]) -> Result<usize, KdbxError> {
    let mut cursor = Cursor::new(data);
    // Skip signatures (8 bytes) + version (4 bytes)
    cursor.read_u32::<LittleEndian>()?;
    cursor.read_u32::<LittleEndian>()?;
    cursor.read_u16::<LittleEndian>()?;
    cursor.read_u16::<LittleEndian>()?;

    loop {
        let field_id = cursor.read_u8()?;
        let field_size = cursor.read_u32::<LittleEndian>()? as usize;
        if field_size > 0 {
            cursor.read_exact(&mut vec![0u8; field_size])?;
        }
        if field_id == 0 {
            break;
        }
    }
    Ok(cursor.position() as usize)
}

// ── Public API ──

pub fn parse_kdbx(
    data: &[u8],
    password: Option<&str>,
    key_file: Option<&[u8]>,
) -> Result<KdbxSession, KdbxError> {
    let kdbx_header = header::parse_header(data)?;
    let header_end = find_header_end(data)?;

    if data.len() < header_end + 64 {
        return Err(KdbxError::InvalidFileFormat);
    }

    // Verify header SHA-256
    let stored_sha = &data[header_end..header_end + 32];
    let computed_sha = Sha256::digest(&data[..header_end]);
    if stored_sha != computed_sha.as_slice() {
        return Err(KdbxError::ValidationError("Header SHA-256 mismatch".into()));
    }

    // Verify header HMAC
    let stored_hmac = &data[header_end + 32..header_end + 64];
    let master_key = combine_master_key(password, key_file)?;
    let hmac_base_key = derive_hmac_base_key(&master_key, &kdbx_header)?;
    let header_hmac_key = derive_hmac_block_key(&hmac_base_key, u64::MAX);
    let expected_hmac = compute_hmac_sha256(&header_hmac_key, &data[..header_end])?;
    if stored_hmac != expected_hmac.as_slice() {
        return Err(KdbxError::HmacVerificationFailed);
    }

    // Decrypt
    let encryption_key = derive_encryption_key(&master_key, &kdbx_header)?;
    let encrypted = &data[header_end + 64..];
    let decrypted = parse_hmac_block_stream(
        encrypted, &hmac_base_key, &encryption_key,
        &kdbx_header.encryption_iv, &kdbx_header.encryption,
    )?;

    // Decompress + parse
    let decompressed = decompress(&decrypted, kdbx_header.compression)?;
    let (groups, entries, deleted_objects, metadata) = parse_data_stream(&decompressed)?;

    Ok(KdbxSession { header: kdbx_header, groups, entries, deleted_objects, metadata })
}

pub fn generate_kdbx(
    session: &KdbxSession,
    password: Option<&str>,
    key_file: Option<&[u8]>,
) -> Result<Vec<u8>, KdbxError> {
    let stream_key = session.header.inner_random_stream_key
        .clone()
        .unwrap_or_else(|| {
            let mut bytes = vec![0u8; 64];
            rand::rng().fill_bytes(&mut bytes);
            bytes
        });

    let data_stream = generate_data_stream(
        &session.groups, &session.entries, &session.deleted_objects, &session.metadata, &stream_key,
    )?;
    let compressed = compress(&data_stream, session.header.compression)?;
    let master_key = combine_master_key(password, key_file)?;
    let encryption_key = derive_encryption_key(&master_key, &session.header)?;
    let hmac_base_key = derive_hmac_base_key(&master_key, &session.header)?;
    let encrypted = encrypt_block(&compressed, &encryption_key, &session.header)?;

    let header_data = header::generate_header(&session.header)?;
    let header_sha = Sha256::digest(&header_data);
    let header_hmac_key = derive_hmac_block_key(&hmac_base_key, u64::MAX);
    let header_hmac = compute_hmac_sha256(&header_hmac_key, &header_data)?;
    let hmac_blocks = generate_hmac_block_stream(&encrypted, &hmac_base_key)?;

    let mut file = Vec::new();
    file.extend_from_slice(&header_data);
    file.extend_from_slice(&header_sha);
    file.extend_from_slice(&header_hmac);
    file.extend_from_slice(&hmac_blocks);
    Ok(file)
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
        let key = combine_master_key(Some("password"), Some(b"test_key_file")).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_aes_kdf_full_flow() {
        let composite = combine_master_key(Some("redhat"), None).unwrap();
        let expected = hex::decode("f7bbe6812e0fefadf10358d9d947c392fd35605191c7ad8d839c32a6a63bdce7").unwrap();
        assert_eq!(composite, expected);

        let salt = hex::decode("35e2f8638d230481e7268c51738330e6022c3f4f8d8b60b812d7b9b88489921d").unwrap();
        let transformed = derive_key_aes_kdf(&composite, &salt, 600000, 32).unwrap();
        let expected = hex::decode("fab896ca4366e7adbc101f5800da8bd91e735f07b23df1b566f4e9d64dac7990").unwrap();
        assert_eq!(transformed, expected);

        let master_seed = hex::decode("01fbd84c41214a48a006908a05a034cf3742935f19d2c083f8d8a4698bded6d0").unwrap();
        let mut input = Vec::new();
        input.extend_from_slice(&master_seed);
        input.extend_from_slice(&transformed);
        let final_key = Sha256::digest(&input).to_vec();
        let expected = hex::decode("6ab1ecd4dc2fe8877aa100c75b54005d59fbb12320f3b079a207d4d22b48925b").unwrap();
        assert_eq!(final_key, expected);
    }

    #[test]
    fn test_parse_pass_kdbx() {
        let data = std::fs::read(format!("{}\\pass.kdbx", env!("CARGO_MANIFEST_DIR"))).unwrap();
        let session = parse_kdbx(&data, Some("redhat"), None).unwrap();
        assert!(!session.entries.is_empty());
    }

    #[test]
    fn test_roundtrip_kdbx4() {
        let data = std::fs::read(format!("{}\\pass.kdbx", env!("CARGO_MANIFEST_DIR"))).unwrap();
        let session = parse_kdbx(&data, Some("redhat"), None).unwrap();
        let exported = generate_kdbx(&session, Some("redhat"), None).unwrap();
        let reparsed = parse_kdbx(&exported, Some("redhat"), None).unwrap();
        assert_eq!(reparsed.entries.len(), session.entries.len());
        assert_eq!(reparsed.groups.len(), session.groups.len());
    }

    #[test]
    fn test_hmac_rejects_tampering() {
        let data = std::fs::read(format!("{}\\pass.kdbx", env!("CARGO_MANIFEST_DIR"))).unwrap();
        let mut tampered = data.clone();
        let header_end = find_header_end(&tampered).unwrap();
        tampered[header_end + 64 + 36] ^= 0x01;
        assert!(matches!(parse_kdbx(&tampered, Some("redhat"), None), Err(KdbxError::HmacVerificationFailed)));
    }

    #[test]
    fn test_data_stream_roundtrip() {
        let mut groups = HashMap::new();
        let group = Group::new("Test Group".to_string(), None);
        let gid = group.id;
        groups.insert(group.id, group);

        let mut entries = HashMap::new();
        let entry = Entry::new(gid, "Test Entry".to_string(), SecString::from_str("password"));
        entries.insert(entry.id, entry);

        let metadata = Metadata::default();
        let key = vec![0xAB; 64];
        let stream = generate_data_stream(&groups, &entries, &[], &metadata, &key).unwrap();
        assert!(!stream.is_empty());

        let (pg, pe, _, _) = parse_data_stream(&stream).unwrap();
        assert_eq!(pg.len(), 1);
        assert_eq!(pe.len(), 1);
    }
}
