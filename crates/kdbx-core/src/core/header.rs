use crate::core::types::*;
use crate::error::KdbxError;
use byteorder::{LittleEndian, ReadBytesExt};
use std::io::{Cursor, Read};

// ── Well-known UUIDs ──

const AES_CIPHER_UUID: [u8; 16] = [
    0x31, 0xc1, 0xf2, 0xe6, 0xbf, 0x71, 0x43, 0x50, 0xbe, 0x58, 0x05, 0x21, 0x6a, 0xfc, 0x5a, 0xff,
];
const CHACHA20_CIPHER_UUID: [u8; 16] = [
    0xd6, 0x03, 0x8a, 0x2b, 0x8b, 0x6f, 0x4c, 0xb5, 0xa5, 0x24, 0x33, 0x9a, 0x31, 0xdb, 0xb5, 0x9a,
];
const ARGON2D_KDF_UUID: [u8; 16] = [
    0xef, 0x63, 0x6d, 0xdf, 0x8c, 0x29, 0x44, 0x4b, 0x91, 0xf7, 0xa9, 0xa4, 0x03, 0xe3, 0x0a, 0x0c,
];
const ARGON2ID_KDF_UUID: [u8; 16] = [
    0x9e, 0x29, 0x8b, 0x19, 0x56, 0xdb, 0x47, 0x73, 0xb2, 0x3d, 0xfc, 0x3e, 0xc6, 0xf0, 0xa1, 0xe6,
];
const AES_KDF_UUID: [u8; 16] = [
    0xc9, 0xd9, 0xf3, 0x9a, 0x62, 0x8a, 0x44, 0x60, 0xbf, 0x74, 0x0d, 0x08, 0xc1, 0x8a, 0x4f, 0xea,
];

// ── Header Field IDs ──

#[repr(u8)]
enum FieldId {
    End = 0,
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

// ── Parse Header ──

pub fn parse_header(data: &[u8]) -> Result<KdbxHeader, KdbxError> {
    let mut cursor = Cursor::new(data);

    let sig1 = cursor.read_u32::<LittleEndian>()?;
    let sig2 = cursor.read_u32::<LittleEndian>()?;
    if sig1 != SIGNATURE1 || sig2 != SIGNATURE2 {
        return Err(KdbxError::InvalidSignature);
    }

    let version_minor = cursor.read_u16::<LittleEndian>()?;
    let version_major = cursor.read_u16::<LittleEndian>()?;
    let version = FileVersion::new(version_major, version_minor);
    if !version.is_kdbx4() {
        return Err(KdbxError::UnsupportedVersion(version_major, version_minor));
    }

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
        let field_size = cursor.read_u32::<LittleEndian>()? as usize;
        // Reject lengths that exceed the remaining input before allocating.
        let remaining = data.len() - cursor.position() as usize;
        if field_size > remaining {
            return Err(KdbxError::InvalidFileFormat);
        }
        let mut field_data = vec![0u8; field_size];
        if field_size > 0 {
            cursor.read_exact(&mut field_data)?;
        }
        if field_id == FieldId::End as u8 {
            break;
        }
        match field_id {
            id if id == FieldId::CipherId as u8 => {
                encryption = Some(parse_encryption_uuid(&field_data)?);
            }
            id if id == FieldId::CompressionFlags as u8 => {
                let flags = u32::from_le_bytes(
                    field_data
                        .try_into()
                        .map_err(|_| KdbxError::InvalidFileFormat)?,
                );
                compression = CompressionAlgorithm::from_u32(flags);
            }
            id if id == FieldId::MasterSeed as u8 => master_seed = Some(field_data),
            id if id == FieldId::TransformSeed as u8 => transform_seed = Some(field_data),
            id if id == FieldId::TransformRounds as u8 => {
                transform_rounds = Some(u64::from_le_bytes(
                    field_data
                        .try_into()
                        .map_err(|_| KdbxError::InvalidFileFormat)?,
                ));
            }
            id if id == FieldId::EncryptionIv as u8 => encryption_iv = Some(field_data),
            id if id == FieldId::StreamStartBytes as u8 => stream_start_bytes = Some(field_data),
            id if id == FieldId::InnerRandomStreamKey as u8 => {
                inner_random_stream_key = Some(field_data)
            }
            id if id == FieldId::KdfParameters as u8 => {
                kdf = Some(parse_kdf_parameters(&field_data)?)
            }
            _ => {}
        }
    }

    Ok(KdbxHeader {
        version,
        encryption: encryption.ok_or_else(|| KdbxError::MissingField("encryption".into()))?,
        compression: compression.ok_or_else(|| KdbxError::MissingField("compression".into()))?,
        kdf: kdf.ok_or_else(|| KdbxError::MissingField("kdf".into()))?,
        master_seed: master_seed.ok_or_else(|| KdbxError::MissingField("master_seed".into()))?,
        encryption_iv: encryption_iv
            .ok_or_else(|| KdbxError::MissingField("encryption_iv".into()))?,
        transform_seed,
        transform_rounds,
        stream_start_bytes,
        inner_random_stream_key,
    })
}

fn parse_encryption_uuid(uuid: &[u8]) -> Result<EncryptionAlgorithm, KdbxError> {
    if uuid == AES_CIPHER_UUID {
        Ok(EncryptionAlgorithm::Aes256)
    } else if uuid == CHACHA20_CIPHER_UUID {
        Ok(EncryptionAlgorithm::ChaCha20)
    } else {
        Err(KdbxError::UnsupportedEncryptionAlgorithm)
    }
}

fn parse_kdf_parameters(data: &[u8]) -> Result<KdfAlgorithm, KdbxError> {
    let mut cursor = Cursor::new(data);
    let _version = cursor.read_u16::<LittleEndian>()?;

    let mut kdf_uuid: Option<[u8; 16]> = None;
    let mut memory = None;
    let mut iterations = None;
    let mut parallelism = None;
    let mut rounds = None;
    let mut salt = None;

    loop {
        let entry_type = cursor.read_u8()?;
        if entry_type == 0 {
            break;
        }
        let key_len = cursor.read_u32::<LittleEndian>()? as usize;
        let remaining = data.len() - cursor.position() as usize;
        if key_len > remaining {
            return Err(KdbxError::InvalidFileFormat);
        }
        let mut key = vec![0u8; key_len];
        cursor.read_exact(&mut key)?;
        let key_str = String::from_utf8_lossy(&key);

        let value_len = cursor.read_u32::<LittleEndian>()? as usize;
        let remaining = data.len() - cursor.position() as usize;
        if value_len > remaining {
            return Err(KdbxError::InvalidFileFormat);
        }
        let mut value = vec![0u8; value_len];
        cursor.read_exact(&mut value)?;

        match key_str.as_ref() {
            "$UUID" if value.len() == 16 => {
                let mut arr = [0u8; 16];
                arr.copy_from_slice(&value);
                kdf_uuid = Some(arr);
            }
            "M" | "Memory" => {
                let v: [u8; 8] = value
                    .as_slice()
                    .try_into()
                    .map_err(|_| KdbxError::InvalidFileFormat)?;
                memory = Some(u64::from_le_bytes(v));
            }
            "I" | "Iterations" => {
                let v: [u8; 8] = value
                    .as_slice()
                    .try_into()
                    .map_err(|_| KdbxError::InvalidFileFormat)?;
                iterations = Some(u64::from_le_bytes(v));
            }
            "P" | "Parallelism" => {
                let v: [u8; 4] = value
                    .as_slice()
                    .try_into()
                    .map_err(|_| KdbxError::InvalidFileFormat)?;
                parallelism = Some(u32::from_le_bytes(v));
            }
            "R" | "Rounds" => {
                let v: [u8; 8] = value
                    .as_slice()
                    .try_into()
                    .map_err(|_| KdbxError::InvalidFileFormat)?;
                rounds = Some(u64::from_le_bytes(v));
            }
            "S" => salt = Some(value),
            _ => {}
        }
    }

    let uuid = kdf_uuid.ok_or_else(|| KdbxError::MissingField("kdf_uuid".into()))?;
    let salt = salt.unwrap_or_else(|| vec![0u8; 32]);

    if uuid == ARGON2D_KDF_UUID {
        Ok(KdfAlgorithm::Argon2d {
            memory: memory.unwrap_or(65536),
            iterations: iterations.unwrap_or(3),
            parallelism: parallelism.unwrap_or(4),
            salt,
        })
    } else if uuid == ARGON2ID_KDF_UUID {
        Ok(KdfAlgorithm::Argon2id {
            memory: memory.unwrap_or(65536),
            iterations: iterations.unwrap_or(3),
            parallelism: parallelism.unwrap_or(4),
            salt,
        })
    } else if uuid == AES_KDF_UUID {
        Ok(KdfAlgorithm::AesKdf {
            rounds: rounds.unwrap_or(100000),
            salt,
        })
    } else {
        Err(KdbxError::UnsupportedKdfAlgorithm)
    }
}

// ── Generate Header ──

pub fn generate_header(header: &KdbxHeader) -> Result<Vec<u8>, KdbxError> {
    let mut data = Vec::new();

    // Signatures + version
    data.extend_from_slice(&SIGNATURE1.to_le_bytes());
    data.extend_from_slice(&SIGNATURE2.to_le_bytes());
    data.extend_from_slice(&header.version.minor.to_le_bytes());
    data.extend_from_slice(&header.version.major.to_le_bytes());

    // Cipher ID
    write_field(
        &mut data,
        FieldId::CipherId as u8,
        &get_encryption_uuid(&header.encryption),
    );

    // Compression flags
    write_field(
        &mut data,
        FieldId::CompressionFlags as u8,
        &header.compression.to_u32().to_le_bytes(),
    );

    // Master seed
    write_field(&mut data, FieldId::MasterSeed as u8, &header.master_seed);

    // Encryption IV
    write_field(
        &mut data,
        FieldId::EncryptionIv as u8,
        &header.encryption_iv,
    );

    // Optional KDBX 3.1 compatibility fields
    if let Some(ref seed) = header.transform_seed {
        write_field(&mut data, FieldId::TransformSeed as u8, seed);
    }
    if let Some(rounds) = header.transform_rounds {
        write_field(
            &mut data,
            FieldId::TransformRounds as u8,
            &rounds.to_le_bytes(),
        );
    }
    if let Some(ref bytes) = header.stream_start_bytes {
        write_field(&mut data, FieldId::StreamStartBytes as u8, bytes);
    }
    if let Some(ref key) = header.inner_random_stream_key {
        write_field(&mut data, FieldId::InnerRandomStreamKey as u8, key);
    }

    // KDF parameters
    let kdf_params = generate_kdf_parameters(&header.kdf)?;
    write_field(&mut data, FieldId::KdfParameters as u8, &kdf_params);

    // End marker
    data.push(FieldId::End as u8);
    data.extend_from_slice(&4u32.to_le_bytes());
    data.extend_from_slice(&[0x0D, 0x0A, 0x0D, 0x0A]);

    Ok(data)
}

fn write_field(data: &mut Vec<u8>, field_id: u8, field_data: &[u8]) {
    data.push(field_id);
    data.extend_from_slice(&(field_data.len() as u32).to_le_bytes());
    data.extend_from_slice(field_data);
}

fn get_encryption_uuid(encryption: &EncryptionAlgorithm) -> Vec<u8> {
    match encryption {
        EncryptionAlgorithm::Aes256 => AES_CIPHER_UUID.to_vec(),
        EncryptionAlgorithm::ChaCha20 => CHACHA20_CIPHER_UUID.to_vec(),
    }
}

fn generate_kdf_parameters(kdf: &KdfAlgorithm) -> Result<Vec<u8>, KdbxError> {
    let mut data = Vec::new();
    data.extend_from_slice(&0x0100u16.to_le_bytes());

    let kdf_uuid = match kdf {
        KdfAlgorithm::Argon2d { .. } => &ARGON2D_KDF_UUID,
        KdfAlgorithm::Argon2id { .. } => &ARGON2ID_KDF_UUID,
        KdfAlgorithm::AesKdf { .. } => &AES_KDF_UUID,
    };

    // $UUID
    write_variant_entry(&mut data, 0x42, b"$UUID", kdf_uuid);

    match kdf {
        KdfAlgorithm::Argon2d {
            memory,
            iterations,
            parallelism,
            salt,
        }
        | KdfAlgorithm::Argon2id {
            memory,
            iterations,
            parallelism,
            salt,
        } => {
            write_variant_entry(&mut data, 0x42, b"S", salt);
            write_variant_entry(&mut data, 0x05, b"M", &memory.to_le_bytes());
            write_variant_entry(&mut data, 0x05, b"I", &iterations.to_le_bytes());
            write_variant_entry(&mut data, 0x04, b"P", &parallelism.to_le_bytes());
        }
        KdfAlgorithm::AesKdf { rounds, salt } => {
            write_variant_entry(&mut data, 0x42, b"S", salt);
            write_variant_entry(&mut data, 0x05, b"R", &rounds.to_le_bytes());
        }
    }

    data.push(0x00); // End marker
    Ok(data)
}

fn write_variant_entry(data: &mut Vec<u8>, entry_type: u8, key: &[u8], value: &[u8]) {
    data.push(entry_type);
    data.extend_from_slice(&(key.len() as u32).to_le_bytes());
    data.extend_from_slice(key);
    data.extend_from_slice(&(value.len() as u32).to_le_bytes());
    data.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_incomplete_header_returns_error() {
        let mut data = Vec::new();
        data.extend_from_slice(&SIGNATURE1.to_le_bytes());
        data.extend_from_slice(&SIGNATURE2.to_le_bytes());
        data.extend_from_slice(&4u16.to_le_bytes());
        data.extend_from_slice(&4u16.to_le_bytes());
        data.push(0); // End header
        let result = parse_header(&data);
        assert!(result.is_err());
    }
}
