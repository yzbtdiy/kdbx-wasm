use argon2::{Algorithm, Argon2, Params, Version};
use crate::error::KdbxError;

/// 使用Argon2d派生密钥
pub fn derive_key_argon2d(
    password: &[u8],
    salt: &[u8],
    memory: u64,
    iterations: u64,
    parallelism: u32,
    output_length: usize,
) -> Result<Vec<u8>, KdbxError> {
    let params = Params::new(
        memory as u32,
        iterations as u32,
        parallelism,
        Some(output_length),
    )
    .map_err(|e| KdbxError::ValidationError(e.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2d, Version::V0x13, params);

    let mut output = vec![0u8; output_length];
    argon2
        .hash_password_into(password, salt, &mut output)
        .map_err(|e| KdbxError::ValidationError(e.to_string()))?;

    Ok(output)
}

/// 使用Argon2id派生密钥
pub fn derive_key_argon2id(
    password: &[u8],
    salt: &[u8],
    memory: u64,
    iterations: u64,
    parallelism: u32,
    output_length: usize,
) -> Result<Vec<u8>, KdbxError> {
    let params = Params::new(
        memory as u32,
        iterations as u32,
        parallelism,
        Some(output_length),
    )
    .map_err(|e| KdbxError::ValidationError(e.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output = vec![0u8; output_length];
    argon2
        .hash_password_into(password, salt, &mut output)
        .map_err(|e| KdbxError::ValidationError(e.to_string()))?;

    Ok(output)
}

/// 使用AES-KDF派生密钥（传统方式）
/// AES-KDF使用AES-256-ECB进行多轮加密
/// seed作为AES密钥，对密码哈希进行rounds轮加密
pub fn derive_key_aes_kdf(
    password: &[u8],
    seed: &[u8],
    rounds: u64,
    output_length: usize,
) -> Result<Vec<u8>, KdbxError> {
    use aes::cipher::{BlockEncrypt, KeyInit};
    use sha2::{Digest, Sha256};

    // KDBX 4 AES-KDF 直接变换 composite key，完成后再做一次 SHA-256。
    if password.len() != 32 {
        return Err(KdbxError::ValidationError("AES-KDF input must be 32 bytes".to_string()));
    }

    let mut result = password.to_vec();

    // 2. seed必须是32字节
    if seed.len() != 32 {
        return Err(KdbxError::ValidationError("AES-KDF seed must be 32 bytes".to_string()));
    }

    // 3. 创建AES-256-ECB加密器，使用seed作为密钥
    let key_array: [u8; 32] = seed.try_into().map_err(|_| {
        KdbxError::ValidationError("Invalid seed length".to_string())
    })?;
    let cipher = aes::Aes256Enc::new_from_slice(&key_array)
        .map_err(|e| KdbxError::ValidationError(e.to_string()))?;

    // 4. 进行rounds轮加密
    // 每轮对两个16字节块分别进行AES加密
    for _ in 0..rounds {
        // 第一个16字节块
        let block1: [u8; 16] = result[0..16].try_into().unwrap();
        let mut block1 = aes::Block::from(block1);
        cipher.encrypt_block(&mut block1);
        result[0..16].copy_from_slice(&block1);

        // 第二个16字节块
        let block2: [u8; 16] = result[16..32].try_into().unwrap();
        let mut block2 = aes::Block::from(block2);
        cipher.encrypt_block(&mut block2);
        result[16..32].copy_from_slice(&block2);
    }

    // 5. 对变换后的32字节结果再做一次 SHA-256，得到 transformed key
    let transformed = Sha256::digest(&result);

    // 6. 截取到所需长度
    Ok(transformed[..output_length].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn test_argon2d_derive_key() {
        let password = b"test_password";
        let salt = b"test_salt_123456";
        let key = derive_key_argon2d(password, salt, 65536, 3, 4, 32).unwrap();

        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_argon2id_derive_key() {
        let password = b"test_password";
        let salt = b"test_salt_123456";
        let key = derive_key_argon2id(password, salt, 65536, 3, 4, 32).unwrap();

        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_aes_kdf_derive_key() {
        let password = Sha256::digest(b"test_password");
        // AES-KDF seed must be 32 bytes
        let salt = b"0123456789abcdef0123456789abcdef";
        let key = derive_key_aes_kdf(password.as_slice(), salt, 1000, 32).unwrap();

        assert_eq!(key.len(), 32);
    }
}
