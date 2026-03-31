use crate::error::KdbxError;
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20::cipher::StreamCipher;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type HmacSha256 = Hmac<Sha256>;

// ── AES-256-CBC ──

pub fn encrypt_aes256_cbc(plaintext: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, KdbxError> {
    let key: [u8; 32] = key.try_into().map_err(|_| KdbxError::InvalidFieldValue("Key must be 32 bytes".into()))?;
    let iv: [u8; 16] = iv.try_into().map_err(|_| KdbxError::InvalidFieldValue("IV must be 16 bytes".into()))?;

    let cipher = Aes256CbcEnc::new(&key.into(), &iv.into());
    let padding_len = 16 - (plaintext.len() % 16);
    let mut buf = plaintext.to_vec();
    buf.extend(std::iter::repeat(0).take(padding_len));

    let ciphertext = cipher
        .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
        .map_err(|_| KdbxError::DecryptionFailed)?;
    Ok(ciphertext.to_vec())
}

pub fn decrypt_aes256_cbc(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, KdbxError> {
    let key: [u8; 32] = key.try_into().map_err(|_| KdbxError::InvalidFieldValue("Key must be 32 bytes".into()))?;
    let iv: [u8; 16] = iv.try_into().map_err(|_| KdbxError::InvalidFieldValue("IV must be 16 bytes".into()))?;

    let cipher = Aes256CbcDec::new(&key.into(), &iv.into());
    let mut buf = ciphertext.to_vec();
    let plaintext = cipher
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|_| KdbxError::DecryptionFailed)?;
    Ok(plaintext.to_vec())
}

// ── ChaCha20 ──

pub fn encrypt_chacha20(data: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>, KdbxError> {
    let key: [u8; 32] = key.try_into().map_err(|_| KdbxError::InvalidFieldValue("Key must be 32 bytes".into()))?;
    let nonce: [u8; 12] = nonce.try_into().map_err(|_| KdbxError::InvalidFieldValue("Nonce must be 12 bytes".into()))?;

    let mut cipher = chacha20::ChaCha20::new(&key.into(), &nonce.into());
    let mut output = data.to_vec();
    cipher.apply_keystream(&mut output);
    Ok(output)
}

pub fn decrypt_chacha20(ciphertext: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>, KdbxError> {
    encrypt_chacha20(ciphertext, key, nonce)
}

// ── Argon2 ──

fn derive_key_argon2(
    algorithm: Algorithm,
    password: &[u8],
    salt: &[u8],
    memory: u64,
    iterations: u64,
    parallelism: u32,
    output_length: usize,
) -> Result<Vec<u8>, KdbxError> {
    let params = Params::new(memory as u32, iterations as u32, parallelism, Some(output_length))
        .map_err(|e| KdbxError::ValidationError(e.to_string()))?;
    let argon2 = Argon2::new(algorithm, Version::V0x13, params);
    let mut output = vec![0u8; output_length];
    argon2
        .hash_password_into(password, salt, &mut output)
        .map_err(|e| KdbxError::ValidationError(e.to_string()))?;
    Ok(output)
}

pub fn derive_key_argon2d(
    password: &[u8], salt: &[u8], memory: u64, iterations: u64, parallelism: u32, output_length: usize,
) -> Result<Vec<u8>, KdbxError> {
    derive_key_argon2(Algorithm::Argon2d, password, salt, memory, iterations, parallelism, output_length)
}

pub fn derive_key_argon2id(
    password: &[u8], salt: &[u8], memory: u64, iterations: u64, parallelism: u32, output_length: usize,
) -> Result<Vec<u8>, KdbxError> {
    derive_key_argon2(Algorithm::Argon2id, password, salt, memory, iterations, parallelism, output_length)
}

// ── AES-KDF ──

pub fn derive_key_aes_kdf(
    password: &[u8],
    seed: &[u8],
    rounds: u64,
    output_length: usize,
) -> Result<Vec<u8>, KdbxError> {
    use aes::cipher::{BlockEncrypt, KeyInit};
    use sha2::Digest;

    if password.len() != 32 {
        return Err(KdbxError::ValidationError("AES-KDF input must be 32 bytes".into()));
    }
    if seed.len() != 32 {
        return Err(KdbxError::ValidationError("AES-KDF seed must be 32 bytes".into()));
    }

    let mut result = password.to_vec();
    let cipher = aes::Aes256Enc::new_from_slice(seed)
        .map_err(|e| KdbxError::ValidationError(e.to_string()))?;

    for _ in 0..rounds {
        let mut block1 = aes::Block::from(<[u8; 16]>::try_from(&result[0..16]).unwrap());
        cipher.encrypt_block(&mut block1);
        result[0..16].copy_from_slice(&block1);

        let mut block2 = aes::Block::from(<[u8; 16]>::try_from(&result[16..32]).unwrap());
        cipher.encrypt_block(&mut block2);
        result[16..32].copy_from_slice(&block2);
    }

    let transformed = Sha256::digest(&result);
    Ok(transformed[..output_length].to_vec())
}

// ── HMAC-SHA256 ──

pub fn compute_hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>, KdbxError> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|e| KdbxError::ValidationError(e.to_string()))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

pub fn verify_hmac_sha256(key: &[u8], data: &[u8], expected: &[u8]) -> Result<bool, KdbxError> {
    let computed = compute_hmac_sha256(key, data)?;
    Ok(computed == expected)
}

// ── Random Bytes ──

pub fn generate_random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    rand::rng().fill_bytes(&mut bytes);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;

    #[test]
    fn test_aes256_encrypt_decrypt() {
        let key = [0u8; 32];
        let iv = [0u8; 16];
        let plaintext = b"Hello, World!";
        let ciphertext = encrypt_aes256_cbc(plaintext, &key, &iv).unwrap();
        let decrypted = decrypt_aes256_cbc(&ciphertext, &key, &iv).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_aes256_invalid_key() {
        let result = encrypt_aes256_cbc(b"Hello", &[0u8; 16], &[0u8; 16]);
        assert!(result.is_err());
    }

    #[test]
    fn test_chacha20_encrypt_decrypt() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let plaintext = b"Hello, World!";
        let ciphertext = encrypt_chacha20(plaintext, &key, &nonce).unwrap();
        let decrypted = decrypt_chacha20(&ciphertext, &key, &nonce).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_argon2d_derive_key() {
        let key = derive_key_argon2d(b"test_password", b"test_salt_123456", 65536, 3, 4, 32).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_argon2id_derive_key() {
        let key = derive_key_argon2id(b"test_password", b"test_salt_123456", 65536, 3, 4, 32).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_aes_kdf_derive_key() {
        let password = Sha256::digest(b"test_password");
        let salt = b"0123456789abcdef0123456789abcdef";
        let key = derive_key_aes_kdf(password.as_slice(), salt, 1000, 32).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_hmac_sha256() {
        let key = b"secret_key";
        let data = b"test_data";
        let hmac = compute_hmac_sha256(key, data).unwrap();
        assert_eq!(hmac.len(), 32);
        assert!(verify_hmac_sha256(key, data, &hmac).unwrap());
        assert!(!verify_hmac_sha256(key, data, &[0u8; 32]).unwrap());
    }
}
