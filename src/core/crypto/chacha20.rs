use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use crate::error::KdbxError;

/// ChaCha20加密/解密（流加密，加密和解密使用同一函数）
pub fn encrypt_chacha20(plaintext: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>, KdbxError> {
    if key.len() != 32 {
        return Err(KdbxError::InvalidFieldValue("Key must be 32 bytes".to_string()));
    }
    if nonce.len() != 12 {
        return Err(KdbxError::InvalidFieldValue("Nonce must be 12 bytes".to_string()));
    }

    // 将key和nonce转换为数组
    let key_array: [u8; 32] = key.try_into().map_err(|_| KdbxError::InvalidFieldValue("Invalid key length".to_string()))?;
    let nonce_array: [u8; 12] = nonce.try_into().map_err(|_| KdbxError::InvalidFieldValue("Invalid nonce length".to_string()))?;

    let mut cipher = ChaCha20::new(&key_array.into(), &nonce_array.into());
    let mut data = plaintext.to_vec();
    cipher.apply_keystream(&mut data);

    Ok(data)
}

/// ChaCha20解密（与加密相同）
pub fn decrypt_chacha20(ciphertext: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>, KdbxError> {
    encrypt_chacha20(ciphertext, key, nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_chacha20_invalid_key() {
        let key = [0u8; 16]; // 错误的密钥长度
        let nonce = [0u8; 12];
        let plaintext = b"Hello, World!";

        let result = encrypt_chacha20(plaintext, &key, &nonce);
        assert!(result.is_err());
    }
}
