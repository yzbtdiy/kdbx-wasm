use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use crate::error::KdbxError;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// AES-256-CBC加密
pub fn encrypt_aes256_cbc(plaintext: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, KdbxError> {
    if key.len() != 32 {
        return Err(KdbxError::InvalidFieldValue("Key must be 32 bytes".to_string()));
    }
    if iv.len() != 16 {
        return Err(KdbxError::InvalidFieldValue("IV must be 16 bytes".to_string()));
    }

    // 转换为数组
    let key_array: [u8; 32] = key.try_into().map_err(|_| KdbxError::InvalidFieldValue("Invalid key length".to_string()))?;
    let iv_array: [u8; 16] = iv.try_into().map_err(|_| KdbxError::InvalidFieldValue("Invalid IV length".to_string()))?;

    let cipher = Aes256CbcEnc::new(&key_array.into(), &iv_array.into());
    let mut buf = plaintext.to_vec();
    // 计算需要的缓冲区大小（包含填充）
    let padding_len = 16 - (plaintext.len() % 16);
    buf.extend(std::iter::repeat(0).take(padding_len));

    let ciphertext = cipher.encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
        .map_err(|_| KdbxError::DecryptionFailed)?;

    Ok(ciphertext.to_vec())
}

/// AES-256-CBC解密
pub fn decrypt_aes256_cbc(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, KdbxError> {
    if key.len() != 32 {
        return Err(KdbxError::InvalidFieldValue("Key must be 32 bytes".to_string()));
    }
    if iv.len() != 16 {
        return Err(KdbxError::InvalidFieldValue("IV must be 16 bytes".to_string()));
    }

    // 转换为数组
    let key_array: [u8; 32] = key.try_into().map_err(|_| KdbxError::InvalidFieldValue("Invalid key length".to_string()))?;
    let iv_array: [u8; 16] = iv.try_into().map_err(|_| KdbxError::InvalidFieldValue("Invalid IV length".to_string()))?;

    let cipher = Aes256CbcDec::new(&key_array.into(), &iv_array.into());
    let mut buf = ciphertext.to_vec();

    let plaintext = cipher.decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|_| KdbxError::DecryptionFailed)?;

    Ok(plaintext.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let key = [0u8; 16]; // 错误的密钥长度
        let iv = [0u8; 16];
        let plaintext = b"Hello, World!";

        let result = encrypt_aes256_cbc(plaintext, &key, &iv);
        assert!(result.is_err());
    }
}
