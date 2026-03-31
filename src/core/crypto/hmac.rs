use hmac::{Hmac, Mac};
use sha2::Sha256;
use crate::error::KdbxError;

type HmacSha256 = Hmac<Sha256>;

/// 计算HMAC-SHA256
pub fn compute_hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>, KdbxError> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|e| KdbxError::ValidationError(e.to_string()))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// 验证HMAC-SHA256
pub fn verify_hmac_sha256(key: &[u8], data: &[u8], expected_hmac: &[u8]) -> Result<bool, KdbxError> {
    let computed = compute_hmac_sha256(key, data)?;
    Ok(computed == expected_hmac)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_sha256() {
        let key = b"secret_key";
        let data = b"test_data";
        let hmac = compute_hmac_sha256(key, data).unwrap();

        assert_eq!(hmac.len(), 32);
        assert!(verify_hmac_sha256(key, data, &hmac).unwrap());
    }

    #[test]
    fn test_hmac_verification_failure() {
        let key = b"secret_key";
        let data = b"test_data";
        let wrong_hmac = vec![0u8; 32];

        assert!(!verify_hmac_sha256(key, data, &wrong_hmac).unwrap());
    }
}
