use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::ops::{Deref, DerefMut};

/// 安全向量，在释放时自动清零内存
pub struct SecVec<T> {
    data: Vec<T>,
}

impl<T> SecVec<T> {
    pub fn new(data: Vec<T>) -> Self {
        Self { data }
    }

    pub fn into_vec(mut self) -> Vec<T> {
        // 防止在移动时清零
        let data = std::mem::take(&mut self.data);
        std::mem::forget(self); // 防止调用Drop
        data
    }
}

impl<T> Drop for SecVec<T> {
    fn drop(&mut self) {
        // 使用volatile_write清零内存
        unsafe {
            for byte in self.data.iter_mut() {
                std::ptr::write_volatile(byte, std::mem::zeroed());
            }
        }
        // 防止编译器优化掉清零操作
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

impl<T> Deref for SecVec<T> {
    type Target = Vec<T>;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<T> DerefMut for SecVec<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl<T: Clone> Clone for SecVec<T> {
    fn clone(&self) -> Self {
        Self {
            data: self.data.clone(),
        }
    }
}

/// 安全字符串，包装SecVec<u8>
pub struct SecString(SecVec<u8>);

// 实现Debug trait，但不显示实际内容
impl std::fmt::Debug for SecString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecString([REDACTED])")
    }
}

impl SecString {
    pub fn from_str(s: &str) -> Self {
        Self(SecVec::new(s.as_bytes().to_vec()))
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(SecVec::new(bytes))
    }

    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).unwrap_or("")
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0.into_vec()
    }
}

impl Clone for SecString {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

// 实现Serialize for SecString
impl Serialize for SecString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // 序列化为base64字符串
        let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &**self);
        serializer.serialize_str(&encoded)
    }
}

// 实现Deserialize for SecString
impl<'de> Deserialize<'de> for SecString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &s)
            .map_err(serde::de::Error::custom)?;
        Ok(SecString::from_bytes(bytes))
    }
}

impl Deref for SecString {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sec_vec_zeroing() {
        let mut sec_vec = SecVec::new(vec![1u8, 2, 3, 4, 5]);

        // 修改数据
        sec_vec[0] = 10;

        // 释放后检查内存是否被清零
        drop(sec_vec);

        // 注意：这个测试可能不可靠，因为内存可能已被重用
        // 但它展示了清零的意图
    }

    #[test]
    fn test_sec_string() {
        let password = SecString::from_str("my_secret_password");
        assert_eq!(password.as_str(), "my_secret_password");
        assert_eq!(password.as_bytes(), b"my_secret_password");
    }
}
