//! WebAssembly bindings for KDBX parser
//! 
//! This module provides JavaScript bindings for the KDBX password database parser.

use wasm_bindgen::prelude::*;
use js_sys::{Array, Uint8Array};
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use std::collections::HashMap;

use crate::core::{
    parser::{parse_kdbx, generate_kdbx, KdbxSession},
    types::{Entry, Group, EncryptionAlgorithm, KdfAlgorithm, CompressionAlgorithm},
};

/// Initialize panic hook for better error messages in WASM
#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
}

/// JavaScript-facing entry representation
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct JsEntry {
    pub uuid: String,
    pub icon_id: u32,
    pub group_id: String,
    pub title: String,
    pub username: Option<String>,
    pub password: String,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub accessed_at: String,
    pub expires_at: Option<String>,
    pub tags: Vec<String>,
    pub custom_fields: HashMap<String, String>,
}

/// JavaScript-facing group representation
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct JsGroup {
    pub uuid: String,
    pub name: String,
    pub icon_id: u32,
    pub parent_id: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub notes: Option<String>,
    pub child_groups: Vec<String>,
    pub entries: Vec<String>,
}





/// KDBX Database handle for JavaScript
#[wasm_bindgen]
pub struct KdbxDatabase {
    session: KdbxSession,
}

#[wasm_bindgen]
impl KdbxDatabase {
    /// Open a KDBX file from bytes with optional password and key file
    /// 
    /// # Arguments
    /// * `data` - The KDBX file bytes as Uint8Array
    /// * `password` - Optional master password
    /// * `key_file` - Optional key file bytes as Uint8Array
    /// 
    /// # Returns
    /// * `Ok(KdbxDatabase)` on success
    /// * `Err(String)` on error
    #[wasm_bindgen(constructor)]
    pub fn new(data: &Uint8Array, password: Option<String>, key_file: Option<Uint8Array>) -> Result<KdbxDatabase, String> {
        let mut rust_data = vec![0u8; data.length() as usize];
        data.copy_to(&mut rust_data);
        
        let key_file_data = key_file.map(|k| {
            let mut buf = vec![0u8; k.length() as usize];
            k.copy_to(&mut buf);
            buf
        });
        
        let key_file_ref = key_file_data.as_deref();
        
        match parse_kdbx(&rust_data, password.as_deref(), key_file_ref) {
            Ok(session) => Ok(KdbxDatabase { session }),
            Err(e) => Err(format!("{:?}", e)),
        }
    }
    
    /// Get database metadata
    #[wasm_bindgen(getter)]
    pub fn metadata(&self) -> Result<JsValue, JsValue> {
        let meta = &self.session.metadata;
        let js_meta = serde_json::json!({
            "databaseName": meta.database_name,
            "databaseDescription": meta.database_description,
            "defaultUsername": meta.default_username,
            "maintenanceHistoryDays": meta.maintenance_history_days,
            "color": meta.color,
        });
        serde_wasm_bindgen::to_value(&js_meta)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
    }
    
    /// Get header information
    #[wasm_bindgen(getter)]
    pub fn header_info(&self) -> Result<JsValue, JsValue> {
        let header = &self.session.header;
        
        let (kdf_name, kdf_params): (&str, serde_json::Value) = match &header.kdf {
            KdfAlgorithm::Argon2d { memory, iterations, parallelism, .. } => {
                ("Argon2d", serde_json::json!({
                    "memory": memory,
                    "iterations": iterations,
                    "parallelism": parallelism,
                }))
            }
            KdfAlgorithm::Argon2id { memory, iterations, parallelism, .. } => {
                ("Argon2id", serde_json::json!({
                    "memory": memory,
                    "iterations": iterations,
                    "parallelism": parallelism,
                }))
            }
            KdfAlgorithm::AesKdf { rounds, .. } => {
                ("AES-KDF", serde_json::json!({
                    "rounds": rounds,
                }))
            }
        };
        
        let info = serde_json::json!({
            "version": "4.0",
            "encryptionAlgorithm": match header.encryption {
                EncryptionAlgorithm::Aes256 => "AES-256",
                EncryptionAlgorithm::ChaCha20 => "ChaCha20",
            },
            "kdfAlgorithm": kdf_name,
            "kdfParams": kdf_params,
            "compression": match header.compression {
                CompressionAlgorithm::None => "None",
                CompressionAlgorithm::Gzip => "Gzip",
            },
            "entryCount": self.session.entries.len(),
            "groupCount": self.session.groups.len(),
        });
        
        serde_wasm_bindgen::to_value(&info)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
    }
    
    /// Get all entries as an array
    #[wasm_bindgen(js_name = getEntries)]
    pub fn get_entries(&self) -> Result<Array, JsValue> {
        let array = Array::new();
        
        for (_, entry) in &self.session.entries {
            let js_entry = self.entry_to_js(entry)?;
            array.push(&js_entry);
        }
        
        Ok(array)
    }
    
    /// Get a specific entry by UUID
    #[wasm_bindgen(js_name = getEntry)]
    pub fn get_entry(&self, uuid: &str) -> Result<JsValue, JsValue> {
        let uuid = Uuid::parse_str(uuid)
            .map_err(|e| JsValue::from_str(&format!("Invalid UUID: {}", e)))?;
        
        match self.session.entries.get(&uuid) {
            Some(entry) => self.entry_to_js(entry),
            None => Err(JsValue::from_str("Entry not found")),
        }
    }
    
    /// Get all groups as an array
    #[wasm_bindgen(js_name = getGroups)]
    pub fn get_groups(&self) -> Result<Array, JsValue> {
        let array = Array::new();
        
        for (_, group) in &self.session.groups {
            let js_group = self.group_to_js(group)?;
            array.push(&js_group);
        }
        
        Ok(array)
    }
    
    /// Get a specific group by UUID
    #[wasm_bindgen(js_name = getGroup)]
    pub fn get_group(&self, uuid: &str) -> Result<JsValue, JsValue> {
        let uuid = Uuid::parse_str(uuid)
            .map_err(|e| JsValue::from_str(&format!("Invalid UUID: {}", e)))?;
        
        match self.session.groups.get(&uuid) {
            Some(group) => self.group_to_js(group),
            None => Err(JsValue::from_str("Group not found")),
        }
    }
    
    /// Get the root group UUID
    #[wasm_bindgen(getter, js_name = rootGroupUuid)]
    pub fn root_group_uuid(&self) -> String {
        // Find the root group (group with no parent)
        for (uuid, group) in &self.session.groups {
            if group.parent_id.is_none() {
                return (*uuid).to_string();
            }
        }
        String::new()
    }
    
    /// Get entries in a specific group
    #[wasm_bindgen(js_name = getEntriesByGroup)]
    pub fn get_entries_by_group(&self, group_uuid: &str) -> Result<Array, JsValue> {
        let group_uuid = Uuid::parse_str(group_uuid)
            .map_err(|e| JsValue::from_str(&format!("Invalid UUID: {}", e)))?;
        
        let array = Array::new();
        
        for (_, entry) in &self.session.entries {
            if entry.group_id == group_uuid {
                let js_entry = self.entry_to_js(entry)?;
                array.push(&js_entry);
            }
        }
        
        Ok(array)
    }
    
    /// Search entries by keyword
    #[wasm_bindgen(js_name = searchEntries)]
    pub fn search_entries(&self, query: &str) -> Result<Array, JsValue> {
        let query = query.to_lowercase();
        let array = Array::new();
        
        for (_, entry) in &self.session.entries {
            let username = entry.username.as_deref().unwrap_or("");
            let url = entry.url.as_deref().unwrap_or("");
            let notes = entry.notes.as_deref().unwrap_or("");
            
            let matches = entry.title.to_lowercase().contains(&query)
                || username.to_lowercase().contains(&query)
                || url.to_lowercase().contains(&query)
                || notes.to_lowercase().contains(&query)
                || entry.tags.iter().any(|t: &String| t.to_lowercase().contains(&query));
            
            if matches {
                let js_entry = self.entry_to_js(entry)?;
                array.push(&js_entry);
            }
        }
        
        Ok(array)
    }
    
    /// Export the database to KDBX format bytes
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self, password: Option<String>, key_file: Option<Uint8Array>) -> Result<Uint8Array, String> {
        let key_file_data = key_file.map(|k| {
            let mut buf = vec![0u8; k.length() as usize];
            k.copy_to(&mut buf);
            buf
        });
        
        let key_file_ref = key_file_data.as_deref();
        
        match generate_kdbx(&self.session, password.as_deref(), key_file_ref) {
            Ok(bytes) => Ok(Uint8Array::from(&bytes[..])),
            Err(e) => Err(format!("{:?}", e)),
        }
    }
    
    // Helper methods
    
    fn entry_to_js(&self, entry: &Entry) -> Result<JsValue, JsValue> {
        let js_entry = JsEntry {
            uuid: entry.id.to_string(),
            icon_id: entry.icon_id,
            group_id: entry.group_id.to_string(),
            title: entry.title.clone(),
            username: entry.username.clone(),
            password: entry.password.as_ref().map(|p| p.as_str().to_string()).unwrap_or_default(),
            url: entry.url.clone(),
            notes: entry.notes.clone(),
            created_at: entry.created_at.to_rfc3339(),
            updated_at: entry.updated_at.to_rfc3339(),
            accessed_at: entry.accessed_at.to_rfc3339(),
            expires_at: entry.expires_at.map(|e| e.to_rfc3339()),
            tags: entry.tags.clone(),
            custom_fields: entry.custom_fields.clone(),
        };
        
        serde_wasm_bindgen::to_value(&js_entry)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
    }
    
    fn group_to_js(&self, group: &Group) -> Result<JsValue, JsValue> {
        // Collect child groups
        let mut child_groups = Vec::new();
        let mut entries = Vec::new();
        
        for (uuid, g) in &self.session.groups {
            if let Some(parent) = g.parent_id {
                if parent == group.id {
                    child_groups.push((*uuid).to_string());
                }
            }
        }
        
        for (uuid, e) in &self.session.entries {
            if e.group_id == group.id {
                entries.push((*uuid).to_string());
            }
        }
        
        let js_group = JsGroup {
            uuid: group.id.to_string(),
            name: group.name.clone(),
            icon_id: group.icon_id,
            parent_id: group.parent_id.map(|p| p.to_string()),
            created_at: group.created_at.to_rfc3339(),
            updated_at: group.updated_at.to_rfc3339(),
            notes: group.notes.clone(),
            child_groups,
            entries,
        };
        
        serde_wasm_bindgen::to_value(&js_group)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
    }
}

/// Check if data appears to be a valid KDBX file
#[wasm_bindgen(js_name = isKdbxFile)]
pub fn is_kdbx_file(data: &Uint8Array) -> bool {
    if data.length() < 8 {
        return false;
    }
    
    let mut sig = [0u8; 8];
    data.slice(0, 8).copy_to(&mut sig);
    
    // KDBX signature: 0x03D9A29A67FB4BB5 (little endian)
    sig == [0x03, 0xD9, 0xA2, 0x9A, 0x67, 0xFB, 0x4B, 0xB5]
}

/// Get KDBX file version info without decrypting
#[wasm_bindgen(js_name = getFileInfo)]
pub fn get_file_info(data: &Uint8Array) -> Result<JsValue, String> {
    let mut rust_data = vec![0u8; data.length() as usize];
    data.copy_to(&mut rust_data);
    
    match crate::core::parser::header::parse_header(&rust_data) {
        Ok(header) => {
            let info = serde_json::json!({
                "version": "4.0",
                "encryptionAlgorithm": match header.encryption {
                    EncryptionAlgorithm::Aes256 => "AES-256",
                    EncryptionAlgorithm::ChaCha20 => "ChaCha20",
                },
                "kdfAlgorithm": match &header.kdf {
                    KdfAlgorithm::Argon2d { .. } => "Argon2d",
                    KdfAlgorithm::Argon2id { .. } => "Argon2id",
                    KdfAlgorithm::AesKdf { .. } => "AES-KDF",
                },
                "compression": match header.compression {
                    CompressionAlgorithm::None => "None",
                    CompressionAlgorithm::Gzip => "Gzip",
                },
            });
            
            serde_wasm_bindgen::to_value(&info)
                .map_err(|e| format!("Serialization error: {}", e))
        }
        Err(e) => Err(format!("{:?}", e)),
    }
}
