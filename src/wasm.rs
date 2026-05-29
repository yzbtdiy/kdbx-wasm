use wasm_bindgen::prelude::*;
use js_sys::{Array, Uint8Array};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use uuid::Uuid;

use crate::core::{
    parser::{parse_kdbx, generate_kdbx},
    types::{Entry, Group, EncryptionAlgorithm, KdfAlgorithm, CompressionAlgorithm, KdbxSession},
};

#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
}

// ── JS-facing DTOs ──

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsEntry {
    uuid: String,
    icon_id: u32,
    group_id: String,
    title: String,
    username: Option<String>,
    password: String,
    url: Option<String>,
    notes: Option<String>,
    created_at: String,
    updated_at: String,
    accessed_at: String,
    expires_at: Option<String>,
    tags: Vec<String>,
    custom_fields: HashMap<String, String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsGroup {
    uuid: String,
    name: String,
    icon_id: u32,
    parent_id: Option<String>,
    created_at: String,
    updated_at: String,
    notes: Option<String>,
    child_groups: Vec<String>,
    entries: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsMetadata {
    database_name: Option<String>,
    database_description: Option<String>,
    default_username: Option<String>,
    maintenance_history_days: u32,
    color: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsKdfParams {
    memory: Option<u64>,
    iterations: Option<u64>,
    parallelism: Option<u32>,
    rounds: Option<u64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsHeaderInfo {
    version: String,
    encryption_algorithm: String,
    kdf_algorithm: String,
    kdf_params: JsKdfParams,
    compression: String,
    entry_count: usize,
    group_count: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsFileInfo {
    version: String,
    encryption_algorithm: String,
    kdf_algorithm: String,
    compression: String,
}

// ── KDBX Database ──

#[wasm_bindgen]
pub struct KdbxDatabase {
    session: KdbxSession,
}

#[wasm_bindgen]
impl KdbxDatabase {
    #[wasm_bindgen(constructor)]
    pub fn new(data: &Uint8Array, password: Option<String>, key_file: Option<Uint8Array>) -> Result<KdbxDatabase, String> {
        let rust_data = uint8array_to_vec(data);
        let key_file_data = key_file.map(|k| uint8array_to_vec(&k));
        let session = parse_kdbx(&rust_data, password.as_deref(), key_file_data.as_deref())
            .map_err(|e| format!("{e:?}"))?;
        Ok(KdbxDatabase { session })
    }

    #[wasm_bindgen(getter)]
    pub fn metadata(&self) -> Result<JsValue, JsValue> {
        let meta = &self.session.metadata;
        to_js(&JsMetadata {
            database_name: meta.database_name.clone(),
            database_description: meta.database_description.clone(),
            default_username: meta.default_username.clone(),
            maintenance_history_days: meta.maintenance_history_days,
            color: meta.color.clone(),
        })
    }

    #[wasm_bindgen(getter, js_name = headerInfo)]
    pub fn header_info(&self) -> Result<JsValue, JsValue> {
        let h = &self.session.header;
        let (kdf_name, kdf_params) = match &h.kdf {
            KdfAlgorithm::Argon2d { memory, iterations, parallelism, .. } =>
                ("Argon2d", JsKdfParams {
                    memory: Some(*memory),
                    iterations: Some(*iterations),
                    parallelism: Some(*parallelism),
                    rounds: None,
                }),
            KdfAlgorithm::Argon2id { memory, iterations, parallelism, .. } =>
                ("Argon2id", JsKdfParams {
                    memory: Some(*memory),
                    iterations: Some(*iterations),
                    parallelism: Some(*parallelism),
                    rounds: None,
                }),
            KdfAlgorithm::AesKdf { rounds, .. } =>
                ("AES-KDF", JsKdfParams {
                    memory: None,
                    iterations: None,
                    parallelism: None,
                    rounds: Some(*rounds),
                }),
        };
        to_js(&JsHeaderInfo {
            version: "4.0".to_string(),
            encryption_algorithm: encryption_name(&h.encryption).to_string(),
            kdf_algorithm: kdf_name.to_string(),
            kdf_params,
            compression: compression_name(&h.compression).to_string(),
            entry_count: self.session.entries.len(),
            group_count: self.session.groups.len(),
        })
    }

    #[wasm_bindgen(js_name = getEntries)]
    pub fn get_entries(&self) -> Result<Array, JsValue> {
        let array = Array::new();
        for entry in self.session.entries.values() {
            array.push(&self.entry_to_js(entry)?);
        }
        Ok(array)
    }

    #[wasm_bindgen(js_name = getEntry)]
    pub fn get_entry(&self, uuid: &str) -> Result<JsValue, JsValue> {
        let uuid = parse_uuid(uuid)?;
        let entry = self.session.entries.get(&uuid)
            .ok_or_else(|| JsValue::from_str("Entry not found"))?;
        self.entry_to_js(entry)
    }

    #[wasm_bindgen(js_name = getGroups)]
    pub fn get_groups(&self) -> Result<Array, JsValue> {
        let array = Array::new();

        // Pre-build indexes to avoid O(n²) scans in group_to_js
        let mut child_groups_map: HashMap<Uuid, Vec<String>> = HashMap::new();
        let mut entries_map: HashMap<Uuid, Vec<String>> = HashMap::new();
        for g in self.session.groups.values() {
            if let Some(pid) = g.parent_id {
                child_groups_map.entry(pid).or_default().push(g.id.to_string());
            }
        }
        for e in self.session.entries.values() {
            entries_map.entry(e.group_id).or_default().push(e.id.to_string());
        }

        for group in self.session.groups.values() {
            let child_groups = child_groups_map.get(&group.id).cloned().unwrap_or_default();
            let entries = entries_map.get(&group.id).cloned().unwrap_or_default();
            array.push(&self.group_to_js_with(group, child_groups, entries)?);
        }
        Ok(array)
    }

    #[wasm_bindgen(js_name = getGroup)]
    pub fn get_group(&self, uuid: &str) -> Result<JsValue, JsValue> {
        let uuid = parse_uuid(uuid)?;
        let group = self.session.groups.get(&uuid)
            .ok_or_else(|| JsValue::from_str("Group not found"))?;
        self.group_to_js(group)
    }

    #[wasm_bindgen(getter, js_name = rootGroupUuid)]
    pub fn root_group_uuid(&self) -> String {
        self.session.groups.values()
            .find(|g| g.parent_id.is_none())
            .map(|g| g.id.to_string())
            .unwrap_or_default()
    }

    #[wasm_bindgen(js_name = getEntriesByGroup)]
    pub fn get_entries_by_group(&self, group_uuid: &str) -> Result<Array, JsValue> {
        let gid = parse_uuid(group_uuid)?;
        let array = Array::new();
        for entry in self.session.entries.values().filter(|e| e.group_id == gid) {
            array.push(&self.entry_to_js(entry)?);
        }
        Ok(array)
    }

    #[wasm_bindgen(js_name = searchEntries)]
    pub fn search_entries(&self, query: &str) -> Result<Array, JsValue> {
        let q = query.to_lowercase();
        let array = Array::new();
        for entry in self.session.entries.values() {
            let matches = entry.title.to_lowercase().contains(&q)
                || entry.username.as_deref().unwrap_or("").to_lowercase().contains(&q)
                || entry.url.as_deref().unwrap_or("").to_lowercase().contains(&q)
                || entry.notes.as_deref().unwrap_or("").to_lowercase().contains(&q)
                || entry.tags.iter().any(|t| t.to_lowercase().contains(&q));
            if matches {
                array.push(&self.entry_to_js(entry)?);
            }
        }
        Ok(array)
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self, password: Option<String>, key_file: Option<Uint8Array>) -> Result<Uint8Array, String> {
        let key_file_data = key_file.map(|k| uint8array_to_vec(&k));
        let bytes = generate_kdbx(&self.session, password.as_deref(), key_file_data.as_deref())
            .map_err(|e| format!("{e:?}"))?;
        Ok(Uint8Array::from(&bytes[..]))
    }

    fn entry_to_js(&self, entry: &Entry) -> Result<JsValue, JsValue> {
        to_js(&JsEntry {
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
        })
    }

    fn group_to_js(&self, group: &Group) -> Result<JsValue, JsValue> {
        let child_groups: Vec<String> = self.session.groups.values()
            .filter(|g| g.parent_id == Some(group.id))
            .map(|g| g.id.to_string())
            .collect();
        let entries: Vec<String> = self.session.entries.values()
            .filter(|e| e.group_id == group.id)
            .map(|e| e.id.to_string())
            .collect();
        self.group_to_js_with(group, child_groups, entries)
    }

    fn group_to_js_with(&self, group: &Group, child_groups: Vec<String>, entries: Vec<String>) -> Result<JsValue, JsValue> {
        to_js(&JsGroup {
            uuid: group.id.to_string(),
            name: group.name.clone(),
            icon_id: group.icon_id,
            parent_id: group.parent_id.map(|p| p.to_string()),
            created_at: group.created_at.to_rfc3339(),
            updated_at: group.updated_at.to_rfc3339(),
            notes: group.notes.clone(),
            child_groups,
            entries,
        })
    }
}

// ── Standalone Functions ──

#[wasm_bindgen(js_name = isKdbxFile)]
pub fn is_kdbx_file(data: &Uint8Array) -> bool {
    if data.length() < 8 { return false; }
    let mut sig = [0u8; 8];
    data.slice(0, 8).copy_to(&mut sig);
    sig == [0x03, 0xD9, 0xA2, 0x9A, 0x67, 0xFB, 0x4B, 0xB5]
}

#[wasm_bindgen(js_name = getFileInfo)]
pub fn get_file_info(data: &Uint8Array) -> Result<JsValue, String> {
    let rust_data = uint8array_to_vec(data);
    let header = crate::core::header::parse_header(&rust_data).map_err(|e| format!("{e:?}"))?;
    let info = JsFileInfo {
        version: "4.0".to_string(),
        encryption_algorithm: encryption_name(&header.encryption).to_string(),
        kdf_algorithm: match &header.kdf {
            KdfAlgorithm::Argon2d { .. } => "Argon2d".to_string(),
            KdfAlgorithm::Argon2id { .. } => "Argon2id".to_string(),
            KdfAlgorithm::AesKdf { .. } => "AES-KDF".to_string(),
        },
        compression: compression_name(&header.compression).to_string(),
    };
    to_js(&info).map_err(|e| format!("{e:?}"))
}

// ── Helpers ──

fn uint8array_to_vec(arr: &Uint8Array) -> Vec<u8> {
    let mut buf = vec![0u8; arr.length() as usize];
    arr.copy_to(&mut buf);
    buf
}

fn parse_uuid(s: &str) -> Result<Uuid, JsValue> {
    Uuid::parse_str(s).map_err(|e| JsValue::from_str(&format!("Invalid UUID: {e}")))
}

fn to_js<T: serde::Serialize>(value: &T) -> Result<JsValue, JsValue> {
    let serializer = serde_wasm_bindgen::Serializer::json_compatible();
    value.serialize(&serializer)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {e}")))
}

fn encryption_name(enc: &EncryptionAlgorithm) -> &'static str {
    match enc {
        EncryptionAlgorithm::Aes256 => "AES-256",
        EncryptionAlgorithm::ChaCha20 => "ChaCha20",
    }
}

fn compression_name(comp: &CompressionAlgorithm) -> &'static str {
    match comp {
        CompressionAlgorithm::None => "None",
        CompressionAlgorithm::Gzip => "Gzip",
    }
}
