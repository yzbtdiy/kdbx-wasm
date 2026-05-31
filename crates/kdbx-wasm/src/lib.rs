use js_sys::{Array, Uint8Array};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;
use wasm_bindgen::prelude::*;

use kdbx_core::{
    error::KdbxError,
    parser::{generate_kdbx, parse_kdbx},
    types::{CompressionAlgorithm, EncryptionAlgorithm, Entry, Group, KdbxSession, KdfAlgorithm},
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
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<String>,
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

// ── KDBX Database ──

// ── Strongly-typed JS-facing structs ──

#[wasm_bindgen]
pub struct JsMetadata {
    database_name: Option<String>,
    database_description: Option<String>,
    default_username: Option<String>,
    maintenance_history_days: u32,
    color: Option<String>,
}

#[wasm_bindgen]
impl JsMetadata {
    #[wasm_bindgen(getter, js_name = databaseName)]
    pub fn database_name(&self) -> Option<String> {
        self.database_name.clone()
    }
    #[wasm_bindgen(getter, js_name = databaseDescription)]
    pub fn database_description(&self) -> Option<String> {
        self.database_description.clone()
    }
    #[wasm_bindgen(getter, js_name = defaultUsername)]
    pub fn default_username(&self) -> Option<String> {
        self.default_username.clone()
    }
    #[wasm_bindgen(getter, js_name = maintenanceHistoryDays)]
    pub fn maintenance_history_days(&self) -> u32 {
        self.maintenance_history_days
    }
    #[wasm_bindgen(getter, js_name = color)]
    pub fn color(&self) -> Option<String> {
        self.color.clone()
    }
}

#[wasm_bindgen]
pub struct JsKdfParams {
    memory: Option<u64>,
    iterations: Option<u64>,
    parallelism: Option<u32>,
    rounds: Option<u64>,
}

#[wasm_bindgen]
impl JsKdfParams {
    #[wasm_bindgen(getter)]
    pub fn memory(&self) -> Option<u64> {
        self.memory
    }
    #[wasm_bindgen(getter)]
    pub fn iterations(&self) -> Option<u64> {
        self.iterations
    }
    #[wasm_bindgen(getter)]
    pub fn parallelism(&self) -> Option<u32> {
        self.parallelism
    }
    #[wasm_bindgen(getter)]
    pub fn rounds(&self) -> Option<u64> {
        self.rounds
    }
}

#[wasm_bindgen]
pub struct JsHeaderInfo {
    version: String,
    encryption_algorithm: String,
    kdf_algorithm: String,
    kdf_params: JsKdfParams,
    compression: String,
    entry_count: usize,
    group_count: usize,
}

#[wasm_bindgen]
impl JsHeaderInfo {
    #[wasm_bindgen(getter, js_name = version)]
    pub fn version(&self) -> String {
        self.version.clone()
    }
    #[wasm_bindgen(getter, js_name = encryptionAlgorithm)]
    pub fn encryption_algorithm(&self) -> String {
        self.encryption_algorithm.clone()
    }
    #[wasm_bindgen(getter, js_name = kdfAlgorithm)]
    pub fn kdf_algorithm(&self) -> String {
        self.kdf_algorithm.clone()
    }
    #[wasm_bindgen(getter, js_name = kdfParams)]
    pub fn kdf_params(&self) -> JsKdfParams {
        JsKdfParams {
            memory: self.kdf_params.memory,
            iterations: self.kdf_params.iterations,
            parallelism: self.kdf_params.parallelism,
            rounds: self.kdf_params.rounds,
        }
    }
    #[wasm_bindgen(getter, js_name = compression)]
    pub fn compression(&self) -> String {
        self.compression.clone()
    }
    #[wasm_bindgen(getter, js_name = entryCount)]
    pub fn entry_count(&self) -> usize {
        self.entry_count
    }
    #[wasm_bindgen(getter, js_name = groupCount)]
    pub fn group_count(&self) -> usize {
        self.group_count
    }
}

#[wasm_bindgen]
pub struct KdbxDatabase {
    session: KdbxSession,
}

#[wasm_bindgen]
impl KdbxDatabase {
    #[wasm_bindgen(constructor)]
    pub fn new(
        data: &Uint8Array,
        password: Option<String>,
        key_file: Option<Uint8Array>,
    ) -> Result<KdbxDatabase, String> {
        let rust_data = uint8array_to_vec(data);
        let key_file_data = key_file.map(|k| uint8array_to_vec(&k));
        let session = parse_kdbx(&rust_data, password.as_deref(), key_file_data.as_deref())
            .map_err(to_js_error)?;
        Ok(KdbxDatabase { session })
    }

    #[wasm_bindgen(getter, js_name = metadata)]
    pub fn metadata(&self) -> JsMetadata {
        let meta = &self.session.metadata;
        JsMetadata {
            database_name: meta.database_name.clone(),
            database_description: meta.database_description.clone(),
            default_username: meta.default_username.clone(),
            maintenance_history_days: meta.maintenance_history_days,
            color: meta.color.clone(),
        }
    }

    #[wasm_bindgen(getter, js_name = headerInfo)]
    pub fn header_info(&self) -> JsHeaderInfo {
        let h = &self.session.header;
        let (kdf_name, kdf_params) = match &h.kdf {
            KdfAlgorithm::Argon2d {
                memory,
                iterations,
                parallelism,
                ..
            } => (
                "Argon2d",
                JsKdfParams {
                    memory: Some(*memory),
                    iterations: Some(*iterations),
                    parallelism: Some(*parallelism),
                    rounds: None,
                },
            ),
            KdfAlgorithm::Argon2id {
                memory,
                iterations,
                parallelism,
                ..
            } => (
                "Argon2id",
                JsKdfParams {
                    memory: Some(*memory),
                    iterations: Some(*iterations),
                    parallelism: Some(*parallelism),
                    rounds: None,
                },
            ),
            KdfAlgorithm::AesKdf { rounds, .. } => (
                "AES-KDF",
                JsKdfParams {
                    memory: None,
                    iterations: None,
                    parallelism: None,
                    rounds: Some(*rounds),
                },
            ),
        };
        JsHeaderInfo {
            version: "4.0".into(),
            encryption_algorithm: encryption_name(&h.encryption).into(),
            kdf_algorithm: kdf_name.into(),
            kdf_params,
            compression: compression_name(&h.compression).into(),
            entry_count: self.session.entries.len(),
            group_count: self.session.groups.len(),
        }
    }

    #[wasm_bindgen(js_name = getEntries)]
    pub fn get_entries(&self, include_password: Option<bool>) -> Result<Array, JsValue> {
        let include_password = include_password.unwrap_or(false);
        let array = Array::new();
        for entry in self.session.entries.values() {
            array.push(&self.entry_to_js(entry, include_password)?);
        }
        Ok(array)
    }

    #[wasm_bindgen(js_name = getEntry)]
    pub fn get_entry(
        &self,
        uuid: &str,
        include_password: Option<bool>,
    ) -> Result<JsValue, JsValue> {
        let include_password = include_password.unwrap_or(false);
        let uuid = parse_uuid(uuid)?;
        let entry = self
            .session
            .entries
            .get(&uuid)
            .ok_or_else(|| JsValue::from_str("Entry not found"))?;
        self.entry_to_js(entry, include_password)
    }

    #[wasm_bindgen(js_name = getGroups)]
    pub fn get_groups(&self) -> Result<Array, JsValue> {
        let array = Array::new();

        // Pre-build indexes to avoid O(n²) scans in group_to_js
        let mut child_groups_map: HashMap<Uuid, Vec<String>> = HashMap::new();
        let mut entries_map: HashMap<Uuid, Vec<String>> = HashMap::new();
        for g in self.session.groups.values() {
            if let Some(pid) = g.parent_id {
                child_groups_map
                    .entry(pid)
                    .or_default()
                    .push(g.id.to_string());
            }
        }
        for e in self.session.entries.values() {
            entries_map
                .entry(e.group_id)
                .or_default()
                .push(e.id.to_string());
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
        let group = self
            .session
            .groups
            .get(&uuid)
            .ok_or_else(|| JsValue::from_str("Group not found"))?;
        self.group_to_js(group)
    }

    #[wasm_bindgen(getter, js_name = rootGroupUuid)]
    pub fn root_group_uuid(&self) -> String {
        self.session
            .root_group
            .map(|u| u.to_string())
            .unwrap_or_default()
    }

    #[wasm_bindgen(js_name = getEntriesByGroup)]
    pub fn get_entries_by_group(
        &self,
        group_uuid: &str,
        include_password: Option<bool>,
    ) -> Result<Array, JsValue> {
        let include_password = include_password.unwrap_or(false);
        let gid = parse_uuid(group_uuid)?;
        let array = Array::new();
        if let Some(entry_ids) = self.session.group_entries.get(&gid) {
            for id in entry_ids {
                if let Some(entry) = self.session.entries.get(id) {
                    array.push(&self.entry_to_js(entry, include_password)?);
                }
            }
        }
        Ok(array)
    }

    #[wasm_bindgen(js_name = searchEntries)]
    pub fn search_entries(
        &self,
        query: &str,
        include_password: Option<bool>,
    ) -> Result<Array, JsValue> {
        let include_password = include_password.unwrap_or(false);
        let q = query.to_lowercase();
        let array = Array::new();
        for entry in self.session.entries.values() {
            let matches = entry.title.to_lowercase().contains(&q)
                || entry
                    .username
                    .as_deref()
                    .unwrap_or("")
                    .to_lowercase()
                    .contains(&q)
                || entry
                    .url
                    .as_deref()
                    .unwrap_or("")
                    .to_lowercase()
                    .contains(&q)
                || entry
                    .notes
                    .as_deref()
                    .unwrap_or("")
                    .to_lowercase()
                    .contains(&q)
                || entry.tags.iter().any(|t| t.to_lowercase().contains(&q))
                || entry
                    .custom_fields
                    .values()
                    .any(|v| v.to_lowercase().contains(&q));
            if matches {
                array.push(&self.entry_to_js(entry, include_password)?);
            }
        }
        Ok(array)
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(
        &self,
        password: Option<String>,
        key_file: Option<Uint8Array>,
    ) -> Result<Uint8Array, String> {
        let key_file_data = key_file.map(|k| uint8array_to_vec(&k));
        let bytes = generate_kdbx(&self.session, password.as_deref(), key_file_data.as_deref())
            .map_err(to_js_error)?;
        Ok(Uint8Array::from(&bytes[..]))
    }

    fn entry_to_js(&self, entry: &Entry, include_password: bool) -> Result<JsValue, JsValue> {
        let js_value = to_js(&JsEntry {
            uuid: entry.id.to_string(),
            icon_id: entry.icon_id,
            group_id: entry.group_id.to_string(),
            title: entry.title.clone(),
            username: entry.username.clone(),
            password: if include_password {
                entry.password.as_ref().map(|p| p.as_str().to_string())
            } else {
                None
            },
            url: entry.url.clone(),
            notes: entry.notes.clone(),
            created_at: entry.created_at.to_rfc3339(),
            updated_at: entry.updated_at.to_rfc3339(),
            accessed_at: entry.accessed_at.to_rfc3339(),
            expires_at: entry.expires_at.map(|e| e.to_rfc3339()),
            tags: entry.tags.clone(),
            custom_fields: HashMap::new(),
        })?;
        // Replace Map with plain Object for customFields
        let obj = js_sys::Object::from(js_value);
        let custom = js_sys::Object::new();
        for (k, v) in &entry.custom_fields {
            js_sys::Reflect::set(&custom, &JsValue::from_str(k), &JsValue::from_str(v))
                .map_err(|_| JsValue::from_str("Failed to set custom field"))?;
        }
        js_sys::Reflect::set(&obj, &JsValue::from_str("customFields"), &custom)
            .map_err(|_| JsValue::from_str("Failed to set customFields"))?;
        Ok(obj.into())
    }

    fn group_to_js(&self, group: &Group) -> Result<JsValue, JsValue> {
        let child_groups = self
            .session
            .group_children
            .get(&group.id)
            .map(|v| v.iter().map(|u| u.to_string()).collect())
            .unwrap_or_default();
        let entries = self
            .session
            .group_entries
            .get(&group.id)
            .map(|v| v.iter().map(|u| u.to_string()).collect())
            .unwrap_or_default();
        self.group_to_js_with(group, child_groups, entries)
    }

    fn group_to_js_with(
        &self,
        group: &Group,
        child_groups: Vec<String>,
        entries: Vec<String>,
    ) -> Result<JsValue, JsValue> {
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

    // ── Entry Mutations ──

    #[wasm_bindgen(js_name = createEntry)]
    pub fn create_entry(
        &mut self,
        group_uuid: &str,
        title: &str,
        password: &str,
    ) -> Result<String, String> {
        let gid = parse_uuid(group_uuid).map_err(|e| e.as_string().unwrap_or_default())?;
        let id = self
            .session
            .create_entry(
                gid,
                title.into(),
                kdbx_core::types::SecString::from_plain(password),
            )
            .map_err(to_js_error)?;
        Ok(id.to_string())
    }

    #[wasm_bindgen(js_name = deleteEntry)]
    pub fn delete_entry(&mut self, uuid: &str) -> Result<(), String> {
        let id = parse_uuid(uuid).map_err(|e| e.as_string().unwrap_or_default())?;
        self.session.delete_entry(id).map_err(to_js_error)?;
        Ok(())
    }

    #[wasm_bindgen(js_name = moveEntry)]
    pub fn move_entry(&mut self, entry_uuid: &str, target_group_uuid: &str) -> Result<(), String> {
        let eid = parse_uuid(entry_uuid).map_err(|e| e.as_string().unwrap_or_default())?;
        let gid = parse_uuid(target_group_uuid).map_err(|e| e.as_string().unwrap_or_default())?;
        self.session.move_entry(eid, gid).map_err(to_js_error)?;
        Ok(())
    }

    #[wasm_bindgen(js_name = setEntryTitle)]
    pub fn set_entry_title(&mut self, uuid: &str, title: &str) -> Result<(), String> {
        let id = parse_uuid(uuid).map_err(|e| e.as_string().unwrap_or_default())?;
        let entry = self
            .session
            .entries
            .get_mut(&id)
            .ok_or_else(|| to_js_error(KdbxError::EntryNotFound(id)))?;
        entry.title = title.into();
        entry.update();
        Ok(())
    }

    #[wasm_bindgen(js_name = setEntryUsername)]
    pub fn set_entry_username(
        &mut self,
        uuid: &str,
        username: Option<String>,
    ) -> Result<(), String> {
        let id = parse_uuid(uuid).map_err(|e| e.as_string().unwrap_or_default())?;
        let entry = self
            .session
            .entries
            .get_mut(&id)
            .ok_or_else(|| to_js_error(KdbxError::EntryNotFound(id)))?;
        entry.username = username.filter(|s| !s.is_empty());
        entry.update();
        Ok(())
    }

    #[wasm_bindgen(js_name = setEntryPassword)]
    pub fn set_entry_password(&mut self, uuid: &str, password: &str) -> Result<(), String> {
        let id = parse_uuid(uuid).map_err(|e| e.as_string().unwrap_or_default())?;
        let entry = self
            .session
            .entries
            .get_mut(&id)
            .ok_or_else(|| to_js_error(KdbxError::EntryNotFound(id)))?;
        entry.password = Some(kdbx_core::types::SecString::from_plain(password));
        entry.update();
        Ok(())
    }

    #[wasm_bindgen(js_name = setEntryUrl)]
    pub fn set_entry_url(&mut self, uuid: &str, url: Option<String>) -> Result<(), String> {
        let id = parse_uuid(uuid).map_err(|e| e.as_string().unwrap_or_default())?;
        let entry = self
            .session
            .entries
            .get_mut(&id)
            .ok_or_else(|| to_js_error(KdbxError::EntryNotFound(id)))?;
        entry.url = url.filter(|s| !s.is_empty());
        entry.update();
        Ok(())
    }

    #[wasm_bindgen(js_name = setEntryNotes)]
    pub fn set_entry_notes(&mut self, uuid: &str, notes: Option<String>) -> Result<(), String> {
        let id = parse_uuid(uuid).map_err(|e| e.as_string().unwrap_or_default())?;
        let entry = self
            .session
            .entries
            .get_mut(&id)
            .ok_or_else(|| to_js_error(KdbxError::EntryNotFound(id)))?;
        entry.notes = notes.filter(|s| !s.is_empty());
        entry.update();
        Ok(())
    }

    #[wasm_bindgen(js_name = setEntryIconId)]
    pub fn set_entry_icon_id(&mut self, uuid: &str, icon_id: u32) -> Result<(), String> {
        let id = parse_uuid(uuid).map_err(|e| e.as_string().unwrap_or_default())?;
        let entry = self
            .session
            .entries
            .get_mut(&id)
            .ok_or_else(|| to_js_error(KdbxError::EntryNotFound(id)))?;
        entry.icon_id = icon_id;
        entry.update();
        Ok(())
    }

    #[wasm_bindgen(js_name = addEntryTag)]
    pub fn add_entry_tag(&mut self, uuid: &str, tag: &str) -> Result<(), String> {
        let id = parse_uuid(uuid).map_err(|e| e.as_string().unwrap_or_default())?;
        let entry = self
            .session
            .entries
            .get_mut(&id)
            .ok_or_else(|| to_js_error(KdbxError::EntryNotFound(id)))?;
        if !entry.tags.contains(&tag.to_string()) {
            entry.tags.push(tag.into());
            entry.update();
        }
        Ok(())
    }

    #[wasm_bindgen(js_name = removeEntryTag)]
    pub fn remove_entry_tag(&mut self, uuid: &str, tag: &str) -> Result<(), String> {
        let id = parse_uuid(uuid).map_err(|e| e.as_string().unwrap_or_default())?;
        let entry = self
            .session
            .entries
            .get_mut(&id)
            .ok_or_else(|| to_js_error(KdbxError::EntryNotFound(id)))?;
        entry.tags.retain(|t| t != tag);
        entry.update();
        Ok(())
    }

    #[wasm_bindgen(js_name = setEntryCustomField)]
    pub fn set_entry_custom_field(
        &mut self,
        uuid: &str,
        key: &str,
        value: Option<String>,
    ) -> Result<(), String> {
        let id = parse_uuid(uuid).map_err(|e| e.as_string().unwrap_or_default())?;
        let entry = self
            .session
            .entries
            .get_mut(&id)
            .ok_or_else(|| to_js_error(KdbxError::EntryNotFound(id)))?;
        match value.filter(|s| !s.is_empty()) {
            Some(v) => {
                entry.custom_fields.insert(key.into(), v);
            }
            None => {
                entry.custom_fields.remove(key);
            }
        }
        entry.update();
        Ok(())
    }

    #[wasm_bindgen(js_name = setEntryExpires)]
    pub fn set_entry_expires(
        &mut self,
        uuid: &str,
        expires_at: Option<String>,
    ) -> Result<(), String> {
        let id = parse_uuid(uuid).map_err(|e| e.as_string().unwrap_or_default())?;
        let entry = self
            .session
            .entries
            .get_mut(&id)
            .ok_or_else(|| to_js_error(KdbxError::EntryNotFound(id)))?;
        entry.expires_at = match expires_at {
            Some(s) => Some(
                chrono::DateTime::parse_from_rfc3339(&s)
                    .map_err(|_| "Invalid RFC 3339 date".to_string())?
                    .with_timezone(&chrono::Utc),
            ),
            None => None,
        };
        entry.update();
        Ok(())
    }

    // ── Group Mutations ──

    #[wasm_bindgen(js_name = createGroup)]
    pub fn create_group(
        &mut self,
        name: &str,
        parent_uuid: Option<String>,
    ) -> Result<String, String> {
        let parent_id = match parent_uuid {
            Some(s) => Some(parse_uuid(&s).map_err(|e| e.as_string().unwrap_or_default())?),
            None => None,
        };
        let id = self
            .session
            .create_group(name.into(), parent_id)
            .map_err(to_js_error)?;
        Ok(id.to_string())
    }

    #[wasm_bindgen(js_name = deleteGroup)]
    pub fn delete_group(&mut self, uuid: &str) -> Result<(), String> {
        let id = parse_uuid(uuid).map_err(|e| e.as_string().unwrap_or_default())?;
        self.session.delete_group(id).map_err(to_js_error)?;
        Ok(())
    }

    #[wasm_bindgen(js_name = renameGroup)]
    pub fn rename_group(&mut self, uuid: &str, name: &str) -> Result<(), String> {
        let id = parse_uuid(uuid).map_err(|e| e.as_string().unwrap_or_default())?;
        let group = self
            .session
            .groups
            .get_mut(&id)
            .ok_or_else(|| to_js_error(KdbxError::GroupNotFound(id)))?;
        group.name = name.into();
        group.update();
        Ok(())
    }

    #[wasm_bindgen(js_name = setGroupNotes)]
    pub fn set_group_notes(&mut self, uuid: &str, notes: Option<String>) -> Result<(), String> {
        let id = parse_uuid(uuid).map_err(|e| e.as_string().unwrap_or_default())?;
        let group = self
            .session
            .groups
            .get_mut(&id)
            .ok_or_else(|| to_js_error(KdbxError::GroupNotFound(id)))?;
        group.notes = notes.filter(|s| !s.is_empty());
        group.update();
        Ok(())
    }

    #[wasm_bindgen(js_name = setGroupIconId)]
    pub fn set_group_icon_id(&mut self, uuid: &str, icon_id: u32) -> Result<(), String> {
        let id = parse_uuid(uuid).map_err(|e| e.as_string().unwrap_or_default())?;
        let group = self
            .session
            .groups
            .get_mut(&id)
            .ok_or_else(|| to_js_error(KdbxError::GroupNotFound(id)))?;
        group.icon_id = icon_id;
        group.update();
        Ok(())
    }

    // ── Metadata Mutations ──

    #[wasm_bindgen(js_name = setDatabaseName)]
    pub fn set_database_name(&mut self, name: Option<String>) {
        self.session.metadata.database_name = name.filter(|s| !s.is_empty());
    }

    #[wasm_bindgen(js_name = setDatabaseDescription)]
    pub fn set_database_description(&mut self, description: Option<String>) {
        self.session.metadata.database_description = description.filter(|s| !s.is_empty());
    }

    #[wasm_bindgen(js_name = setDefaultUsername)]
    pub fn set_default_username(&mut self, username: Option<String>) {
        self.session.metadata.default_username = username.filter(|s| !s.is_empty());
    }

    // ── Advanced Search & Convenience ──

    #[wasm_bindgen(js_name = searchEntriesAdvanced)]
    pub fn search_entries_advanced(
        &self,
        query: Option<String>,
        group_uuid: Option<String>,
        exclude_expired: Option<bool>,
        include_password: Option<bool>,
    ) -> Result<Array, JsValue> {
        let include_password = include_password.unwrap_or(false);
        let group_id = match group_uuid {
            Some(s) => Some(parse_uuid(&s)?),
            None => None,
        };
        let now = chrono::Utc::now();
        let search_query = kdbx_core::types::SearchQuery {
            text: query.as_deref(),
            group_id,
            tags: Vec::new(),
            exclude_expired: exclude_expired.unwrap_or(false),
        };
        let array = Array::new();
        for entry in self.session.entries.values() {
            if search_query.matches(entry, now) {
                array.push(&self.entry_to_js(entry, include_password)?);
            }
        }
        Ok(array)
    }

    #[wasm_bindgen(js_name = getChildGroups)]
    pub fn get_child_groups(&self, group_uuid: &str) -> Result<Array, JsValue> {
        let gid = parse_uuid(group_uuid)?;
        let array = Array::new();
        for group in self
            .session
            .groups
            .values()
            .filter(|g| g.parent_id == Some(gid))
        {
            array.push(&self.group_to_js(group)?);
        }
        Ok(array)
    }
}

// ── Standalone Functions ──

#[wasm_bindgen(js_name = isKdbxFile)]
pub fn is_kdbx_file(data: &Uint8Array) -> bool {
    if data.length() < 8 {
        return false;
    }
    let mut sig = [0u8; 8];
    data.slice(0, 8).copy_to(&mut sig);
    sig == [0x03, 0xD9, 0xA2, 0x9A, 0x67, 0xFB, 0x4B, 0xB5]
}

#[wasm_bindgen]
pub struct JsFileInfo {
    version: String,
    encryption_algorithm: String,
    kdf_algorithm: String,
    compression: String,
}

#[wasm_bindgen]
impl JsFileInfo {
    #[wasm_bindgen(getter, js_name = version)]
    pub fn version(&self) -> String {
        self.version.clone()
    }
    #[wasm_bindgen(getter, js_name = encryptionAlgorithm)]
    pub fn encryption_algorithm(&self) -> String {
        self.encryption_algorithm.clone()
    }
    #[wasm_bindgen(getter, js_name = kdfAlgorithm)]
    pub fn kdf_algorithm(&self) -> String {
        self.kdf_algorithm.clone()
    }
    #[wasm_bindgen(getter, js_name = compression)]
    pub fn compression(&self) -> String {
        self.compression.clone()
    }
}

#[wasm_bindgen(js_name = getFileInfo)]
pub fn get_file_info(data: &Uint8Array) -> Result<JsFileInfo, String> {
    let rust_data = uint8array_to_vec(data);
    let header = kdbx_core::header::parse_header(&rust_data).map_err(to_js_error)?;
    Ok(JsFileInfo {
        version: "4.0".into(),
        encryption_algorithm: encryption_name(&header.encryption).into(),
        kdf_algorithm: match &header.kdf {
            KdfAlgorithm::Argon2d { .. } => "Argon2d",
            KdfAlgorithm::Argon2id { .. } => "Argon2id",
            KdfAlgorithm::AesKdf { .. } => "AES-KDF",
        }
        .into(),
        compression: compression_name(&header.compression).into(),
    })
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
    serde_wasm_bindgen::to_value(value)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {e}")))
}

fn to_js_error(e: KdbxError) -> String {
    match e {
        KdbxError::InvalidSignature => "Not a valid KDBX file".into(),
        KdbxError::UnsupportedVersion(maj, min) => {
            format!("Unsupported KDBX version: {}.{}", maj, min)
        }
        KdbxError::InvalidMasterKey | KdbxError::HmacVerificationFailed => {
            "Incorrect password or key file, or the file has been tampered with".into()
        }
        KdbxError::DecryptionFailed => "Failed to decrypt database".into(),
        KdbxError::InvalidFileFormat => "Database file is corrupted".into(),
        KdbxError::EntryNotFound(_) => "Entry not found".into(),
        KdbxError::GroupNotFound(_) => "Group not found".into(),
        _ => "An unexpected error occurred".into(),
    }
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
