use crate::core::types::{DeletedObject, Entry, Group, SecString};
use crate::core::parser::Metadata;
use crate::error::KdbxError;
use chrono::{DateTime, Duration, NaiveDate, TimeZone, Utc};
use chacha20::cipher::{KeyIvInit, StreamCipher};
use roxmltree::Node;
use sha2::{Digest, Sha512};
use std::collections::HashMap;
use uuid::Uuid;

/// 解析XML数据
pub fn parse_xml(
    data: &[u8],
    mut protected_stream: Option<&mut ProtectedStream>,
) -> Result<(HashMap<Uuid, Group>, HashMap<Uuid, Entry>, Vec<DeletedObject>, Metadata), KdbxError> {
    let xml_str = std::str::from_utf8(data)
        .map_err(|e| KdbxError::SerializationError(e.to_string()))?;

    let doc = roxmltree::Document::parse(xml_str)
        .map_err(|e| KdbxError::SerializationError(e.to_string()))?;

    let root = doc.root_element();
    if !root.has_tag_name("KeePassFile") {
        return Err(KdbxError::InvalidFileFormat);
    }

    let mut groups = HashMap::new();
    let mut entries = HashMap::new();
    let mut deleted_objects = Vec::new();
    let metadata = parse_metadata(root.children().find(|n| n.has_tag_name("Meta")));

    if let Some(root_node) = root.children().find(|n| n.has_tag_name("Root")) {
        for child in root_node.children().filter(|n| n.is_element()) {
            if child.has_tag_name("Group") {
                parse_group_node(child, None, &mut groups, &mut entries, &mut protected_stream)?;
            } else if child.has_tag_name("DeletedObjects") {
                deleted_objects.extend(parse_deleted_objects(child));
            }
        }
    }

    Ok((groups, entries, deleted_objects, metadata))
}

pub enum ProtectedStream {
    ChaCha20(chacha20::ChaCha20),
}

impl ProtectedStream {
    pub fn new(stream_id: u32, key: &[u8]) -> Result<Self, KdbxError> {
        match stream_id {
            3 => {
                let hash = Sha512::digest(key);
                let mut key_bytes = [0u8; 32];
                key_bytes.copy_from_slice(&hash[..32]);
                let mut nonce_bytes = [0u8; 12];
                nonce_bytes.copy_from_slice(&hash[32..44]);
                let cipher = chacha20::ChaCha20::new((&key_bytes).into(), (&nonce_bytes).into());
                Ok(ProtectedStream::ChaCha20(cipher))
            }
            _ => Err(KdbxError::UnsupportedEncryptionAlgorithm),
        }
    }

    pub fn process(&mut self, data: &[u8]) -> Vec<u8> {
        let mut output = data.to_vec();
        match self {
            ProtectedStream::ChaCha20(cipher) => cipher.apply_keystream(&mut output),
        }
        output
    }
}

fn parse_metadata(node: Option<Node<'_, '_>>) -> Metadata {
    let mut metadata = Metadata::default();
    let Some(node) = node else {
        return metadata;
    };

    metadata.database_name = direct_child_text(node, "DatabaseName");
    metadata.database_description = direct_child_text(node, "DatabaseDescription");
    metadata.default_username = direct_child_text(node, "DefaultUserName");
    metadata.color = direct_child_text(node, "Color");
    metadata.maintenance_history_days = direct_child_text(node, "MaintenanceHistoryDays")
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or_default();

    metadata
}

fn parse_group_node(
    node: Node<'_, '_>,
    parent_id: Option<Uuid>,
    groups: &mut HashMap<Uuid, Group>,
    entries: &mut HashMap<Uuid, Entry>,
    protected_stream: &mut Option<&mut ProtectedStream>,
) -> Result<Uuid, KdbxError> {
    let now = Utc::now();
    let group_id = direct_child_text(node, "UUID")
        .as_deref()
        .map(parse_uuid)
        .transpose()?
        .unwrap_or_else(Uuid::new_v4);

    let times = node.children().find(|n| n.has_tag_name("Times"));
    let mut group = Group {
        id: group_id,
        name: direct_child_text(node, "Name").unwrap_or_else(|| "Group".to_string()),
        parent_id,
        icon_id: direct_child_text(node, "IconID")
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or_default(),
        created_at: parse_time_field(times, "CreationTime").unwrap_or(now),
        updated_at: parse_time_field(times, "LastModificationTime").unwrap_or(now),
        notes: direct_child_text(node, "Notes"),
    };

    if let Some(notes) = group.notes.as_ref() {
        if notes.is_empty() {
            group.notes = None;
        }
    }

    groups.insert(group_id, group);

    for child in node.children().filter(|n| n.is_element()) {
        if child.has_tag_name("Group") {
            parse_group_node(child, Some(group_id), groups, entries, protected_stream)?;
        } else if child.has_tag_name("Entry") {
            let entry = parse_entry_node(child, group_id, protected_stream)?;
            entries.insert(entry.id, entry);
        }
    }

    Ok(group_id)
}

fn parse_entry_node(
    node: Node<'_, '_>,
    group_id: Uuid,
    protected_stream: &mut Option<&mut ProtectedStream>,
) -> Result<Entry, KdbxError> {
    let now = Utc::now();
    let times = node.children().find(|n| n.has_tag_name("Times"));
    let mut entry = Entry {
        id: direct_child_text(node, "UUID")
            .as_deref()
            .map(parse_uuid)
            .transpose()?
            .unwrap_or_else(Uuid::new_v4),
        group_id,
        title: String::new(),
        username: None,
        password: None,
        url: None,
        notes: None,
        icon_id: direct_child_text(node, "IconID")
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or_default(),
        created_at: parse_time_field(times, "CreationTime").unwrap_or(now),
        updated_at: parse_time_field(times, "LastModificationTime").unwrap_or(now),
        accessed_at: parse_time_field(times, "LastAccessTime").unwrap_or(now),
        expires_at: parse_expires(node, times),
        tags: direct_child_text(node, "Tags")
            .map(|tags| tags.split(';').filter(|s| !s.is_empty()).map(|s| s.to_string()).collect())
            .unwrap_or_default(),
        custom_fields: HashMap::new(),
    };

    for string_node in node.children().filter(|n| n.has_tag_name("String")) {
        let Some(key) = direct_child_text(string_node, "Key") else {
            continue;
        };
        let value_node = string_node.children().find(|n| n.has_tag_name("Value"));
        let value = parse_value_node(value_node, protected_stream)?;

        match key.as_str() {
            "Title" => entry.title = value,
            "UserName" => entry.username = some_if_not_empty(value),
            "Password" => {
                if !value.is_empty() {
                    entry.password = Some(SecString::from_str(&value));
                }
            }
            "URL" => entry.url = some_if_not_empty(value),
            "Notes" => entry.notes = some_if_not_empty(value),
            _ => {
                entry.custom_fields.insert(key, value);
            }
        }
    }

    // Process <History> entries' protected values to keep the ChaCha20 stream in sync.
    // History entries contain protected fields that must be consumed in document order.
    if let Some(history_node) = node.children().find(|n| n.has_tag_name("History")) {
        for history_entry in history_node.children().filter(|n| n.has_tag_name("Entry")) {
            for string_node in history_entry.children().filter(|n| n.has_tag_name("String")) {
                let value_node = string_node.children().find(|n| n.has_tag_name("Value"));
                // Consume the protected value to advance the stream cipher state
                let _ = parse_value_node(value_node, protected_stream)?;
            }
        }
    }

    if entry.title.is_empty() {
        entry.title = "Untitled".to_string();
    }

    Ok(entry)
}

fn parse_deleted_objects(node: Node<'_, '_>) -> Vec<DeletedObject> {
    node.children()
        .filter(|n| n.has_tag_name("DeletedObject"))
        .filter_map(|deleted| {
            let id = direct_child_text(deleted, "UUID")
                .as_deref()
                .and_then(|value| parse_uuid(value).ok())?;
            let deletion_time = direct_child_text(deleted, "DeletionTime")
                .as_deref()
                .and_then(parse_time)
                .unwrap_or_else(Utc::now);

            Some(DeletedObject { id, deletion_time })
        })
        .collect()
}

fn parse_value_node(
    node: Option<Node<'_, '_>>,
    protected_stream: &mut Option<&mut ProtectedStream>,
) -> Result<String, KdbxError> {
    let Some(node) = node else {
        return Ok(String::new());
    };

    let raw_value = node.text().unwrap_or_default();
    let is_protected = node.attribute("Protected")
        .map(|value| value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    if !is_protected || raw_value.is_empty() {
        return Ok(raw_value.to_string());
    }

    let encrypted = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, raw_value)
        .map_err(|e| KdbxError::SerializationError(e.to_string()))?;

    let decrypted = if let Some(stream) = protected_stream.as_deref_mut() {
        stream.process(&encrypted)
    } else {
        encrypted
    };

    String::from_utf8(decrypted)
        .map_err(|e| KdbxError::SerializationError(e.to_string()))
}

fn parse_expires(node: Node<'_, '_>, times: Option<Node<'_, '_>>) -> Option<DateTime<Utc>> {
    let expires = direct_child_text(node, "Expires")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    if !expires {
        return None;
    }

    parse_time_field(times, "ExpiryTime")
}

fn parse_time_field(parent: Option<Node<'_, '_>>, field_name: &str) -> Option<DateTime<Utc>> {
    parent
        .and_then(|node| direct_child_text(node, field_name))
        .as_deref()
        .and_then(parse_time)
}

fn parse_time(value: &str) -> Option<DateTime<Utc>> {
    if value.is_empty() {
        return None;
    }

    if let Ok(parsed) = DateTime::parse_from_rfc3339(value) {
        return Some(parsed.with_timezone(&Utc));
    }

    let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, value).ok()?;
    if decoded.len() != 8 {
        return None;
    }

    let seconds = i64::from_le_bytes(decoded.try_into().ok()?);
    let base = NaiveDate::from_ymd_opt(1, 1, 1)?.and_hms_opt(0, 0, 0)?;
    let naive = base.checked_add_signed(Duration::seconds(seconds))?;
    Some(Utc.from_utc_datetime(&naive))
}

fn parse_uuid(value: &str) -> Result<Uuid, KdbxError> {
    let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, value)
        .map_err(|e| KdbxError::SerializationError(e.to_string()))?;
    Uuid::from_slice(&decoded).map_err(|e| KdbxError::SerializationError(e.to_string()))
}

fn direct_child_text(node: Node<'_, '_>, tag_name: &str) -> Option<String> {
    node.children()
        .find(|child| child.has_tag_name(tag_name))
        .and_then(|child| child.text())
        .map(|text| text.to_string())
}

fn some_if_not_empty(value: String) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

/// 生成XML数据
pub fn generate_xml(
    groups: &HashMap<Uuid, Group>,
    entries: &HashMap<Uuid, Entry>,
    deleted_objects: &[DeletedObject],
    metadata: &Metadata,
    mut protected_stream: Option<&mut ProtectedStream>,
) -> Result<Vec<u8>, KdbxError> {
    let mut xml = String::new();

    xml.push_str(r#"<?xml version="1.0" encoding="utf-8" standalone="yes"?>"#);
    xml.push_str("<KeePassFile>");

    // 元数据
    xml.push_str("<Meta>");
    if let Some(name) = &metadata.database_name {
        xml.push_str(&format!("<DatabaseName>{}</DatabaseName>", escape_xml(name)));
    }
    if let Some(desc) = &metadata.database_description {
        xml.push_str(&format!("<DatabaseDescription>{}</DatabaseDescription>", escape_xml(desc)));
    }
    if let Some(username) = &metadata.default_username {
        xml.push_str(&format!("<DefaultUserName>{}</DefaultUserName>", escape_xml(username)));
    }
    xml.push_str("</Meta>");

    // 根节点
    xml.push_str("<Root>");

    let mut top_level_groups: Vec<&Group> = groups
        .values()
        .filter(|group| group.parent_id.is_none())
        .collect();
    top_level_groups.sort_by(|left, right| left.name.cmp(&right.name).then(left.id.cmp(&right.id)));

    for group in top_level_groups {
        xml.push_str(&generate_group_xml(
            group,
            groups,
            entries,
            &mut protected_stream,
        )?);
    }

    // 删除对象
    if !deleted_objects.is_empty() {
        xml.push_str("<DeletedObjects>");
        for obj in deleted_objects {
            xml.push_str(&format!(
                "<DeletedObject><UUID>{}</UUID><DeletionTime>{}</DeletionTime></DeletedObject>",
                uuid_to_bytes(&obj.id),
                obj.deletion_time.to_rfc3339()
            ));
        }
        xml.push_str("</DeletedObjects>");
    }

    xml.push_str("</Root>");

    xml.push_str("</KeePassFile>");

    Ok(xml.into_bytes())
}

/// 生成分组XML
fn generate_group_xml(
    group: &Group,
    groups: &HashMap<Uuid, Group>,
    entries: &HashMap<Uuid, Entry>,
    protected_stream: &mut Option<&mut ProtectedStream>,
) -> Result<String, KdbxError> {
    let mut xml = String::new();
    let mut child_groups: Vec<&Group> = groups
        .values()
        .filter(|candidate| candidate.parent_id == Some(group.id))
        .collect();
    child_groups.sort_by(|left, right| left.name.cmp(&right.name).then(left.id.cmp(&right.id)));

    let mut child_entries: Vec<&Entry> = entries
        .values()
        .filter(|entry| entry.group_id == group.id)
        .collect();
    child_entries.sort_by(|left, right| left.title.cmp(&right.title).then(left.id.cmp(&right.id)));

    xml.push_str("<Group>");
    xml.push_str(&format!("<UUID>{}</UUID>", uuid_to_bytes(&group.id)));
    xml.push_str(&format!("<Name>{}</Name>", escape_xml(&group.name)));

    xml.push_str(&format!("<IconID>{}</IconID>", group.icon_id));
    xml.push_str(&generate_times_xml(
        group.created_at,
        group.updated_at,
        group.updated_at,
        None,
    ));

    if let Some(notes) = &group.notes {
        xml.push_str(&format!("<Notes>{}</Notes>", escape_xml(notes)));
    }

    for child_group in child_groups {
        xml.push_str(&generate_group_xml(
            child_group,
            groups,
            entries,
            protected_stream,
        )?);
    }

    for entry in child_entries {
        xml.push_str(&generate_entry_xml(entry, protected_stream)?);
    }

    xml.push_str("</Group>");

    Ok(xml)
}

/// 生成条目XML
fn generate_entry_xml(
    entry: &Entry,
    protected_stream: &mut Option<&mut ProtectedStream>,
) -> Result<String, KdbxError> {
    let mut xml = String::new();

    xml.push_str("<Entry>");
    xml.push_str(&format!("<UUID>{}</UUID>", uuid_to_bytes(&entry.id)));
    xml.push_str(&format!("<IconID>{}</IconID>", entry.icon_id));

    // 字符串字段
    xml.push_str(&generate_string_field_xml("Title", &entry.title, None));

    if let Some(username) = &entry.username {
        xml.push_str(&generate_string_field_xml("UserName", username, None));
    }

    if let Some(password) = &entry.password {
        xml.push_str(&generate_string_field_xml(
            "Password",
            password.as_str(),
            protected_stream.as_deref_mut(),
        ));
    }

    if let Some(url) = &entry.url {
        xml.push_str(&generate_string_field_xml("URL", url, None));
    }

    if let Some(notes) = &entry.notes {
        xml.push_str(&generate_string_field_xml("Notes", notes, None));
    }

    let mut custom_fields: Vec<(&String, &String)> = entry.custom_fields.iter().collect();
    custom_fields.sort_by(|left, right| left.0.cmp(right.0));
    for (key, value) in custom_fields {
        xml.push_str(&generate_string_field_xml(key, value, None));
    }

    if !entry.tags.is_empty() {
        xml.push_str(&format!("<Tags>{}</Tags>", escape_xml(&entry.tags.join(";"))));
    }

    xml.push_str(&generate_times_xml(
        entry.created_at,
        entry.updated_at,
        entry.accessed_at,
        entry.expires_at,
    ));

    xml.push_str("</Entry>");

    Ok(xml)
}

fn generate_string_field_xml(
    key: &str,
    value: &str,
    protected_stream: Option<&mut ProtectedStream>,
) -> String {
    let value_xml = if let Some(stream) = protected_stream {
        let encrypted = stream.process(value.as_bytes());
        format!(
            "<Value Protected=\"True\">{}</Value>",
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, encrypted)
        )
    } else {
        format!("<Value>{}</Value>", escape_xml(value))
    };

    format!(
        "<String><Key>{}</Key>{}</String>",
        escape_xml(key),
        value_xml,
    )
}

fn generate_times_xml(
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    accessed_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
) -> String {
    let expiry_time = expires_at
        .map(|value| value.to_rfc3339())
        .unwrap_or_else(|| created_at.to_rfc3339());
    let expires = if expires_at.is_some() { "True" } else { "False" };

    format!(
        "<Times><CreationTime>{}</CreationTime><LastModificationTime>{}</LastModificationTime><LastAccessTime>{}</LastAccessTime><ExpiryTime>{}</ExpiryTime></Times><Expires>{}</Expires>",
        created_at.to_rfc3339(),
        updated_at.to_rfc3339(),
        accessed_at.to_rfc3339(),
        expiry_time,
        expires,
    )
}

/// UUID转换为字节数组字符串
fn uuid_to_bytes(uuid: &Uuid) -> String {
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, uuid.as_bytes())
}

/// 转义XML特殊字符
fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// 从字节数组解析UUID
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_xml() {
        assert_eq!(escape_xml("a<b>c&d"), "a&lt;b&gt;c&amp;d");
    }

    #[test]
    fn test_generate_xml() {
        let mut groups = HashMap::new();
        let group = Group::new("Test".to_string(), None);
        let group_id = group.id;
        groups.insert(group.id, group);

        let mut entries = HashMap::new();
        let entry = Entry::new(group_id, "Entry".to_string(), SecString::from_str("secret"));
        entries.insert(entry.id, entry);
        let deleted_objects = vec![];
        let metadata = Metadata::default();
        let mut protected_stream = ProtectedStream::new(3, &[0x11; 64]).unwrap();

        let xml = generate_xml(
            &groups,
            &entries,
            &deleted_objects,
            &metadata,
            Some(&mut protected_stream),
        )
        .unwrap();
        assert!(xml.starts_with(b"<?xml"));

        let mut parse_stream = ProtectedStream::new(3, &[0x11; 64]).unwrap();
        let (_, parsed_entries, _, _) = parse_xml(&xml, Some(&mut parse_stream)).unwrap();
        assert_eq!(parsed_entries.len(), 1);
    }

        #[test]
        fn test_parse_xml_with_tags_and_custom_fields() {
                let xml = br#"<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<KeePassFile>
    <Meta />
    <Root>
        <Group>
            <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
            <Name>Root</Name>
            <IconID>0</IconID>
            <Times>
                <CreationTime>2024-01-01T00:00:00Z</CreationTime>
                <LastModificationTime>2024-01-01T00:00:00Z</LastModificationTime>
                <LastAccessTime>2024-01-01T00:00:00Z</LastAccessTime>
                <ExpiryTime>2024-01-01T00:00:00Z</ExpiryTime>
            </Times>
            <Entry>
                <UUID>AQEBAQEBAQEBAQEBAQEBAQ==</UUID>
                <IconID>1</IconID>
                <String><Key>Title</Key><Value>Example</Value></String>
                <String><Key>UserName</Key><Value>alice</Value></String>
                <String><Key>Password</Key><Value>secret</Value></String>
                <String><Key>Environment</Key><Value>prod</Value></String>
                <String><Key>Owner</Key><Value>team-a</Value></String>
                <Tags>ops;prod</Tags>
                <Times>
                    <CreationTime>2024-01-01T00:00:00Z</CreationTime>
                    <LastModificationTime>2024-01-01T00:00:00Z</LastModificationTime>
                    <LastAccessTime>2024-01-01T00:00:00Z</LastAccessTime>
                    <ExpiryTime>2024-01-01T00:00:00Z</ExpiryTime>
                </Times>
            </Entry>
        </Group>
    </Root>
</KeePassFile>"#;

                let (_, entries, _, _) = parse_xml(xml, None).unwrap();
                let entry = entries.values().next().unwrap();

                assert_eq!(entry.tags, vec!["ops".to_string(), "prod".to_string()]);
                assert_eq!(entry.custom_fields.get("Environment"), Some(&"prod".to_string()));
                assert_eq!(entry.custom_fields.get("Owner"), Some(&"team-a".to_string()));
        }
}
