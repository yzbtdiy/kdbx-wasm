use crate::core::types::*;
use crate::error::KdbxError;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chrono::{DateTime, Duration, NaiveDate, TimeZone, Utc};
use roxmltree::Node;
use sha2::{Digest, Sha512};
use std::collections::HashMap;
use uuid::Uuid;

// ── Protected Stream ──

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
                Ok(ProtectedStream::ChaCha20(chacha20::ChaCha20::new(
                    (&key_bytes).into(),
                    (&nonce_bytes).into(),
                )))
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

// ── Parse XML ──

pub type ParsedXml = (
    HashMap<Uuid, Group>,
    HashMap<Uuid, Entry>,
    Vec<DeletedObject>,
    Metadata,
);

pub fn parse_xml(
    data: &[u8],
    mut protected_stream: Option<&mut ProtectedStream>,
) -> Result<ParsedXml, KdbxError> {
    let xml_str =
        std::str::from_utf8(data).map_err(|e| KdbxError::SerializationError(e.to_string()))?;
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
                parse_group_node(
                    child,
                    None,
                    &mut groups,
                    &mut entries,
                    &mut protected_stream,
                )?;
            } else if child.has_tag_name("DeletedObjects") {
                deleted_objects.extend(parse_deleted_objects(child));
            }
        }
    }

    Ok((groups, entries, deleted_objects, metadata))
}

fn parse_metadata(node: Option<Node<'_, '_>>) -> Metadata {
    let Some(node) = node else {
        return Metadata::default();
    };
    Metadata {
        database_name: child_text(node, "DatabaseName"),
        database_description: child_text(node, "DatabaseDescription"),
        default_username: child_text(node, "DefaultUserName"),
        color: child_text(node, "Color"),
        maintenance_history_days: child_text(node, "MaintenanceHistoryDays")
            .and_then(|v| v.parse().ok())
            .unwrap_or_default(),
    }
}

fn parse_group_node(
    node: Node<'_, '_>,
    parent_id: Option<Uuid>,
    groups: &mut HashMap<Uuid, Group>,
    entries: &mut HashMap<Uuid, Entry>,
    protected_stream: &mut Option<&mut ProtectedStream>,
) -> Result<Uuid, KdbxError> {
    let now = Utc::now();
    let group_id = child_text(node, "UUID")
        .as_deref()
        .map(parse_uuid)
        .transpose()?
        .unwrap_or_else(Uuid::new_v4);

    let times = node.children().find(|n| n.has_tag_name("Times"));
    let mut group = Group {
        id: group_id,
        name: child_text(node, "Name").unwrap_or_else(|| "Group".to_string()),
        parent_id,
        icon_id: child_text(node, "IconID")
            .and_then(|v| v.parse().ok())
            .unwrap_or_default(),
        created_at: time_field(times, "CreationTime").unwrap_or(now),
        updated_at: time_field(times, "LastModificationTime").unwrap_or(now),
        notes: child_text(node, "Notes"),
    };

    if group.notes.as_ref().is_some_and(|n| n.is_empty()) {
        group.notes = None;
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
        id: child_text(node, "UUID")
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
        icon_id: child_text(node, "IconID")
            .and_then(|v| v.parse().ok())
            .unwrap_or_default(),
        created_at: time_field(times, "CreationTime").unwrap_or(now),
        updated_at: time_field(times, "LastModificationTime").unwrap_or(now),
        accessed_at: time_field(times, "LastAccessTime").unwrap_or(now),
        expires_at: parse_expires(node, times),
        tags: child_text(node, "Tags")
            .map(|t| {
                t.split(';')
                    .filter(|s| !s.is_empty())
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default(),
        custom_fields: HashMap::new(),
        history: Vec::new(),
    };

    for string_node in node.children().filter(|n| n.has_tag_name("String")) {
        let Some(key) = child_text(string_node, "Key") else {
            continue;
        };
        let value_node = string_node.children().find(|n| n.has_tag_name("Value"));
        let value = parse_value_node(value_node, protected_stream)?;

        match key.as_str() {
            "Title" => entry.title = value,
            "UserName" => entry.username = non_empty(value),
            "Password" if !value.is_empty() => entry.password = Some(SecString::from_plain(&value)),
            "URL" => entry.url = non_empty(value),
            "Notes" => entry.notes = non_empty(value),
            _ => {
                entry.custom_fields.insert(key, value);
            }
        }
    }

    // Parse history entries
    if let Some(history_node) = node.children().find(|n| n.has_tag_name("History")) {
        for history_entry in history_node.children().filter(|n| n.has_tag_name("Entry")) {
            // History entries are stored without nested history to avoid recursion
            let mut hist = parse_entry_node(history_entry, group_id, protected_stream)?;
            hist.history.clear(); // prevent nested history
            entry.history.push(hist);
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
        .filter_map(|n| {
            let id = child_text(n, "UUID")
                .as_deref()
                .and_then(|v| parse_uuid(v).ok())?;
            let deletion_time = child_text(n, "DeletionTime")
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
    let is_protected = node
        .attribute("Protected")
        .is_some_and(|v| v.eq_ignore_ascii_case("true"));

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
    String::from_utf8(decrypted).map_err(|e| KdbxError::SerializationError(e.to_string()))
}

fn parse_expires(node: Node<'_, '_>, times: Option<Node<'_, '_>>) -> Option<DateTime<Utc>> {
    let expires = child_text(node, "Expires").is_some_and(|v| v.eq_ignore_ascii_case("true"));
    if expires {
        time_field(times, "ExpiryTime")
    } else {
        None
    }
}

// ── Generate XML ──

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

    // Metadata
    xml.push_str("<Meta>");
    if let Some(name) = &metadata.database_name {
        xml.push_str(&format!(
            "<DatabaseName>{}</DatabaseName>",
            escape_xml(name)
        ));
    }
    if let Some(desc) = &metadata.database_description {
        xml.push_str(&format!(
            "<DatabaseDescription>{}</DatabaseDescription>",
            escape_xml(desc)
        ));
    }
    if let Some(username) = &metadata.default_username {
        xml.push_str(&format!(
            "<DefaultUserName>{}</DefaultUserName>",
            escape_xml(username)
        ));
    }
    xml.push_str(&format!(
        "<MaintenanceHistoryDays>{}</MaintenanceHistoryDays>",
        metadata.maintenance_history_days
    ));
    if let Some(color) = &metadata.color {
        xml.push_str(&format!("<Color>{}</Color>", escape_xml(color)));
    }
    xml.push_str("</Meta>");

    // Root
    xml.push_str("<Root>");

    let mut top_groups: Vec<&Group> = groups.values().filter(|g| g.parent_id.is_none()).collect();
    top_groups.sort_by(|a, b| a.name.cmp(&b.name).then(a.id.cmp(&b.id)));
    for group in top_groups {
        write_group_xml(&mut xml, group, groups, entries, &mut protected_stream)?;
    }

    if !deleted_objects.is_empty() {
        xml.push_str("<DeletedObjects>");
        for obj in deleted_objects {
            xml.push_str(&format!(
                "<DeletedObject><UUID>{}</UUID><DeletionTime>{}</DeletionTime></DeletedObject>",
                uuid_to_base64(&obj.id),
                obj.deletion_time.to_rfc3339()
            ));
        }
        xml.push_str("</DeletedObjects>");
    }

    xml.push_str("</Root></KeePassFile>");
    Ok(xml.into_bytes())
}

fn write_group_xml(
    xml: &mut String,
    group: &Group,
    groups: &HashMap<Uuid, Group>,
    entries: &HashMap<Uuid, Entry>,
    protected_stream: &mut Option<&mut ProtectedStream>,
) -> Result<(), KdbxError> {
    let mut children: Vec<&Group> = groups
        .values()
        .filter(|g| g.parent_id == Some(group.id))
        .collect();
    children.sort_by(|a, b| a.name.cmp(&b.name).then(a.id.cmp(&b.id)));

    let mut child_entries: Vec<&Entry> = entries
        .values()
        .filter(|e| e.group_id == group.id)
        .collect();
    child_entries.sort_by(|a, b| a.title.cmp(&b.title).then(a.id.cmp(&b.id)));

    xml.push_str("<Group>");
    xml.push_str(&format!("<UUID>{}</UUID>", uuid_to_base64(&group.id)));
    xml.push_str(&format!("<Name>{}</Name>", escape_xml(&group.name)));
    xml.push_str(&format!("<IconID>{}</IconID>", group.icon_id));
    write_times_xml(
        xml,
        group.created_at,
        group.updated_at,
        group.updated_at,
        None,
    );

    if let Some(notes) = &group.notes {
        xml.push_str(&format!("<Notes>{}</Notes>", escape_xml(notes)));
    }

    for child in children {
        write_group_xml(xml, child, groups, entries, protected_stream)?;
    }
    for entry in child_entries {
        write_entry_xml(xml, entry, protected_stream)?;
    }

    xml.push_str("</Group>");
    Ok(())
}

fn write_entry_xml(
    xml: &mut String,
    entry: &Entry,
    protected_stream: &mut Option<&mut ProtectedStream>,
) -> Result<(), KdbxError> {
    xml.push_str("<Entry>");
    xml.push_str(&format!("<UUID>{}</UUID>", uuid_to_base64(&entry.id)));
    xml.push_str(&format!("<IconID>{}</IconID>", entry.icon_id));

    write_string_field(xml, "Title", &entry.title, None);
    if let Some(username) = &entry.username {
        write_string_field(xml, "UserName", username, None);
    }
    if let Some(password) = &entry.password {
        write_string_field(
            xml,
            "Password",
            password.as_str(),
            protected_stream.as_deref_mut(),
        );
    }
    if let Some(url) = &entry.url {
        write_string_field(xml, "URL", url, None);
    }
    if let Some(notes) = &entry.notes {
        write_string_field(xml, "Notes", notes, None);
    }

    let mut custom: Vec<_> = entry.custom_fields.iter().collect();
    custom.sort_by_key(|(k, _)| *k);
    for (key, value) in custom {
        write_string_field(xml, key, value, None);
    }

    if !entry.tags.is_empty() {
        xml.push_str(&format!(
            "<Tags>{}</Tags>",
            escape_xml(&entry.tags.join(";"))
        ));
    }

    write_times_xml(
        xml,
        entry.created_at,
        entry.updated_at,
        entry.accessed_at,
        entry.expires_at,
    );

    if !entry.history.is_empty() {
        xml.push_str("<History>");
        for hist in &entry.history {
            write_entry_xml(xml, hist, protected_stream)?;
        }
        xml.push_str("</History>");
    }

    xml.push_str("</Entry>");
    Ok(())
}

fn write_string_field(
    xml: &mut String,
    key: &str,
    value: &str,
    stream: Option<&mut ProtectedStream>,
) {
    let value_xml = if let Some(stream) = stream {
        let encrypted = stream.process(value.as_bytes());
        format!(
            "<Value Protected=\"True\">{}</Value>",
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, encrypted)
        )
    } else {
        format!("<Value>{}</Value>", escape_xml(value))
    };
    xml.push_str(&format!(
        "<String><Key>{}</Key>{}</String>",
        escape_xml(key),
        value_xml
    ));
}

fn write_times_xml(
    xml: &mut String,
    created: DateTime<Utc>,
    modified: DateTime<Utc>,
    accessed: DateTime<Utc>,
    expires: Option<DateTime<Utc>>,
) {
    let expiry = expires.unwrap_or(created).to_rfc3339();
    let expires_flag = if expires.is_some() { "True" } else { "False" };
    xml.push_str(&format!(
        "<Times><CreationTime>{}</CreationTime><LastModificationTime>{}</LastModificationTime>\
         <LastAccessTime>{}</LastAccessTime><ExpiryTime>{}</ExpiryTime></Times><Expires>{}</Expires>",
        created.to_rfc3339(), modified.to_rfc3339(), accessed.to_rfc3339(), expiry, expires_flag,
    ));
}

// ── Helpers ──

fn time_field(parent: Option<Node<'_, '_>>, name: &str) -> Option<DateTime<Utc>> {
    parent
        .and_then(|n| child_text(n, name))
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

fn uuid_to_base64(uuid: &Uuid) -> String {
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, uuid.as_bytes())
}

fn child_text(node: Node<'_, '_>, tag: &str) -> Option<String> {
    node.children()
        .find(|c| c.has_tag_name(tag))
        .and_then(|c| c.text())
        .map(String::from)
}

fn non_empty(value: String) -> Option<String> {
    if value.is_empty() { None } else { Some(value) }
}

fn escape_xml(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => result.push_str("&amp;"),
            '<' => result.push_str("&lt;"),
            '>' => result.push_str("&gt;"),
            '"' => result.push_str("&quot;"),
            '\'' => result.push_str("&apos;"),
            // Skip invalid XML 1.0 control characters (except tab, newline, carriage return)
            c if c < '\u{20}' && c != '\t' && c != '\n' && c != '\r' => {}
            c => result.push(c),
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_xml() {
        assert_eq!(escape_xml("a<b>c&d"), "a&lt;b&gt;c&amp;d");
    }

    #[test]
    fn test_generate_and_parse_xml() {
        let mut groups = HashMap::new();
        let group = Group::new("Test".to_string(), None);
        let group_id = group.id;
        groups.insert(group.id, group);

        let mut entries = HashMap::new();
        let entry = Entry::new(
            group_id,
            "Entry".to_string(),
            SecString::from_plain("secret"),
        );
        entries.insert(entry.id, entry);

        let metadata = Metadata::default();
        let mut stream = ProtectedStream::new(3, &[0x11; 64]).unwrap();
        let xml = generate_xml(&groups, &entries, &[], &metadata, Some(&mut stream)).unwrap();
        assert!(xml.starts_with(b"<?xml"));

        let mut parse_stream = ProtectedStream::new(3, &[0x11; 64]).unwrap();
        let (_, parsed, _, _) = parse_xml(&xml, Some(&mut parse_stream)).unwrap();
        assert_eq!(parsed.len(), 1);
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
        assert_eq!(
            entry.custom_fields.get("Environment"),
            Some(&"prod".to_string())
        );
        assert_eq!(
            entry.custom_fields.get("Owner"),
            Some(&"team-a".to_string())
        );
    }
}
