use crate::core::parser::{xml, Metadata};
use crate::core::types::{DeletedObject, Entry, Group};
use crate::error::KdbxError;
use byteorder::{LittleEndian, ReadBytesExt};
use std::collections::HashMap;
use std::io::{Cursor, Read};
use uuid::Uuid;

const INNER_RANDOM_STREAM_ID_CHACHA20: u32 = 3;

/// 解析内部数据流
pub fn parse_data_stream(
    data: &[u8],
) -> Result<(HashMap<Uuid, Group>, HashMap<Uuid, Entry>, Vec<DeletedObject>, Metadata), KdbxError> {
    let mut cursor = Cursor::new(data);
    let mut protected_stream_id: Option<u32> = None;
    let mut protected_stream_key: Option<Vec<u8>> = None;

    loop {
        let field_id = cursor.read_u8()?;
        let field_size = cursor.read_u32::<LittleEndian>()? as usize;

        let mut field_data = vec![0u8; field_size];
        if field_size > 0 {
            cursor.read_exact(&mut field_data)?;
        }

        match field_id {
            0 => break,
            1 => {
                if field_data.len() != 4 {
                    return Err(KdbxError::InvalidFileFormat);
                }
                protected_stream_id = Some(u32::from_le_bytes([
                    field_data[0],
                    field_data[1],
                    field_data[2],
                    field_data[3],
                ]));
            }
            2 => {
                protected_stream_key = Some(field_data);
            }
            3 => {
                // 暂不处理二进制附件，但需要消费字段以便继续读取 XML。
            }
            _ => {
                return Err(KdbxError::InvalidFileFormat);
            }
        }
    }

    let xml_data = &data[cursor.position() as usize..];
    let mut protected_stream = match (protected_stream_id, protected_stream_key) {
        (Some(stream_id), Some(stream_key)) => Some(xml::ProtectedStream::new(stream_id, &stream_key)?),
        (None, None) => None,
        _ => return Err(KdbxError::InvalidFileFormat),
    };

    xml::parse_xml(xml_data, protected_stream.as_mut())
}

/// 生成内部数据流
pub fn generate_data_stream(
    groups: &HashMap<Uuid, Group>,
    entries: &HashMap<Uuid, Entry>,
    deleted_objects: &[DeletedObject],
    metadata: &Metadata,
    protected_stream_key: &[u8],
) -> Result<Vec<u8>, KdbxError> {
    let mut data_stream = Vec::new();
    let mut protected_stream = xml::ProtectedStream::new(
        INNER_RANDOM_STREAM_ID_CHACHA20,
        protected_stream_key,
    )?;
    let xml_data = xml::generate_xml(
        groups,
        entries,
        deleted_objects,
        metadata,
        Some(&mut protected_stream),
    )?;

    data_stream.push(1);
    data_stream.extend_from_slice(&4u32.to_le_bytes());
    data_stream.extend_from_slice(&INNER_RANDOM_STREAM_ID_CHACHA20.to_le_bytes());

    data_stream.push(2);
    data_stream.extend_from_slice(&(protected_stream_key.len() as u32).to_le_bytes());
    data_stream.extend_from_slice(protected_stream_key);

    data_stream.push(0);
    data_stream.extend_from_slice(&0u32.to_le_bytes());

    data_stream.extend_from_slice(&xml_data);

    Ok(data_stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_parse_data_stream() {
        let mut groups = HashMap::new();
        let group = Group::new("Test Group".to_string(), None);
        let group_id = group.id;
        groups.insert(group.id, group);

        let mut entries = HashMap::new();
        let entry = Entry::new(
            group_id,
            "Test Entry".to_string(),
            crate::core::SecString::from_str("password"),
        );
        entries.insert(entry.id, entry);

        let deleted_objects = vec![];
        let metadata = Metadata::default();
        let protected_stream_key = vec![0xAB; 64];

        let stream = generate_data_stream(
            &groups,
            &entries,
            &deleted_objects,
            &metadata,
            &protected_stream_key,
        )
        .unwrap();
        assert!(!stream.is_empty());

        let (parsed_groups, parsed_entries, _, _) = parse_data_stream(&stream).unwrap();
        assert_eq!(parsed_groups.len(), 1);
        assert_eq!(parsed_entries.len(), 1);
    }
}
