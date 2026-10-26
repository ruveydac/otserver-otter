//! Read only the server's NTLM challenge. Never construct an AUTHENTICATE message.
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub(super) fn negotiate() -> Vec<u8> {
    let mut token = b"NTLMSSP\0".to_vec();
    token.extend_from_slice(&1_u32.to_le_bytes());
    // Unicode, request target, NTLM, extended session security, target info, version.
    token.extend_from_slice(&0x0288_0205_u32.to_le_bytes());
    token.extend_from_slice(&[0; 16]);
    token.extend_from_slice(&[10, 0, 0, 0, 0, 0, 0, 15]);
    token
}

pub(super) fn u16le(bytes: &[u8], offset: usize) -> Result<u16, String> {
    let bytes = bytes.get(offset..offset + 2).ok_or("truncated integer")?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

pub(super) fn u32le(bytes: &[u8], offset: usize) -> Result<u32, String> {
    let bytes = bytes.get(offset..offset + 4).ok_or("truncated integer")?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn buffer(bytes: &[u8], offset: usize, header: usize) -> Result<&[u8], String> {
    let length = usize::from(u16le(bytes, offset)?);
    if u16le(bytes, offset + 2)? < length as u16 {
        return Err("invalid NTLM maximum length".into());
    }
    let start = u32le(bytes, offset + 4)? as usize;
    if length == 0 {
        return Ok(&[]);
    }
    if start < header {
        return Err("NTLM payload overlaps header".into());
    }
    bytes
        .get(start..start.checked_add(length).ok_or("NTLM length overflow")?)
        .ok_or_else(|| "truncated NTLM payload".into())
}

pub(super) fn unicode(bytes: &[u8]) -> Result<String, String> {
    if !bytes.len().is_multiple_of(2) {
        return Err("odd NTLM Unicode length".into());
    }
    let words = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|v| u16::from_le_bytes(*v));
    let value: String = char::decode_utf16(words)
        .collect::<Result<_, _>>()
        .map_err(|_| "invalid NTLM Unicode")?;
    if value.chars().any(char::is_control) {
        return Err("control character in NTLM name".into());
    }
    Ok(value)
}

pub(super) fn challenge(bytes: &[u8]) -> Result<(BTreeMap<String, Value>, Value), String> {
    if bytes.len() < 32
        || bytes.len() > 65536
        || &bytes[..8] != b"NTLMSSP\0"
        || u32le(bytes, 8)? != 2
    {
        return Err("invalid NTLM challenge".into());
    }
    let flags = u32le(bytes, 20)?;
    // Older Type 2 messages can omit Reserved and TargetInfoFields entirely (MS-NLMP).
    let has_info = flags & 0x0280_0000 != 0
        || (bytes.len() >= 48 && (u32le(bytes, 16)? >= 48 || u16le(bytes, 12)? == 0));
    let header = if flags & 0x0200_0000 != 0 {
        56
    } else if has_info {
        48
    } else {
        32
    };
    if bytes.len() < header || flags & 1 == 0 {
        return Err("unsupported NTLM challenge layout".into());
    }
    let target = unicode(buffer(bytes, 12, header)?)?;
    let info = if has_info {
        buffer(bytes, 40, header)?
    } else {
        &[]
    };
    if !info.is_empty() {
        if flags & 0x0080_0000 == 0 {
            return Err("NTLM target info without negotiated flag".into());
        }
        let target_start = u32le(bytes, 16)? as usize;
        let target_length = usize::from(u16le(bytes, 12)?);
        let info_start = u32le(bytes, 44)? as usize;
        if target_length != 0
            && target_start < info_start + info.len()
            && info_start < target_start + target_length
        {
            return Err("overlapping NTLM payloads".into());
        }
    }
    let mut names = BTreeMap::<String, Value>::new();
    let mut cursor = 0;
    let mut ended = info.is_empty();
    while cursor < info.len() {
        let id = u16le(info, cursor)?;
        let length = usize::from(u16le(info, cursor + 2)?);
        cursor += 4;
        let value = info
            .get(cursor..cursor + length)
            .ok_or("truncated NTLM AV pair")?;
        cursor += length;
        if id == 0 {
            if length != 0 || cursor != info.len() {
                return Err("invalid NTLM AV terminator".into());
            }
            ended = true;
            break;
        }
        let key = match id {
            1 => Some("netbiosComputerName"),
            2 => Some("netbiosDomainName"),
            3 => Some("dnsComputerName"),
            4 => Some("dnsDomainName"),
            5 => Some("dnsTreeName"),
            _ => None,
        };
        if matches!((id, length), (6, n) if n != 4)
            || matches!((id, length), (7, n) if n != 8)
            || matches!((id, length), (10, n) if n != 16)
        {
            return Err("invalid NTLM AV value length".into());
        }
        if let Some(key) = key
            && names.insert(key.into(), json!(unicode(value)?)).is_some()
        {
            return Err("duplicate NTLM name".into());
        }
    }
    if !ended {
        return Err("missing NTLM AV terminator".into());
    }
    let mut fields = BTreeMap::new();
    if let Some(name) = names
        .get("dnsComputerName")
        .or_else(|| names.get("netbiosComputerName"))
        && name.as_str().is_some_and(|name| !name.is_empty())
    {
        fields.insert("name".into(), name.clone());
    }
    let mut raw = json!({"targetName": target, "names": names, "negotiateFlags": flags,
                         "challengeHex": crate::contract::hex(bytes)});
    if header == 56 {
        if bytes[52..55] != [0; 3] || bytes[55] != 15 {
            return Err("invalid NTLM version".into());
        }
        let (major, minor, build) = (bytes[48], bytes[49], u16le(bytes, 50)?);
        raw["reportedVersion"] = json!({"major": major, "minor": minor, "build": build});
        // This is a peer-reported NT version, not proof of edition, UBR, or patch state.
        if major != 0 && build != 0 {
            fields.insert(
                "operatingSystem".into(),
                json!(format!(
                    "Windows-compatible NT {major}.{minor} build {build}"
                )),
            );
            fields.insert("osAccuracy".into(), json!(80));
            raw["windowsCandidates"] = json!(candidates(major, minor, build));
        }
    }
    Ok((fields, raw))
}

fn candidates(major: u8, minor: u8, build: u16) -> &'static [&'static str] {
    match (major, minor, build) {
        (5, 1, 2600) => &["Windows XP"],
        (5, 2, 3790) => &["Windows Server 2003", "Windows XP x64"],
        (6, 0, 6000..=6002) => &["Windows Vista", "Windows Server 2008"],
        (6, 1, 7600..=7601) => &["Windows 7", "Windows Server 2008 R2"],
        (6, 2, 9200) => &["Windows 8", "Windows Server 2012"],
        (6, 3, 9600) => &["Windows 8.1", "Windows Server 2012 R2"],
        (10, 0, 10240) => &["Windows 10 1507"],
        (10, 0, 10586) => &["Windows 10 1511"],
        (10, 0, 14393) => &["Windows 10 1607", "Windows Server 2016"],
        (10, 0, 17763) => &["Windows 10 1809", "Windows Server 2019"],
        (10, 0, 15063) => &["Windows 10 1703"],
        (10, 0, 16299) => &["Windows 10 1709", "Windows Server 1709"],
        (10, 0, 17134) => &["Windows 10 1803", "Windows Server 1803"],
        (10, 0, 18362) => &["Windows 10 1903", "Windows Server 1903"],
        (10, 0, 18363) => &["Windows 10 1909", "Windows Server 1909"],
        (10, 0, 19041) => &["Windows 10 2004 (or enablement-package successor)"],
        (10, 0, 19045) => &["Windows 10 22H2"],
        (10, 0, 19042) => &["Windows 10 20H2", "Windows Server 20H2"],
        (10, 0, 19043) => &["Windows 10 21H1"],
        (10, 0, 19044) => &["Windows 10 21H2"],
        (10, 0, 20348) => &["Windows Server 2022"],
        (10, 0, 22000) => &["Windows 11 21H2"],
        (10, 0, 22621) => &["Windows 11 22H2 (or enablement-package successor)"],
        (10, 0, 22631) => &["Windows 11 23H2"],
        (10, 0, 26100) => &["Windows 11 24H2", "Windows Server 2025"],
        (10, 0, 26200) => &["Windows 11 25H2"],
        _ => &[],
    }
}

#[cfg(test)]
pub(super) fn fixture() -> Vec<u8> {
    let mut bytes = vec![0; 56];
    bytes[..8].copy_from_slice(b"NTLMSSP\0");
    bytes[8..12].copy_from_slice(&2_u32.to_le_bytes());
    bytes[20..24].copy_from_slice(&0x0280_0001_u32.to_le_bytes());
    bytes[48..56].copy_from_slice(&[10, 0, 0x63, 0x45, 0, 0, 0, 15]);
    let name: Vec<u8> = "OTTER-WIN"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let length = (name.len() + 8) as u16;
    bytes[40..42].copy_from_slice(&length.to_le_bytes());
    bytes[42..44].copy_from_slice(&length.to_le_bytes());
    bytes[44..48].copy_from_slice(&56_u32.to_le_bytes());
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&(name.len() as u16).to_le_bytes());
    bytes.extend(name);
    bytes.extend_from_slice(&[0; 4]);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_build_and_preserves_client_server_ambiguity() {
        let (fields, raw) = challenge(&fixture()).unwrap();
        assert_eq!(fields["name"], "OTTER-WIN");
        assert_eq!(raw["reportedVersion"]["build"], 17763);
        assert_eq!(
            raw["windowsCandidates"],
            json!(["Windows 10 1809", "Windows Server 2019"])
        );
        assert!(!fields.contains_key("firmwareVersion"));
        assert!(candidates(10, 0, 9999).is_empty());
    }

    #[test]
    fn rejects_truncation_offsets_invalid_unicode_and_wrong_message_type() {
        let bytes = fixture();
        for end in 0..bytes.len() {
            assert!(challenge(&bytes[..end]).is_err(), "length {end}");
        }
        for (offset, value) in [(8, 3), (44, 1), (55, 0), (58, 255), (60, 0)] {
            let mut bad = bytes.clone();
            bad[offset] = value;
            assert!(challenge(&bad).is_err(), "offset {offset}");
        }
    }

    #[test]
    fn missing_version_does_not_infer_windows_from_names() {
        let mut bytes = fixture();
        bytes[23] = 0;
        let (fields, raw) = challenge(&bytes).unwrap();
        assert_eq!(fields["name"], "OTTER-WIN");
        assert!(!fields.contains_key("operatingSystem"));
        assert!(raw.get("reportedVersion").is_none());
    }

    #[test]
    fn legacy_type_two_without_optional_target_info_retains_reported_target_only() {
        let mut bytes = vec![0; 32];
        bytes[..8].copy_from_slice(b"NTLMSSP\0");
        bytes[8] = 2;
        bytes[20] = 1;
        let target = b"O\0T\0L\0A\0B\0";
        bytes[12..16].copy_from_slice(&[10, 0, 10, 0]);
        bytes[16] = 32;
        bytes.extend_from_slice(target);
        let (fields, raw) = challenge(&bytes).unwrap();
        assert!(fields.is_empty());
        assert_eq!(raw["targetName"], "OTLAB");
        for end in 0..bytes.len() {
            assert!(challenge(&bytes[..end]).is_err());
        }
    }

    #[test]
    fn rejects_conflicting_names_overlaps_and_invalid_text() {
        let bytes = fixture();
        for (offset, value) in [(22, 0), (40, 255), (42, 1), (61, 0xd8)] {
            let mut bad = bytes.clone();
            bad[offset] = value;
            assert!(challenge(&bad).is_err(), "offset {offset}");
        }
        assert!(unicode(&[1]).is_err());
        let mut duplicate = bytes.clone();
        duplicate.truncate(duplicate.len() - 4);
        duplicate.extend_from_slice(&bytes[56..]);
        let length = (duplicate.len() - 56) as u16;
        duplicate[40..44].copy_from_slice(&[
            length as u8,
            (length >> 8) as u8,
            length as u8,
            (length >> 8) as u8,
        ]);
        assert!(challenge(&duplicate).is_err());
        let mut overlap = bytes;
        overlap[12..16].copy_from_slice(&[2, 0, 2, 0]);
        overlap[16..20].copy_from_slice(&60_u32.to_le_bytes());
        assert!(challenge(&overlap).is_err());
    }

    #[test]
    fn preserves_names_and_does_not_claim_an_os_for_zero_builds() {
        let mut bytes = fixture();
        bytes[50..52].fill(0);
        let (fields, raw) = challenge(&bytes).unwrap();
        assert!(!fields.contains_key("operatingSystem"));
        assert_eq!(raw["reportedVersion"]["build"], 0);
        assert_eq!(raw["challengeHex"], crate::contract::hex(&bytes));
        for (major, minor, build) in [
            (5, 1, 2600),
            (5, 2, 3790),
            (6, 0, 6002),
            (6, 1, 7601),
            (6, 2, 9200),
            (6, 3, 9600),
            (10, 0, 10240),
            (10, 0, 10586),
            (10, 0, 15063),
            (10, 0, 16299),
            (10, 0, 17134),
            (10, 0, 14393),
            (10, 0, 18362),
            (10, 0, 18363),
            (10, 0, 19041),
            (10, 0, 19042),
            (10, 0, 19043),
            (10, 0, 19044),
            (10, 0, 19045),
            (10, 0, 20348),
            (10, 0, 22000),
            (10, 0, 22621),
            (10, 0, 22631),
            (10, 0, 26100),
            (10, 0, 26200),
        ] {
            assert!(!candidates(major, minor, build).is_empty());
        }
    }

    #[test]
    fn recognizes_target_info_names_and_ignores_unknown_attributes() {
        let pairs = [
            (1_u16, "netbiosComputerName"),
            (2, "netbiosDomainName"),
            (3, "dnsComputerName"),
            (4, "dnsDomainName"),
            (5, "dnsTreeName"),
        ];
        for (id, key) in pairs {
            let mut bytes = fixture();
            bytes[56..58].copy_from_slice(&id.to_le_bytes());
            let (fields, raw) = challenge(&bytes).unwrap();
            assert_eq!(raw["names"][key], "OTTER-WIN");
            if key == "dnsComputerName" {
                assert_eq!(fields["name"], "OTTER-WIN");
            }
        }

        let mut unknown = fixture();
        unknown[56..58].copy_from_slice(&99_u16.to_le_bytes());
        let (fields, raw) = challenge(&unknown).unwrap();
        assert!(!fields.contains_key("name"));
        assert_eq!(raw["names"], json!({}));
    }

    #[test]
    fn validates_target_info_flags_and_attribute_lengths() {
        let fixture = fixture();

        let mut missing_flag = fixture.clone();
        missing_flag[22] &= !0x80;
        assert!(
            challenge(&missing_flag)
                .unwrap_err()
                .contains("without negotiated flag")
        );

        for (id, length) in [(6_u16, 3_u16), (7, 7), (10, 15)] {
            let mut malformed = fixture.clone();
            malformed[56..58].copy_from_slice(&id.to_le_bytes());
            malformed[58..60].copy_from_slice(&length.to_le_bytes());
            assert!(
                challenge(&malformed)
                    .unwrap_err()
                    .contains("invalid NTLM AV value length")
            );
        }

        let mut invalid_terminator = fixture.clone();
        invalid_terminator.extend_from_slice(&[0xaa, 0xbb]);
        invalid_terminator[40..44].copy_from_slice(&28_u16.to_le_bytes().repeat(2));
        invalid_terminator[80..82].copy_from_slice(&2_u16.to_le_bytes());
        assert!(
            challenge(&invalid_terminator)
                .unwrap_err()
                .contains("invalid NTLM AV terminator")
        );

        let mut missing_terminator = fixture;
        missing_terminator[40..44].copy_from_slice(&22_u16.to_le_bytes().repeat(2));
        assert!(
            challenge(&missing_terminator)
                .unwrap_err()
                .contains("missing NTLM AV terminator")
        );
    }
}
