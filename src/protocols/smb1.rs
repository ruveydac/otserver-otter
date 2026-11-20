//! MS-SMB NT LM 0.12 identity: negotiate, then at most one extended-security Type 1.
use super::{Finding, TIMEOUT, hex, ntlm, port, smb};
use crate::contract::Source;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use tokio::net::TcpStream;

const EXTENDED_SECURITY: u32 = 0x8000_0000;
const PID: u16 = 0x4f54;

fn header(command: u8, mid: u16, unicode: bool) -> Vec<u8> {
    let mut bytes = vec![0; 32];
    bytes[..4].copy_from_slice(b"\xffSMB");
    bytes[4] = command;
    bytes[9] = 0x18;
    let flags: u16 = 0x4800 | if unicode { 0x8000 } else { 0 };
    bytes[10..12].copy_from_slice(&flags.to_le_bytes());
    bytes[26..28].copy_from_slice(&PID.to_le_bytes());
    bytes[30..32].copy_from_slice(&mid.to_le_bytes());
    bytes
}

fn negotiate() -> Vec<u8> {
    let mut bytes = header(0x72, 0, true);
    let dialect = b"\x02NT LM 0.12\0";
    bytes.push(0);
    bytes.extend_from_slice(&(dialect.len() as u16).to_le_bytes());
    bytes.extend_from_slice(dialect);
    bytes
}

fn session_setup(session_key: u32, unicode: bool) -> Vec<u8> {
    let token = smb::negotiate_token();
    let mut bytes = header(0x73, 1, unicode);
    bytes.extend_from_slice(&[12, 0xff, 0, 0, 0]); // WordCount and no AndX command.
    bytes.extend_from_slice(&4096_u16.to_le_bytes());
    bytes.extend_from_slice(&1_u16.to_le_bytes()); // One outstanding operation.
    bytes.extend_from_slice(&1_u16.to_le_bytes()); // Fresh virtual circuit, not VC zero.
    bytes.extend_from_slice(&session_key.to_le_bytes());
    bytes.extend_from_slice(&(token.len() as u16).to_le_bytes());
    bytes.extend_from_slice(&[0; 4]);
    let capabilities = EXTENDED_SECURITY | 0x40 | if unicode { 4 } else { 0 };
    bytes.extend_from_slice(&capabilities.to_le_bytes());
    let mut data = token;
    if unicode && !(59 + data.len()).is_multiple_of(2) {
        data.push(0);
    }
    // Empty client NativeOS/NativeLanMan; no username, password, LM/NT response or Type 3.
    data.extend_from_slice(if unicode { &[0; 4][..] } else { &[0; 2][..] });
    bytes.extend_from_slice(&(data.len() as u16).to_le_bytes());
    bytes.extend(data);
    bytes
}

fn validate_header(bytes: &[u8], command: u8, mid: u16) -> Result<(), String> {
    if bytes.len() < 35
        || bytes.len() > 65536
        || &bytes[..4] != b"\xffSMB"
        || bytes[4] != command
        || bytes[9] & 0x80 == 0
        || bytes[12..14] != [0; 2]
        || ntlm::u16le(bytes, 24)? != 0
        || ntlm::u16le(bytes, 26)? != PID
        || ntlm::u16le(bytes, 30)? != mid
        || (command == 0x72 && ntlm::u16le(bytes, 28)? != 0)
    {
        return Err("mismatched SMB1 response".into());
    }
    Ok(())
}

fn data(bytes: &[u8], words: u8) -> Result<&[u8], String> {
    if bytes.get(32) != Some(&words) {
        return Err("invalid SMB1 word count".into());
    }
    let count = 33 + usize::from(words) * 2;
    let length = usize::from(ntlm::u16le(bytes, count)?);
    if count + 2 + length != bytes.len() {
        return Err("invalid SMB1 byte count".into());
    }
    Ok(&bytes[count + 2..])
}

fn string(bytes: &[u8], cursor: &mut usize, unicode: bool) -> Result<Option<String>, String> {
    let start = *cursor;
    let width = if unicode { 2 } else { 1 };
    loop {
        let word = bytes
            .get(*cursor..*cursor + width)
            .ok_or("unterminated SMB1 string")?;
        *cursor += width;
        if word.iter().all(|byte| *byte == 0) {
            break;
        }
        if *cursor - start > 2048 {
            return Err("oversized SMB1 string".into());
        }
    }
    let text = &bytes[start..*cursor - width];
    if unicode {
        return ntlm::unicode(text).map(Some);
    }
    // OEM codepages aren't negotiated. Retain non-ASCII bytes as raw evidence, not lossy names.
    if !text.is_ascii() {
        return Ok(None);
    }
    if text.iter().any(u8::is_ascii_control) {
        return Err("control character in SMB1 string".into());
    }
    std::str::from_utf8(text)
        .map(|value| Some(value.to_owned()))
        .map_err(|e| e.to_string())
}

fn parse_negotiation(bytes: &[u8], number: u16) -> Result<Option<Finding>, String> {
    validate_header(bytes, 0x72, 0)?;
    let status = ntlm::u32le(bytes, 5)?;
    if status != 0 {
        return Err(format!(
            "SMB1 negotiate was rejected with NTSTATUS 0x{status:08X}."
        ));
    }
    if bytes[32] == 1 && ntlm::u16le(bytes, 33)? == 0xffff {
        data(bytes, 1)?;
        return Ok(None);
    }
    let payload = data(bytes, 17)?;
    if ntlm::u16le(bytes, 33)? != 0 {
        return Err("unoffered SMB1 dialect".into());
    }
    let capabilities = ntlm::u32le(bytes, 52)?;
    let extended = capabilities & EXTENDED_SECURITY != 0;
    let mut raw = json!({"protocol": "smb", "smbVersion": 1, "dialect": "NT LM 0.12",
        "dialectIndex": 0, "securityMode": bytes[35], "capabilities": capabilities,
        "extendedSecurity": extended, "negotiateResponseHex": hex(bytes), "authenticationCompleted": false});
    if extended {
        if ntlm::u16le(bytes, 10)? & 0x0800 == 0 || payload.len() < 16 {
            return Err("invalid SMB1 extended-security negotiation".into());
        }
        raw["serverGuid"] = json!(hex(&payload[..16]));
    } else {
        let mut cursor = usize::from(bytes[66]);
        if !matches!(cursor, 0 | 8) || cursor > payload.len() {
            return Err("invalid SMB1 challenge length".into());
        }
        // NEGOTIATE DomainName is Unicode when CAP_UNICODE is set, without string alignment.
        raw["domainName"] = json!(string(payload, &mut cursor, capabilities & 4 != 0)?);
        raw["legacyIdentityBytesHex"] = json!(hex(payload));
    }
    Ok(Some(Finding {
        source: Source::OsFingerprint,
        fields: BTreeMap::from([("protocols".into(), json!(["smb"]))]),
        raw,
        ports: vec![port(
            "tcp",
            number,
            Source::OsFingerprint,
            json!({"protocol": "smb", "smbVersion": 1, "dialect": "NT LM 0.12"}),
        )],
        warnings: vec![],
    }))
}

fn identity(bytes: &[u8]) -> Result<(BTreeMap<String, Value>, Value), String> {
    validate_header(bytes, 0x73, 1)?;
    if ntlm::u16le(bytes, 10)? & 0x4800 != 0x4800 || ntlm::u32le(bytes, 5)? != 0xc000_0016 {
        return Err("SMB1 did not return an extended-security challenge".into());
    }
    let payload = data(bytes, 4)?;
    if bytes[33..37] != [0xff, 0, 0, 0] || ntlm::u16le(bytes, 37)? != 0 {
        return Err("chained or guest SMB1 session response".into());
    }
    let length = usize::from(ntlm::u16le(bytes, 39)?);
    let token = payload
        .get(..length)
        .ok_or("truncated SMB1 security blob")?;
    let (mut fields, ntlm) = ntlm::challenge(smb::response_token(token)?)?;
    let mut cursor = length;
    let unicode = ntlm::u16le(bytes, 10)? & 0x8000 != 0;
    if cursor < payload.len() && unicode && !(43 + cursor).is_multiple_of(2) {
        if payload[cursor] != 0 {
            return Err("invalid SMB1 string alignment".into());
        }
        cursor += 1;
    }
    let mut strings = BTreeMap::new();
    for key in ["nativeOs", "nativeLanMan", "primaryDomain"] {
        if cursor == payload.len() {
            break;
        }
        strings.insert(key, json!(string(payload, &mut cursor, unicode)?));
    }
    if cursor != payload.len() {
        return Err("unexpected SMB1 session data".into());
    }
    if !fields.contains_key("operatingSystem")
        && let Some(os) = strings.get("nativeOs").and_then(Value::as_str)
        && os.starts_with("Windows ")
    {
        fields.insert("operatingSystem".into(), json!(os));
        fields.insert("osAccuracy".into(), json!(80));
    }
    Ok((
        fields,
        json!({"ntlm": ntlm, "serverStrings": strings, "sessionResponseHex": hex(bytes)}),
    ))
}

pub(super) async fn exchange(target: Ipv4Addr, number: u16) -> Result<Option<Finding>, String> {
    let negotiated = tokio::time::timeout(TIMEOUT, async {
        crate::traffic::wait().await;
        let Ok(mut stream) = TcpStream::connect((target, number)).await else {
            return Ok::<_, String>(None);
        };
        smb::send(&mut stream, &negotiate()).await?;
        let Some(response) = smb::read_frame(&mut stream).await? else {
            return Ok(None);
        };
        Ok(Some((stream, response)))
    })
    .await;
    let (mut stream, response) = match negotiated {
        Ok(result) => match result? {
            Some(value) => value,
            None => return Ok(None),
        },
        Err(_) => return Ok(None),
    };
    let Some(mut finding) = parse_negotiation(&response, number)? else {
        return Ok(None);
    };
    if finding.raw["extendedSecurity"] != true {
        finding.warnings.push("SMB1 lacks extended security; retained negotiation identity without attempting a login".into());
        return Ok(Some(finding));
    }
    let unicode = ntlm::u32le(&response, 52)? & 4 != 0;
    let request = session_setup(ntlm::u32le(&response, 48)?, unicode);
    if request.len() > ntlm::u32le(&response, 40)? as usize {
        finding
            .warnings
            .push("SMB1 identity request exceeds the server's receive limit".into());
        return Ok(Some(finding));
    }
    let result = tokio::time::timeout(TIMEOUT, async {
        smb::send(&mut stream, &request).await?;
        let bytes = smb::read_frame(&mut stream)
            .await?
            .ok_or("SMB1 peer closed before identity")?;
        identity(&bytes)
    })
    .await;
    match result {
        Ok(Ok((fields, raw))) => {
            finding.fields.extend(fields);
            for (key, value) in raw.as_object().into_iter().flatten() {
                finding.raw[key] = value.clone();
            }
        }
        Ok(Err(error)) => finding
            .warnings
            .push(format!("SMB1 identity unavailable: {error}")),
        Err(_) => finding
            .warnings
            .push("SMB1 identity challenge timed out".into()),
    }
    Ok(Some(finding))
}

#[cfg(test)]
pub(super) fn negotiate_fixture(extended: bool) -> Vec<u8> {
    let mut bytes = header(0x72, 0, true);
    bytes[9] |= 0x80;
    bytes.resize(69, 0);
    bytes[32] = 17;
    bytes[35] = 3;
    bytes[36] = 1;
    bytes[40..44].copy_from_slice(&4096_u32.to_le_bytes());
    bytes[48..52].copy_from_slice(&123_u32.to_le_bytes());
    bytes[52..56]
        .copy_from_slice(&(4 | if extended { EXTENDED_SECURITY } else { 0 }).to_le_bytes());
    if extended {
        bytes.extend_from_slice(&[1; 16]);
    } else {
        bytes[66] = 8;
        bytes.extend_from_slice(&[1; 8]);
        bytes.extend("OTLAB\0".encode_utf16().flat_map(u16::to_le_bytes));
    }
    let count = (bytes.len() - 69) as u16;
    bytes[67..69].copy_from_slice(&count.to_le_bytes());
    bytes
}

#[cfg(test)]
pub(super) fn identity_fixture(unicode: bool) -> Vec<u8> {
    identity_fixture_with(&ntlm::fixture(), unicode)
}

#[cfg(test)]
fn identity_fixture_with(challenge: &[u8], unicode: bool) -> Vec<u8> {
    let token = smb::der(
        0xa1,
        &smb::der(0x30, &smb::der(0xa2, &smb::der(4, challenge))),
    );
    let mut bytes = header(0x73, 1, unicode);
    bytes[9] |= 0x80;
    bytes[5..9].copy_from_slice(&0xc000_0016_u32.to_le_bytes());
    bytes.extend_from_slice(&[4, 0xff, 0, 0, 0, 0, 0]);
    bytes.extend_from_slice(&(token.len() as u16).to_le_bytes());
    bytes.extend_from_slice(&[0; 2]);
    bytes.extend(token);
    if unicode && !bytes.len().is_multiple_of(2) {
        bytes.push(0);
    }
    for value in ["Windows 10.0", "Windows LAN Manager"] {
        if unicode {
            bytes.extend(value.encode_utf16().flat_map(u16::to_le_bytes));
            bytes.extend_from_slice(&[0; 2]);
        } else {
            bytes.extend_from_slice(value.as_bytes());
            bytes.push(0);
        }
    }
    let count = (bytes.len() - 43) as u16;
    bytes[41..43].copy_from_slice(&count.to_le_bytes());
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn parses_ntlm_identity_and_both_native_string_encodings() {
        for unicode in [false, true] {
            let (fields, raw) = identity(&identity_fixture(unicode)).unwrap();
            assert_eq!(fields["name"], "OTTER-WIN");
            assert_eq!(raw["ntlm"]["reportedVersion"]["build"], 17763);
            assert_eq!(raw["serverStrings"]["nativeOs"], "Windows 10.0");
            assert_eq!(raw["serverStrings"]["nativeLanMan"], "Windows LAN Manager");
            assert!(!fields.contains_key("firmwareVersion"));
        }
    }

    #[test]
    fn validates_smb1_header_identity_and_size_limits() {
        let valid = negotiate_fixture(true);
        let mut mismatches = Vec::new();
        let mut bytes = valid.clone();
        bytes[..4].copy_from_slice(b"BAD!");
        mismatches.push(bytes);
        let mut bytes = valid.clone();
        bytes[4] = 0x73;
        mismatches.push(bytes);
        let mut bytes = valid.clone();
        bytes[9] &= !0x80;
        mismatches.push(bytes);
        let mut bytes = valid.clone();
        bytes[12] = 1;
        mismatches.push(bytes);
        let mut bytes = valid.clone();
        bytes[24] = 1;
        mismatches.push(bytes);
        let mut bytes = valid.clone();
        bytes[26] = 1;
        mismatches.push(bytes);
        let mut bytes = valid.clone();
        bytes[28] = 1;
        mismatches.push(bytes);
        let mut bytes = valid.clone();
        bytes[30] = 1;
        mismatches.push(bytes);
        for bytes in mismatches {
            assert!(validate_header(&bytes, 0x72, 0).is_err());
        }

        let mut oversized = valid;
        oversized.resize(65_537, 0);
        assert!(validate_header(&oversized, 0x72, 0).is_err());
        assert!(validate_header(&negotiate_fixture(true)[..34], 0x72, 0).is_err());
    }

    #[test]
    fn rejects_oversized_oem_strings() {
        let mut bytes = vec![b'A'; 2049];
        bytes.push(0);
        assert!(
            string(&bytes, &mut 0, false)
                .unwrap_err()
                .contains("oversized")
        );
    }

    #[test]
    fn handles_rejected_and_incomplete_negotiate_variants() {
        let mut rejected = negotiate_fixture(true);
        rejected[5..9].copy_from_slice(&0xc000_0022_u32.to_le_bytes());
        assert!(
            parse_negotiation(&rejected, 445)
                .err()
                .unwrap()
                .contains("rejected")
        );

        let mut no_dialect = header(0x72, 0, true);
        no_dialect[9] |= 0x80;
        no_dialect.extend_from_slice(&[1, 0xff, 0xff, 0, 0]);
        assert!(parse_negotiation(&no_dialect, 445).unwrap().is_none());

        let mut missing_unicode_flag = negotiate_fixture(true);
        missing_unicode_flag[11] &= !0x08;
        assert!(
            parse_negotiation(&missing_unicode_flag, 445)
                .err()
                .unwrap()
                .contains("extended-security")
        );

        let mut short_server_guid = negotiate_fixture(true);
        short_server_guid.truncate(84);
        short_server_guid[67..69].copy_from_slice(&15_u16.to_le_bytes());
        assert!(
            parse_negotiation(&short_server_guid, 445)
                .err()
                .unwrap()
                .contains("extended-security")
        );

        let mut unsupported_challenge_length = negotiate_fixture(false);
        unsupported_challenge_length[66] = 7;
        assert!(
            parse_negotiation(&unsupported_challenge_length, 445)
                .err()
                .unwrap()
                .contains("challenge length")
        );

        let mut challenge_past_payload = negotiate_fixture(false);
        challenge_past_payload.truncate(73);
        challenge_past_payload[66] = 8;
        challenge_past_payload[67..69].copy_from_slice(&4_u16.to_le_bytes());
        assert!(
            parse_negotiation(&challenge_past_payload, 445)
                .err()
                .unwrap()
                .contains("challenge length")
        );
    }

    #[test]
    fn rejects_bad_unicode_alignment_and_unparsed_session_data() {
        let mut misaligned = identity_fixture(true);
        let token_length = usize::from(ntlm::u16le(&misaligned, 39).unwrap());
        let padding = 43 + token_length;
        assert_eq!((43 + token_length) % 2, 1);
        misaligned[padding] = 1;
        assert!(
            identity(&misaligned)
                .unwrap_err()
                .contains("string alignment")
        );

        let mut trailing_data = identity_fixture(true);
        trailing_data.extend([0, 0, b'X']);
        let byte_count = ntlm::u16le(&trailing_data, 41).unwrap() + 3;
        trailing_data[41..43].copy_from_slice(&byte_count.to_le_bytes());
        assert!(
            identity(&trailing_data)
                .unwrap_err()
                .contains("unexpected SMB1 session data")
        );
    }

    #[test]
    fn classic_security_retains_domain_but_never_infers_an_os() {
        let finding = parse_negotiation(&negotiate_fixture(false), 445)
            .unwrap()
            .unwrap();
        assert_eq!(finding.raw["domainName"], "OTLAB");
        assert_eq!(finding.raw["extendedSecurity"], false);
        assert!(!finding.fields.contains_key("operatingSystem"));
        let mut cursor = 0;
        assert_eq!(string(&[0x82, 0], &mut cursor, false).unwrap(), None);
        assert!(string(b"A", &mut 0, false).is_err());
        assert!(string(&[1, 0], &mut 0, false).is_err());
    }

    #[test]
    fn legacy_challenge_can_supply_reported_native_os_without_an_ntlm_version() {
        let mut challenge = vec![0; 32];
        challenge[..8].copy_from_slice(b"NTLMSSP\0");
        challenge[8] = 2;
        challenge[20] = 1;
        let bytes = identity_fixture_with(&challenge, true);
        let (fields, raw) = identity(&bytes).unwrap();
        assert_eq!(fields["operatingSystem"], "Windows 10.0");
        assert!(raw["ntlm"].get("reportedVersion").is_none());
        assert!(!fields.contains_key("name"));
    }

    #[test]
    fn handles_unaligned_and_missing_legacy_server_strings() {
        let mut challenge = vec![0; 32];
        challenge[..8].copy_from_slice(b"NTLMSSP\0");
        challenge[8] = 2;
        challenge[20] = 1;
        challenge.push(0);

        let bytes = identity_fixture_with(&challenge, true);
        let (fields, raw) = identity(&bytes).unwrap();
        assert_eq!(raw["serverStrings"]["nativeOs"], "Windows 10.0");
        assert_eq!(fields["operatingSystem"], "Windows 10.0");

        let mut without_strings = bytes;
        let token_length = usize::from(ntlm::u16le(&without_strings, 39).unwrap());
        without_strings.truncate(43 + token_length);
        without_strings[41..43].copy_from_slice(&(token_length as u16).to_le_bytes());
        let (fields, raw) = identity(&without_strings).unwrap();
        assert!(raw["serverStrings"].as_object().unwrap().is_empty());
        assert!(!fields.contains_key("operatingSystem"));
    }

    #[test]
    fn does_not_infer_os_from_non_windows_native_os() {
        let mut challenge = vec![0; 32];
        challenge[..8].copy_from_slice(b"NTLMSSP\0");
        challenge[8] = 2;
        challenge[20] = 1;
        challenge.push(0);
        let mut bytes = identity_fixture_with(&challenge, true);
        let windows: Vec<u8> = "Windows 10.0"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let start = bytes
            .windows(windows.len())
            .position(|value| value == windows.as_slice())
            .unwrap();
        bytes[start] = b'L';

        let (fields, raw) = identity(&bytes).unwrap();
        assert_eq!(raw["serverStrings"]["nativeOs"], "Lindows 10.0");
        assert!(!fields.contains_key("operatingSystem"));
    }

    #[test]
    fn builds_session_setup_without_unicode() {
        let request = session_setup(123, false);
        assert_eq!(ntlm::u16le(&request, 10).unwrap() & 0x8000, 0);
        assert_eq!(ntlm::u32le(&request, 53).unwrap(), 0x8000_0040);
    }

    #[test]
    fn rejects_truncation_bad_counts_unsolicited_and_chained_responses() {
        let negotiation = negotiate_fixture(true);
        for end in 0..negotiation.len() {
            assert!(parse_negotiation(&negotiation[..end], 445).is_err());
        }
        for (offset, value) in [
            (4, 0x73),
            (9, 0),
            (24, 1),
            (26, 0),
            (28, 1),
            (30, 1),
            (32, 16),
            (33, 1),
            (67, 15),
        ] {
            let mut bytes = negotiation.clone();
            bytes[offset] = value;
            assert!(parse_negotiation(&bytes, 445).is_err(), "offset {offset}");
        }
        let session = identity_fixture(true);
        for end in 0..session.len() {
            assert!(identity(&session[..end]).is_err());
        }
        for (offset, value) in [
            (5, 0),
            (11, 0),
            (30, 0),
            (32, 3),
            (33, 0x75),
            (35, 1),
            (37, 1),
            (39, 255),
            (41, 0),
        ] {
            let mut bytes = session.clone();
            bytes[offset] = value;
            assert!(identity(&bytes).is_err(), "offset {offset}");
        }
    }

    async fn request(stream: &mut TcpStream) -> Vec<u8> {
        let length = stream.read_u32().await.unwrap();
        assert!(length <= 512);
        let mut bytes = vec![0; length as usize];
        stream.read_exact(&mut bytes).await.unwrap();
        bytes
    }

    #[tokio::test]
    async fn only_extended_security_sends_a_type_one_and_never_authenticates() {
        for extended in [false, true] {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let number = listener.local_addr().unwrap().port();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                assert_eq!(request(&mut stream).await, negotiate());
                smb::send(&mut stream, &negotiate_fixture(extended))
                    .await
                    .unwrap();
                if extended {
                    let bytes = request(&mut stream).await;
                    assert_eq!(bytes, session_setup(123, true));
                    assert!(
                        bytes
                            .windows(12)
                            .any(|bytes| bytes == b"NTLMSSP\0\x01\0\0\0")
                    );
                    let response = identity_fixture(true);
                    stream
                        .write_all(&(response.len() as u32).to_be_bytes())
                        .await
                        .unwrap();
                    for chunk in response.chunks(7) {
                        stream.write_all(chunk).await.unwrap();
                    }
                }
                assert_eq!(
                    stream.read(&mut [0; 1]).await.unwrap(),
                    0,
                    "no classic/anonymous login, Type 3, or tree request"
                );
            });
            let finding = exchange(Ipv4Addr::LOCALHOST, number)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(finding.raw["smbVersion"], 1);
            assert_eq!(finding.fields.contains_key("operatingSystem"), extended);
            assert_eq!(finding.raw["authenticationCompleted"], false);
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn reports_connection_refusal_without_attempting_smb1_authentication() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let number = listener.local_addr().unwrap().port();
        drop(listener);
        assert!(
            exchange(Ipv4Addr::LOCALHOST, number)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn returns_none_when_peer_closes_or_does_not_offer_a_dialect() {
        for no_dialect in [false, true] {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let number = listener.local_addr().unwrap().port();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                request(&mut stream).await;
                if no_dialect {
                    let mut response = header(0x72, 0, true);
                    response[9] |= 0x80;
                    response.extend_from_slice(&[1, 0xff, 0xff, 0, 0]);
                    smb::send(&mut stream, &response).await.unwrap();
                }
            });

            assert!(
                exchange(Ipv4Addr::LOCALHOST, number)
                    .await
                    .unwrap()
                    .is_none()
            );
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn retains_negotiation_when_identity_request_exceeds_server_receive_limit() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let number = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            request(&mut stream).await;
            let mut reply = negotiate_fixture(true);
            reply[40..44].copy_from_slice(&1_u32.to_le_bytes());
            smb::send(&mut stream, &reply).await.unwrap();
            assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
        });

        let finding = exchange(Ipv4Addr::LOCALHOST, number)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(finding.raw["smbVersion"], 1);
        assert!(finding.warnings[0].contains("exceeds the server's receive limit"));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn retains_negotiation_when_identity_is_denied_or_times_out() {
        for timeout in [false, true] {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let number = listener.local_addr().unwrap().port();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                request(&mut stream).await;
                smb::send(&mut stream, &negotiate_fixture(true))
                    .await
                    .unwrap();
                request(&mut stream).await;
                if !timeout {
                    let mut bytes = header(0x73, 1, true);
                    bytes[9] |= 0x80;
                    bytes[5..9].copy_from_slice(&0xc000_0022_u32.to_le_bytes());
                    bytes.extend_from_slice(&[0; 3]);
                    smb::send(&mut stream, &bytes).await.unwrap();
                }
                assert_eq!(
                    tokio::time::timeout(TIMEOUT * 2, stream.read(&mut [0; 1]))
                        .await
                        .unwrap()
                        .unwrap(),
                    0
                );
            });
            let finding = exchange(Ipv4Addr::LOCALHOST, number)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(finding.warnings.len(), 1);
            assert!(!finding.fields.contains_key("operatingSystem"));
            assert_eq!(finding.raw["smbVersion"], 1);
            server.await.unwrap();
        }
    }
}
