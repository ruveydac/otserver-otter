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
    if ntlm::u32le(bytes, 5)? != 0 {
        return Ok(None);
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
