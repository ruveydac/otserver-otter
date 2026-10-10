//! SMB2 first, with one SMB1 fallback on negotiation rejection/connection close. No login.
use super::{Finding, TIMEOUT, hex, ntlm, port};
use crate::contract::Source;
use serde_json::json;
use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const DIALECTS: [u16; 4] = [0x0202, 0x0210, 0x0300, 0x0302];

pub(super) async fn probe(target: Ipv4Addr) -> Result<Option<Finding>, String> {
    exchange(target, 445)
        .await
        .map_err(|error| format!("SMB {target}: {error}"))
}

fn header(command: u16, id: u64) -> Vec<u8> {
    let mut bytes = vec![0; 64];
    bytes[..4].copy_from_slice(b"\xfeSMB");
    bytes[4..6].copy_from_slice(&64_u16.to_le_bytes());
    bytes[12..14].copy_from_slice(&command.to_le_bytes());
    bytes[14..16].copy_from_slice(&1_u16.to_le_bytes());
    bytes[24..32].copy_from_slice(&id.to_le_bytes());
    bytes
}

fn negotiate() -> Vec<u8> {
    let mut bytes = header(0, 0);
    bytes.extend_from_slice(&36_u16.to_le_bytes());
    bytes.extend_from_slice(&(DIALECTS.len() as u16).to_le_bytes());
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&[0; 6]);
    bytes.extend_from_slice(uuid::Uuid::new_v4().as_bytes());
    bytes.extend_from_slice(&[0; 8]);
    for dialect in DIALECTS {
        bytes.extend_from_slice(&dialect.to_le_bytes());
    }
    bytes
}

pub(super) fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut bytes = vec![tag];
    if content.len() < 128 {
        bytes.push(content.len() as u8);
    } else {
        bytes.extend_from_slice(&[0x82, (content.len() >> 8) as u8, content.len() as u8]);
    }
    bytes.extend_from_slice(content);
    bytes
}

pub(super) fn negotiate_token() -> Vec<u8> {
    // SPNEGO NegTokenInit, NTLM mechanism OID, and Type 1 token (MS-SPNG/MS-NTLM).
    let mechanism = der(
        0xa0,
        &der(0x30, &der(6, &[0x2b, 6, 1, 4, 1, 0x82, 0x37, 2, 2, 10])),
    );
    let mut init = mechanism;
    init.extend(der(0xa2, &der(4, &ntlm::negotiate())));
    let mut gss = der(6, &[0x2b, 6, 1, 5, 5, 2]);
    gss.extend(der(0xa0, &der(0x30, &init)));
    der(0x60, &gss)
}

fn session_setup() -> Vec<u8> {
    let token = negotiate_token();
    let mut bytes = header(1, 1);
    bytes.extend_from_slice(&[25, 0, 0, 1]);
    bytes.extend_from_slice(&[0; 8]);
    bytes.extend_from_slice(&88_u16.to_le_bytes());
    bytes.extend_from_slice(&(token.len() as u16).to_le_bytes());
    bytes.extend_from_slice(&[0; 8]);
    bytes.extend(token);
    bytes
}

pub(super) async fn send(stream: &mut TcpStream, bytes: &[u8]) -> Result<(), String> {
    crate::traffic::wait().await;
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .await
        .map_err(|e| e.to_string())?;
    stream.write_all(bytes).await.map_err(|e| e.to_string())
}

async fn receive(stream: &mut TcpStream, command: u16, id: u64) -> Result<Vec<u8>, String> {
    let bytes = read_frame(stream)
        .await?
        .ok_or("SMB peer closed before response")?;
    validate_header(&bytes, command, id)?;
    Ok(bytes)
}

// Only a close/reset before any frame bytes permits legacy negotiation. Partial frames are errors.
pub(super) async fn read_frame(stream: &mut TcpStream) -> Result<Option<Vec<u8>>, String> {
    let mut length = [0; 4];
    match stream.read_exact(&mut length[..1]).await {
        Ok(_) => {}
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
            ) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error.to_string()),
    }
    stream
        .read_exact(&mut length[1..])
        .await
        .map_err(|e| e.to_string())?;
    let length = u32::from_be_bytes(length) as usize;
    if !(32..=65536).contains(&length) {
        return Err("invalid SMB frame length".into());
    }
    let mut bytes = vec![0; length];
    stream
        .read_exact(&mut bytes)
        .await
        .map_err(|e| e.to_string())?;
    Ok(Some(bytes))
}

fn validate_header(bytes: &[u8], command: u16, id: u64) -> Result<(), String> {
    if bytes.len() < 64
        || &bytes[..4] != b"\xfeSMB"
        || ntlm::u16le(bytes, 4)? != 64
        || ntlm::u16le(bytes, 12)? != command
        || ntlm::u32le(bytes, 16)? & 3 != 1
        || ntlm::u32le(bytes, 20)? != 0
        || bytes[24..32] != id.to_le_bytes()
    {
        return Err("mismatched or compound SMB response".into());
    }
    Ok(())
}

// Decode the NegTokenResp responseToken explicitly, never search arbitrary payloads for NTLM.
pub(super) fn response_token(bytes: &[u8]) -> Result<&[u8], String> {
    fn tlv(bytes: &[u8]) -> Result<(u8, &[u8], &[u8]), String> {
        let tag = *bytes.first().ok_or("truncated SPNEGO tag")?;
        let first = *bytes.get(1).ok_or("truncated SPNEGO length")?;
        let (length, start) = match first {
            0..=127 => (usize::from(first), 2),
            0x81 => (
                usize::from(*bytes.get(2).ok_or("truncated SPNEGO length")?),
                3,
            ),
            0x82 => (
                usize::from(u16::from_be_bytes([
                    *bytes.get(2).ok_or("truncated SPNEGO length")?,
                    *bytes.get(3).ok_or("truncated SPNEGO length")?,
                ])),
                4,
            ),
            _ => return Err("unsupported SPNEGO length".into()),
        };
        let content = bytes
            .get(start..start + length)
            .ok_or("truncated SPNEGO content")?;
        Ok((tag, content, &bytes[start + length..]))
    }
    let (tag, content, rest) = tlv(bytes)?;
    if tag != 0xa1 || !rest.is_empty() {
        return Err("invalid SPNEGO response".into());
    }
    let (tag, mut sequence, rest) = tlv(content)?;
    if tag != 0x30 || !rest.is_empty() {
        return Err("invalid SPNEGO sequence".into());
    }
    let mut token = None;
    let mut seen = 0_u8;
    while !sequence.is_empty() {
        let (tag, content, rest) = tlv(sequence)?;
        if !(0xa0..=0xa3).contains(&tag) || seen & (1 << (tag - 0xa0)) != 0 {
            return Err("invalid or repeated SPNEGO field".into());
        }
        seen |= 1 << (tag - 0xa0);
        if tag == 0xa2 {
            let (tag, value, rest) = tlv(content)?;
            if tag != 4 || !rest.is_empty() || token.replace(value).is_some() {
                return Err("invalid SPNEGO response token".into());
            }
        } else {
            let (inner_tag, value, rest) = tlv(content)?;
            if !rest.is_empty()
                || match tag {
                    0xa0 => inner_tag != 10 || value.len() != 1 || value[0] > 3 || value[0] == 2,
                    0xa1 => inner_tag != 6 || value != [0x2b, 6, 1, 4, 1, 0x82, 0x37, 2, 2, 10],
                    0xa3 => inner_tag != 4,
                    _ => true,
                }
            {
                return Err("mismatched SPNEGO mechanism or state".into());
            }
        }
        sequence = rest;
    }
    token.ok_or_else(|| "missing SPNEGO response token".into())
}

fn session_identity(
    bytes: &[u8],
) -> Result<(BTreeMap<String, serde_json::Value>, serde_json::Value), String> {
    validate_header(bytes, 1, 1)?;
    if ntlm::u32le(bytes, 8)? != 0xc000_0016 || ntlm::u16le(bytes, 64)? != 9 {
        return Err("SMB did not return an authentication challenge".into());
    }
    let offset = usize::from(ntlm::u16le(bytes, 68)?);
    let length = usize::from(ntlm::u16le(bytes, 70)?);
    if offset < 72 {
        return Err("SMB security buffer overlaps header".into());
    }
    let token = bytes
        .get(offset..offset + length)
        .ok_or("truncated SMB security buffer")?;
    ntlm::challenge(response_token(token)?)
}

enum Negotiation {
    Absent,
    Closed,
    Response(TcpStream, Vec<u8>),
}

pub(super) async fn exchange(target: Ipv4Addr, number: u16) -> Result<Option<Finding>, String> {
    let negotiated = tokio::time::timeout(TIMEOUT, async {
        crate::traffic::wait().await;
        let Ok(mut stream) = TcpStream::connect((target, number)).await else {
            return Ok::<_, String>(Negotiation::Absent);
        };
        send(&mut stream, &negotiate()).await?;
        let Some(response) = read_frame(&mut stream).await? else {
            return Ok(Negotiation::Closed);
        };
        validate_header(&response, 0, 0)?;
        Ok(Negotiation::Response(stream, response))
    })
    .await;
    let (mut stream, response) = match negotiated {
        Ok(result) => match result? {
            Negotiation::Response(stream, response) => (stream, response),
            Negotiation::Closed => return super::smb1::exchange(target, number).await,
            Negotiation::Absent => return Ok(None),
        },
        Err(_) => return Ok(None),
    };
    if ntlm::u32le(&response, 8)? == 0xc000_00bb {
        drop(stream);
        return super::smb1::exchange(target, number).await;
    }
    if ntlm::u32le(&response, 8)? != 0 {
        return Ok(None);
    }
    if response.len() < 128 || ntlm::u16le(&response, 64)? != 65 {
        return Err("invalid SMB negotiate response".into());
    }
    let dialect = ntlm::u16le(&response, 68)?;
    if !DIALECTS.contains(&dialect) {
        return Err("unoffered SMB dialect".into());
    }
    let security_offset = usize::from(ntlm::u16le(&response, 120)?);
    let security_length = usize::from(ntlm::u16le(&response, 122)?);
    if security_length != 0
        && (security_offset < 128
            || response
                .get(security_offset..security_offset + security_length)
                .is_none())
    {
        return Err("invalid SMB negotiate security buffer".into());
    }
    let mut finding = Finding {
        source: Source::OsFingerprint,
        fields: BTreeMap::from([("protocols".into(), json!(["smb"]))]),
        raw: json!({"protocol": "smb", "dialect": dialect, "securityMode": ntlm::u16le(&response, 66)?, "serverGuid": hex(&response[72..88]), "negotiateResponseHex": hex(&response), "authenticationCompleted": false}),
        ports: vec![port(
            "tcp",
            number,
            Source::OsFingerprint,
            json!({"protocol": "smb", "dialect": dialect}),
        )],
        warnings: vec![],
    };
    // Keep validated SMB service evidence if NTLM is disabled, refused, or times out.
    let identity = tokio::time::timeout(TIMEOUT, async {
        send(&mut stream, &session_setup()).await?;
        let response = receive(&mut stream, 1, 1).await?;
        session_identity(&response)
    })
    .await;
    match identity {
        Ok(Ok((fields, raw))) => {
            finding.fields.extend(fields);
            finding.raw["ntlm"] = raw;
        }
        Ok(Err(error)) => finding
            .warnings
            .push(format!("SMB identity unavailable: {error}")),
        Err(_) => finding
            .warnings
            .push("SMB identity challenge timed out".into()),
    }
    Ok(Some(finding))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    fn response(command: u16, id: u64) -> Vec<u8> {
        let mut bytes = header(command, id);
        bytes[16] = 1;
        bytes
    }

    #[test]
    fn parses_only_correlated_challenges_and_rejects_truncation() {
        let token = der(0xa1, &der(0x30, &der(0xa2, &der(4, &ntlm::fixture()))));
        let mut bytes = response(1, 1);
        bytes[8..12].copy_from_slice(&0xc000_0016_u32.to_le_bytes());
        bytes.extend_from_slice(&[9, 0, 0, 0, 72, 0]);
        bytes.extend_from_slice(&(token.len() as u16).to_le_bytes());
        bytes.extend(token);
        assert_eq!(session_identity(&bytes).unwrap().0["name"], "OTTER-WIN");
        for end in 0..bytes.len() {
            assert!(session_identity(&bytes[..end]).is_err());
        }
        bytes[24] = 2;
        assert!(session_identity(&bytes).is_err());
        assert!(response_token(b"NTLMSSP\0").is_err());
        assert!(response_token(&[0xa1, 0x80]).is_err());
    }

    #[tokio::test]
    async fn negotiates_without_authenticating_and_retains_service_on_denial() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let number = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut length = [0; 4];
            stream.read_exact(&mut length).await.unwrap();
            let mut request = vec![0; u32::from_be_bytes(length) as usize];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request[100..], &[2, 2, 16, 2, 0, 3, 2, 3]);
            let mut reply = response(0, 0);
            reply.resize(128, 0);
            reply[64] = 65;
            reply[68..70].copy_from_slice(&0x0302_u16.to_le_bytes());
            send(&mut stream, &reply).await.unwrap();
            stream.read_exact(&mut length).await.unwrap();
            request.resize(u32::from_be_bytes(length) as usize, 0);
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request[12..14], &[1, 0]);
            assert!(request.windows(12).any(|v| v == b"NTLMSSP\0\x01\0\0\0"));
            let mut reply = response(1, 1);
            reply[8..12].copy_from_slice(&0xc000_0022_u32.to_le_bytes());
            send(&mut stream, &reply).await.unwrap();
            assert_eq!(
                stream.read(&mut [0; 1]).await.unwrap(),
                0,
                "no AUTHENTICATE follows"
            );
        });
        let finding = exchange(Ipv4Addr::LOCALHOST, number)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(finding.raw["dialect"], 0x0302);
        assert_eq!(finding.warnings.len(), 1);
        assert!(!finding.fields.contains_key("operatingSystem"));
        server.await.unwrap();
    }

    #[test]
    fn rejects_spnego_mechanism_conflicts_and_duplicate_tokens() {
        let token = der(0xa2, &der(4, &ntlm::fixture()));
        for extra in [
            der(0xa0, &der(10, &[2])),
            der(0xa1, &der(6, &[1])),
            der(0xa3, &der(6, &[1])),
            der(0xa4, &[]),
            token.clone(),
        ] {
            let mut content = extra;
            content.extend_from_slice(&token);
            assert!(response_token(&der(0xa1, &der(0x30, &content))).is_err());
        }
        assert!(response_token(&der(0xa1, &der(0x30, &[]))).is_err());
        assert!(response_token(&der(0xa1, &der(0x31, &token))).is_err());
        let mut content = der(0xa0, &der(10, &[1]));
        content.extend(der(
            0xa1,
            &der(6, &[0x2b, 6, 1, 4, 1, 0x82, 0x37, 2, 2, 10]),
        ));
        content.extend(token);
        assert_eq!(
            response_token(&der(0xa1, &der(0x30, &content))).unwrap(),
            ntlm::fixture()
        );
    }

    async fn request(stream: &mut TcpStream) -> Vec<u8> {
        let length = stream.read_u32().await.unwrap();
        assert!(length <= 512);
        let mut bytes = vec![0; length as usize];
        stream.read_exact(&mut bytes).await.unwrap();
        bytes
    }

    #[tokio::test]
    async fn collects_windows_identity_and_keeps_negotiation_on_challenge_timeout() {
        for timeout in [false, true] {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let number = listener.local_addr().unwrap().port();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                assert_eq!(&request(&mut stream).await[12..14], &[0, 0]);
                let mut reply = response(0, 0);
                reply.resize(128, 0);
                reply[64] = 65;
                reply[68..70].copy_from_slice(&0x0210_u16.to_le_bytes());
                send(&mut stream, &reply).await.unwrap();
                assert_eq!(&request(&mut stream).await[12..14], &[1, 0]);
                if !timeout {
                    let token = der(0xa1, &der(0x30, &der(0xa2, &der(4, &ntlm::fixture()))));
                    let mut reply = response(1, 1);
                    reply[8..12].copy_from_slice(&0xc000_0016_u32.to_le_bytes());
                    reply.extend_from_slice(&[9, 0, 0, 0, 72, 0]);
                    reply.extend_from_slice(&(token.len() as u16).to_le_bytes());
                    reply.extend(token);
                    send(&mut stream, &reply).await.unwrap();
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
            assert_eq!(finding.fields.contains_key("operatingSystem"), !timeout);
            if timeout {
                assert_eq!(finding.warnings, ["SMB identity challenge timed out"]);
            } else {
                assert_eq!(finding.raw["ntlm"]["reportedVersion"]["build"], 17763);
                assert!(finding.warnings.is_empty());
            }
            assert_eq!(finding.raw["authenticationCompleted"], false);
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn rejects_oversized_frames_and_unoffered_dialects_before_session_setup() {
        for oversized in [false, true] {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let number = listener.local_addr().unwrap().port();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                request(&mut stream).await;
                if oversized {
                    stream.write_all(&65537_u32.to_be_bytes()).await.unwrap();
                } else {
                    let mut reply = response(0, 0);
                    reply.resize(128, 0);
                    reply[64] = 65;
                    reply[68..70].copy_from_slice(&0x0311_u16.to_le_bytes());
                    send(&mut stream, &reply).await.unwrap();
                }
                assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
            });
            assert!(exchange(Ipv4Addr::LOCALHOST, number).await.is_err());
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn legacy_fallback_reconnects_once_on_close_or_explicit_rejection() {
        for rejection in [false, true] {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let number = listener.local_addr().unwrap().port();
            let server = tokio::spawn(async move {
                let (mut modern, _) = listener.accept().await.unwrap();
                assert_eq!(&request(&mut modern).await[..4], b"\xfeSMB");
                if rejection {
                    let mut bytes = response(0, 0);
                    bytes[8..12].copy_from_slice(&0xc000_00bb_u32.to_le_bytes());
                    send(&mut modern, &bytes).await.unwrap();
                    assert_eq!(modern.read(&mut [0; 1]).await.unwrap(), 0);
                }
                drop(modern);
                let (mut legacy, _) = listener.accept().await.unwrap();
                let bytes = request(&mut legacy).await;
                assert_eq!(&bytes[..5], b"\xffSMBr");
                assert_eq!(&bytes[35..], b"\x02NT LM 0.12\0");
                send(&mut legacy, &super::super::smb1::negotiate_fixture(true))
                    .await
                    .unwrap();
                let bytes = request(&mut legacy).await;
                assert_eq!(bytes[4], 0x73);
                assert!(
                    bytes
                        .windows(12)
                        .any(|bytes| bytes == b"NTLMSSP\0\x01\0\0\0")
                );
                send(&mut legacy, &super::super::smb1::identity_fixture(true))
                    .await
                    .unwrap();
                assert_eq!(legacy.read(&mut [0; 1]).await.unwrap(), 0);
                assert!(
                    tokio::time::timeout(std::time::Duration::from_millis(50), listener.accept())
                        .await
                        .is_err()
                );
            });
            let finding = exchange(Ipv4Addr::LOCALHOST, number)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(finding.raw["smbVersion"], 1);
            assert_eq!(finding.fields["name"], "OTTER-WIN");
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn truncated_modern_response_does_not_trigger_legacy_fallback() {
        for partial in [vec![0, 0], vec![0, 0, 0, 64, 0xfe]] {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let number = listener.local_addr().unwrap().port();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                request(&mut stream).await;
                stream.write_all(&partial).await.unwrap();
                drop(stream);
                assert!(
                    tokio::time::timeout(std::time::Duration::from_millis(50), listener.accept())
                        .await
                        .is_err()
                );
            });
            assert!(exchange(Ipv4Addr::LOCALHOST, number).await.is_err());
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn timed_out_modern_negotiation_does_not_trigger_legacy_fallback() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let number = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            request(&mut stream).await;
            assert_eq!(
                tokio::time::timeout(TIMEOUT * 2, stream.read(&mut [0; 1]))
                    .await
                    .unwrap()
                    .unwrap(),
                0
            );
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(50), listener.accept())
                    .await
                    .is_err()
            );
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
