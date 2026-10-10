//! One EPM bind with NTLM Type 1. No AUTH3, endpoint walk, DCOM activation, or WMI calls.
use super::{Finding, TIMEOUT, hex, ntlm, port};
use crate::contract::Source;
use serde_json::json;
use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const EPM: [u8; 20] = [
    8, 0x83, 0xaf, 0xe1, 0x1f, 0x5d, 0xc9, 0x11, 0x91, 0xa4, 8, 0, 0x2b, 0x14, 0xa0, 0xfa, 3, 0, 0,
    0,
];
const NDR: [u8; 20] = [
    4, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 8, 0, 0x2b, 0x10, 0x48, 0x60, 2, 0, 0,
    0,
];

fn bind() -> Vec<u8> {
    let token = ntlm::negotiate();
    let mut bytes = vec![5, 0, 11, 3, 0x10, 0, 0, 0];
    bytes.extend_from_slice(&((80 + token.len()) as u16).to_le_bytes());
    bytes.extend_from_slice(&(token.len() as u16).to_le_bytes());
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&[0xb8, 0x10, 0xb8, 0x10, 0, 0, 0, 0]);
    bytes.extend_from_slice(&[1, 0, 0, 0, 0, 0, 1, 0]);
    bytes.extend_from_slice(&EPM);
    bytes.extend_from_slice(&NDR);
    // RPC_C_AUTHN_WINNT, RPC_C_AUTHN_LEVEL_CONNECT, no padding, context ID zero.
    bytes.extend_from_slice(&[10, 2, 0, 0, 0, 0, 0, 0]);
    bytes.extend(token);
    bytes
}

pub(super) async fn probe(target: Ipv4Addr) -> Result<Option<Finding>, String> {
    match tokio::time::timeout(TIMEOUT, exchange(target, 135)).await {
        Ok(result) => result.map_err(|error| format!("RPC {target}: {error}")),
        Err(_) => Ok(None),
    }
}

async fn exchange(target: Ipv4Addr, number: u16) -> Result<Option<Finding>, String> {
    crate::traffic::wait().await;
    let Ok(mut stream) = TcpStream::connect((target, number)).await else {
        return Ok(None);
    };
    crate::traffic::wait().await;
    stream.write_all(&bind()).await.map_err(|e| e.to_string())?;
    let mut header = [0; 16];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|e| e.to_string())?;
    let length = usize::from(ntlm::u16le(&header, 8)?);
    if !(16..=16384).contains(&length) {
        return Err("invalid RPC fragment length".into());
    }
    let mut bytes = vec![0; length];
    bytes[..16].copy_from_slice(&header);
    stream
        .read_exact(&mut bytes[16..])
        .await
        .map_err(|e| e.to_string())?;
    parse(&bytes, number)
}

fn parse(bytes: &[u8], number: u16) -> Result<Option<Finding>, String> {
    if bytes.len() < 16
        || bytes.len() > 16384
        || bytes[..2] != [5, 0]
        || bytes[3] & 3 != 3
        || bytes[3] & !0x13 != 0
        || bytes[4..8] != [0x10, 0, 0, 0]
        || usize::from(ntlm::u16le(bytes, 8)?) != bytes.len()
        || ntlm::u32le(bytes, 12)? != 1
    {
        return Err("mismatched or fragmented RPC bind response".into());
    }
    if bytes[2] == 13 {
        if bytes.len() < 19 {
            return Err("truncated RPC bind rejection".into());
        }
        return Ok(None);
    }
    if bytes[2] != 12 {
        return Err("unsolicited RPC PDU".into());
    }
    let auth_length = usize::from(ntlm::u16le(bytes, 10)?);
    let (body_end, token) = if auth_length == 0 {
        (bytes.len(), None)
    } else {
        let trailer = bytes
            .len()
            .checked_sub(auth_length + 8)
            .ok_or("truncated RPC auth trailer")?;
        let auth = bytes
            .get(trailer..trailer + 8)
            .ok_or("truncated RPC auth trailer")?;
        if auth[0..2] != [10, 2] || auth[3..8] != [0; 5] || auth[2] > 3 || trailer % 4 != 0 {
            return Err("mismatched RPC authentication context".into());
        }
        let end = trailer
            .checked_sub(usize::from(auth[2]))
            .ok_or("invalid RPC auth padding")?;
        (end, Some(&bytes[trailer + 8..]))
    };
    let body = bytes.get(..body_end).ok_or("truncated RPC bind body")?;
    let address_len = usize::from(ntlm::u16le(body, 24)?);
    let address = body
        .get(26..26 + address_len)
        .ok_or("truncated RPC secondary address")?;
    if !address.is_empty() && address.last() != Some(&0) {
        return Err("invalid RPC secondary address".into());
    }
    let results = (26 + address_len + 3) & !3;
    let result = body
        .get(results..results + 28)
        .ok_or("truncated RPC bind result")?;
    if results + 28 != body.len() || result[..4] != [1, 0, 0, 0] {
        return Err("invalid RPC context result count".into());
    }
    if ntlm::u16le(result, 4)? != 0 {
        return Ok(None);
    }
    if ntlm::u16le(result, 6)? != 0 || result[8..28] != NDR {
        return Err("unoffered RPC transfer syntax".into());
    }
    let mut finding = Finding {
        source: Source::OsFingerprint,
        fields: BTreeMap::from([("protocols".into(), json!(["rpc"]))]),
        raw: json!({"protocol": "rpc", "interface": "e1af8308-5d1f-11c9-91a4-08002b14a0fa", "interfaceVersion": 3, "bindResponseHex": hex(bytes), "authenticationCompleted": false}),
        ports: vec![port(
            "tcp",
            number,
            Source::OsFingerprint,
            json!({"protocol": "rpc"}),
        )],
        warnings: vec![],
    };
    if let Some(token) = token {
        let (fields, raw) = ntlm::challenge(token)?;
        finding.fields.extend(fields);
        finding.raw["ntlm"] = raw;
    }
    Ok(Some(finding))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    fn reply() -> Vec<u8> {
        let token = ntlm::fixture();
        let mut bytes = vec![5, 0, 12, 3, 0x10, 0, 0, 0, 0, 0];
        bytes.extend_from_slice(&(token.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&[0xb8, 0x10, 0xb8, 0x10, 1, 0, 0, 0, 4, 0]);
        bytes.extend_from_slice(b"135\0");
        bytes.extend_from_slice(&[0; 2]);
        bytes.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0]);
        bytes.extend_from_slice(&NDR);
        bytes.extend_from_slice(&[10, 2, 0, 0, 0, 0, 0, 0]);
        bytes.extend(token);
        let length = bytes.len() as u16;
        bytes[8..10].copy_from_slice(&length.to_le_bytes());
        bytes
    }

    #[test]
    fn rejects_truncated_unsolicited_and_mismatched_bind_responses() {
        let bytes = reply();
        assert_eq!(
            parse(&bytes, 135).unwrap().unwrap().fields["name"],
            "OTTER-WIN"
        );
        for end in 0..bytes.len() {
            assert!(parse(&bytes[..end], 135).is_err());
        }
        for (offset, value) in [
            (2, 2),
            (3, 1),
            (4, 0),
            (12, 2),
            (24, 255),
            (32, 2),
            (40, 0),
            (60, 9),
            (61, 5),
            (62, 4),
            (64, 1),
        ] {
            let mut bad = bytes.clone();
            bad[offset] = value;
            assert!(parse(&bad, 135).is_err(), "offset {offset}");
        }
    }

    #[tokio::test]
    async fn reads_split_tcp_response_and_stops_before_auth3() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let number = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0; bind().len()];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(request, bind());
            for chunk in reply().chunks(7) {
                stream.write_all(chunk).await.unwrap();
            }
            assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
        });
        let finding = exchange(Ipv4Addr::LOCALHOST, number)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(finding.raw["ntlm"]["reportedVersion"]["build"], 17763);
        assert_eq!(finding.raw["authenticationCompleted"], false);
        server.await.unwrap();
    }

    #[test]
    fn records_service_without_a_version_and_handles_bind_rejections() {
        let mut bytes = reply();
        bytes.truncate(60);
        bytes[8..12].copy_from_slice(&[60, 0, 0, 0]);
        let finding = parse(&bytes, 135).unwrap().unwrap();
        assert!(!finding.fields.contains_key("operatingSystem"));
        assert!(finding.raw.get("ntlm").is_none());
        bytes[36] = 2; // Provider rejected the single presentation context.
        assert!(parse(&bytes, 135).unwrap().is_none());
        bytes.truncate(19);
        bytes[2] = 13;
        bytes[8] = 19;
        bytes[16..19].copy_from_slice(&[2, 0, 0]);
        assert!(parse(&bytes, 135).unwrap().is_none());
    }
}
