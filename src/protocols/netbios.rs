use super::{Finding, TIMEOUT, hex, port, text};
use crate::contract::{Source, format_mac};
use serde_json::json;
use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr};
use tokio::net::UdpSocket;
use tokio::time::timeout;

const PORT: u16 = 137;
const MAX_RESPONSE: usize = 576;
// RFC 1002: first-level encoding of '*' followed by fifteen NUL bytes, no scope.
const WILDCARD: &[u8; 34] = b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\0";

pub async fn probe(target: Ipv4Addr) -> Result<Option<Finding>, String> {
    probe_at(SocketAddr::from((target, PORT)))
        .await
        .map_err(|error| format!("NetBIOS {target}: {error}"))
}

async fn probe_at(address: SocketAddr) -> Result<Option<Finding>, String> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .map_err(|error| error.to_string())?;
    // A connected UDP socket accepts replies only from the queried IP and port.
    socket
        .connect(address)
        .await
        .map_err(|error| error.to_string())?;
    let id = uuid::Uuid::new_v4();
    let transaction = [id.as_bytes()[0], id.as_bytes()[1]];
    crate::traffic::wait().await;
    socket
        .send(&request(transaction))
        .await
        .map_err(|error| error.to_string())?;
    // The extra byte detects oversized datagrams even when recv truncates them.
    let mut response = [0; MAX_RESPONSE + 1];
    match timeout(TIMEOUT, socket.recv(&mut response)).await {
        Ok(Ok(length)) => parse(&response[..length], transaction).map(Some),
        Ok(Err(error))
            if matches!(
                error.kind(),
                ErrorKind::ConnectionRefused | ErrorKind::ConnectionReset
            ) =>
        {
            Ok(None)
        }
        Ok(Err(error)) => Err(error.to_string()),
        Err(_) => Ok(None),
    }
}

fn request(transaction: [u8; 2]) -> [u8; 50] {
    let mut request = [0; 50];
    request[..2].copy_from_slice(&transaction);
    request[5] = 1;
    request[12..46].copy_from_slice(WILDCARD);
    request[46..].copy_from_slice(&[0, 0x21, 0, 1]); // NBSTAT, IN
    request
}

// Only the unscoped wildcard we queried is a solicited response name. Follow
// compression pointers with a bounded walk, comparing labels as they expand.
fn name_end(response: &[u8], start: usize) -> Result<usize, String> {
    let mut cursor = start;
    let mut end = None;
    let mut matched = 0;
    for _ in 0..16 {
        let length = *response.get(cursor).ok_or("truncated NetBIOS name")? as usize;
        if length & 0xc0 == 0xc0 {
            let low = *response.get(cursor + 1).ok_or("truncated name pointer")?;
            let offset = ((length & 0x3f) << 8) | usize::from(low);
            if offset < 12 || offset >= cursor {
                return Err("invalid NetBIOS name pointer".into());
            }
            end.get_or_insert(cursor + 2);
            cursor = offset;
            continue;
        }
        let label = WILDCARD
            .get(matched..matched + 1 + length)
            .ok_or("invalid NetBIOS name length")?;
        if response.get(cursor..cursor + 1 + length) != Some(label) {
            return Err("mismatched NetBIOS response name".into());
        }
        cursor += 1 + length;
        matched += 1 + length;
        if length == 0 {
            return Ok(end.unwrap_or(cursor));
        }
    }
    Err("too many NetBIOS name pointers".into())
}

fn parse(response: &[u8], transaction: [u8; 2]) -> Result<Finding, String> {
    if response.len() < 12
        || response.len() > MAX_RESPONSE
        || response[..2] != transaction
        || response[2..4] != [0x84, 0] // authoritative, successful, untruncated query response
        || response[4] != 0
        || response[5] > 1
        || response[6..12] != [0, 1, 0, 0, 0, 0]
    {
        return Err("invalid Node Status response header".into());
    }
    let mut cursor = 12;
    if response[5] == 1 {
        cursor = name_end(response, cursor)?;
        if response.get(cursor..cursor + 4) != Some(&[0, 0x21, 0, 1]) {
            return Err("invalid Node Status question".into());
        }
        cursor += 4;
    }
    cursor = name_end(response, cursor)?;
    let header = response
        .get(cursor..cursor + 10)
        .ok_or("truncated Node Status record")?;
    if header[..8] != [0, 0x21, 0, 1, 0, 0, 0, 0] {
        return Err("invalid Node Status record type, class, or TTL".into());
    }
    let length = usize::from(u16::from_be_bytes([header[8], header[9]]));
    let data = &response[cursor + 10..];
    if data.len() != length || data.is_empty() || data.len() != 1 + usize::from(data[0]) * 18 + 46 {
        return Err("invalid Node Status name table or statistics length".into());
    }
    let table_end = 1 + usize::from(data[0]) * 18;
    let mut names = Vec::new();
    let mut workstation = None;
    let mut server = None;
    let mut workgroup = None;
    for entry in data[1..table_end].as_chunks::<18>().0 {
        let name = text(&entry[..15]).filter(|name| !name.chars().any(char::is_control));
        let suffix = entry[15];
        let flags = u16::from_be_bytes([entry[16], entry[17]]);
        let group = flags & 0x8000 != 0;
        // Prefer an active workstation name; server names are the fallback.
        // Conflicting or deregistering entries remain evidence only.
        if flags & 0x1c00 == 0x0400 {
            match (group, suffix) {
                (false, 0x00) if workstation.is_none() => workstation = name.clone(),
                (false, 0x20) if server.is_none() => server = name.clone(),
                (true, 0x00) if workgroup.is_none() => workgroup = name.clone(),
                _ => {}
            }
        }
        names.push(json!({ "name": name, "suffix": suffix, "flags": flags, "group": group }));
    }
    let mut fields = BTreeMap::from([("protocols".into(), json!(["netbios"]))]);
    if let Some(name) = workstation.or(server) {
        fields.insert("name".into(), json!(name));
    }
    Ok(Finding {
        source: Source::Netbios,
        fields,
        raw: json!({
            "names": names,
            "workgroup": workgroup,
            // UNIT_ID can be zero or refer to a different adapter. Never use it
            // to override the shared ARP/DCP identity or resolve a routed target.
            "unitId": format_mac(&data[table_end..table_end + 6]),
            "response": hex(response),
        }),
        ports: vec![port(
            "udp",
            PORT,
            Source::Netbios,
            json!({ "state": "open" }),
        )],
        warnings: vec![],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(entries: &[(&str, u8, u16)]) -> Vec<u8> {
        let mut response = vec![0x12, 0x34, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        response.extend(WILDCARD);
        response.extend([0, 0x21, 0, 1, 0, 0, 0, 0]);
        response.extend(((1 + entries.len() * 18 + 46) as u16).to_be_bytes());
        response.push(entries.len() as u8);
        for (name, suffix, flags) in entries {
            response.extend(format!("{name:<15}").as_bytes());
            response.push(*suffix);
            response.extend(flags.to_be_bytes());
        }
        response.extend([0; 46]);
        response
    }

    #[test]
    fn builds_unicast_wildcard_node_status_query() {
        let query = request([0x12, 0x34]);
        assert_eq!(&query[..12], &[0x12, 0x34, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        let decoded: Vec<u8> = query[13..45]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| ((pair[0] - b'A') << 4) | (pair[1] - b'A'))
            .collect();
        assert_eq!(decoded, b"*\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
        assert_eq!(&query[45..], &[0, 0, 0x21, 0, 1]);
    }

    #[test]
    fn extracts_workstation_and_preserves_name_table_and_zero_unit_id() {
        let bytes = response(&[
            ("OTLAB", 0, 0x8400),
            ("FILESERVER", 0x20, 0x0400),
            ("ENGINEERING", 0, 0x0400),
            ("OPERATOR", 3, 0x0400),
        ]);
        let finding = parse(&bytes, [0x12, 0x34]).unwrap();
        assert_eq!(finding.fields["name"], "ENGINEERING");
        assert_eq!(finding.fields["protocols"], json!(["netbios"]));
        assert!(!finding.fields.contains_key("macAddress"));
        assert_eq!(finding.raw["workgroup"], "OTLAB");
        assert_eq!(finding.raw["unitId"], "00:00:00:00:00:00");
        assert_eq!(finding.raw["names"].as_array().unwrap().len(), 4);
        assert_eq!(finding.raw["names"][1]["suffix"], 0x20);
        assert_eq!(finding.raw["response"], hex(&bytes));
        assert_eq!(finding.ports[0].key, "udp:137");
    }

    #[test]
    fn ignores_unusable_names_and_falls_back_to_server() {
        let bytes = response(&[
            ("INACTIVE", 0, 0),
            ("CONFLICT", 0, 0x0c00),
            ("DELETING", 0, 0x1400),
            ("BAD\nNAME", 0, 0x0400),
            ("", 0, 0x0400),
            ("SERVER", 0x20, 0x0400),
        ]);
        assert_eq!(
            parse(&bytes, [0x12, 0x34]).unwrap().fields["name"],
            "SERVER"
        );
        assert!(
            !parse(&response(&[]), [0x12, 0x34])
                .unwrap()
                .fields
                .contains_key("name")
        );
    }

    #[test]
    fn accepts_echoed_question_and_compressed_answer_name() {
        let bytes = response(&[("PLC", 0, 0x0400)]);
        let mut compressed = bytes[..12].to_vec();
        compressed[5] = 1;
        compressed.extend(&request([0x12, 0x34])[12..]);
        compressed.extend([0xc0, 12]);
        compressed.extend(&bytes[46..]);
        assert_eq!(
            parse(&compressed, [0x12, 0x34]).unwrap().fields["name"],
            "PLC"
        );
        compressed[47] = 0x20;
        assert!(parse(&compressed, [0x12, 0x34]).is_err());
    }

    #[test]
    fn rejects_truncation_mismatches_and_oversized_responses() {
        let bytes = response(&[("PLC", 0, 0x0400)]);
        for length in 0..bytes.len() {
            assert!(
                parse(&bytes[..length], [0x12, 0x34]).is_err(),
                "length {length}"
            );
        }
        for offset in [0, 2, 3, 4, 5, 6, 7, 8, 10, 12, 13, 45, 47, 49, 51, 55, 56] {
            let mut invalid = bytes.clone();
            invalid[offset] ^= 2;
            assert!(parse(&invalid, [0x12, 0x34]).is_err(), "offset {offset}");
        }
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(parse(&extra, [0x12, 0x34]).is_err());
        extra.resize(MAX_RESPONSE + 1, 0);
        assert!(parse(&extra, [0x12, 0x34]).is_err());
    }

    #[test]
    fn bounds_compression_pointer_walks() {
        for pointer in [[0xc0, 12], [0xff, 0xff], [0xc0, 0]] {
            let mut bytes = response(&[]);
            bytes[12..14].copy_from_slice(&pointer);
            assert!(parse(&bytes, [0x12, 0x34]).is_err());
        }
        assert!(name_end(&[0xc0], 0).is_err());
        let mut bytes = vec![0; 12];
        bytes.extend(WILDCARD);
        let mut previous = 12;
        for _ in 0..16 {
            let next = bytes.len();
            bytes.extend([0xc0, previous as u8]);
            previous = next;
        }
        assert!(name_end(&bytes, previous).is_err());
    }

    #[tokio::test]
    async fn queries_udp_peer_and_rejects_wrong_transaction() {
        for mismatched in [false, true] {
            let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let address = socket.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let mut query = [0; 51];
                let (length, peer) = socket.recv_from(&mut query).await.unwrap();
                assert_eq!(length, 50);
                assert_eq!(query[..50], request([query[0], query[1]]));
                let mut reply = response(&[("PLC", 0, 0x0400)]);
                reply[..2].copy_from_slice(&query[..2]);
                if mismatched {
                    reply[0] ^= 1;
                }
                socket.send_to(&reply, peer).await.unwrap();
            });
            let result = probe_at(address).await;
            if mismatched {
                assert!(result.is_err());
            } else {
                assert_eq!(result.unwrap().unwrap().fields["name"], "PLC");
            }
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn ignores_other_udp_senders_and_times_out_without_retry() {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = socket.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut query = [0; 50];
            let (_, peer) = socket.recv_from(&mut query).await.unwrap();
            let other = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let mut reply = response(&[]);
            reply[..2].copy_from_slice(&query[..2]);
            other.send_to(&reply, peer).await.unwrap();
            assert!(
                timeout(TIMEOUT + TIMEOUT, socket.recv_from(&mut query))
                    .await
                    .is_err()
            );
        });
        assert!(probe_at(address).await.unwrap().is_none());
        server.await.unwrap();
    }
}
