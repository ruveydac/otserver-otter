use super::{Finding, TIMEOUT, hex, port, text};
use crate::contract::Source;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

const LIST_IDENTITY: [u8; 24] = [
    0x63, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xc1, 0xde, 0xbe, 0xd1, 0, 0, 0, 0,
];

pub async fn probe(target: Ipv4Addr) -> Result<Option<Finding>, String> {
    let mut request = LIST_IDENTITY;
    request[12..20].copy_from_slice(&uuid::Uuid::new_v4().as_bytes()[..8]);
    let (tcp, udp) = tokio::join!(tcp(target, &request), udp(target, &request));
    let mut responses = Vec::new();
    let mut ports = Vec::new();
    let mut warnings = Vec::new();
    for (protocol, result) in [("tcp", tcp), ("udp", udp)] {
        match result {
            Ok(Some(response)) => {
                match parse(&response, &request[12..20]) {
                    Ok((fields, raw)) => responses.push((protocol, fields, raw)),
                    Err(error) => {
                        warnings.push(format!("EtherNet/IP {target} {protocol}: {error}"))
                    }
                }
                ports.push(port(
                    protocol,
                    44818,
                    Source::EthernetIp,
                    json!({ "state": "open" }),
                ));
            }
            Ok(None) => {}
            Err(error) => warnings.push(format!("EtherNet/IP {target} {protocol}: {error}")),
        }
    }
    let Some((_, fields, mut raw)) = responses.first().cloned() else {
        if let Some(error) = warnings.into_iter().next() {
            return Err(error);
        }
        return Ok(None);
    };
    if let Value::Object(raw) = &mut raw {
        raw.insert(
            "fieldSources".into(),
            json!({
                "model": {"command": "0x0063", "itemType": "0x000C", "field": "productName"},
                "vendor": {"command": "0x0063", "field": "vendorId", "derivation": "vendor-lookup"},
                "serialNumber": {"command": "0x0063", "field": "serialNumber"},
                "firmwareVersion": {"command": "0x0063", "field": "revision"}
            }),
        );
        if responses
            .iter()
            .any(|(transport, _, _)| *transport == "tcp")
        {
            match cip_reads(target).await {
                Ok(records) => {
                    if let Some(identity) = records.first().and_then(|record| record.get("value")) {
                        for key in [
                            "vendorId",
                            "deviceType",
                            "productCode",
                            "revisionMajor",
                            "revisionMinor",
                            "serialNumber",
                        ] {
                            if identity.get(key).is_some_and(|value| {
                                !value.is_null() && raw.get(key) != Some(value)
                            }) {
                                warnings.push(format!(
                                    "EtherNet/IP CIP Identity differs from ListIdentity for {key}"
                                ));
                            }
                        }
                    }
                    raw.insert("cipReads".into(), json!(records));
                }
                Err(error) => warnings.push(format!("EtherNet/IP CIP {target}: {error}")),
            }
        }
        let scope = serial_scope(raw.get("deviceType").and_then(Value::as_u64).unwrap_or(0));
        raw.insert(
            "transportResponses".into(),
            responses
                .into_iter()
                .map(|(transport, _, identity)| {
                    json!({
                        "transport": transport,
                        "identity": identity,
                    })
                })
                .collect(),
        );
        raw.insert(
            "serialClaim".into(),
            json!({
                "scope": scope,
                "issuer": fields.get("vendor"),
                "manufacturerId": raw.get("vendorId"),
                "original": fields.get("serialNumber"),
                "encoding": "cip-uint32-hex",
                "catalogNumber": raw.get("productCode").and_then(Value::as_u64).map(|code| code.to_string()),
                "normalizationVersion": 1,
            }),
        );
    }
    Ok(Some(Finding {
        source: Source::EthernetIp,
        fields,
        raw,
        ports,
        warnings,
    }))
}

fn serial_scope(device_type: u64) -> &'static str {
    match device_type {
        12 => "adapter",
        14 => "cpu",
        _ => "device",
    }
}

async fn tcp(target: Ipv4Addr, request: &[u8]) -> Result<Option<Vec<u8>>, String> {
    let address = SocketAddr::new(IpAddr::V4(target), 44818);
    crate::traffic::wait().await;
    let mut stream = match timeout(TIMEOUT, TcpStream::connect(address)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) if error.kind() == ErrorKind::ConnectionRefused => return Ok(None),
        Ok(Err(error)) => return Err(error.to_string()),
        Err(_) => return Ok(None),
    };
    crate::traffic::wait().await;
    timeout(TIMEOUT, stream.write_all(request))
        .await
        .map_err(|_| "write timed out".to_string())?
        .map_err(|error| error.to_string())?;
    let mut header = [0; 24];
    timeout(TIMEOUT, stream.read_exact(&mut header))
        .await
        .map_err(|_| "response timed out".to_string())?
        .map_err(|error| error.to_string())?;
    let length = u16::from_le_bytes([header[2], header[3]]) as usize;
    if length > 65_511 {
        return Err("oversized response".into());
    }
    let mut response = vec![0; 24 + length];
    response[..24].copy_from_slice(&header);
    timeout(TIMEOUT, stream.read_exact(&mut response[24..]))
        .await
        .map_err(|_| "response timed out".to_string())?
        .map_err(|error| error.to_string())?;
    Ok(Some(response))
}

async fn udp(target: Ipv4Addr, request: &[u8]) -> Result<Option<Vec<u8>>, String> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .map_err(|error| error.to_string())?;
    socket
        .connect((target, 44818))
        .await
        .map_err(|error| error.to_string())?;
    crate::traffic::wait().await;
    socket
        .send(request)
        .await
        .map_err(|error| error.to_string())?;
    let mut response = vec![0; 65_535];
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    let mut rejected = false;
    for _ in 0..32 {
        match tokio::time::timeout_at(deadline, socket.recv(&mut response)).await {
            Ok(Ok(length)) => {
                if parse(&response[..length], &request[12..20]).is_ok() {
                    return Ok(Some(response[..length].to_vec()));
                }
                rejected = true;
            }
            Ok(Err(error)) if error.kind() == ErrorKind::ConnectionRefused => return Ok(None),
            Ok(Err(error)) => return Err(error.to_string()),
            Err(_) => {
                return if rejected {
                    Err("malformed or uncorrelated ListIdentity response".into())
                } else {
                    Ok(None)
                };
            }
        }
    }
    Err("too many uncorrelated ListIdentity responses".into())
}

fn parse(response: &[u8], context: &[u8]) -> Result<(BTreeMap<String, Value>, Value), String> {
    if response.len() < 26
        || u16::from_le_bytes([response[0], response[1]]) != 0x63
        || 24 + u16::from_le_bytes([response[2], response[3]]) as usize != response.len()
        || response[8..12] != [0; 4]
        || response[20..24] != [0; 4]
        || &response[12..20] != context
        || response[4..8] != [0; 4]
    {
        return Err("invalid List Identity response".into());
    }
    let count = u16::from_le_bytes([response[24], response[25]]) as usize;
    let mut cursor = 26;
    let mut identity = None;
    for _ in 0..count {
        let header = response
            .get(cursor..cursor + 4)
            .ok_or("truncated CPF item")?;
        let item_type = u16::from_le_bytes([header[0], header[1]]);
        let length = u16::from_le_bytes([header[2], header[3]]) as usize;
        cursor += 4;
        let payload = response
            .get(cursor..cursor + length)
            .ok_or("truncated CPF item")?;
        if item_type == 0x000c {
            if identity.is_some() {
                return Err("ambiguous List Identity items".into());
            }
            identity = Some(payload);
        }
        cursor += length;
    }
    if cursor != response.len() {
        return Err("invalid CPF item count".into());
    }
    let identity = identity.ok_or("List Identity item is missing")?;
    if identity.len() < 34 || identity[2..4] != [0, 2] || identity[..2] != [1, 0] {
        return Err("invalid List Identity item".into());
    }
    let device_ip = Ipv4Addr::new(identity[6], identity[7], identity[8], identity[9]);
    let vendor_id = u16::from_le_bytes([identity[18], identity[19]]);
    let device_type = u16::from_le_bytes([identity[20], identity[21]]);
    let product_code = u16::from_le_bytes([identity[22], identity[23]]);
    let revision = format!("{}.{}", identity[24], identity[25]);
    let status = u16::from_le_bytes([identity[26], identity[27]]);
    let serial = u32::from_le_bytes(identity[28..32].try_into().unwrap());
    let name_length = identity[32] as usize;
    if 34 + name_length != identity.len() {
        return Err("truncated product name".into());
    }
    let product_name = text(&identity[33..33 + name_length]);
    let state = identity[33 + name_length];
    let mut fields = BTreeMap::from([
        ("firmwareVersion".into(), json!(revision)),
        ("protocols".into(), json!(["ethernet-ip"])),
        ("serialNumber".into(), json!(format!("{serial:08X}"))),
    ]);
    if let Some(name) = &product_name {
        fields.insert("model".into(), json!(name));
        fields.insert("name".into(), json!(name));
    }
    if let Some(vendor) = vendor(vendor_id) {
        fields.insert("vendor".into(), json!(vendor));
    }
    let raw = json!({
        "deviceIp": device_ip,
        "deviceType": device_type,
        "productCode": product_code,
        "productName": product_name,
        "response": hex(response),
        "revision": revision,
        "revisionMajor": identity[24],
        "revisionMinor": identity[25],
        "protocolVersion": 1,
        "serialNumber": format!("{serial:08X}"),
        "state": state,
        "status": status,
        "vendorId": vendor_id,
    });
    Ok((fields, raw))
}

async fn encapsulation(
    stream: &mut TcpStream,
    command: u16,
    session: u32,
    body: &[u8],
    context: [u8; 8],
) -> Result<Vec<u8>, String> {
    let mut request = Vec::new();
    request.extend(command.to_le_bytes());
    request.extend((body.len() as u16).to_le_bytes());
    request.extend(session.to_le_bytes());
    request.extend([0; 4]);
    request.extend(context);
    request.extend([0; 4]);
    request.extend(body);
    crate::traffic::wait().await;
    timeout(TIMEOUT, stream.write_all(&request))
        .await
        .map_err(|_| "CIP write timeout")?
        .map_err(|error| error.to_string())?;
    let mut header = [0; 24];
    timeout(TIMEOUT, stream.read_exact(&mut header))
        .await
        .map_err(|_| "CIP header timeout")?
        .map_err(|error| error.to_string())?;
    let length = u16::from_le_bytes([header[2], header[3]]) as usize;
    if header[..2] != command.to_le_bytes()
        || header[8..12] != [0; 4]
        || header[12..20] != context
        || header[20..] != [0; 4]
        || (session != 0 && header[4..8] != session.to_le_bytes())
        || length > 4096
    {
        return Err("mismatched/oversized CIP encapsulation response".into());
    }
    let mut result = header.to_vec();
    result.resize(24 + length, 0);
    timeout(TIMEOUT, stream.read_exact(&mut result[24..]))
        .await
        .map_err(|_| "CIP body timeout")?
        .map_err(|error| error.to_string())?;
    Ok(result)
}

async fn cip_reads(target: Ipv4Addr) -> Result<Vec<Value>, String> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(8);
    crate::traffic::wait().await;
    let mut stream = timeout(TIMEOUT, TcpStream::connect((target, 44818)))
        .await
        .map_err(|_| "CIP connect timeout")?
        .map_err(|error| error.to_string())?;
    let mut context = [0; 8];
    context.copy_from_slice(&uuid::Uuid::new_v4().as_bytes()[..8]);
    let register = tokio::time::timeout_at(
        deadline,
        encapsulation(&mut stream, 0x65, 0, &[1, 0, 0, 0], context),
    )
    .await
    .map_err(|_| "CIP exchange timed out")??;
    if register.get(24..) != Some(&[1, 0, 0, 0][..]) {
        return Err("invalid RegisterSession response".into());
    }
    let session = u32::from_le_bytes(register[4..8].try_into().map_err(|_| "invalid session")?);
    if session == 0 {
        return Err("zero CIP session".into());
    }
    let mut records = Vec::new();
    for (class, attribute, service) in [
        (1_u8, None, 1_u8),
        (0xf5, Some(5_u8), 0x0e),
        (0xf5, Some(6), 0x0e),
    ] {
        let mut cip = vec![
            service,
            if attribute.is_some() { 3 } else { 2 },
            0x20,
            class,
            0x24,
            1,
        ];
        if let Some(attribute) = attribute {
            cip.extend([0x30, attribute]);
        }
        let mut body = vec![0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0xb2, 0];
        body.extend((cip.len() as u16).to_le_bytes());
        body.extend(cip);
        context[0] = context[0].wrapping_add(1);
        let response = match tokio::time::timeout_at(
            deadline,
            encapsulation(&mut stream, 0x6f, session, &body, context),
        )
        .await
        {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => {
                records.push(json!({"class": class, "attribute": attribute, "outcome": "read-error", "detail": error}));
                break;
            }
            Err(_) => {
                records.push(json!({"class":class, "attribute":attribute,"outcome":"timeout"}));
                break;
            }
        };
        match cip_payload(&response, service) {
            Ok((status, value)) => {
                let decoded = if status == 0 {
                    decode_cip(class, attribute, value)
                } else {
                    None
                };
                let outcome = match status {
                    0 if decoded.is_some() => "success",
                    0 => "malformed",
                    0x08 | 0x05 | 0x14 => "unsupported",
                    0x0f => "access-denied",
                    _ => "protocol-error",
                };
                records.push(json!({"class":class,"instance":1,"attribute":attribute,"service":service,"status":status,"outcome":outcome,"value":decoded,"response":hex(&response)}));
            }
            Err(error) => {
                records.push(json!({"class": class, "attribute": attribute, "outcome": "malformed", "detail": error}));
                break;
            }
        }
    }
    Ok(records)
}

fn cip_payload(response: &[u8], service: u8) -> Result<(u8, &[u8]), String> {
    let body = response.get(24..).ok_or("missing CPF")?;
    if body.len() < 16 || body[..6] != [0; 6] || body[6..14] != [2, 0, 0, 0, 0, 0, 0xb2, 0] {
        return Err("invalid CIP CPF".into());
    }
    let size = u16::from_le_bytes([body[14], body[15]]) as usize;
    let cip = &body[16..];
    if cip.len() != size || cip.len() < 4 || cip[0] != service | 0x80 || cip[1] != 0 {
        return Err("invalid CIP response".into());
    }
    let offset = 4 + usize::from(cip[3]) * 2;
    Ok((cip[2], cip.get(offset..).ok_or("truncated CIP status")?))
}

fn decode_cip(class: u8, attribute: Option<u8>, value: &[u8]) -> Option<Value> {
    match (class, attribute) {
        (1, None) if value.len() >= 15 => {
            let name_len = value[14] as usize;
            let name = value.get(15..15 + name_len)?;
            Some(
                json!({"vendorId": u16::from_le_bytes([value[0], value[1]]), "deviceType": u16::from_le_bytes([value[2], value[3]]), "productCode": u16::from_le_bytes([value[4], value[5]]), "revisionMajor": value[6], "revisionMinor": value[7], "serialNumber": format!("{:08X}", u32::from_le_bytes(value[10..14].try_into().ok()?)), "productName": text(name), "raw": hex(value)}),
            )
        }
        (0xf5, Some(5)) if value.len() >= 22 => {
            let domain_length = u16::from_le_bytes([value[20], value[21]]) as usize;
            let domain = value.get(22..22 + domain_length)?;
            Some(
                json!({"ipAddress": Ipv4Addr::from(u32::from_le_bytes(value[..4].try_into().ok()?)), "networkMask": Ipv4Addr::from(u32::from_le_bytes(value[4..8].try_into().ok()?)), "gateway": Ipv4Addr::from(u32::from_le_bytes(value[8..12].try_into().ok()?)), "primaryNameServer":Ipv4Addr::from(u32::from_le_bytes(value[12..16].try_into().ok()?)), "secondaryNameServer":Ipv4Addr::from(u32::from_le_bytes(value[16..20].try_into().ok()?)), "domainName":text(domain), "raw": hex(value)}),
            )
        }
        (0xf5, Some(6)) if value.len() >= 2 => {
            let length = u16::from_le_bytes([value[0], value[1]]) as usize;
            Some(json!({"hostname": text(value.get(2..2+length)?), "raw": hex(value)}))
        }
        _ => None,
    }
}

fn vendor(id: u16) -> Option<&'static str> {
    match id {
        1 => Some("Rockwell Automation/Allen-Bradley"),
        47 => Some("Omron Corporation"),
        108 => Some("Beckhoff Automation GmbH"),
        145 => Some("Siemens"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    fn identity_response() -> Vec<u8> {
        let mut response = vec![0; 68];
        response[0] = 0x63;
        response[12..20].copy_from_slice(&LIST_IDENTITY[12..20]);
        response[2..4].copy_from_slice(&44_u16.to_le_bytes());
        response[24..26].copy_from_slice(&1_u16.to_le_bytes());
        response[26..28].copy_from_slice(&0x000c_u16.to_le_bytes());
        response[28..30].copy_from_slice(&38_u16.to_le_bytes());
        response[30] = 1;
        response[32..34].copy_from_slice(&2_u16.to_be_bytes());
        response[36..40].copy_from_slice(&[192, 0, 2, 1]);
        response[48..50].copy_from_slice(&1_u16.to_le_bytes());
        response[50..52].copy_from_slice(&12_u16.to_le_bytes());
        response[52..54].copy_from_slice(&158_u16.to_le_bytes());
        response[54..56].copy_from_slice(&[3, 7]);
        response[58..62].copy_from_slice(&42_u32.to_le_bytes());
        response[62] = 4;
        response[63..67].copy_from_slice(b"PLC1");
        response
    }

    #[test]
    fn parses_list_identity() {
        let mut response = identity_response();
        let (fields, raw) = parse(&response, &LIST_IDENTITY[12..20]).unwrap();
        assert_eq!(fields["model"], "PLC1");
        assert_eq!(fields["vendor"], "Rockwell Automation/Allen-Bradley");
        assert_eq!(raw["deviceIp"], "192.0.2.1");
        response[2..4].copy_from_slice(&48_u16.to_le_bytes());
        response[24..26].copy_from_slice(&2_u16.to_le_bytes());
        response.extend([0x34, 0x12, 0, 0]);
        assert!(parse(&response, &LIST_IDENTITY[12..20]).is_ok());
        response[8] = 1;
        assert!(parse(&response, &LIST_IDENTITY[12..20]).is_err());
    }

    #[test]
    fn scopes_serial_claim_to_the_reported_device_type() {
        for (device_type, expected_scope) in [(12, "adapter"), (14, "cpu"), (2, "device")] {
            assert_eq!(serial_scope(device_type), expected_scope);
        }
    }

    #[test]
    fn rejects_wrong_context_and_ambiguous_identity_items() {
        let mut response = identity_response();
        response[12] ^= 1;
        assert!(parse(&response, &LIST_IDENTITY[12..20]).is_err());
        response = identity_response();
        let item = response[26..].to_vec();
        response.extend(item);
        let length = (response.len() - 24) as u16;
        response[2..4].copy_from_slice(&length.to_le_bytes());
        response[24] = 2;
        assert!(
            parse(&response, &LIST_IDENTITY[12..20])
                .unwrap_err()
                .contains("ambiguous")
        );
    }

    #[test]
    fn cip_rejects_bad_cpf_service_status_lengths_and_truncated_attributes() {
        let mut response = vec![0; 24];
        response.extend([
            0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0xb2, 0, 4, 0, 0x8e, 0, 0, 0,
        ]);
        assert_eq!(cip_payload(&response, 0x0e).unwrap(), (0, &[][..]));
        for end in 0..response.len() {
            assert!(cip_payload(&response[..end], 0x0e).is_err());
        }
        assert!(cip_payload(&response, 1).is_err());
        response[43] = 1;
        assert!(cip_payload(&response, 0x0e).is_err());
        assert!(decode_cip(1, None, &[0; 14]).is_none());
        let mut identity = vec![0; 15];
        identity[14] = 9;
        assert!(decode_cip(1, None, &identity).is_none());
        assert!(decode_cip(0xf5, Some(6), &[9, 0, b'A']).is_none());
        let mut config = vec![0; 22];
        config[20] = 1;
        assert!(decode_cip(0xf5, Some(5), &config).is_none());
    }

    #[tokio::test]
    async fn cip_extension_sends_only_three_allowlisted_reads() {
        let _network = crate::network_test_lock().await;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 44818))
            .await
            .unwrap();
        let responder = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            for index in 0..4 {
                let mut header = [0; 24];
                stream.read_exact(&mut header).await.unwrap();
                let mut body = vec![0; u16::from_le_bytes([header[2], header[3]]) as usize];
                stream.read_exact(&mut body).await.unwrap();
                let result = if index == 0 {
                    assert_eq!(header[..2], [0x65, 0]);
                    assert_eq!(body, [1, 0, 0, 0]);
                    header[4..8].copy_from_slice(&42_u32.to_le_bytes());
                    body
                } else {
                    assert_eq!(header[..2], [0x6f, 0]);
                    assert_eq!(header[4..8], 42_u32.to_le_bytes());
                    let expected: &[u8] = match index {
                        1 => &[1, 2, 0x20, 1, 0x24, 1],
                        2 => &[0x0e, 3, 0x20, 0xf5, 0x24, 1, 0x30, 5],
                        _ => &[0x0e, 3, 0x20, 0xf5, 0x24, 1, 0x30, 6],
                    };
                    assert_eq!(&body[16..], expected);
                    let value = match index {
                        1 => vec![
                            1, 0, 12, 0, 42, 0, 2, 3, 0, 0, 1, 0, 0, 0, 3, b'P', b'L', b'C', 0,
                        ],
                        2 => vec![0; 22],
                        _ => vec![3, 0, b'P', b'L', b'C'],
                    };
                    let mut cip = vec![expected[0] | 0x80, 0, 0, 0];
                    cip.extend(value);
                    let mut reply = body[..14].to_vec();
                    reply.extend((cip.len() as u16).to_le_bytes());
                    reply.extend(cip);
                    reply
                };
                header[2..4].copy_from_slice(&(result.len() as u16).to_le_bytes());
                stream.write_all(&header).await.unwrap();
                stream.write_all(&result).await.unwrap();
            }
        });
        let records = cip_reads(Ipv4Addr::LOCALHOST).await.unwrap();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0]["value"]["serialNumber"], "00000001");
        assert_eq!(records[2]["value"]["hostname"], "PLC");
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn probes_tcp_and_udp_identity() {
        let _network = crate::network_test_lock().await;
        let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 44818))
            .await
            .unwrap();
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 44818)).await.unwrap();
        let response = identity_response();
        let tcp_response = response.clone();
        let tcp_task = tokio::spawn(async move {
            let (mut stream, _) = tcp.accept().await.unwrap();
            let mut request = [0; 24];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request[..12], &LIST_IDENTITY[..12]);
            let mut tcp_response = tcp_response;
            tcp_response[12..20].copy_from_slice(&request[12..20]);
            stream.write_all(&tcp_response).await.unwrap();
        });
        let udp_task = tokio::spawn(async move {
            let mut request = [0; 24];
            let (_, peer) = udp.recv_from(&mut request).await.unwrap();
            assert_eq!(&request[..12], &LIST_IDENTITY[..12]);
            let mut response = response;
            response[12..20].copy_from_slice(&request[12..20]);
            let mut unrelated = response.clone();
            unrelated[12] ^= 1;
            udp.send_to(&unrelated, peer).await.unwrap();
            udp.send_to(&response, peer).await.unwrap();
        });

        let finding = probe(Ipv4Addr::LOCALHOST).await.unwrap().unwrap();
        assert_eq!(finding.fields["model"], "PLC1");
        assert_eq!(finding.ports.len(), 2);
        assert_eq!(
            finding.raw["transportResponses"].as_array().unwrap().len(),
            2
        );
        assert_eq!(finding.raw["serialClaim"]["scope"], "adapter");
        assert_eq!(finding.raw["serialClaim"]["catalogNumber"], "158");
        let mut scan: crate::contract::ScanExport =
            serde_json::from_str(include_str!("../../contracts/otserver-scan-v2-valid.json"))
                .unwrap();
        let observation = &mut scan.devices[0].observations[0];
        observation.source = finding.source;
        observation.fields = finding.fields;
        observation.raw = finding.raw;
        crate::contract::validate(&scan).unwrap();
        tcp_task.await.unwrap();
        udp_task.await.unwrap();
    }
}
