use super::{Finding, TIMEOUT, hex, port, text};
use crate::contract::Source;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

const UDP_REQUEST: [u8; 13] = [0x80, 0, 2, 0, 0, 0, 0, 0x63, 0, 0xef, 5, 1, 0];
const TCP_ADDRESS_REQUEST: [u8; 20] = [
    b'F', b'I', b'N', b'S', 0, 0, 0, 0x0c, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

pub async fn probe(target: Ipv4Addr) -> Result<Option<Finding>, String> {
    let (tcp, udp) = tokio::join!(tcp(target), udp(target));
    let mut ports = Vec::new();
    let mut parsed: Option<Parsed> = None;
    let mut responses = Vec::new();
    let mut warnings = Vec::new();
    for (protocol, offset, result) in [("tcp", 16, tcp), ("udp", 0, udp)] {
        match result {
            Ok(Some(response)) => {
                let value = match parse(&response, offset) {
                    Ok(value) => value,
                    Err(error) => {
                        warnings.push(format!("Omron FINS {target} {protocol}: {error}"));
                        continue;
                    }
                };
                responses.push(json!({"transport": protocol, "identity": value.1}));
                if let Some((fields, _, _)) = &parsed {
                    for key in ["model", "firmwareVersion"] {
                        if fields
                            .get(key)
                            .zip(value.0.get(key))
                            .is_some_and(|(first, second)| first != second)
                        {
                            warnings.push(format!(
                                "Omron FINS {protocol} differs from the first identity for {key}"
                            ));
                        }
                    }
                }
                if parsed
                    .as_ref()
                    .is_none_or(|(fields, _, _)| !fields.contains_key("model"))
                {
                    parsed = Some(value);
                }
                ports.push(port(
                    protocol,
                    9600,
                    Source::OmronFins,
                    json!({ "state": "open" }),
                ));
            }
            Ok(None) => {}
            Err(error) => warnings.push(format!("Omron FINS {target} {protocol}: {error}")),
        }
    }
    let Some((fields, mut raw, mut parsed_warnings)) = parsed else {
        if let Some(error) = warnings.into_iter().next() {
            return Err(error);
        }
        return Ok(None);
    };
    warnings.append(&mut parsed_warnings);
    raw["transportResponses"] = json!(responses);
    Ok(Some(Finding {
        source: Source::OmronFins,
        fields,
        raw,
        ports,
        warnings,
    }))
}

async fn udp(target: Ipv4Addr) -> Result<Option<Vec<u8>>, String> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .map_err(|error| error.to_string())?;
    socket
        .connect((target, 9600))
        .await
        .map_err(|error| error.to_string())?;
    crate::traffic::wait().await;
    socket
        .send(&UDP_REQUEST)
        .await
        .map_err(|error| error.to_string())?;
    let mut response = vec![0; 65_535];
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    let mut rejected = false;
    for _ in 0..32 {
        match tokio::time::timeout_at(deadline, socket.recv(&mut response)).await {
            Ok(Ok(length)) => {
                if validate_route(&response[..length], &UDP_REQUEST).is_ok()
                    && parse(&response[..length], 0).is_ok()
                {
                    return Ok(Some(response[..length].to_vec()));
                }
                rejected = true;
            }
            Ok(Err(error))
                if matches!(
                    error.kind(),
                    ErrorKind::ConnectionRefused | ErrorKind::ConnectionReset
                ) =>
            {
                return Err(format!("FINS UDP port 9600 returned {}", error));
            }
            Ok(Err(error)) => return Err(error.to_string()),
            Err(_) => {
                return if rejected {
                    Err("malformed or uncorrelated FINS response".into())
                } else {
                    Ok(None)
                };
            }
        }
    }
    Err("too many uncorrelated FINS responses".into())
}

async fn tcp(target: Ipv4Addr) -> Result<Option<Vec<u8>>, String> {
    crate::traffic::wait().await;
    let mut stream = match timeout(
        TIMEOUT,
        TcpStream::connect(SocketAddr::new(IpAddr::V4(target), 9600)),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) if error.kind() == ErrorKind::ConnectionRefused => {
            return Err("FINS TCP connection refused on port 9600".into());
        }
        Ok(Err(error)) => return Err(error.to_string()),
        Err(_) => return Ok(None),
    };
    write(&mut stream, &TCP_ADDRESS_REQUEST).await?;
    let address_response = read_tcp(&mut stream).await?;
    if address_response.len() != 24
        || &address_response[..4] != b"FINS"
        || address_response[8..12] != [0, 0, 0, 1]
        || address_response[12..16] != [0; 4]
        || address_response[16..19] != [0; 3]
        || address_response[20..23] != [0; 3]
        || !matches!(address_response[19], 1..=254)
        || !matches!(address_response[23], 1..=254)
    {
        return Err("FINS/TCP node-address negotiation returned an invalid signature, status, or node address.".into());
    }
    let address = address_response[23];
    let mut request = vec![
        b'F', b'I', b'N', b'S', 0, 0, 0, 0x15, 0, 0, 0, 2, 0, 0, 0, 0, 0x80, 0, 2, 0,
    ];
    request.extend([address, 0, 0, address_response[19], 0, 5, 5, 1, 0]);
    write(&mut stream, &request).await?;
    let response = read_tcp(&mut stream).await?;
    validate_route(
        response.get(16..).ok_or("truncated FINS/TCP response")?,
        &request[16..],
    )?;
    Ok(Some(response))
}

fn validate_route(response: &[u8], request: &[u8]) -> Result<(), String> {
    if response.len() < 14
        || request.len() < 12
        || response[1] != 0
        || response[3..6] != request[6..9]
        || response[6] != request[3]
        || response[8] != request[5]
        || (request[4] != 0 && response[7] != request[4])
        || response[9..12] != request[9..12]
    {
        return Err("mismatched FINS response route/transaction".into());
    }
    Ok(())
}

async fn write(stream: &mut TcpStream, value: &[u8]) -> Result<(), String> {
    crate::traffic::wait().await;
    timeout(TIMEOUT, stream.write_all(value))
        .await
        .map_err(|_| "write timed out".to_string())?
        .map_err(|error| error.to_string())
}

async fn read_tcp(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut header = [0; 8];
    timeout(TIMEOUT, stream.read_exact(&mut header))
        .await
        .map_err(|_| "response timed out".to_string())?
        .map_err(|error| error.to_string())?;
    if &header[..4] != b"FINS" {
        return Err("invalid FINS/TCP header".into());
    }
    let length = u32::from_be_bytes(header[4..8].try_into().unwrap()) as usize;
    if length > 65_527 {
        return Err("oversized FINS/TCP response".into());
    }
    let mut response = vec![0; 8 + length];
    response[..8].copy_from_slice(&header);
    timeout(TIMEOUT, stream.read_exact(&mut response[8..]))
        .await
        .map_err(|_| "response timed out".to_string())?
        .map_err(|error| error.to_string())?;
    Ok(response)
}

type Parsed = (BTreeMap<String, Value>, Value, Vec<String>);

fn parse(response: &[u8], offset: usize) -> Result<Parsed, String> {
    if offset == 16
        && (response.len() < 16
            || &response[..4] != b"FINS"
            || u32::from_be_bytes(response[4..8].try_into().unwrap()) as usize
                != response.len() - 8
            || response[8..12] != [0, 0, 0, 2]
            || response[12..16] != [0; 4])
    {
        return Err("invalid FINS/TCP response".into());
    }
    let expected_sid = if offset == 16 { 5 } else { 0xef };
    if response.len() < 14 + offset
        || response[offset] & 0x40 == 0
        || response[offset + 9] != expected_sid
        || response[offset + 10..offset + 12] != [5, 1]
    {
        return Err("invalid controller response".into());
    }
    let code = u16::from_be_bytes([response[12 + offset], response[13 + offset]]);
    let mut fields = BTreeMap::from([
        ("protocols".into(), json!(["omron-fins"])),
        ("vendor".into(), json!("Omron")),
    ]);
    let mut warnings = Vec::new();
    let mut raw = if code == 0 {
        if response.len() < 106 + offset {
            return Err("truncated FINS controller data".into());
        }
        let model = text(&response[14 + offset..34 + offset]);
        let version = text(&response[34 + offset..54 + offset]);
        if let Some(model) = &model {
            fields.insert("model".into(), json!(model));
            fields.insert("name".into(), json!(model));
        }
        if let Some(version) = &version {
            fields.insert("firmwareVersion".into(), json!(version));
        }
        json!({
            "controllerModel": model,
            "controllerVersion": version,
            "programAreaSize": u16::from_be_bytes(response[94 + offset..96 + offset].try_into().unwrap()),
            "iomSize": response[96 + offset],
            "dmWords": u16::from_be_bytes(response[97 + offset..99 + offset].try_into().unwrap()),
            "timerCounterSize": response[99 + offset],
            "expansionDmSize": response[100 + offset],
            "steps": u16::from_be_bytes(response[101 + offset..103 + offset].try_into().unwrap()),
            "memoryCardKind": response[103 + offset],
            "memoryCardSize": u16::from_be_bytes(response[104 + offset..106 + offset].try_into().unwrap()),
        })
    } else {
        warnings.push(format!("Controller returned FINS status {code:04X}."));
        json!({})
    };
    raw["response"] = json!(hex(response));
    raw["responseCode"] = json!(format!("{code:04X}"));
    raw["route"] = json!({"destination": &response[offset+3..offset+6], "source": &response[offset+6..offset+9], "sid": response[offset+9]});
    raw["fieldSources"] = json!({"model": {"command": "0501", "offset": 14}, "firmwareVersion": {"command": "0501", "offset": 34}});
    Ok((fields, raw, warnings))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    fn controller_response() -> Vec<u8> {
        let mut response = vec![0; 106];
        response[0] = 0xc0;
        response[4] = 0x63;
        response[9] = 0xef;
        response[10..12].copy_from_slice(&[5, 1]);
        response[14..24].copy_from_slice(b"CJ2M-CPU32");
        response[24] = 0;
        response[34..39].copy_from_slice(b"02.01");
        response
    }

    #[test]
    fn parses_controller_identity() {
        let mut response = controller_response();
        response[94..106]
            .copy_from_slice(&[0x12, 0x34, 2, 0x56, 0x78, 3, 4, 0x9a, 0xbc, 5, 0xde, 0xf0]);
        let (fields, raw, _) = parse(&response, 0).unwrap();
        assert_eq!(fields["model"], "CJ2M-CPU32");
        assert_eq!(fields["firmwareVersion"], "02.01");
        assert_eq!(
            raw,
            json!({
                "response": hex(&response), "responseCode": "0000",
                "controllerModel": "CJ2M-CPU32", "controllerVersion": "02.01",
                "programAreaSize": 0x1234, "iomSize": 2, "dmWords": 0x5678,
                "timerCounterSize": 3, "expansionDmSize": 4, "steps": 0x9abc,
                "memoryCardKind": 5, "memoryCardSize": 0xdef0,
                "route": {"destination":[0,99,0], "source":[0,0,0], "sid":239},
                "fieldSources":{"model":{"command":"0501","offset":14},"firmwareVersion":{"command":"0501","offset":34}},
            })
        );
    }

    #[test]
    fn request_and_response_validation_match_fins() {
        assert_eq!(UDP_REQUEST.last(), Some(&0));
        let mut response = vec![0; 106];
        response[0] = 0xc0;
        response[9] = 0xef;
        response[10..12].copy_from_slice(&[5, 1]);
        response[12..14].copy_from_slice(&1_u16.to_be_bytes());
        let (_, raw, warnings) = parse(&response, 0).unwrap();
        assert_eq!(warnings[0], "Controller returned FINS status 0001.");
        assert_eq!(
            raw,
            json!({"response": hex(&response), "responseCode": "0001", "route":{"destination":[0,0,0],"source":[0,0,0],"sid":239}, "fieldSources":{"model":{"command":"0501","offset":14},"firmwareVersion":{"command":"0501","offset":34}}})
        );
        response[10] = 4;
        assert!(parse(&response, 0).is_err());
    }

    #[test]
    fn validates_routes_and_accepts_short_error_pdus() {
        let mut response = controller_response();
        assert!(validate_route(&response, &UDP_REQUEST).is_ok());
        response[4] ^= 1;
        assert!(validate_route(&response, &UDP_REQUEST).is_err());
        response[4] ^= 1;
        response[13] = 1;
        response.truncate(14);
        assert_eq!(parse(&response, 0).unwrap().1["responseCode"], "0001");
        response[13] = 0;
        assert!(parse(&response, 0).is_err());
    }

    #[tokio::test]
    async fn keeps_udp_identity_when_tcp_is_malformed() {
        let _network = crate::network_test_lock().await;
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 9600)).await.unwrap();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 9600))
            .await
            .unwrap();
        let responder = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 20];
            stream.read_exact(&mut request).await.unwrap();
            stream.write_all(b"NOT-FINS").await.unwrap();
            let mut request = [0; 13];
            let (_, peer) = socket.recv_from(&mut request).await.unwrap();
            socket.send_to(&controller_response(), peer).await.unwrap();
        });
        let finding = probe(Ipv4Addr::LOCALHOST).await.unwrap().unwrap();
        assert_eq!(finding.fields["model"], "CJ2M-CPU32");
        assert_eq!(finding.raw["transportResponses"][0]["transport"], "udp");
        assert_eq!(finding.warnings.len(), 1);
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn probes_udp_controller_identity() {
        let _network = crate::network_test_lock().await;
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 9600)).await.unwrap();
        let responder = tokio::spawn(async move {
            let mut request = [0; UDP_REQUEST.len()];
            let (_, peer) = socket.recv_from(&mut request).await.unwrap();
            assert_eq!(request, UDP_REQUEST);
            let mut unrelated = controller_response();
            unrelated[9] ^= 1;
            socket.send_to(&unrelated, peer).await.unwrap();
            socket.send_to(&controller_response(), peer).await.unwrap();
        });
        let finding = probe(Ipv4Addr::LOCALHOST).await.unwrap().unwrap();
        assert_eq!(finding.fields["model"], "CJ2M-CPU32");
        assert_eq!(finding.ports.len(), 1);
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn probes_tcp_controller_identity() {
        let _network = crate::network_test_lock().await;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 9600))
            .await
            .unwrap();
        let responder = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; TCP_ADDRESS_REQUEST.len()];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(request, TCP_ADDRESS_REQUEST);
            let mut address = vec![0; 24];
            address[..4].copy_from_slice(b"FINS");
            address[4..8].copy_from_slice(&16_u32.to_be_bytes());
            address[8..12].copy_from_slice(&1_u32.to_be_bytes());
            address[19] = 10;
            address[23] = 1;
            stream.write_all(&address).await.unwrap();

            let mut header = [0; 8];
            stream.read_exact(&mut header).await.unwrap();
            let length = u32::from_be_bytes(header[4..8].try_into().unwrap()) as usize;
            let mut body = vec![0; length];
            stream.read_exact(&mut body).await.unwrap();
            let mut response = vec![0; 16];
            response[..4].copy_from_slice(b"FINS");
            response[8..12].copy_from_slice(&2_u32.to_be_bytes());
            let mut controller = controller_response();
            controller[3..6].copy_from_slice(&body[14..17]);
            controller[6..9].copy_from_slice(&body[11..14]);
            controller[9] = 5;
            response.extend(controller);
            let length = (response.len() - 8) as u32;
            response[4..8].copy_from_slice(&length.to_be_bytes());
            stream.write_all(&response).await.unwrap();
        });
        let finding = probe(Ipv4Addr::LOCALHOST).await.unwrap().unwrap();
        assert_eq!(finding.fields["model"], "CJ2M-CPU32");
        assert_eq!(finding.ports.len(), 1);
        responder.await.unwrap();
    }
}
