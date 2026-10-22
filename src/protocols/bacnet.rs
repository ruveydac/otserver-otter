use super::{Finding, TIMEOUT, hex, port};
use crate::contract::Source;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::net::Ipv4Addr;
use tokio::net::UdpSocket;

const PROPERTIES: [(&str, u32); 11] = [
    ("firmware", 0x2c),
    ("applicationSoftware", 0x0c),
    ("model", 0x46),
    ("objectName", 0x4d),
    ("description", 0x1c),
    ("location", 0x3a),
    ("vendor", 0x79),
    ("vendorId", 0x78),
    ("protocolVersion", 98),
    ("protocolRevision", 139),
    ("serialNumber", 372),
];

pub async fn probe(target: Ipv4Addr) -> Result<Option<Finding>, String> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .map_err(|error| format!("BACnet {target}: {error}"))?;
    socket
        .connect((target, 47808))
        .await
        .map_err(|error| format!("BACnet {target}: {error}"))?;
    let Some(initial) = exchange(&socket, 0x4b, 1, None).await? else {
        return Ok(None);
    };
    let instance = decode(&initial, 0x4b, 1).and_then(|value| value.as_u64());
    if instance.is_none() {
        return Err(format!("BACnet {target}: invalid response"));
    }
    let mut values = Map::from_iter([("instanceNumber".into(), json!(instance))]);
    let mut responses = vec![
        json!({"property": 75, "invokeId": 1, "response": hex(&initial), "outcome": "success"}),
    ];
    let mut sources = Map::new();
    let mut warnings = Vec::new();
    for (index, (name, property)) in PROPERTIES.into_iter().enumerate() {
        let invoke = index as u8 + 2;
        match exchange(&socket, property, invoke, instance).await {
            Ok(Some(response)) => {
                let value = decode_for(&response, property, invoke, instance);
                let outcome = if value.is_some() {
                    "success"
                } else {
                    error_outcome(&response, invoke).unwrap_or("malformed")
                };
                responses.push(json!({"property": property, "invokeId": invoke, "response": hex(&response), "outcome": outcome}));
                if let Some(value) = value {
                    values.insert(name.into(), value);
                } else {
                    warnings.push(format!(
                        "BACnet property {property}: error/reject/abort response"
                    ));
                }
            }
            Ok(None) => {
                responses
                    .push(json!({"property": property, "invokeId": invoke, "outcome": "timeout"}));
                warnings.push(format!(
                    "BACnet property {property}: no correlated response"
                ));
            }
            Err(error) => {
                warnings.push(format!("BACnet property {property}: {error}"));
            }
        }
    }
    let mut fields = BTreeMap::from([("protocols".into(), json!(["bacnet"]))]);
    for (source, field) in [
        ("objectName", "name"),
        ("model", "model"),
        ("firmware", "firmwareVersion"),
        ("applicationSoftware", "applicationSoftwareVersion"),
        ("description", "description"),
        ("location", "location"),
        ("vendor", "vendor"),
        ("serialNumber", "serialNumber"),
    ] {
        if let Some(value) = values.get(source).filter(|value| value.is_string()) {
            fields.insert(field.into(), value.clone());
            sources.insert(field.into(), json!({"property": PROPERTIES.iter().find(|(name, _)| *name == source).map(|(_, id)| id), "deviceInstance": instance, "mutable": matches!(source, "objectName" | "description" | "location")}));
        }
    }
    values.insert("initialResponse".into(), json!(hex(&initial)));
    values.insert("propertyResponses".into(), json!(responses));
    values.insert("fieldSources".into(), sources.into());
    Ok(Some(Finding {
        source: Source::Bacnet,
        fields,
        raw: Value::Object(values),
        ports: vec![port(
            "udp",
            47808,
            Source::Bacnet,
            json!({ "state": "open" }),
        )],
        warnings,
    }))
}

async fn exchange(
    socket: &UdpSocket,
    property: u32,
    invoke: u8,
    instance: Option<u64>,
) -> Result<Option<Vec<u8>>, String> {
    let object = (8_u32 << 22) | instance.map_or(0x3f_ffff, |value| value as u32);
    let mut query = vec![0x81, 0x0a, 0, 0, 1, 4, 0, 5, invoke, 0x0c, 0x0c];
    query.extend(object.to_be_bytes());
    if property <= 255 {
        query.extend([0x19, property as u8]);
    } else {
        query.push(0x1a);
        query.extend((property as u16).to_be_bytes());
    }
    let length = query.len() as u16;
    query[2..4].copy_from_slice(&length.to_be_bytes());
    crate::traffic::wait().await;
    socket
        .send(&query)
        .await
        .map_err(|error| error.to_string())?;
    let mut response = vec![0; 65_535];
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    let mut rejected = false;
    for _ in 0..32 {
        match tokio::time::timeout_at(deadline, socket.recv(&mut response)).await {
            Ok(Ok(length)) => {
                if decode_for(&response[..length], property, invoke, instance).is_some()
                    || error_outcome(&response[..length], invoke).is_some()
                {
                    return Ok(Some(response[..length].to_vec()));
                }
                rejected = true;
            }
            Ok(Err(error)) if error.kind() == ErrorKind::ConnectionRefused => return Ok(None),
            Ok(Err(error)) => return Err(error.to_string()),
            Err(_) => {
                return if rejected {
                    Err("BACnet received malformed or uncorrelated responses".into())
                } else {
                    Ok(None)
                };
            }
        }
    }
    Ok(None)
}

fn apdu(response: &[u8]) -> Option<&[u8]> {
    if response.len() < 9
        || response[0] != 0x81
        || u16::from_be_bytes([response[2], response[3]]) as usize != response.len()
        || response[4] != 1
        || response[5] & 0x80 != 0
    {
        return None;
    }
    if response[1] != 0x0a {
        return None;
    }
    let mut offset = 6;
    if response[5] & 0x20 != 0 {
        offset += 4 + usize::from(*response.get(offset + 2)?);
    }
    if response[5] & 0x08 != 0 {
        offset += 3 + usize::from(*response.get(offset + 2)?);
    }
    response.get(offset..).filter(|pdu| !pdu.is_empty())
}

fn error_outcome(response: &[u8], invoke: u8) -> Option<&'static str> {
    let pdu = apdu(response)?;
    if pdu.get(1) != Some(&invoke) {
        return None;
    }
    match pdu[0] {
        0x50 if pdu.len() >= 5 && pdu[2] == 0x0c => Some("protocol-error"),
        0x60 if pdu.len() == 3 => Some("rejected"),
        0x71 if pdu.len() == 3 => Some("aborted"),
        _ => None,
    }
}

fn decode(response: &[u8], property: u32, invoke: u8) -> Option<Value> {
    decode_for(response, property, invoke, None)
}

fn decode_for(response: &[u8], property: u32, invoke: u8, instance: Option<u64>) -> Option<Value> {
    let response = apdu(response)?;
    let mut offset = 0;
    let pdu = *response.first()?;
    if pdu >> 4 != 3
        || pdu & 8 != 0
        || response.get(offset + 1) != Some(&invoke)
        || response.get(offset + 2) != Some(&0x0c)
    {
        return None;
    }
    offset += 3;
    let object = tag(response, &mut offset)?;
    let property_tag = tag(response, &mut offset)?;
    if !object.context
        || object.number != 0
        || object.bytes.len() != 4
        || !property_tag.context
        || property_tag.number != 1
        || number(property_tag.bytes)? != u64::from(property)
    {
        return None;
    }
    let object_id = u32::from_be_bytes(object.bytes.try_into().ok()?);
    if object_id >> 22 != 8
        || instance.is_some_and(|value| u64::from(object_id & 0x3f_ffff) != value)
    {
        return None;
    }
    if response.get(offset).is_some_and(|value| value >> 4 == 2) {
        tag(response, &mut offset)?;
    }
    let opening = tag(response, &mut offset)?;
    if !opening.context || opening.number != 3 || !opening.opening {
        return None;
    }
    let value = tag(response, &mut offset)?;
    if value.context || value.opening || value.closing {
        return None;
    }
    let closing = tag(response, &mut offset)?;
    if !closing.context || closing.number != 3 || !closing.closing || offset != response.len() {
        return None;
    }
    let expected = match property {
        75 => 12,
        120 | 98 | 139 => 2,
        _ => 7,
    };
    if value.number != expected && !(property == 120 && value.number == 9) {
        return None;
    }
    match value.number {
        2 | 9 => Some(json!(number(value.bytes)?)),
        7 => {
            let (encoding, bytes) = value.bytes.split_first()?;
            let text = match encoding {
                4 if bytes.len() % 2 == 0 => String::from_utf16(
                    &bytes
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
                        .collect::<Vec<_>>(),
                )
                .ok()?,
                5 => bytes.iter().map(|byte| char::from(*byte)).collect(),
                0 => std::str::from_utf8(bytes).ok()?.to_owned(),
                _ => return None,
            };
            let text = text.trim_matches('\0').trim().to_owned();
            (!text.is_empty()).then(|| json!(text))
        }
        12 if value.bytes.len() == 4
            && u32::from_be_bytes(value.bytes.try_into().ok()?) >> 22 == 8 =>
        {
            Some(json!(
                u32::from_be_bytes(value.bytes.try_into().ok()?) & 0x003f_ffff
            ))
        }
        _ => None,
    }
}

struct Tag<'a> {
    number: u8,
    context: bool,
    opening: bool,
    closing: bool,
    bytes: &'a [u8],
}

fn tag<'a>(packet: &'a [u8], offset: &mut usize) -> Option<Tag<'a>> {
    let first = *packet.get(*offset)?;
    *offset += 1;
    let mut number = first >> 4;
    if number == 15 {
        number = *packet.get(*offset)?;
        *offset += 1;
    }
    let context = first & 8 != 0;
    let lvt = first & 7;
    let opening = context && lvt == 6;
    let closing = context && lvt == 7;
    let length = if opening || closing {
        0
    } else if lvt < 5 {
        usize::from(lvt)
    } else {
        let extended = *packet.get(*offset)?;
        *offset += 1;
        match extended {
            0..=253 => usize::from(extended),
            254 => {
                let value = u16::from_be_bytes(packet.get(*offset..*offset + 2)?.try_into().ok()?);
                *offset += 2;
                usize::from(value)
            }
            255 => {
                let value = u32::from_be_bytes(packet.get(*offset..*offset + 4)?.try_into().ok()?);
                *offset += 4;
                usize::try_from(value).ok()?
            }
        }
    };
    let bytes = packet.get(*offset..offset.checked_add(length)?)?;
    *offset += length;
    Some(Tag {
        number,
        context,
        opening,
        closing,
        bytes,
    })
}

fn number(bytes: &[u8]) -> Option<u64> {
    (bytes.len() <= 8).then(|| {
        bytes
            .iter()
            .fold(0, |value, byte| value << 8 | u64::from(*byte))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(property: u32, invoke: u8, object: bool) -> Vec<u8> {
        let mut response = if object {
            vec![
                0x81,
                0x0a,
                0,
                0,
                1,
                4,
                0x30,
                invoke,
                0x0c,
                0x0c,
                0x02,
                0x3f,
                0xff,
                0xff,
                0x19,
                property as u8,
                0x3e,
                0xc4,
                0x02,
                0,
                0,
                0x2a,
                0x3f,
            ]
        } else {
            vec![
                0x81,
                0x0a,
                0,
                0,
                1,
                4,
                0x30,
                invoke,
                0x0c,
                0x0c,
                0x02,
                0x3f,
                0xff,
                0xff,
                0x19,
                property as u8,
                0x3e,
                0x75,
                4,
                0,
                b'P',
                b'L',
                b'C',
                0x3f,
            ]
        };
        response[10..14].copy_from_slice(&[0x02, 0, 0, 0x2a]);
        if property > 255 {
            response[14] = 0x1a;
            response[15] = (property >> 8) as u8;
            response.insert(16, property as u8);
        }
        if matches!(property, 98 | 139 | 120) {
            let opening = if property > 255 { 18 } else { 17 };
            response.truncate(opening);
            response.extend([0x21, 42, 0x3f]);
        }
        let length = response.len() as u16;
        response[2..4].copy_from_slice(&length.to_be_bytes());
        response
    }

    #[test]
    fn decodes_routed_values_and_rejects_segmentation() {
        let mut string = vec![
            0x81, 0x0a, 0, 0, 1, 4, 0x30, 1, 0x0c, 0x0c, 0x02, 0x3f, 0xff, 0xff, 0x19, 0x4d, 0x3e,
            0x75, 4, 0, b'P', b'L', b'C', 0x3f,
        ];
        let length = string.len() as u16;
        string[2..4].copy_from_slice(&length.to_be_bytes());
        assert_eq!(decode(&string, 0x4d, 1), Some(json!("PLC")));

        let mut object = vec![
            0x81, 0x0a, 0, 0, 1, 0x20, 0, 1, 0, 5, 0x30, 1, 0x0c, 0x0c, 0x02, 0x3f, 0xff, 0xff,
            0x19, 0x4b, 0x3e, 0xc4, 0x02, 0, 0, 0x2a, 0x3f,
        ];
        let length = object.len() as u16;
        object[2..4].copy_from_slice(&length.to_be_bytes());
        assert_eq!(decode(&object, 0x4b, 1), Some(json!(42)));
        object[10] |= 8;
        assert_eq!(decode(&object, 0x4b, 1), None);
    }

    #[tokio::test]
    async fn probes_device_properties() {
        let _network = crate::network_test_lock().await;
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 47808)).await.unwrap();
        let responder = tokio::spawn(async move {
            for _ in 0..=PROPERTIES.len() {
                let mut request = [0; 32];
                let (_, peer) = socket.recv_from(&mut request).await.unwrap();
                let property = if request[15] == 0x1a {
                    u32::from(u16::from_be_bytes([request[16], request[17]]))
                } else {
                    u32::from(request[16])
                };
                let invoke = request[8];
                if property == 0x4b {
                    socket
                        .send_to(&response(property, invoke.wrapping_add(1), true), peer)
                        .await
                        .unwrap();
                }
                if property == 0x46 {
                    socket
                        .send_to(&[0x81, 0x0a, 0, 9, 1, 4, 0x60, invoke, 9], peer)
                        .await
                        .unwrap();
                    continue;
                }
                let mut answer = response(property, invoke, property == 0x4b);
                if property == 0x0c {
                    answer[20..23].copy_from_slice(b"APP");
                }
                socket.send_to(&answer, peer).await.unwrap();
            }
        });
        let finding = probe(Ipv4Addr::LOCALHOST).await.unwrap().unwrap();
        assert_eq!(finding.fields["name"], "PLC");
        assert_eq!(finding.fields["vendor"], "PLC");
        assert_eq!(finding.fields["firmwareVersion"], "PLC");
        assert_eq!(finding.fields["applicationSoftwareVersion"], "APP");
        assert_eq!(finding.raw["applicationSoftware"], "APP");
        assert!(!finding.fields.contains_key("model"));
        assert_eq!(finding.warnings.len(), 1);
        responder.await.unwrap();
    }

    #[test]
    fn decodes_extended_tags_and_value_encodings() {
        let mut offset = 0;
        let packet = [0xf5, 7, 254, 0, 2, 0xaa, 0xbb];
        let value = tag(&packet, &mut offset).unwrap();
        assert_eq!(value.number, 7);
        assert_eq!(value.bytes, [0xaa, 0xbb]);
        let mut offset = 0;
        let packet = [0xf5, 7, 255, 0, 0, 0, 1, 0xaa];
        assert_eq!(tag(&packet, &mut offset).unwrap().bytes, [0xaa]);
        assert_eq!(number(&[1, 2]), Some(258));
        assert_eq!(number(&[0; 9]), None);

        let mut latin = response(0x4d, 1, false);
        latin[19] = 5;
        assert_eq!(decode(&latin, 0x4d, 1), Some(json!("PLC")));
        let mut unknown = response(0x4d, 1, false);
        unknown[17] = 0x65;
        assert_eq!(decode(&unknown, 0x4d, 1), None);
    }

    #[test]
    fn rejects_wrong_object_instance_type_and_unclosed_values() {
        let response = response(0x4d, 3, false);
        assert!(decode_for(&response, 0x4d, 3, Some(42)).is_some());
        assert!(decode_for(&response, 0x4d, 3, Some(43)).is_none());
        let mut bad = response.clone();
        bad[10] = 0;
        assert!(decode(&bad, 0x4d, 3).is_none());
        bad = response.clone();
        *bad.last_mut().unwrap() = 0;
        assert!(decode(&bad, 0x4d, 3).is_none());
        assert!(decode(&response, 120, 3).is_none());
    }
}
