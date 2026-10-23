use super::{Finding, TIMEOUT, hex, port, text};
use crate::contract::Source;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

// (source, destination) TSAP pairings: connection type PG 0x01xx, OP 0x02xx, S7 basic
// 0x03xx, with destination slot 0/1 for S7-1200/1500, 2 for S7-300, and 3 for S7-400.
const TSAP_PAIRS: [(u16, u16); 13] = [
    (0x0100, 0x0100),
    (0x0100, 0x0101),
    (0x0100, 0x0102),
    (0x0100, 0x0103),
    (0x0100, 0x0200), // s7-info.nse's alternate uses a PG source with an OP destination.
    (0x0200, 0x0200),
    (0x0200, 0x0201),
    (0x0200, 0x0202),
    (0x0200, 0x0203),
    (0x0300, 0x0300),
    (0x0300, 0x0301),
    (0x0300, 0x0302),
    (0x0300, 0x0303),
];
// S7 Setup Communication request.
const SETUP: &[u8] = &[
    0x03, 0x00, 0x00, 0x19, 0x02, 0xf0, 0x80, 0x32, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00,
    0x00, 0xf0, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0xe0,
];
// Index zero requests the complete identification list, including revision records.
const SZL_11: &[u8] = &[
    0x03, 0x00, 0x00, 0x21, 0x02, 0xf0, 0x80, 0x32, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00,
    0x08, 0x00, 0x01, 0x12, 0x04, 0x11, 0x44, 0x01, 0x00, 0xff, 0x09, 0x00, 0x04, 0x00, 0x11, 0x00,
    0x00,
];
const SZL_1C: &[u8] = &[
    0x03, 0x00, 0x00, 0x21, 0x02, 0xf0, 0x80, 0x32, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00,
    0x08, 0x00, 0x01, 0x12, 0x04, 0x11, 0x44, 0x01, 0x00, 0xff, 0x09, 0x00, 0x04, 0x00, 0x1c, 0x00,
    0x00,
];
#[cfg(not(test))]
const CONNECT_PORT: u16 = 102;
#[cfg(test)]
const CONNECT_PORT: u16 = 10_102;

pub async fn probe(target: Ipv4Addr) -> Result<Option<Finding>, String> {
    // Real CPUs reject a connect request whose TSAP does not match a configured
    // connection (RST, FIN, or silence), so every TSAP pairing gets its own connection.
    for (src_tsap, dst_tsap) in TSAP_PAIRS {
        let request = connect_request(src_tsap, dst_tsap);
        crate::traffic::wait().await;
        let mut stream = match timeout(
            TIMEOUT,
            TcpStream::connect(SocketAddr::new(IpAddr::V4(target), CONNECT_PORT)),
        )
        .await
        {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) if matches!(error.kind(), std::io::ErrorKind::ConnectionRefused) => {
                return Ok(None);
            }
            Ok(Err(error)) => return Err(format!("S7 {target}: {error}")),
            Err(_) => return Ok(None),
        };
        if negotiate(&mut stream, &request).await.unwrap_or(false)
            && let Some(finding) = read_identity(stream, target, src_tsap, dst_tsap).await?
        {
            return Ok(Some(finding));
        }
    }
    Ok(None)
}

fn connect_request(src_tsap: u16, dst_tsap: u16) -> [u8; 22] {
    let mut frame = [
        0x03, 0x00, 0x00, 0x16, 0x11, 0xe0, 0x00, 0x00, 0x00, 0x14, 0x00, 0xc1, 0x02, 0x00, 0x00,
        0xc2, 0x02, 0x00, 0x00, 0xc0, 0x01, 0x0a,
    ];
    frame[13..15].copy_from_slice(&src_tsap.to_be_bytes());
    frame[17..19].copy_from_slice(&dst_tsap.to_be_bytes());
    frame
}

async fn negotiate(stream: &mut TcpStream, request: &[u8]) -> Result<bool, String> {
    write(stream, request).await?;
    let response = read_frame(stream).await?;
    Ok(response.len() >= 7 && response[5] == 0xd0 && response[4] as usize + 5 == response.len())
}

async fn read_identity(
    mut stream: TcpStream,
    target: Ipv4Addr,
    src_tsap: u16,
    dst_tsap: u16,
) -> Result<Option<Finding>, String> {
    // COTP acceptance alone does not identify a usable S7 TSAP. A CPU can reject
    // S7 setup on this slot, and an MMS endpoint on port 102 can also accept COTP.
    if write(&mut stream, SETUP).await.is_err() {
        return Ok(None);
    }
    let Ok(frame) = read_frame(&mut stream).await else {
        return Ok(None);
    };
    if !setup_response(&frame) {
        return Ok(None);
    }
    let mut warnings = Vec::new();
    let mut responses = Vec::new();
    for (id, request) in [(0x0011, SZL_11), (0x001c, SZL_1C)] {
        match read_szl(&mut stream, request).await {
            Ok(value) => responses.push((id, value)),
            Err(error) => warnings.push(format!("S7 {target} SZL {id:04X}: {error}")),
        }
    }
    let response = |id| {
        responses
            .iter()
            .find(|(key, _)| *key == id)
            .map(|(_, value)| value.as_slice())
            .unwrap_or_default()
    };
    let mut finding = parse(response(0x11), response(0x1c))?;
    finding.warnings.extend(warnings);
    if let Value::Object(raw) = &mut finding.raw {
        raw.insert(
            "accessPath".into(),
            json!({
                "sourceTsap": format!("{src_tsap:04X}"),
                "destinationTsap": format!("{dst_tsap:04X}"),
                "rack": (dst_tsap & 0xff) >> 5,
                "slot": dst_tsap & 0x1f,
            }),
        );
    }
    Ok(Some(finding))
}

async fn read_szl(stream: &mut TcpStream, request: &[u8]) -> Result<Vec<u8>, String> {
    timeout(
        std::time::Duration::from_secs(4),
        read_szl_inner(stream, request),
    )
    .await
    .map_err(|_| "S7 SZL exchange timed out".to_string())?
}

async fn read_szl_inner(stream: &mut TcpStream, request: &[u8]) -> Result<Vec<u8>, String> {
    write(stream, request).await?;
    let mut output = Vec::new();
    let mut fragment_reference = None;
    let mut sequence = None;
    for _ in 0..=255 {
        let frame = read_frame(stream).await?;
        let (payload, last) = userdata(&frame)?;
        if frame[11..13] != request[11..13] {
            return Err("mismatched S7 PDU reference".into());
        }
        let (_, parameters, _, _) = s7_frame(&frame)?;
        if fragment_reference.is_some_and(|value| value != parameters[8])
            || sequence.is_some_and(|value: u8| parameters[7] != value.wrapping_add(1))
        {
            return Err("mismatched S7 userdata fragment".into());
        }
        fragment_reference = Some(parameters[8]);
        sequence = Some(parameters[7]);
        if output.len() + payload.len() > 65_535 {
            return Err("oversized S7 SZL response".into());
        }
        output.extend_from_slice(payload);
        if last {
            if output.get(..4) != Some(&request[29..33]) {
                return Err("mismatched S7 SZL ID/index".into());
            }
            return Ok(output);
        }
    }
    Err("too many S7 SZL fragments".into())
}

async fn write(stream: &mut TcpStream, value: &[u8]) -> Result<(), String> {
    crate::traffic::wait().await;
    timeout(TIMEOUT, stream.write_all(value))
        .await
        .map_err(|_| "write timed out".to_string())?
        .map_err(|error| error.to_string())
}

async fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut header = [0; 4];
    timeout(TIMEOUT, stream.read_exact(&mut header))
        .await
        .map_err(|_| "response timed out".to_string())?
        .map_err(|error| error.to_string())?;
    let length = u16::from_be_bytes([header[2], header[3]]) as usize;
    if header[0] != 3 || !(4..=65_535).contains(&length) {
        return Err("invalid TPKT header".into());
    }
    let mut frame = vec![0; length];
    frame[..4].copy_from_slice(&header);
    timeout(TIMEOUT, stream.read_exact(&mut frame[4..]))
        .await
        .map_err(|_| "response timed out".to_string())?
        .map_err(|error| error.to_string())?;
    Ok(frame)
}

fn parse(hardware: &[u8], identity: &[u8]) -> Result<Finding, String> {
    let hardware_response = hardware;
    let identity_response = identity;
    let mut warnings = Vec::new();
    let hardware = optional_szl(hardware, 0x0011, &mut warnings);
    let identity = optional_szl(identity, 0x001c, &mut warnings);
    let module = record(&hardware, 1)
        .and_then(|value| value.get(2..22))
        .and_then(text);
    let basic_hardware = record(&hardware, 6)
        .and_then(|value| value.get(2..22))
        .and_then(text);
    let version = record(&hardware, 7)
        .and_then(|record| record.get(25..28))
        .map(|bytes| format!("{}.{}.{}", bytes[0], bytes[1], bytes[2]));
    let identity_text = |index: u16, length: usize| {
        record(&identity, index)
            .and_then(|value| value.get(2..2 + length))
            .and_then(text)
    };
    let system_name = identity_text(1, 24);
    let module_type = identity_text(2, 24).or_else(|| identity_text(7, 32));
    let plant = identity_text(3, 32);
    let copyright = identity_text(4, 26);
    let serial = identity_text(5, 24);

    let mut fields = BTreeMap::from([
        ("protocols".into(), json!(["s7"])),
        ("vendor".into(), json!("Siemens")),
    ]);
    if let Some(version) = &version {
        fields.insert("firmwareVersion".into(), json!(version));
    }
    if let Some(name) = system_name.as_ref() {
        fields.insert("name".into(), json!(name));
    }
    if let Some(model) = module_type
        .as_ref()
        .or(module.as_ref())
        .or(basic_hardware.as_ref())
    {
        fields.insert("model".into(), json!(model));
    }
    if let Some(serial) = &serial {
        fields.insert("serialNumber".into(), json!(serial));
    }
    let mut field_sources = BTreeMap::new();
    for (field, id, record) in [
        ("name", "0x001C", 1),
        ("serialNumber", "0x001C", 5),
        ("firmwareVersion", "0x0011", 7),
    ] {
        if fields.contains_key(field) {
            field_sources.insert(
                field,
                json!({"szlId":id,"index":0,"record":record,"mutable":field == "name"}),
            );
        }
    }
    if fields.contains_key("model") {
        let (id, record) = if module_type.is_some() {
            ("0x001C", if identity_text(2, 24).is_some() { 2 } else { 7 })
        } else {
            ("0x0011", if module.is_some() { 1 } else { 6 })
        };
        field_sources.insert("model", json!({"szlId":id,"index":0,"record":record}));
    }
    field_sources.insert(
        "vendor",
        json!({"derivation":"protocol-family","confidence":"inferred"}),
    );
    let raw = json!({
        "basicHardware": basic_hardware,
        "copyright": copyright,
        "module": module,
        "moduleType": module_type,
        "plantIdentification": plant,
        "response": hex(hardware_response),
        "identityResponse": hex(identity_response),
        "systemName": system_name,
        "version": version,
        "fieldSources": field_sources,
        "collectionOutcomes": [
            {"szlId":"0x0011", "index":0,"outcome":if hardware_response.is_empty() {"not-collected"} else if hardware.is_empty() {"malformed"} else {"success"}},
            {"szlId":"0x001C", "index":0,"outcome":if identity_response.is_empty() {"not-collected"} else if identity.is_empty() {"malformed"} else {"success"}}
        ],
        "serialClaim": serial.as_ref().map(|serial| json!({
            "scope": "cpu",
            "issuer": "Siemens",
            "original": serial,
            "encoding": "s7-szl-text",
            "catalogNumber": module.as_ref(),
            "normalizationVersion": 1,
        })),
    });
    Ok(Finding {
        source: Source::S7,
        fields,
        ports: vec![port("tcp", 102, Source::S7, json!({ "state": "open" }))],
        raw,
        warnings,
    })
}

fn record<'a>(records: &[(u16, &'a [u8])], index: u16) -> Option<&'a [u8]> {
    records
        .iter()
        .find(|(value, _)| *value == index)
        .map(|(_, value)| *value)
}

fn optional_szl<'a>(data: &'a [u8], id: u16, warnings: &mut Vec<String>) -> Vec<(u16, &'a [u8])> {
    if data.is_empty() {
        return Vec::new();
    }
    match szl(data, id) {
        Ok(records) => records,
        Err(error) => {
            warnings.push(format!("S7 SZL {id:04X}: {error}"));
            Vec::new()
        }
    }
}

fn setup_response(frame: &[u8]) -> bool {
    let Ok((rosctr, parameter, _, error)) = s7_frame(frame) else {
        return false;
    };
    rosctr == 3 && error == 0 && parameter.first() == Some(&0xf0)
}

fn userdata(frame: &[u8]) -> Result<(&[u8], bool), String> {
    let (rosctr, parameter, data, error) = s7_frame(frame)?;
    if rosctr != 7
        || error != 0
        || parameter.len() < 12
        || parameter[..5] != [0, 1, 0x12, 8, 0x12]
        || parameter[5] >> 6 != 2
        || parameter[5] & 0x3f != 4
        || parameter[6] != 1
        || parameter[10..12] != [0, 0]
        || data.len() < 4
        || data[0] != 0xff
        || data[1] != 9
    {
        return Err("invalid S7 SZL response".into());
    }
    let length = u16::from_be_bytes([data[2], data[3]]) as usize;
    if length != data.len() - 4 {
        return Err("invalid S7 SZL data length".into());
    }
    Ok((&data[4..], parameter[9] == 0))
}

type S7Frame<'a> = (u8, &'a [u8], &'a [u8], u16);

fn s7_frame(frame: &[u8]) -> Result<S7Frame<'_>, String> {
    if frame.len() < 17
        || frame[0] != 3
        || u16::from_be_bytes([frame[2], frame[3]]) as usize != frame.len()
        || frame[4..7] != [2, 0xf0, 0x80]
        || frame[7] != 0x32
    {
        return Err("invalid S7 frame".into());
    }
    let rosctr = frame[8];
    let parameter_length = u16::from_be_bytes([frame[13], frame[14]]) as usize;
    let data_length = u16::from_be_bytes([frame[15], frame[16]]) as usize;
    let header_length = if matches!(rosctr, 2 | 3) { 12 } else { 10 };
    let parameter_start: usize = 7 + header_length;
    let parameter_end = parameter_start
        .checked_add(parameter_length)
        .ok_or("invalid S7 length")?;
    let data_end = parameter_end
        .checked_add(data_length)
        .ok_or("invalid S7 length")?;
    if data_end != frame.len() {
        return Err("invalid S7 payload length".into());
    }
    let error = if header_length == 12 {
        u16::from_be_bytes([frame[17], frame[18]])
    } else {
        0
    };
    Ok((
        rosctr,
        &frame[parameter_start..parameter_end],
        &frame[parameter_end..data_end],
        error,
    ))
}

fn szl(data: &[u8], expected_id: u16) -> Result<Vec<(u16, &[u8])>, String> {
    if data.len() < 8
        || u16::from_be_bytes([data[0], data[1]]) != expected_id
        || data[2..4] != [0, 0]
    {
        return Err("unexpected S7 SZL identity".into());
    }
    let record_length = u16::from_be_bytes([data[4], data[5]]) as usize;
    let count = u16::from_be_bytes([data[6], data[7]]) as usize;
    if record_length < 2
        || 8 + record_length
            .checked_mul(count)
            .ok_or("invalid S7 SZL count")?
            != data.len()
    {
        return Err("invalid S7 SZL records".into());
    }
    Ok(data[8..]
        .chunks_exact(record_length)
        .map(|record| (u16::from_be_bytes([record[0], record[1]]), record))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    fn identities() -> (Vec<u8>, Vec<u8>) {
        let mut hardware = vec![0, 0x11, 0, 0, 0, 28, 0, 3];
        for (index, value) in [(1, "CPU-01"), (6, "6ES7-X"), (7, "Firmware")] {
            let mut record = vec![0; 28];
            record[..2].copy_from_slice(&u16::to_be_bytes(index));
            record[2..2 + value.len()].copy_from_slice(value.as_bytes());
            if index == 7 {
                record[25..28].copy_from_slice(&[3, 2, 1]);
            }
            hardware.extend(record);
        }
        let mut identity = vec![0, 0x1c, 0, 0, 0, 34, 0, 3];
        for (index, value) in [(1, "PLC1"), (2, "S7-1500"), (5, "SERIAL")] {
            let mut record = vec![0; 34];
            record[..2].copy_from_slice(&u16::to_be_bytes(index));
            record[2..2 + value.len()].copy_from_slice(value.as_bytes());
            identity.extend(record);
        }
        (hardware, identity)
    }

    fn s7_300_identities() -> (Vec<u8>, Vec<u8>) {
        // Synthetic records for the reported CPU model/firmware, with a test-only serial.
        let mut hardware = vec![0, 0x11, 0, 0, 0, 28, 0, 4];
        for (index, value) in [
            (1_u16, "6ES7 315-2EH14-0AB0"),
            (6, "6ES7 315-2EH14-0AB0"),
            (7, ""),
            (0x81, "Boot Loader"),
        ] {
            let mut record = [0; 28];
            record[..2].copy_from_slice(&index.to_be_bytes());
            record[2..2 + value.len()].copy_from_slice(value.as_bytes());
            if index == 7 {
                record[24..28].copy_from_slice(&[b'V', 3, 2, 14]);
            } else if index == 0x81 {
                record[24..28].copy_from_slice(&[b'A', 1, 0, 0]);
            }
            hardware.extend(record);
        }
        let mut identity = vec![0, 0x1c, 0, 0, 0, 34, 0, 3];
        for (index, value) in [
            (1_u16, "S7-300 LAB"),
            (2, "CPU 315-2 PN/DP"),
            (5, "TEST-S7-300"),
        ] {
            let mut record = [0; 34];
            record[..2].copy_from_slice(&index.to_be_bytes());
            record[2..2 + value.len()].copy_from_slice(value.as_bytes());
            identity.extend(record);
        }
        (hardware, identity)
    }

    async fn read_tpkt(stream: &mut TcpStream) -> Vec<u8> {
        let mut header = [0; 4];
        stream.read_exact(&mut header).await.unwrap();
        let mut frame = vec![0; u16::from_be_bytes([header[2], header[3]]) as usize];
        frame[..4].copy_from_slice(&header);
        stream.read_exact(&mut frame[4..]).await.unwrap();
        frame
    }

    fn setup_frame() -> Vec<u8> {
        vec![
            3, 0, 0, 20, 2, 0xf0, 0x80, 0x32, 3, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0xf0,
        ]
    }

    fn userdata_frame(payload: &[u8]) -> Vec<u8> {
        let parameter = [0, 1, 0x12, 8, 0x12, 0x84, 1, 0, 1, 0, 0, 0];
        let data_length = payload.len() + 4;
        let length = 17 + parameter.len() + data_length;
        let mut frame = vec![
            3,
            0,
            0,
            0,
            2,
            0xf0,
            0x80,
            0x32,
            7,
            0,
            0,
            0,
            0,
            0,
            parameter.len() as u8,
            0,
            data_length as u8,
        ];
        frame[2..4].copy_from_slice(&(length as u16).to_be_bytes());
        frame.extend(parameter);
        frame.extend([0xff, 9]);
        frame.extend((payload.len() as u16).to_be_bytes());
        frame.extend(payload);
        frame
    }

    #[test]
    fn parses_s7_identity_fields() {
        assert_eq!(&SZL_11[29..], &[0, 0x11, 0, 0]);
        assert_eq!(&SZL_1C[29..], &[0, 0x1c, 0, 0]);
        let (hardware, identity) = identities();
        let result = parse(&hardware, &identity).unwrap();
        assert_eq!(result.fields["name"], "PLC1");
        assert_eq!(result.fields["serialNumber"], "SERIAL");
        assert_eq!(result.raw["serialClaim"]["scope"], "cpu");
        assert_eq!(result.raw["identityResponse"], hex(&identity));
    }

    #[test]
    fn selects_firmware_by_record_id_in_reordered_s7_300_records() {
        let (mut hardware, identity) = s7_300_identities();
        hardware[8..].rotate_left(2 * 28);
        let finding = parse(&hardware, &identity).unwrap();
        assert_eq!(finding.fields["firmwareVersion"], "3.2.14");
        assert_eq!(finding.raw["version"], "3.2.14");
        assert_eq!(finding.raw["fieldSources"]["firmwareVersion"]["record"], 7);
        assert_eq!(finding.raw["response"], hex(&hardware));
        assert!(finding.warnings.is_empty());
    }

    #[test]
    fn rejects_truncated_firmware_records_without_losing_component_identity() {
        let (hardware, identity) = s7_300_identities();
        for length in [8 + 2 * 28 + 27, hardware.len() - 1] {
            let finding = parse(&hardware[..length], &identity).unwrap();
            assert!(!finding.fields.contains_key("firmwareVersion"));
            assert_eq!(finding.fields["serialNumber"], "TEST-S7-300");
            assert_eq!(finding.raw["collectionOutcomes"][0]["outcome"], "malformed");
            assert_eq!(finding.warnings, ["S7 SZL 0011: invalid S7 SZL records"]);
        }
    }

    #[test]
    fn retains_independent_szls_without_firmware_or_component_list() {
        let (mut hardware, identity) = identities();
        assert_eq!(
            parse(&[], &identity).unwrap().fields["serialNumber"],
            "SERIAL"
        );
        assert_eq!(parse(&hardware, &[]).unwrap().raw["module"], "CPU-01");
        hardware.truncate(8 + 2 * 28);
        hardware[7] = 2;
        let finding = parse(&hardware, &identity).unwrap();
        assert!(!finding.fields.contains_key("firmwareVersion"));
        assert_eq!(finding.raw["serialClaim"]["catalogNumber"], "CPU-01");
        assert_eq!(
            parse(&[1], &identity).unwrap().fields["serialNumber"],
            "SERIAL"
        );
        let mut wrong_index = identity;
        wrong_index[3] = 2;
        assert!(szl(&wrong_index, 0x1c).is_err());
    }

    #[test]
    fn builds_connect_request_with_tsaps() {
        let frame = connect_request(0x0100, 0x0102);
        assert_eq!(frame.len(), 22);
        assert_eq!(&frame[..4], &[0x03, 0x00, 0x00, 0x16]);
        assert_eq!(frame[5], 0xe0);
        assert_eq!(&frame[11..15], &[0xc1, 0x02, 0x01, 0x00]);
        assert_eq!(&frame[15..19], &[0xc2, 0x02, 0x01, 0x02]);
        assert_eq!(&frame[19..22], &[0xc0, 0x01, 0x0a]);

        let op = connect_request(0x0200, 0x0203);
        assert_eq!(&op[11..15], &[0xc1, 0x02, 0x02, 0x00]);
        assert_eq!(&op[15..19], &[0xc2, 0x02, 0x02, 0x03]);
    }

    #[test]
    fn tsap_pairs_cover_existing_slots_and_nse_alternate_without_duplicates() {
        assert_eq!(TSAP_PAIRS.len(), 13);
        assert!(TSAP_PAIRS.contains(&(0x0100, 0x0200)));
        for connection_type in [0x0100, 0x0200, 0x0300] {
            for slot in 0..=3 {
                assert!(TSAP_PAIRS.contains(&(connection_type, connection_type | slot)));
            }
        }
        let mut unique = std::collections::BTreeSet::new();
        for (src, dst) in TSAP_PAIRS {
            assert_eq!(src & 0xff, 0, "source TSAP must be rack/slot zero");
            assert!(unique.insert((src, dst)), "duplicate TSAP pairing");
        }
    }

    #[test]
    fn validates_userdata_envelope() {
        let parameter = [0, 1, 0x12, 8, 0x12, 0x84, 1, 0, 1, 0, 0, 0];
        let data = [0xff, 9, 0, 4, 0, 0x11, 0, 1];
        let length = 17 + parameter.len() + data.len();
        let mut frame = vec![
            3,
            0,
            0,
            length as u8,
            2,
            0xf0,
            0x80,
            0x32,
            7,
            0,
            0,
            0,
            0,
            0,
            parameter.len() as u8,
            0,
            data.len() as u8,
        ];
        frame.extend(parameter);
        frame.extend(data);
        assert_eq!(userdata(&frame).unwrap(), (&[0, 0x11, 0, 1][..], true));
        frame[26] = 1;
        assert!(!userdata(&frame).unwrap().1);
        frame[26] = 0;
        let last = frame.len() - 1;
        frame[last] = 2;
        assert!(userdata(&frame).is_ok());
        frame[8] = 3;
        assert!(userdata(&frame).is_err());
    }

    #[tokio::test]
    async fn probes_s7_identity() {
        let _network = crate::network_test_lock().await;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, CONNECT_PORT))
            .await
            .unwrap();
        let (hardware, identity) = identities();
        let responder = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            read_tpkt(&mut stream).await;
            stream.write_all(&[3, 0, 0, 7, 2, 0xd0, 0]).await.unwrap();
            read_tpkt(&mut stream).await;
            stream.write_all(&setup_frame()).await.unwrap();
            read_tpkt(&mut stream).await;
            stream.write_all(&userdata_frame(&hardware)).await.unwrap();
            read_tpkt(&mut stream).await;
            stream.write_all(&userdata_frame(&identity)).await.unwrap();
        });
        let finding = probe(Ipv4Addr::LOCALHOST).await.unwrap().unwrap();
        assert_eq!(finding.fields["name"], "PLC1");
        assert_eq!(finding.fields["model"], "S7-1500");
        assert_eq!(finding.raw["accessPath"]["slot"], 0);
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn retains_component_identity_when_hardware_szl_is_rejected() {
        let _network = crate::network_test_lock().await;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, CONNECT_PORT))
            .await
            .unwrap();
        let (_, identity) = identities();
        let responder = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            read_tpkt(&mut stream).await;
            stream.write_all(&[3, 0, 0, 7, 2, 0xd0, 0]).await.unwrap();
            read_tpkt(&mut stream).await;
            stream.write_all(&setup_frame()).await.unwrap();
            read_tpkt(&mut stream).await;
            let mut rejection = userdata_frame(&[]);
            rejection[27] = 1;
            stream.write_all(&rejection).await.unwrap();
            read_tpkt(&mut stream).await;
            stream.write_all(&userdata_frame(&identity)).await.unwrap();
        });
        let finding = probe(Ipv4Addr::LOCALHOST).await.unwrap().unwrap();
        assert_eq!(finding.fields["serialNumber"], "SERIAL");
        assert!(!finding.fields.contains_key("firmwareVersion"));
        assert!(
            finding
                .warnings
                .iter()
                .any(|warning| warning.contains("0011"))
        );
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn retains_firmware_when_component_szl_is_rejected() {
        let _network = crate::network_test_lock().await;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, CONNECT_PORT))
            .await
            .unwrap();
        let (hardware, _) = s7_300_identities();
        let expected_response = hex(&hardware);
        let responder = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            read_tpkt(&mut stream).await;
            stream.write_all(&[3, 0, 0, 7, 2, 0xd0, 0]).await.unwrap();
            assert_eq!(read_tpkt(&mut stream).await, SETUP);
            stream.write_all(&setup_frame()).await.unwrap();
            assert_eq!(read_tpkt(&mut stream).await, SZL_11);
            stream.write_all(&userdata_frame(&hardware)).await.unwrap();
            assert_eq!(read_tpkt(&mut stream).await, SZL_1C);
            let mut rejection = userdata_frame(&[]);
            rejection[27..29].copy_from_slice(&[0xd4, 0x02]);
            stream.write_all(&rejection).await.unwrap();
        });
        let finding = probe(Ipv4Addr::LOCALHOST).await.unwrap().unwrap();
        responder.await.unwrap();
        assert_eq!(finding.fields["firmwareVersion"], "3.2.14");
        assert_eq!(finding.fields["model"], "6ES7 315-2EH14-0AB0");
        assert!(!finding.fields.contains_key("serialNumber"));
        assert_eq!(finding.raw["response"], expected_response);
        assert_eq!(finding.raw["collectionOutcomes"][0]["outcome"], "success");
        assert!(
            finding
                .warnings
                .iter()
                .any(|warning| warning.contains("001C"))
        );
    }

    #[tokio::test]
    async fn reaches_s7_300_slot_after_cotp_succeeds_but_s7_setup_fails() {
        let _network = crate::network_test_lock().await;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, CONNECT_PORT))
            .await
            .unwrap();
        let (hardware, identity) = s7_300_identities();
        let responder = tokio::spawn(async move {
            for slot in [0, 1] {
                let (mut stream, _) = listener.accept().await.unwrap();
                assert_eq!(
                    read_tpkt(&mut stream).await,
                    connect_request(0x0100, 0x0100 | slot)
                );
                stream.write_all(&[3, 0, 0, 7, 2, 0xd0, 0]).await.unwrap();
                assert_eq!(read_tpkt(&mut stream).await, SETUP);
                if slot == 1 {
                    let mut rejection = setup_frame();
                    rejection[17..19].copy_from_slice(&[0x81, 0x04]);
                    stream.write_all(&rejection).await.unwrap();
                }
            }
            let (mut stream, _) = listener.accept().await.unwrap();
            assert_eq!(
                read_tpkt(&mut stream).await,
                connect_request(0x0100, 0x0102)
            );
            stream.write_all(&[3, 0, 0, 7, 2, 0xd0, 0]).await.unwrap();
            assert_eq!(read_tpkt(&mut stream).await, SETUP);
            stream.write_all(&setup_frame()).await.unwrap();
            assert_eq!(read_tpkt(&mut stream).await, SZL_11);
            stream.write_all(&userdata_frame(&hardware)).await.unwrap();
            assert_eq!(read_tpkt(&mut stream).await, SZL_1C);
            stream.write_all(&userdata_frame(&identity)).await.unwrap();
        });
        let finding = probe(Ipv4Addr::LOCALHOST).await.unwrap().unwrap();
        responder.await.unwrap();
        assert_eq!(finding.fields["firmwareVersion"], "3.2.14");
        assert_eq!(finding.fields["model"], "CPU 315-2 PN/DP");
        assert_eq!(finding.fields["serialNumber"], "TEST-S7-300");
        assert_eq!(
            finding.raw["accessPath"],
            json!({
                "sourceTsap": "0100", "destinationTsap": "0102", "rack": 0, "slot": 2
            })
        );
        assert!(finding.warnings.is_empty());
    }

    #[tokio::test]
    async fn probes_nse_alternate_tsap_pair() {
        let _network = crate::network_test_lock().await;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, CONNECT_PORT))
            .await
            .unwrap();
        let (hardware, identity) = s7_300_identities();
        let responder = tokio::spawn(async move {
            for slot in 0..=3 {
                let (mut stream, _) = listener.accept().await.unwrap();
                assert_eq!(
                    read_tpkt(&mut stream).await,
                    connect_request(0x0100, 0x0100 | slot)
                );
            }
            let (mut stream, _) = listener.accept().await.unwrap();
            assert_eq!(
                read_tpkt(&mut stream).await,
                connect_request(0x0100, 0x0200)
            );
            stream.write_all(&[3, 0, 0, 7, 2, 0xd0, 0]).await.unwrap();
            assert_eq!(read_tpkt(&mut stream).await, SETUP);
            stream.write_all(&setup_frame()).await.unwrap();
            assert_eq!(read_tpkt(&mut stream).await, SZL_11);
            stream.write_all(&userdata_frame(&hardware)).await.unwrap();
            assert_eq!(read_tpkt(&mut stream).await, SZL_1C);
            stream.write_all(&userdata_frame(&identity)).await.unwrap();
        });
        let finding = probe(Ipv4Addr::LOCALHOST).await.unwrap().unwrap();
        responder.await.unwrap();
        assert_eq!(finding.fields["firmwareVersion"], "3.2.14");
        assert_eq!(
            finding.raw["accessPath"],
            json!({
                "sourceTsap": "0100", "destinationTsap": "0200", "rack": 0, "slot": 0
            })
        );
        assert!(finding.warnings.is_empty());
    }

    #[tokio::test]
    async fn rejects_mismatched_and_malformed_szl_responses() {
        let (hardware, _) = s7_300_identities();
        for (offset, value, error) in [
            (12, 1, "mismatched S7 PDU reference"),
            (34, 0x1c, "mismatched S7 SZL ID/index"),
            (36, 1, "mismatched S7 SZL ID/index"),
            (32, 0, "invalid S7 SZL data length"),
        ] {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let address = listener.local_addr().unwrap();
            let mut frame = userdata_frame(&hardware);
            frame[offset] = value;
            let responder = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                assert_eq!(read_tpkt(&mut stream).await, SZL_11);
                stream.write_all(&frame).await.unwrap();
            });
            let mut stream = TcpStream::connect(address).await.unwrap();
            assert_eq!(read_szl(&mut stream, SZL_11).await.unwrap_err(), error);
            responder.await.unwrap();
        }
    }

    #[tokio::test]
    async fn retries_next_tsap_when_connect_request_is_rejected() {
        let _network = crate::network_test_lock().await;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, CONNECT_PORT))
            .await
            .unwrap();
        let (hardware, identity) = identities();
        let responder = tokio::spawn(async move {
            let (mut rejected, _) = listener.accept().await.unwrap();
            let first = read_tpkt(&mut rejected).await;
            assert_eq!(&first[17..19], &[0x01, 0x00]);
            drop(rejected);
            let (mut stream, _) = listener.accept().await.unwrap();
            let second = read_tpkt(&mut stream).await;
            assert_eq!(&second[17..19], &[0x01, 0x01]);
            stream.write_all(&[3, 0, 0, 7, 2, 0xd0, 0]).await.unwrap();
            read_tpkt(&mut stream).await;
            stream.write_all(&setup_frame()).await.unwrap();
            read_tpkt(&mut stream).await;
            stream.write_all(&userdata_frame(&hardware)).await.unwrap();
            read_tpkt(&mut stream).await;
            stream.write_all(&userdata_frame(&identity)).await.unwrap();
        });
        let finding = probe(Ipv4Addr::LOCALHOST).await.unwrap().unwrap();
        assert_eq!(finding.fields["name"], "PLC1");
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn cotp_peer_that_drops_the_s7_exchange_is_not_s7() {
        let _network = crate::network_test_lock().await;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, CONNECT_PORT))
            .await
            .unwrap();
        let responder = tokio::spawn(async move {
            for (source, destination) in TSAP_PAIRS {
                let (mut stream, _) = listener.accept().await.unwrap();
                assert_eq!(
                    read_tpkt(&mut stream).await,
                    connect_request(source, destination)
                );
                stream.write_all(&[3, 0, 0, 7, 2, 0xd0, 0]).await.unwrap();
                assert_eq!(read_tpkt(&mut stream).await, SETUP);
                // An MMS server accepts COTP but drops the S7 setup on every TSAP.
            }
        });
        assert!(
            timeout(
                std::time::Duration::from_secs(5),
                probe(Ipv4Addr::LOCALHOST)
            )
            .await
            .unwrap()
            .unwrap()
            .is_none()
        );
        timeout(TIMEOUT, responder).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn rejects_invalid_and_truncated_tpkt_frames() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut server, _) = listener.accept().await.unwrap();
            server.write_all(&[2, 0, 0, 4]).await.unwrap();
        });
        let mut client = TcpStream::connect(address).await.unwrap();
        assert!(read_frame(&mut client).await.unwrap_err().contains("TPKT"));

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { listener.accept().await.unwrap() });
        let mut client = TcpStream::connect(address).await.unwrap();
        assert!(read_frame(&mut client).await.is_err());
        assert!(!setup_response(&[]));
        assert!(szl(&[], 0x11).is_err());
    }
}
