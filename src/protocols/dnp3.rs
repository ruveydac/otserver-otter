use super::{Finding, TIMEOUT, hex, port};
use crate::contract::Source;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

const PORT: u16 = 20000;
const BLOCK: usize = 16;
const MAX_FRAMES: usize = 64;

// Link layer control bits and function codes (IEEE 1815 clause 5).
const DIR: u8 = 0x80;
const PRM: u8 = 0x40;
const FCV: u8 = 0x10;
const FUNCTION: u8 = 0x0F;
const RESET_LINK_STATES: u8 = 0x00;
const CONFIRMED_USER_DATA: u8 = 0x03;
const ACK: u8 = 0x00;
const NACK: u8 = 0x01;
const USER_DATA: u8 = 0x04;
const LINK_STATUS: u8 = 0x0B;
const NOT_FUNCTIONING: u8 = 0x0E;
const NOT_IMPLEMENTED: u8 = 0x0F;

// Transport layer control bits (clause 8): bit 7 is FIN and bit 6 is FIR.
const TL_FIN: u8 = 0x80;
const TL_FIR: u8 = 0x40;

// Application layer control bits and function codes (clause 4): bit 7 is FIR and bit 6 is FIN.
const AL_FIR: u8 = 0x80;
const AL_FIN: u8 = 0x40;
const READ: u8 = 0x01;
const RESPONSE: u8 = 0x81;
const UNSOLICITED: u8 = 0x82;

// Object header qualifier: the high nibble prefixes each object, the low nibble sizes the range.
const PREFIX: u8 = 0xF0;
const RANGE: u8 = 0x0F;

// Internal indication bits in the second response octet.
const IIN_FUNCTION_NOT_IMPLEMENTED: u8 = 0x01;
const IIN_OBJECTS_UNKNOWN: u8 = 0x02;

/// Outstation and master address pairs sent as one pipelined cold start. An outstation silently
/// drops frames addressed elsewhere, so the matching pair answers and the rest cost only bytes.
const ADDRESSES: [(u16, u16); 4] = [(1, 1), (1, 1024), (1024, 1), (0, 0)];

/// Read Group 0 Variation 254 (all attributes) with the "all objects" qualifier: transport
/// control, application control, function code, group, variation, qualifier.
const READ_ATTRIBUTES: [u8; 6] = [TL_FIN | TL_FIR, AL_FIR | AL_FIN, READ, 0x00, 0xfe, 0x06];

/// Group 0 variations kept as named evidence, per IEEE 1815 device attributes.
const ATTRIBUTES: [(u8, &str); 16] = [
    (196, "configurationId"),
    (197, "configurationVersion"),
    (198, "configurationBuildDate"),
    (199, "configurationLastChangeDate"),
    (200, "configurationDigest"),
    (201, "configurationDigestAlgorithm"),
    (242, "softwareVersion"),
    (243, "hardwareVersion"),
    (244, "owner"),
    (245, "location"),
    (246, "idCode"),
    (247, "deviceName"),
    (248, "serialNumber"),
    (249, "conformance"),
    (250, "productName"),
    (252, "manufacturer"),
];

#[derive(Debug)]
struct Frame {
    control: u8,
    destination: u16,
    source: u16,
    data: Vec<u8>,
}

#[derive(Debug, Default)]
struct Reply {
    response: Option<Vec<u8>>,
    outstation: Option<u16>,
    master: Option<u16>,
    link: bool,
    warnings: Vec<String>,
}

pub async fn probe(target: Ipv4Addr) -> Result<Option<Finding>, String> {
    let address = SocketAddr::new(IpAddr::V4(target), PORT);
    crate::traffic::wait().await;
    let mut stream = match timeout(TIMEOUT, TcpStream::connect(address)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) if error.kind() == ErrorKind::ConnectionRefused => return Ok(None),
        Ok(Err(error)) => return Err(format!("DNP3 {target}:{PORT}: {error}")),
        Err(_) => return Ok(None),
    };
    let mut reply = exchange(&mut stream)
        .await
        .map_err(|error| format!("DNP3 {target}:{PORT}: {error}"))?;
    if !reply.link {
        return Ok(None);
    }
    let ports = vec![port("tcp", PORT, Source::Dnp3, json!({ "state": "open" }))];
    let Some(pdu) = reply.response else {
        reply
            .warnings
            .push("DNP3 link layer replied without an application response.".into());
        return Ok(Some(Finding {
            source: Source::Dnp3,
            fields: BTreeMap::from([("protocols".into(), json!(["dnp3"]))]),
            raw: json!({ "outstationAddress": reply.outstation, "masterAddress": reply.master }),
            ports,
            warnings: reply.warnings,
        }));
    };
    let (mut values, mut parsed) = parse(&pdu)?;
    reply.warnings.append(&mut parsed);
    values.insert("outstationAddress".into(), json!(reply.outstation));
    values.insert("masterAddress".into(), json!(reply.master));
    values.insert("response".into(), json!(hex(&pdu)));
    let mut fields = BTreeMap::from([("protocols".into(), json!(["dnp3"]))]);
    for (source, field) in [
        ("deviceName", "name"),
        ("productName", "model"),
        ("manufacturer", "vendor"),
        ("softwareVersion", "firmwareVersion"),
        ("hardwareVersion", "hardwareVersion"),
        ("serialNumber", "serialNumber"),
        ("location", "location"),
    ] {
        if let Some(value) = values.get(source).filter(|value| value.is_string()) {
            fields.insert(field.into(), value.clone());
        }
    }
    if let Some(model) = fields.get("model").cloned() {
        fields.entry("name".into()).or_insert(model);
    }
    Ok(Some(Finding {
        source: Source::Dnp3,
        fields,
        raw: Value::Object(values),
        ports,
        warnings: reply.warnings,
    }))
}

/// Runs the read-only cold start and keeps the first application response.
async fn exchange(stream: &mut (impl AsyncRead + AsyncWrite + Unpin)) -> Result<Reply, String> {
    crate::traffic::wait().await;
    timeout(TIMEOUT, stream.write_all(&request()))
        .await
        .map_err(|_| "DNP3 write timed out".to_string())?
        .map_err(|error| error.to_string())?;
    let mut reply = Reply::default();
    let mut segment = None;
    let mut fragment = None;
    let mut transport_sequence = None;
    let mut application_sequence = None;
    let deadline = tokio::time::Instant::now() + TIMEOUT * 2;
    for _ in 0..MAX_FRAMES {
        let Some(frame) = (match tokio::time::timeout_at(deadline, read(stream)).await {
            Ok(result) => result?,
            Err(_) => {
                reply.warnings.push("DNP3 exchange timed out".into());
                break;
            }
        }) else {
            break;
        };
        if frame.control & (DIR | PRM) != 0 {
            return Err("reply is not a secondary DNP3 frame".into());
        }
        if !ADDRESSES.contains(&(frame.source, frame.destination)) {
            return Err("unrequested DNP3 address pair".into());
        }
        if (segment.is_some() || fragment.is_some())
            && (reply.outstation != Some(frame.source) || reply.master != Some(frame.destination))
        {
            return Err("mixed DNP3 address pairs".into());
        }
        if reply.outstation.is_none() {
            reply.outstation = Some(frame.source);
            reply.master = Some(frame.destination);
        }
        match frame.control & FUNCTION {
            USER_DATA => {
                reply.outstation = Some(frame.source);
                reply.master = Some(frame.destination);
                reply.link = true;
                let control = *frame.data.first().ok_or("empty DNP3 transport")?;
                check_sequence(
                    &mut transport_sequence,
                    control & 0x3f,
                    control & TL_FIR != 0,
                    0x3f,
                )?;
                if control & TL_FIR != 0 {
                    let app = *frame.data.get(1).ok_or("empty DNP3 application")?;
                    // Unsolicited data is not a reply to our request.
                    if frame.data.get(2) == Some(&UNSOLICITED) {
                        continue;
                    }
                    check_sequence(
                        &mut application_sequence,
                        app & 0x0f,
                        app & AL_FIR != 0,
                        0x0f,
                    )?;
                    if app & AL_FIR != 0 && app & 0x0f != 0 {
                        return Err("mismatched DNP3 application sequence".into());
                    }
                }
                let Some(pdu) = reassemble(&mut segment, &mut fragment, &frame.data)? else {
                    continue;
                };
                match pdu.first() {
                    Some(&RESPONSE) => {
                        reply.response = Some(pdu);
                        break;
                    }
                    // Unsolicited reports prove the protocol but answer no request.
                    Some(&UNSOLICITED) => continue,
                    Some(function) => {
                        return Err(format!("unexpected DNP3 function code {function:#04X}"));
                    }
                    None => return Err("empty DNP3 application response".into()),
                }
            }
            ACK | LINK_STATUS => reply.link = true,
            NACK => {
                reply.link = true;
                reply
                    .warnings
                    .push("DNP3 outstation rejected the request at the link layer.".into());
            }
            NOT_FUNCTIONING | NOT_IMPLEMENTED => {
                reply.link = true;
                reply
                    .warnings
                    .push("DNP3 link service is not functioning.".into());
            }
            function => return Err(format!("unexpected DNP3 link function {function:#04X}")),
        }
    }
    Ok(reply)
}

fn check_sequence(
    previous: &mut Option<u8>,
    sequence: u8,
    first: bool,
    mask: u8,
) -> Result<(), String> {
    if !first && previous.is_none_or(|value| sequence != value.wrapping_add(1) & mask) {
        return Err("out-of-order DNP3 fragment".into());
    }
    *previous = Some(sequence);
    Ok(())
}

/// Folds one user data frame through transport and application reassembly and returns the
/// application PDU once its final fragment arrives.
fn reassemble(
    segment: &mut Option<Vec<u8>>,
    fragment: &mut Option<Vec<u8>>,
    data: &[u8],
) -> Result<Option<Vec<u8>>, String> {
    let (control, payload) = data
        .split_first()
        .ok_or_else(|| "empty DNP3 user data frame".to_string())?;
    fold(segment, control & TL_FIR != 0, payload)?;
    if control & TL_FIN == 0 {
        return Ok(None);
    }
    let assembled = segment.take().unwrap_or_default();
    let Some((&control, payload)) = assembled.split_first() else {
        return Err("empty DNP3 application fragment".into());
    };
    if control & AL_FIR != 0 {
        fold(fragment, true, payload)?;
    } else {
        let previous = fragment
            .as_mut()
            .ok_or("DNP3 continuation without a first frame")?;
        if payload.len() < 3 || previous.len() < 3 || previous[0] != payload[0] {
            return Err("mismatched DNP3 application fragment".into());
        }
        previous[1] |= payload[1];
        previous[2] |= payload[2];
        if previous.len() + payload.len() - 3 > 65_535 {
            return Err("oversized DNP3 response".into());
        }
        previous.extend_from_slice(&payload[3..]);
    }
    if control & AL_FIN == 0 {
        return Ok(None);
    }
    Ok(fragment.take())
}

/// Starts a new buffer on a first-frame flag and appends to it otherwise.
fn fold(buffer: &mut Option<Vec<u8>>, first: bool, payload: &[u8]) -> Result<(), String> {
    if buffer
        .as_ref()
        .is_some_and(|buffer| buffer.len() + payload.len() > 65_535 || first)
    {
        return Err("oversized or restarted DNP3 fragment".into());
    }
    match buffer {
        _ if first => *buffer = Some(payload.to_vec()),
        Some(buffer) => buffer.extend_from_slice(payload),
        None => return Err("DNP3 continuation without a first frame".into()),
    }
    Ok(())
}

/// One read-only cold start per candidate address pair: a link reset so the outstation accepts the
/// first frame count bit, then a confirmed read of all device attributes.
fn request() -> Vec<u8> {
    let mut request = Vec::with_capacity(ADDRESSES.len() * 28);
    for (outstation, master) in ADDRESSES {
        request.extend(frame(
            DIR | PRM | RESET_LINK_STATES,
            outstation,
            master,
            &[],
        ));
        request.extend(frame(
            DIR | PRM | FCV | CONFIRMED_USER_DATA,
            outstation,
            master,
            &READ_ATTRIBUTES,
        ));
    }
    request
}

/// Builds a link frame. The length octet counts the control and address octets plus the user data
/// but no checksums, and the header checksum covers the two start octets.
fn frame(control: u8, destination: u16, source: u16, data: &[u8]) -> Vec<u8> {
    let mut frame = vec![0x05, 0x64, (5 + data.len()) as u8, control];
    frame.extend_from_slice(&destination.to_le_bytes());
    frame.extend_from_slice(&source.to_le_bytes());
    append_crc(&mut frame, 0);
    for block in data.chunks(BLOCK) {
        let start = frame.len();
        frame.extend_from_slice(block);
        append_crc(&mut frame, start);
    }
    frame
}

fn append_crc(frame: &mut Vec<u8>, start: usize) {
    let crc = crc(&frame[start..]);
    frame.extend_from_slice(&crc.to_le_bytes());
}

/// CRC-16/DNP: reflected polynomial 0xA6BC, zero seed, inverted result, little endian on the wire.
fn crc(data: &[u8]) -> u16 {
    let mut crc = 0;
    for byte in data {
        crc ^= u16::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xA6BC
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// Reads and validates one link frame. `Ok(None)` ends the exchange on a timeout or on a close at a
/// frame boundary; anything malformed is an error.
async fn read(stream: &mut (impl AsyncRead + AsyncWrite + Unpin)) -> Result<Option<Frame>, String> {
    let mut header = [0; 8];
    match timeout(TIMEOUT, stream.read_exact(&mut header)).await {
        Ok(Ok(_)) => {}
        // A close or a reset at a frame boundary ends the exchange; the frames already parsed stand.
        Ok(Err(error))
            if matches!(
                error.kind(),
                ErrorKind::UnexpectedEof | ErrorKind::ConnectionReset
            ) =>
        {
            return Ok(None);
        }
        Ok(Err(error)) => return Err(error.to_string()),
        Err(_) => return Ok(None),
    };
    if header[..2] != [0x05, 0x64] {
        return Err("invalid DNP3 start bytes".into());
    }
    if header[2] < 5 {
        return Err("truncated DNP3 frame".into());
    }
    let length = usize::from(header[2]) - 5;
    let mut body = vec![0; 2 + length + 2 * length.div_ceil(BLOCK)];
    timeout(TIMEOUT, stream.read_exact(&mut body))
        .await
        .map_err(|_| "DNP3 response timed out".to_string())?
        .map_err(|_| "truncated DNP3 response".to_string())?;
    if crc(&header) != u16::from_le_bytes(body[..2].try_into().unwrap()) {
        return Err("invalid DNP3 header checksum".into());
    }
    let mut data = Vec::with_capacity(length);
    let mut cursor = 2;
    while cursor < body.len() {
        let block = &body[cursor..cursor + BLOCK.min(length - data.len())];
        cursor += block.len();
        if crc(block) != u16::from_le_bytes(body[cursor..cursor + 2].try_into().unwrap()) {
            return Err("invalid DNP3 data checksum".into());
        }
        cursor += 2;
        data.extend_from_slice(block);
    }
    Ok(Some(Frame {
        control: header[3],
        destination: u16::from_le_bytes(header[4..6].try_into().unwrap()),
        source: u16::from_le_bytes(header[6..8].try_into().unwrap()),
        data,
    }))
}

/// Decodes a reassembled application response into named device attributes and warnings.
fn parse(pdu: &[u8]) -> Result<(Map<String, Value>, Vec<String>), String> {
    let [function, iin1, iin2, objects @ ..] = pdu else {
        return Err("truncated DNP3 application response".into());
    };
    if *function != RESPONSE {
        return Err(format!("unexpected DNP3 function code {function:#04X}"));
    }
    let mut warnings = Vec::new();
    if iin2 & IIN_FUNCTION_NOT_IMPLEMENTED != 0 {
        warnings.push("DNP3 outstation does not implement the read function.".into());
    }
    if iin2 & IIN_OBJECTS_UNKNOWN != 0 {
        warnings.push("DNP3 outstation does not implement Group 0 device attributes.".into());
    }
    let mut attributes = BTreeMap::<u8, Value>::new();
    let mut records = Vec::new();
    let mut sources = Map::new();
    let mut cursor = 0;
    'objects: while cursor + 3 <= objects.len() {
        let group = objects[cursor];
        let variation = objects[cursor + 1];
        let qualifier = objects[cursor + 2];
        cursor += 3;
        let Some((count, size)) = range(group, qualifier, &objects[cursor..]) else {
            warnings.push(format!(
                "Skipped DNP3 object {group}:{variation} with qualifier {qualifier:#04X}."
            ));
            break;
        };
        let start = match qualifier & RANGE {
            0 => usize::from(objects[cursor]),
            1 => usize::from(u16::from_le_bytes([objects[cursor], objects[cursor + 1]])),
            _ => 0,
        };
        cursor += size;
        for index in 0..count {
            let Some(end) = attribute_end(objects, cursor) else {
                warnings.push(format!("Truncated DNP3 device attribute 0:{variation}."));
                break 'objects;
            };
            let data_type = objects[cursor];
            let bytes = &objects[cursor + 2..end];
            let value = typed_attribute(data_type, bytes);
            let set = matches!(qualifier & RANGE, 0 | 1).then_some(start + index);
            records.push(json!({"set": set, "variation": variation, "dataType": data_type, "raw": hex(bytes), "value": value}));
            if set == Some(0)
                && let Some(value) = value
            {
                // Only the standard set contributes to manufacturer identity.
                attributes.entry(variation).or_insert(value);
            }
            cursor = end;
        }
    }
    let mut values = Map::from_iter([
        ("iin1".into(), json!(format!("{iin1:02X}"))),
        ("iin2".into(), json!(format!("{iin2:02X}"))),
        ("attributes".into(), json!(attributes)),
        ("attributeRecords".into(), json!(records)),
        (
            "indications".into(),
            json!({"restart": iin1 & 0x80 != 0, "deviceTrouble": iin1 & 0x40 != 0, "configurationCorrupt": iin2 & 0x20 != 0, "class1Pending": iin1 & 2 != 0, "class2Pending": iin1 & 4 != 0, "class3Pending": iin1 & 8 != 0}),
        ),
    ]);
    for (variation, name) in ATTRIBUTES {
        if let Some(value) = attributes.get(&variation) {
            values.insert(name.into(), value.clone());
            sources.insert(name.into(), json!({"group": 0, "variation": variation, "set": 0, "mutable": matches!(variation, 244..=247)}));
        }
    }
    values.insert("fieldSources".into(), sources.into());
    Ok((values, warnings))
}

fn typed_attribute(data_type: u8, value: &[u8]) -> Option<Value> {
    match (data_type, value.len()) {
        (1, _) => std::str::from_utf8(value)
            .ok()
            .filter(|text| {
                text.bytes()
                    .all(|byte| byte.is_ascii_graphic() || byte == b' ')
            })
            .map(|text| json!(text.trim())),
        (2, 1 | 2 | 4) => Some(json!(
            value
                .iter()
                .rev()
                .fold(0_u32, |number, byte| number << 8 | u32::from(*byte))
        )),
        (3, 1) => Some(json!(value[0] as i8)),
        (3, 2) => Some(json!(i16::from_le_bytes(value.try_into().ok()?))),
        (3, 4) => Some(json!(i32::from_le_bytes(value.try_into().ok()?))),
        (4, 4) => {
            let number = f32::from_le_bytes(value.try_into().ok()?);
            number.is_finite().then(|| json!(number))
        }
        (4, 8) => {
            let number = f64::from_le_bytes(value.try_into().ok()?);
            number.is_finite().then(|| json!(number))
        }
        (5 | 6, _) => Some(json!({"hex": hex(value)})),
        (7, 6) => Some(
            json!({"millisecondsSinceEpoch": value.iter().rev().fold(0_u64, |number, byte| number << 8 | u64::from(*byte))}),
        ),
        _ => None,
    }
}

/// Object count and range-field size for a qualifier. Only unprefixed Group 0 headers are decoded
/// because no other object has a length this scanner can trust.
fn range(group: u8, qualifier: u8, rest: &[u8]) -> Option<(usize, usize)> {
    if group != 0 || qualifier & PREFIX != 0 {
        return None;
    }
    match qualifier & RANGE {
        0x00 => {
            let [start, stop, ..] = rest else {
                return None;
            };
            (stop >= start).then(|| (usize::from(stop - start) + 1, 2))
        }
        0x01 => {
            if rest.len() < 4 {
                return None;
            }
            let start = u16::from_le_bytes(rest[..2].try_into().unwrap());
            let stop = u16::from_le_bytes(rest[2..4].try_into().unwrap());
            (stop >= start).then(|| (usize::from(stop - start) + 1, 4))
        }
        0x06 => Some((1, 0)),
        0x07 => Some((usize::from(*rest.first()?), 1)),
        0x08 => Some((
            usize::from(u16::from_le_bytes(rest.get(..2)?.try_into().unwrap())),
            2,
        )),
        _ => None,
    }
}

/// End offset including the extended attribute-list length, or `None` for truncation.
fn attribute_end(objects: &[u8], cursor: usize) -> Option<usize> {
    let length = usize::from(*objects.get(cursor + 1)?)
        + if objects.get(cursor) == Some(&255) {
            256
        } else {
            0
        };
    let end = cursor.checked_add(2 + length)?;
    (end <= objects.len()).then_some(end)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;
    use tokio::net::TcpListener;

    const OUTSTATION: u16 = 1024;
    const MASTER: u16 = 1;

    fn unhex(value: &str) -> Vec<u8> {
        (0..value.len() / 2)
            .map(|index| u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap())
            .collect()
    }

    /// One Group 0 device attribute from standard set zero.
    fn attribute_object(variation: u8, data_type: u8, value: &[u8]) -> Vec<u8> {
        let mut object = vec![0x00, variation, 0, 0, 0, data_type, value.len() as u8];
        object.extend_from_slice(value);
        object
    }

    /// Standard visible strings plus a numeric attribute.
    fn identity_pdu() -> Vec<u8> {
        let mut pdu = vec![RESPONSE, 0x00, 0x00];
        for object in [
            attribute_object(247, 1, b"PUMP-RTU-1"),
            attribute_object(250, 0x01, b"FB3000"),
            attribute_object(252, 1, b"Emerson"),
            attribute_object(248, 1, b"SN-000123"),
            attribute_object(242, 1, b"5.2.1"),
            attribute_object(243, 1, b"HW-2"),
            attribute_object(245, 1, b"Cell 1  "),
            attribute_object(246, 1, b"ID-42"),
            attribute_object(249, 0x02, &[3]),
        ] {
            pdu.extend(object);
        }
        pdu
    }

    /// Secondary frame carrying one complete transport and application fragment.
    fn reply_frame(pdu: &[u8]) -> Vec<u8> {
        let mut data = vec![TL_FIN | TL_FIR, AL_FIR | AL_FIN];
        data.extend_from_slice(pdu);
        frame(USER_DATA, MASTER, OUTSTATION, &data)
    }

    /// One application fragment split over two transport frames.
    fn segments(pdu: &[u8]) -> Vec<Vec<u8>> {
        let split = pdu.len() / 2;
        let mut first = vec![TL_FIR, AL_FIR | AL_FIN];
        first.extend_from_slice(&pdu[..split]);
        let mut last = vec![TL_FIN | 1];
        last.extend_from_slice(&pdu[split..]);
        [first, last]
            .iter()
            .map(|data| frame(USER_DATA, MASTER, OUTSTATION, data))
            .collect()
    }

    /// One application response split over two complete transport frames.
    fn fragments(pdu: &[u8]) -> Vec<Vec<u8>> {
        let split = pdu.len() / 2;
        let mut first = vec![TL_FIN | TL_FIR, AL_FIR];
        first.extend_from_slice(&pdu[..split]);
        let mut last = vec![TL_FIN | TL_FIR | 1, AL_FIN | 1];
        last.extend_from_slice(&pdu[..3]);
        last.extend_from_slice(&pdu[split..]);
        [first, last]
            .iter()
            .map(|data| frame(USER_DATA, MASTER, OUTSTATION, data))
            .collect()
    }

    /// Outstation side of a link: it drops frames for other addresses like a real device,
    /// acknowledges every frame addressed to it, and answers the confirmed read with `replies`.
    async fn outstation(
        mut server: impl AsyncRead + AsyncWrite + Unpin,
        address: u16,
        replies: Vec<Vec<u8>>,
    ) {
        let mut replied = false;
        for _ in 0..ADDRESSES.len() * 2 {
            let Some(received) = read(&mut server).await.unwrap() else {
                return;
            };
            if received.destination != address {
                continue;
            }
            server
                .write_all(&frame(ACK, received.source, address, &[]))
                .await
                .unwrap();
            if received.control & FUNCTION != RESET_LINK_STATES && !replied {
                for reply in &replies {
                    server.write_all(reply).await.unwrap();
                }
                replied = true;
            }
        }
    }

    /// Writes `replies` after consuming the pipelined request, then closes the link.
    async fn exchanges(replies: &[Vec<u8>]) -> Result<Reply, String> {
        let (mut client, mut server) = duplex(4096);
        let expected = request();
        let replies = replies.to_vec();
        let writer = tokio::spawn(async move {
            let mut buffer = vec![0; expected.len()];
            server.read_exact(&mut buffer).await.unwrap();
            assert_eq!(buffer, expected);
            for reply in &replies {
                server.write_all(reply).await.unwrap();
            }
        });
        let result = exchange(&mut client).await;
        writer.await.unwrap();
        result
    }

    #[tokio::test(start_paused = true)]
    async fn records_an_exchange_timeout_after_a_partial_transport_segment() {
        let (mut client, mut server) = duplex(1024);
        let responder = tokio::spawn(async move {
            let mut request_frame = vec![0; request().len()];
            server.read_exact(&mut request_frame).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
            server
                .write_all(&frame(
                    USER_DATA,
                    MASTER,
                    OUTSTATION,
                    &[TL_FIN | TL_FIR, AL_FIR | AL_FIN, UNSOLICITED],
                ))
                .await
                .unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
            server
                .write_all(&frame(
                    USER_DATA,
                    MASTER,
                    OUTSTATION,
                    &[TL_FIN | TL_FIR | 1, AL_FIR | AL_FIN | 1, UNSOLICITED],
                ))
                .await
                .unwrap();
            std::future::pending::<()>().await;
        });

        let reply = exchange(&mut client).await.unwrap();

        assert!(reply.link);
        assert!(reply.response.is_none());
        assert_eq!(reply.warnings, ["DNP3 exchange timed out"]);
        responder.abort();
    }

    async fn reads(bytes: &[u8]) -> Result<Option<Frame>, String> {
        let (mut client, mut server) = duplex(4096);
        let bytes = bytes.to_vec();
        let writer = tokio::spawn(async move {
            server.write_all(&bytes).await.unwrap();
        });
        let result = read(&mut client).await;
        writer.await.unwrap();
        result
    }

    #[test]
    fn matches_published_link_layer_vectors() {
        assert_eq!(crc(b"123456789"), 0xEA82);
        // Vectors published by the open-source opendnp3 link layer tests: the header checksum
        // covers the start octets and every 16 octet data block carries its own checksum.
        assert_eq!(
            hex(&frame(DIR | PRM | RESET_LINK_STATES, 1, 1024, &[])),
            "056405C001000004E921"
        );
        assert_eq!(
            hex(&frame(ACK, 1024, 1, &[])),
            "0564050000040100 19A6".replace(' ', "")
        );
        assert_eq!(
            hex(&frame(
                0xF3,
                1,
                1024,
                &unhex("C0C3013C02063C03063C04063C0106")
            )),
            "056414F3010000040A3BC0C3013C02063C03063C04063C01069A12"
        );
        assert_eq!(
            hex(&frame(0x73, 1024, 1, &unhex(
                "C1E38196000201280100000001020128010001000102012801000200010201280100030001200228010000\
                 000100002002280100010001000001010100000300001E020100000100010000010000"
                    .replace(' ', "")
                    .as_str()
            ))),
            "056453730004010003FCC1E38196000201280100000001020128052401000100010201280100020001\
             020128B47701000300012002280100000001000020A525022801000100010000010101000003002FAC001E02\
             010000010001000001000016ED"
                .replace(' ', "")
        );
    }

    #[test]
    fn pipelines_a_cold_start_for_every_candidate_address() {
        let request = request();
        assert_eq!(request.len(), ADDRESSES.len() * 28);
        assert_eq!(hex(&request[..10]), "056405C001000100DF53");
        assert_eq!(
            hex(&request[10..28]),
            "05640BD301000100426DC0C00100FE065DB9"
        );
        assert_eq!(request[13] & 0x20, 0, "first frame count bit after a reset");
        assert_eq!(
            &request[20..26],
            &[TL_FIN | TL_FIR, AL_FIR | AL_FIN, READ, 0x00, 0xfe, 0x06]
        );
    }

    #[test]
    fn decodes_typed_device_attributes() {
        let (values, warnings) = parse(&identity_pdu()).unwrap();
        assert!(warnings.is_empty());
        assert_eq!(values["deviceName"], "PUMP-RTU-1");
        assert_eq!(values["productName"], "FB3000");
        assert_eq!(values["manufacturer"], "Emerson");
        assert_eq!(values["serialNumber"], "SN-000123");
        assert_eq!(values["softwareVersion"], "5.2.1");
        assert_eq!(values["hardwareVersion"], "HW-2");
        assert_eq!(values["location"], "Cell 1");
        assert_eq!(values["idCode"], "ID-42");
        assert_eq!(values["conformance"], 3);
        assert_eq!(values["iin1"], "00");
        assert_eq!(values["attributes"]["247"], "PUMP-RTU-1");
        assert_eq!(values["attributes"].as_object().unwrap().len(), 9);
    }

    #[test]
    fn decodes_attribute_values_by_type_not_printability() {
        assert_eq!(typed_attribute(1, b"Pump 7"), Some(json!("Pump 7")));
        assert_eq!(
            typed_attribute(5, b"Pump 7"),
            Some(json!({"hex":"50756D702037"}))
        );
        assert_eq!(typed_attribute(2, b"AB"), Some(json!(16961)));
        assert_eq!(typed_attribute(3, &[0xff]), Some(json!(-1)));
        assert_eq!(typed_attribute(254, b"Pump 7"), None);
        assert_eq!(
            typed_attribute(3, &(-258_i16).to_le_bytes()),
            Some(json!(-258))
        );
        assert_eq!(
            typed_attribute(3, &(-65_538_i32).to_le_bytes()),
            Some(json!(-65_538))
        );
        assert_eq!(typed_attribute(3, &[1, 2, 3]), None);
        assert_eq!(typed_attribute(2, &[1, 2, 3]), None);
        assert_eq!(typed_attribute(4, &1.5_f32.to_le_bytes()), Some(json!(1.5)));
        assert_eq!(typed_attribute(4, &f32::NAN.to_le_bytes()), None);
        assert_eq!(typed_attribute(4, &2.5_f64.to_le_bytes()), Some(json!(2.5)));
        assert_eq!(typed_attribute(4, &f64::INFINITY.to_le_bytes()), None);
        assert_eq!(typed_attribute(6, &[0, 255]), Some(json!({"hex":"00FF"})));
        assert_eq!(
            typed_attribute(7, &[1, 0, 0, 0, 0, 0]),
            Some(json!({"millisecondsSinceEpoch": 1}))
        );
        assert_eq!(typed_attribute(7, &[1]), None);
    }

    #[test]
    fn private_sets_and_unknown_types_never_override_manufacturer_identity() {
        let mut pdu = identity_pdu();
        let mut private = attribute_object(248, 1, b"PRIVATE");
        private[3..5].copy_from_slice(&[9, 9]);
        pdu.extend(private);
        pdu.extend(attribute_object(196, 1, b"CONFIG-1"));
        pdu.extend(attribute_object(250, 254, b"NOT-A-MODEL"));
        let (values, _) = parse(&pdu).unwrap();
        assert_eq!(values["serialNumber"], "SN-000123");
        assert_eq!(values["productName"], "FB3000");
        assert_eq!(values["configurationId"], "CONFIG-1");
        assert!(
            values["attributeRecords"]
                .as_array()
                .unwrap()
                .iter()
                .any(|record| record["set"] == 9)
        );
    }

    #[tokio::test]
    async fn rejects_wrong_address_and_reordered_transport_sequences() {
        assert!(
            exchanges(&[frame(USER_DATA, 44, 55, &[0xc0, 0xc0, 0x81, 0, 0])])
                .await
                .unwrap_err()
                .contains("address")
        );
        let pdu = identity_pdu();
        let split = pdu.len() / 2;
        let mut first = vec![0x40, 0xc0];
        first.extend(&pdu[..split]);
        let mut last = vec![0x83];
        last.extend(&pdu[split..]);
        assert!(
            exchanges(&[
                frame(USER_DATA, MASTER, OUTSTATION, &first),
                frame(USER_DATA, MASTER, OUTSTATION, &last)
            ])
            .await
            .unwrap_err()
            .contains("out-of-order")
        );
    }

    #[test]
    fn decodes_supported_qualifiers_and_skips_untrusted_objects() {
        let value = [1, 0x03, b'S', b'N', b'1'];
        for (qualifier, bounds) in [
            (0x00, &[0, 0][..]),
            (0x01, &[0, 0, 0, 0][..]),
            (0x06, &[][..]),
            (0x07, &[1][..]),
            (0x08, &[1, 0][..]),
        ] {
            let mut pdu = vec![RESPONSE, 0, 0, 0x00, 0xF8, qualifier];
            pdu.extend_from_slice(bounds);
            pdu.extend_from_slice(&value);
            let (values, warnings) = parse(&pdu).unwrap();
            assert!(warnings.is_empty(), "{qualifier:#04X}: {warnings:?}");
            if matches!(qualifier, 0 | 1) {
                assert_eq!(values["serialNumber"], "SN1", "{qualifier:#04X}");
            } else {
                assert!(!values.contains_key("serialNumber"));
                assert!(values["attributeRecords"][0]["set"].is_null());
            }
        }
        for (header, bounds) in [
            ([0x00, 0xF8, 0x17], &[1][..]), // prefixed objects have no trusted size
            ([0x1E, 0x01, 0x07], &[1][..]), // a foreign group cannot be skipped safely
            ([0x00, 0xF8, 0x00], &[9, 0][..]), // inverted range
            ([0x00, 0xF8, 0x0B], &[][..]),  // reserved qualifier
        ] {
            let mut pdu = vec![RESPONSE, 0, 0];
            pdu.extend_from_slice(&header);
            pdu.extend_from_slice(bounds);
            let (values, warnings) = parse(&pdu).unwrap();
            assert!(warnings[0].contains("Skipped"), "{header:?}");
            assert!(!values.contains_key("serialNumber"));
        }
        let mut pdu = vec![RESPONSE, 0, 0];
        pdu.extend_from_slice(&attribute_object(248, 1, b"SN1"));
        pdu.truncate(pdu.len() - 1);
        let (values, warnings) = parse(&pdu).unwrap();
        assert!(warnings[0].contains("Truncated"));
        assert!(!values.contains_key("serialNumber"));
    }

    #[test]
    fn reports_internal_indications_that_explain_missing_identity() {
        let (values, warnings) = parse(&[RESPONSE, 0x80, 0x03]).unwrap();
        assert_eq!(values["iin1"], "80");
        assert_eq!(values["iin2"], "03");
        assert!(warnings.iter().any(|value| value.contains("read function")));
        assert!(warnings.iter().any(|value| value.contains("Group 0")));
        assert!(parse(&[RESPONSE, 0]).is_err());
        assert!(parse(&[UNSOLICITED, 0, 0]).is_err());
    }

    #[tokio::test]
    async fn rejects_malformed_link_frames() {
        let valid = reply_frame(&identity_pdu());
        for (bytes, expected) in [
            (
                vec![0x06, 0x64, 0x05, 0xC0, 0x01, 0x00, 0x00, 0x04, 0xE9, 0x21],
                "start bytes",
            ),
            (
                vec![0x05, 0x64, 0x04, 0xC0, 0x01, 0x00, 0x00, 0x04, 0xE9, 0x21],
                "truncated DNP3 frame",
            ),
            (vec![], "closed"),
        ] {
            let result = reads(&bytes).await;
            if expected == "closed" {
                assert!(result.unwrap().is_none());
            } else {
                assert!(result.unwrap_err().contains(expected), "{bytes:?}");
            }
        }
        let mut header = valid.clone();
        header[8] ^= 0xFF;
        assert!(
            reads(&header)
                .await
                .unwrap_err()
                .contains("header checksum")
        );
        let mut data = valid.clone();
        let last = data.len() - 1;
        data[last] ^= 0xFF;
        assert!(reads(&data).await.unwrap_err().contains("data checksum"));
        assert!(
            reads(&valid[..valid.len() - 3])
                .await
                .unwrap_err()
                .contains("truncated DNP3 response")
        );
        let frame = reads(&valid).await.unwrap().unwrap();
        assert_eq!(frame.control & FUNCTION, USER_DATA);
        assert_eq!(frame.destination, MASTER);
        assert_eq!(frame.source, OUTSTATION);
    }

    #[tokio::test]
    async fn rejects_frames_that_do_not_answer_the_request() {
        assert!(
            exchanges(&[frame(DIR | PRM | ACK, MASTER, OUTSTATION, &[])])
                .await
                .unwrap_err()
                .contains("secondary")
        );
        assert!(
            exchanges(&[frame(0x05, MASTER, OUTSTATION, &[])])
                .await
                .unwrap_err()
                .contains("link function 0x05")
        );
        assert!(
            exchanges(&[frame(USER_DATA, MASTER, OUTSTATION, &[])])
                .await
                .unwrap_err()
                .contains("empty DNP3 transport")
        );
        assert!(
            exchanges(&[frame(USER_DATA, MASTER, OUTSTATION, &[TL_FIN | TL_FIR])])
                .await
                .unwrap_err()
                .contains("empty DNP3 application")
        );
        assert!(
            exchanges(&[frame(
                USER_DATA,
                MASTER,
                OUTSTATION,
                &[TL_FIN, AL_FIR | AL_FIN, RESPONSE, 0, 0]
            )])
            .await
            .unwrap_err()
            .contains("out-of-order")
        );
        assert!(
            exchanges(&[reply_frame(&[0x83, 0, 0])])
                .await
                .unwrap_err()
                .contains("function code 0x83")
        );
        assert!(
            exchanges(&[frame(NOT_IMPLEMENTED, MASTER, OUTSTATION, &[])])
                .await
                .unwrap()
                .warnings[0]
                .contains("not functioning")
        );
    }

    #[tokio::test]
    async fn reassembles_transport_segments_and_application_fragments() {
        let pdu = identity_pdu();
        for replies in [segments(&pdu), fragments(&pdu)] {
            let reply = exchanges(&replies).await.unwrap();
            assert_eq!(reply.response.unwrap(), pdu);
            assert_eq!(reply.outstation, Some(OUTSTATION));
            assert_eq!(reply.master, Some(MASTER));
        }
    }

    #[tokio::test]
    async fn keeps_reading_after_link_replies_and_unsolicited_reports() {
        let pdu = identity_pdu();
        let reply = exchanges(&[
            reply_frame(&[UNSOLICITED, 0x02, 0x00]),
            frame(NACK, MASTER, OUTSTATION, &[]),
            frame(LINK_STATUS, MASTER, OUTSTATION, &[]),
            reply_frame(&pdu),
        ])
        .await
        .unwrap();
        assert_eq!(reply.response.unwrap(), pdu);
        assert!(
            reply
                .warnings
                .iter()
                .any(|warning| warning.contains("rejected the request"))
        );
    }

    #[tokio::test]
    async fn probes_the_candidate_address_the_outstation_owns() {
        let _network = crate::network_test_lock().await;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, PORT))
            .await
            .unwrap();
        let pdu = identity_pdu();
        let reply = reply_frame(&pdu);
        let responder = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            outstation(stream, OUTSTATION, vec![reply]).await;
        });
        let finding = probe(Ipv4Addr::LOCALHOST).await.unwrap().unwrap();
        assert_eq!(finding.source, Source::Dnp3);
        assert_eq!(finding.fields["name"], "PUMP-RTU-1");
        assert_eq!(finding.fields["model"], "FB3000");
        assert_eq!(finding.fields["vendor"], "Emerson");
        assert_eq!(finding.fields["firmwareVersion"], "5.2.1");
        assert_eq!(finding.fields["hardwareVersion"], "HW-2");
        assert_eq!(finding.fields["serialNumber"], "SN-000123");
        assert_eq!(finding.fields["location"], "Cell 1");
        assert_eq!(finding.fields["protocols"], json!(["dnp3"]));
        assert_eq!(finding.ports[0].key, "tcp:20000");
        assert_eq!(finding.raw["outstationAddress"], json!(OUTSTATION));
        assert_eq!(finding.raw["masterAddress"], json!(MASTER));
        assert_eq!(finding.raw["response"], json!(hex(&pdu)));
        assert!(finding.warnings.is_empty());
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn reports_a_link_only_outstation_without_identity() {
        let _network = crate::network_test_lock().await;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, PORT))
            .await
            .unwrap();
        let responder = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            outstation(stream, 1, vec![]).await;
        });
        let finding = probe(Ipv4Addr::LOCALHOST).await.unwrap().unwrap();
        assert_eq!(finding.fields["protocols"], json!(["dnp3"]));
        assert!(!finding.fields.contains_key("name"));
        assert_eq!(finding.ports.len(), 1);
        assert_eq!(finding.raw["outstationAddress"], json!(1));
        assert!(
            finding
                .warnings
                .iter()
                .any(|warning| warning.contains("without an application response"))
        );
        responder.await.unwrap();
    }
}
