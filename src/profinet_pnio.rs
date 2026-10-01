use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use uuid::Uuid;

const RPC_HEADER_LENGTH: usize = 80;
const EPM_PORT: u16 = 34_964;
const PNIO_PORT: u16 = 49_155;
const RPC_CLIENT_PORT: u16 = EPM_PORT;
const DEFAULT_RECORD_DATA_LENGTH: u32 = 32_768;
const MAX_RECORD_DATA_LENGTH: u32 = 32_768;
const MAX_RPC_BODY_LENGTH: usize = MAX_RECORD_DATA_LENGTH as usize + 128;

const EPM_INTERFACE: &str = "e1af8308-5d1f-11c9-91a4-08002b14a0fa";
const PNIO_INTERFACE: &str = "dea00001-6c97-11d1-8271-00a02442df7d";
const NIL_UUID: &str = "00000000-0000-0000-0000-000000000000";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RecordTarget {
    pub api: u32,
    pub slot: u16,
    pub subslot: u16,
    pub index: u16,
    pub data_length: u32,
}

impl RecordTarget {
    fn requested_length(&self) -> u32 {
        if self.data_length == 0 {
            DEFAULT_RECORD_DATA_LENGTH
        } else {
            self.data_length
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EpmHandle {
    entry: u32,
    uuid: Uuid,
}

impl Default for EpmHandle {
    fn default() -> Self {
        Self {
            entry: 0,
            uuid: uuid(NIL_UUID),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RpcEndpoint {
    pub object_uuid: Uuid,
    pub interface_uuid: Uuid,
    pub activity_uuid: Uuid,
    pub port: u16,
    pub ip_address: Ipv4Addr,
    pub big_endian: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EpmResponse {
    pub endpoint: Option<RpcEndpoint>,
    pub handle: EpmHandle,
    pub entries: u32,
    pub return_code: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RpcHeader {
    pub packet_type: u8,
    pub flags: u8,
    pub big_endian: bool,
    pub object_uuid: Uuid,
    pub interface_uuid: Uuid,
    pub activity_uuid: Uuid,
    pub interface_version: u32,
    pub sequence: u32,
    pub operation: u16,
    pub body_length: u16,
    pub fragment_number: u16,
    serial_high: u8,
    serial_low: u8,
}

impl RpcHeader {
    #[expect(
        clippy::too_many_arguments,
        reason = "The constructor mirrors the fixed DCE/RPC header fields."
    )]
    fn new(
        packet_type: u8,
        flags: u8,
        big_endian: bool,
        object_uuid: Uuid,
        interface_uuid: Uuid,
        activity_uuid: Uuid,
        interface_version: u32,
        sequence: u32,
        operation: u16,
        body_length: usize,
    ) -> Result<Self, String> {
        Ok(Self {
            packet_type,
            flags,
            big_endian,
            object_uuid,
            interface_uuid,
            activity_uuid,
            interface_version,
            sequence,
            operation,
            body_length: u16::try_from(body_length)
                .map_err(|_| "DCE/RPC body is too large.".to_string())?,
            fragment_number: 0,
            serial_high: 0,
            serial_low: 0,
        })
    }

    fn is_fragmented(&self) -> bool {
        self.flags & 0x04 != 0
    }

    fn is_last_fragment(&self) -> bool {
        self.flags & 0x02 != 0
    }

    pub(crate) fn requires_fragment_ack(&self) -> bool {
        self.is_fragmented() && !self.is_last_fragment() && self.flags & 0x08 == 0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReadResponse {
    pub target: RecordTarget,
    pub data: Vec<u8>,
    pub status: u32,
}

#[derive(Clone, Debug)]
pub(crate) struct RecordRead {
    pub target: RecordTarget,
    pub data: Vec<u8>,
    pub parsed: Value,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct UdpFrame<'a> {
    pub source_mac: [u8; 6],
    pub destination_mac: [u8; 6],
    pub source_ip: Ipv4Addr,
    pub destination_ip: Ipv4Addr,
    pub source_port: u16,
    pub destination_port: u16,
    pub payload: &'a [u8],
}

pub(crate) fn rpc_port() -> u16 {
    RPC_CLIENT_PORT
}

pub(crate) fn read_records(
    timeout: Duration,
    cancelled: &AtomicBool,
    mut transact: impl FnMut(u16, &[u8], Duration, &AtomicBool) -> Result<(RpcHeader, Vec<u8>), String>,
) -> Result<Vec<RecordRead>, String> {
    let activity_uuid = Uuid::new_v4();
    let mut sequence = 0;
    let epm_request = build_epm_request(activity_uuid, sequence, None)?;
    let (epm_header, mut epm_body) = transact(EPM_PORT, &epm_request, timeout, cancelled)?;
    let mut epm_packet = encode_rpc_header(&epm_header);
    epm_packet.append(&mut epm_body);
    let mut epm = parse_epm_response(&epm_packet)?;
    let mut endpoint = epm.endpoint.take();
    if endpoint.is_none() {
        sequence += 1;
        let request = build_epm_request(activity_uuid, sequence, Some(&epm.handle))?;
        let (header, mut body) = transact(EPM_PORT, &request, timeout, cancelled)?;
        let mut packet = encode_rpc_header(&header);
        packet.append(&mut body);
        endpoint = parse_epm_response(&packet)?.endpoint;
    }
    let mut endpoint = endpoint.ok_or_else(|| {
        format!(
            "PROFINET EPM did not return a PNIO endpoint (status 0x{:08X}).",
            epm.return_code
        )
    })?;
    endpoint.activity_uuid = activity_uuid;

    let primary = |index| RecordTarget {
        api: 0,
        slot: 0,
        subslot: 1,
        index,
        data_length: DEFAULT_RECORD_DATA_LENGTH,
    };
    let mut records = Vec::new();
    let mut read_one = |target: RecordTarget| -> Result<RecordRead, String> {
        sequence = sequence.wrapping_add(1);
        let request = build_read_request(&endpoint, &target, sequence)?;
        let (header, body) = transact(endpoint.port, &request, timeout, cancelled)?;
        let response = parse_read_response(&header, &body, &target)?;
        let parsed = parse_record(target.index, &response.data)?;
        Ok(RecordRead {
            target: response.target,
            data: response.data,
            parsed,
        })
    };

    let api_record = read_one(primary(0xF821))?;
    let apis = api_record.parsed["apis"]
        .as_array()
        .map(|values| {
            values
                .iter()
                .filter_map(|value| value["api"].as_u64().map(|api| api as u32))
                .collect::<Vec<_>>()
        })
        .filter(|values| !values.is_empty())
        .unwrap_or_else(|| vec![0]);
    records.push(api_record);

    let mut module_targets = BTreeSet::new();
    for api in apis {
        for index in [0xF840, 0xF000] {
            let target = RecordTarget {
                api,
                ..primary(index)
            };
            let Ok(record) = read_one(target) else {
                continue;
            };
            collect_module_targets(&record.parsed, api, &mut module_targets);
            records.push(record);
        }
    }
    module_targets.insert((0, 0, 1));
    let mut im_targets = BTreeSet::new();
    for (api, slot, subslot) in module_targets {
        let target = RecordTarget {
            api,
            slot,
            subslot,
            index: 0xAFF0,
            data_length: DEFAULT_RECORD_DATA_LENGTH,
        };
        let Ok(record) = read_one(target) else {
            continue;
        };
        let supported = record.parsed["imSupported"].as_u64().unwrap_or(0) as u16;
        for (mask, index) in [
            (0x0002, 0xAFF1),
            (0x0004, 0xAFF2),
            (0x0008, 0xAFF3),
            (0x0010, 0xAFF4),
            (0x0020, 0xAFF5),
        ] {
            if supported & mask != 0 {
                im_targets.insert((api, slot, subslot, index));
            }
        }
        records.push(record);
    }
    for (api, slot, subslot, index) in im_targets {
        if let Ok(record) = read_one(RecordTarget {
            api,
            slot,
            subslot,
            index,
            data_length: DEFAULT_RECORD_DATA_LENGTH,
        }) {
            records.push(record);
        }
    }
    Ok(records)
}

fn collect_module_targets(value: &Value, api: u32, targets: &mut BTreeSet<(u32, u16, u16)>) {
    let Some(apis) = value["apis"].as_array() else {
        return;
    };
    for item in apis {
        let item_api = item["api"]
            .as_u64()
            .map(|value| value as u32)
            .unwrap_or(api);
        let Some(modules) = item["modules"].as_array() else {
            continue;
        };
        for module in modules {
            let Some(slot) = module["slot"].as_u64().map(|value| value as u16) else {
                continue;
            };
            if let Some(submodules) = module["submodules"].as_array() {
                for submodule in submodules {
                    if let Some(subslot) = submodule["subslot"].as_u64().map(|value| value as u16) {
                        targets.insert((item_api, slot, subslot));
                    }
                }
            }
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "The raw-frame callback keeps platform socket ownership outside this module."
)]
pub(crate) fn exchange(
    source_mac: [u8; 6],
    source_ip: Ipv4Addr,
    target_mac: [u8; 6],
    target_ip: Ipv4Addr,
    target_port: u16,
    request: &[u8],
    timeout: Duration,
    cancelled: &AtomicBool,
    send_frame: &mut impl FnMut(&[u8]) -> Result<(), String>,
    receive_frame: &mut impl FnMut() -> Result<Option<Vec<u8>>, String>,
) -> Result<(RpcHeader, Vec<u8>), String> {
    let request_header = parse_rpc_header(request)?;
    let client_port = rpc_port();
    let frame = ethernet_ipv4_udp_frame(
        source_mac,
        target_mac,
        source_ip,
        target_ip,
        client_port,
        target_port,
        request,
    )?;
    send_frame(&frame)?;
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| "PROFINET RPC response timeout overflowed.".to_string())?;
    let mut fragments = Vec::new();
    while Instant::now() < deadline {
        if cancelled.load(Ordering::Relaxed) {
            return Err("PROFINET RPC read was cancelled.".into());
        }
        let Some(frame) = receive_frame()? else {
            std::thread::sleep(Duration::from_millis(2));
            continue;
        };
        let Some(udp) = parse_ipv4_udp_frame(&frame) else {
            continue;
        };
        if udp.source_mac != target_mac
            || udp.destination_mac != source_mac
            || udp.source_ip != target_ip
            || udp.destination_ip != source_ip
            || udp.source_port != target_port
            || udp.destination_port != client_port
        {
            continue;
        }
        let Ok((header, body)) = parse_rpc_fragment(udp.payload) else {
            continue;
        };
        if header.packet_type != 2
            || header.object_uuid != request_header.object_uuid
            || header.interface_uuid != request_header.interface_uuid
            || header.activity_uuid != request_header.activity_uuid
            || header.sequence != request_header.sequence
            || header.operation != request_header.operation
        {
            continue;
        }
        if header.requires_fragment_ack() {
            let ack = build_fragment_ack(&header);
            let ack_frame = ethernet_ipv4_udp_frame(
                source_mac,
                target_mac,
                source_ip,
                target_ip,
                client_port,
                target_port,
                &ack,
            )?;
            send_frame(&ack_frame)?;
        }
        let last = !header.is_fragmented() || header.is_last_fragment();
        fragments.push((header, body));
        if last {
            return reassemble_rpc_fragments(fragments);
        }
    }
    Err(format!(
        "PROFINET RPC response from {target_ip}:{target_port} timed out."
    ))
}

pub(crate) fn ethernet_ipv4_udp_frame(
    source_mac: [u8; 6],
    destination_mac: [u8; 6],
    source_ip: Ipv4Addr,
    destination_ip: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let udp_length = 8_usize
        .checked_add(payload.len())
        .ok_or_else(|| "UDP payload length overflowed.".to_string())?;
    let ip_length = 20_usize
        .checked_add(udp_length)
        .ok_or_else(|| "IPv4 payload length overflowed.".to_string())?;
    let ip_length_u16 = u16::try_from(ip_length)
        .map_err(|_| "IPv4 payload is too large for one datagram.".to_string())?;
    let udp_length_u16 = u16::try_from(udp_length)
        .map_err(|_| "UDP payload is too large for one datagram.".to_string())?;
    let mut udp = Vec::with_capacity(udp_length);
    udp.extend(source_port.to_be_bytes());
    udp.extend(destination_port.to_be_bytes());
    udp.extend(udp_length_u16.to_be_bytes());
    udp.extend([0, 0]);
    udp.extend(payload);
    let checksum = transport_checksum(source_ip, destination_ip, 17, &udp);
    udp[6..8].copy_from_slice(&checksum.to_be_bytes());

    let mut ip = vec![0; 20];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&ip_length_u16.to_be_bytes());
    ip[4..6].copy_from_slice(&0x4F54_u16.to_be_bytes());
    ip[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
    ip[8] = 64;
    ip[9] = 17;
    ip[12..16].copy_from_slice(&source_ip.octets());
    ip[16..20].copy_from_slice(&destination_ip.octets());
    let checksum = internet_checksum(&ip);
    ip[10..12].copy_from_slice(&checksum.to_be_bytes());

    let mut frame = Vec::with_capacity(14 + ip.len() + udp.len());
    frame.extend(destination_mac);
    frame.extend(source_mac);
    frame.extend([0x08, 0x00]);
    frame.extend(ip);
    frame.extend(udp);
    Ok(frame)
}

pub(crate) fn parse_ipv4_udp_frame(frame: &[u8]) -> Option<UdpFrame<'_>> {
    if frame.len() < 14 + 20 + 8 || frame[12..14] != [0x08, 0x00] {
        return None;
    }
    let ip = &frame[14..];
    let fragment_field = u16::from_be_bytes([ip[6], ip[7]]);
    if ip[0] >> 4 != 4
        || ip[9] != 17
        || fragment_field & 0xA000 != 0
        || fragment_field & 0x1FFF != 0
    {
        return None;
    }
    let header_length = usize::from(ip[0] & 0x0F) * 4;
    let total_length = usize::from(u16::from_be_bytes([ip[2], ip[3]]));
    if header_length < 20 || total_length < header_length + 8 || total_length > ip.len() {
        return None;
    }
    if internet_checksum(&ip[..header_length]) != 0 {
        return None;
    }
    let udp = &ip[header_length..total_length];
    let udp_length = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
    if udp_length < 8 || udp_length != udp.len() {
        return None;
    }
    let source_ip = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
    let destination_ip = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);
    if u16::from_be_bytes([udp[6], udp[7]]) != 0
        && transport_checksum(source_ip, destination_ip, 17, udp) != 0
    {
        return None;
    }
    Some(UdpFrame {
        source_mac: frame[6..12].try_into().ok()?,
        destination_mac: frame[..6].try_into().ok()?,
        source_ip,
        destination_ip,
        source_port: u16::from_be_bytes([udp[0], udp[1]]),
        destination_port: u16::from_be_bytes([udp[2], udp[3]]),
        payload: &udp[8..],
    })
}

fn transport_checksum(
    source_ip: Ipv4Addr,
    destination_ip: Ipv4Addr,
    protocol: u8,
    payload: &[u8],
) -> u16 {
    let mut data = Vec::with_capacity(12 + payload.len());
    data.extend(source_ip.octets());
    data.extend(destination_ip.octets());
    data.extend([0, protocol]);
    data.extend((payload.len() as u16).to_be_bytes());
    data.extend(payload);
    internet_checksum(&data)
}

fn internet_checksum(data: &[u8]) -> u16 {
    let (pairs, remainder) = data.as_chunks::<2>();
    let mut sum = pairs.iter().fold(0_u32, |sum, pair| {
        sum + u32::from(u16::from_be_bytes(*pair))
    });
    if let Some(byte) = remainder.first() {
        sum += u32::from(*byte) << 8;
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

pub(crate) fn build_epm_request(
    activity_uuid: Uuid,
    sequence: u32,
    handle: Option<&EpmHandle>,
) -> Result<Vec<u8>, String> {
    let mut body = Vec::with_capacity(76);
    put_u32(&mut body, 0, false); // Read all registered interfaces.
    put_u32(&mut body, 1, false); // Non-null object pointer.
    put_uuid(&mut body, uuid(NIL_UUID), false);
    put_u32(&mut body, 2, false); // Non-null interface pointer.
    put_uuid(&mut body, uuid(PNIO_INTERFACE), false);
    put_u16(&mut body, 1, false);
    put_u16(&mut body, 0, false);
    put_u32(&mut body, 1, false);
    let handle = handle.cloned().unwrap_or_default();
    put_u32(&mut body, handle.entry, false);
    put_uuid(&mut body, handle.uuid, false);
    put_u32(&mut body, 1, false);

    let header = RpcHeader::new(
        0,
        0x20,
        false,
        uuid(NIL_UUID),
        uuid(EPM_INTERFACE),
        activity_uuid,
        3,
        sequence,
        2,
        body.len(),
    )?;
    let mut packet = encode_rpc_header(&header);
    packet.extend(body);
    Ok(packet)
}

pub(crate) fn build_read_request(
    endpoint: &RpcEndpoint,
    target: &RecordTarget,
    sequence: u32,
) -> Result<Vec<u8>, String> {
    let data_length = target.requested_length();
    if data_length > MAX_RECORD_DATA_LENGTH {
        return Err(format!(
            "PNIO record request exceeds the bounded data length of {MAX_RECORD_DATA_LENGTH} bytes."
        ));
    }
    let mut body = Vec::with_capacity(84);
    let ndr_length = data_length
        .checked_add(64)
        .ok_or_else(|| "PNIO record request length overflowed.".to_string())?;
    put_u32(&mut body, ndr_length, endpoint.big_endian);
    put_u32(&mut body, 64, endpoint.big_endian);
    put_u32(&mut body, ndr_length, endpoint.big_endian);
    put_u32(&mut body, 0, endpoint.big_endian);
    put_u32(&mut body, 64, endpoint.big_endian);

    put_u16(&mut body, 0x0009, true);
    put_u16(&mut body, 60, true);
    body.extend([1, 0]);
    put_u16(&mut body, 0, true);
    put_uuid(&mut body, uuid(NIL_UUID), true);
    put_u32(&mut body, target.api, true);
    put_u16(&mut body, target.slot, true);
    put_u16(&mut body, target.subslot, true);
    put_u16(&mut body, 0, true);
    put_u16(&mut body, target.index, true);
    put_u32(&mut body, data_length, true);
    put_uuid(&mut body, uuid(NIL_UUID), true);
    body.extend([0; 8]);

    let header = RpcHeader::new(
        0,
        0x20,
        endpoint.big_endian,
        endpoint.object_uuid,
        endpoint.interface_uuid,
        endpoint.activity_uuid,
        1,
        sequence,
        5,
        body.len(),
    )?;
    let mut packet = encode_rpc_header(&header);
    packet.extend(body);
    Ok(packet)
}

pub(crate) fn build_fragment_ack(header: &RpcHeader) -> Vec<u8> {
    let ack = RpcHeader {
        packet_type: 9,
        flags: 0,
        big_endian: header.big_endian,
        object_uuid: header.object_uuid,
        interface_uuid: header.interface_uuid,
        activity_uuid: header.activity_uuid,
        interface_version: header.interface_version,
        sequence: header.sequence,
        operation: header.operation,
        body_length: 0,
        fragment_number: header.fragment_number,
        serial_high: header.serial_high,
        serial_low: header.serial_low,
    };
    encode_rpc_header(&ack)
}

pub(crate) fn parse_rpc_fragment(packet: &[u8]) -> Result<(RpcHeader, Vec<u8>), String> {
    let header = parse_rpc_header(packet)?;
    let end = RPC_HEADER_LENGTH + usize::from(header.body_length);
    Ok((header, packet[RPC_HEADER_LENGTH..end].to_vec()))
}

pub(crate) fn reassemble_rpc_fragments(
    mut fragments: Vec<(RpcHeader, Vec<u8>)>,
) -> Result<(RpcHeader, Vec<u8>), String> {
    if fragments.is_empty() {
        return Err("DCE/RPC response contained no fragments.".into());
    }
    fragments.sort_by_key(|(header, _)| header.fragment_number);
    let first = fragments[0].0.clone();
    if first.packet_type != 2 {
        return Err("DCE/RPC response was not a response packet.".into());
    }
    for (header, _) in &fragments {
        if header.packet_type != first.packet_type
            || header.big_endian != first.big_endian
            || header.object_uuid != first.object_uuid
            || header.interface_uuid != first.interface_uuid
            || header.activity_uuid != first.activity_uuid
            || header.sequence != first.sequence
            || header.operation != first.operation
        {
            return Err("DCE/RPC response fragments did not describe one request.".into());
        }
    }
    if !first.is_fragmented() {
        if fragments.len() != 1 {
            return Err("DCE/RPC response had inconsistent fragment flags.".into());
        }
    } else {
        for (expected, (header, _)) in fragments.iter().enumerate() {
            if !header.is_fragmented()
                || header.fragment_number != expected as u16
                || (expected + 1 == fragments.len()) != header.is_last_fragment()
            {
                return Err("DCE/RPC response fragments were incomplete or out of order.".into());
            }
        }
    }
    let total = fragments
        .iter()
        .try_fold(0_usize, |total, (_, body)| total.checked_add(body.len()));
    let total = total.ok_or_else(|| "DCE/RPC response length overflowed.".to_string())?;
    if total > MAX_RPC_BODY_LENGTH {
        return Err("DCE/RPC response exceeded the bounded reassembly length.".into());
    }
    let mut body = Vec::with_capacity(total);
    for (_, fragment) in fragments {
        body.extend(fragment);
    }
    let mut header = first;
    header.body_length =
        u16::try_from(body.len()).map_err(|_| "DCE/RPC response body is too large.".to_string())?;
    header.flags = 0x02;
    Ok((header, body))
}

pub(crate) fn parse_epm_response(packet: &[u8]) -> Result<EpmResponse, String> {
    let (header, body) = parse_rpc_fragment(packet)?;
    if header.packet_type != 2 || header.operation != 2 {
        return Err("DCE/RPC packet was not an EPM response.".into());
    }
    if header.interface_uuid != uuid(EPM_INTERFACE) {
        return Err("DCE/RPC EPM response used an unexpected interface UUID.".into());
    }
    let mut cursor = Cursor::new(&body);
    let handle = EpmHandle {
        entry: cursor.u32(header.big_endian)?,
        uuid: cursor.uuid(header.big_endian)?,
    };
    let entries = cursor.u32(header.big_endian)?;
    let maximum = cursor.u32(header.big_endian)?;
    let offset = cursor.u32(header.big_endian)?;
    let actual = cursor.u32(header.big_endian)?;
    if actual > maximum || offset != 0 || actual > 64 {
        return Err("DCE/RPC EPM response contained invalid entry counts.".into());
    }

    let mut endpoint = None;
    for _ in 0..actual {
        let object_uuid = cursor.uuid(header.big_endian)?;
        let tower = parse_tower(&mut cursor, header.big_endian)?;
        if tower.interface_uuid == uuid(PNIO_INTERFACE) {
            endpoint = Some(RpcEndpoint {
                object_uuid,
                interface_uuid: tower.interface_uuid,
                activity_uuid: header.activity_uuid,
                port: tower.port.unwrap_or(PNIO_PORT),
                ip_address: tower.ip_address.unwrap_or(Ipv4Addr::UNSPECIFIED),
                big_endian: header.big_endian,
            });
        }
    }
    cursor.align(2)?;
    let return_code = cursor.u32(header.big_endian)?;
    if cursor.remaining() != 0 {
        return Err("DCE/RPC EPM response contained trailing bytes.".into());
    }
    Ok(EpmResponse {
        endpoint,
        handle,
        entries,
        return_code,
    })
}

pub(crate) fn parse_read_response(
    header: &RpcHeader,
    body: &[u8],
    requested: &RecordTarget,
) -> Result<ReadResponse, String> {
    if header.packet_type != 2 || header.operation != 5 {
        return Err("DCE/RPC packet was not a PNIO read response.".into());
    }
    if body.len() < 84 {
        return Err("PNIO read response was truncated before its IOD header.".into());
    }
    let status = read_u32(body, 0, header.big_endian)?;
    if status != 0 {
        return Err(format!("PNIO read returned status 0x{status:08X}."));
    }
    let args_length = read_u32(body, 4, header.big_endian)? as usize;
    let maximum_count = read_u32(body, 8, header.big_endian)? as usize;
    let offset = read_u32(body, 12, header.big_endian)?;
    let actual_count = read_u32(body, 16, header.big_endian)? as usize;
    if offset != 0 || args_length != actual_count || maximum_count < actual_count {
        return Err("PNIO read response contained invalid NDR counts.".into());
    }
    let ndr_end = 20_usize
        .checked_add(args_length)
        .ok_or_else(|| "PNIO read response length overflowed.".to_string())?;
    if ndr_end > body.len() || actual_count < 64 {
        return Err("PNIO read response contained a truncated NDR payload.".into());
    }

    let iod = &body[20..84];
    if read_u16(iod, 0, true)? != 0x8009 || read_u16(iod, 2, true)? != 60 || iod[4..6] != [1, 0] {
        return Err("PNIO read response did not contain an IODReadResHeader.".into());
    }
    let target = RecordTarget {
        api: read_u32(iod, 24, true)?,
        slot: read_u16(iod, 28, true)?,
        subslot: read_u16(iod, 30, true)?,
        index: read_u16(iod, 34, true)?,
        data_length: read_u32(iod, 36, true)?,
    };
    if target.api != requested.api
        || target.slot != requested.slot
        || target.subslot != requested.subslot
        || target.index != requested.index
    {
        return Err("PNIO read response did not echo the requested target.".into());
    }
    let record_length = usize::try_from(target.data_length)
        .map_err(|_| "PNIO record length did not fit in memory.".to_string())?;
    if target.data_length > requested.requested_length() {
        return Err("PNIO read response exceeded the requested data length.".into());
    }
    let data_end = 84_usize
        .checked_add(record_length)
        .ok_or_else(|| "PNIO record length overflowed.".to_string())?;
    if data_end > ndr_end {
        return Err("PNIO read response was truncated before the record ended.".into());
    }
    Ok(ReadResponse {
        target,
        data: body[84..data_end].to_vec(),
        status,
    })
}

pub(crate) fn parse_record(index: u16, data: &[u8]) -> Result<Value, String> {
    match index {
        0xAFF0 => parse_im0(data),
        0xAFF1 => parse_im1(data),
        0xAFF2 => parse_im2(data),
        0xAFF3 => parse_im3(data),
        0xAFF4 => parse_im4(data),
        0xAFF5 => parse_im5(data),
        0xF821 => parse_api_record(data, 0x001A),
        0xF000 => parse_api_record(data, 0x0013),
        0xF840 => parse_filter_record(data),
        _ => Err(format!("Unsupported PROFINET record index 0x{index:04X}.")),
    }
}

fn parse_im0(data: &[u8]) -> Result<Value, String> {
    validate_fixed_block(data, 0x0020, 56, "I&M0")?;
    let manufacturer_id = read_be16(data, 6)?;
    let profile_id = read_be16(data, 52)?;
    let mut result = json!({
        "blockType": 0x0020,
        "manufacturerId": format!("{:04X}", manufacturer_id),
        "orderId": clean_text(&data[8..28]),
        "serialNumber": clean_text(&data[28..44]),
        "hardwareRevision": read_be16(data, 44)?.to_string(),
        "softwareRevision": software_revision(&data[46..50]),
        "revisionCounter": read_be16(data, 50)?.to_string(),
        "profileId": format!("{:04X}", profile_id),
        "profileDetails": read_be16(data, 54)?.to_string(),
        "imVersion": format!("{}.{}", data[56], data[57]),
        "imSupported": read_be16(data, 58)?,
    });
    if let Some(name) = crate::profinet_database::manufacturer_name(manufacturer_id) {
        result["manufacturerName"] = json!(name);
    }
    if let Some(name) = crate::profinet_database::profile_name(profile_id) {
        result["profileName"] = json!(name);
    }
    Ok(result)
}

fn parse_im1(data: &[u8]) -> Result<Value, String> {
    validate_fixed_block(data, 0x0021, 56, "I&M1")?;
    Ok(json!({
        "blockType": 0x0021,
        "function": clean_text(&data[6..38]),
        "location": clean_text(&data[38..60]),
    }))
}

fn parse_im2(data: &[u8]) -> Result<Value, String> {
    validate_fixed_block(data, 0x0022, 18, "I&M2")?;
    Ok(json!({
        "blockType": 0x0022,
        "installationDate": clean_text(&data[6..22]),
    }))
}

fn parse_im3(data: &[u8]) -> Result<Value, String> {
    validate_fixed_block(data, 0x0023, 56, "I&M3")?;
    Ok(json!({
        "blockType": 0x0023,
        "descriptor": clean_text(&data[6..60]),
    }))
}

fn parse_im4(data: &[u8]) -> Result<Value, String> {
    validate_fixed_block(data, 0x0024, 56, "I&M4")?;
    let mut result = json!({
        "blockType": 0x0024,
        "imSignature": hex(&data[6..60]),
    });
    if &data[6..10] == b"crc1" {
        let object = result.as_object_mut().expect("JSON object");
        for (name, offset) in [
            ("userStructureIdentifier", 6),
            ("checkOverall", 10),
            ("checkOverallSubs", 14),
            ("checkStaticLocal", 18),
            ("checkStaticSubs", 22),
            ("checkOverallSetup", 26),
            ("checkRemanentLocal", 30),
            ("checkRemanentSubs", 34),
            ("checkWorkingLocal", 38),
            ("checkWorkingSubs", 42),
        ] {
            object.insert(name.into(), json!(read_be32(data, offset)?));
        }
    }
    Ok(result)
}

fn parse_im5(data: &[u8]) -> Result<Value, String> {
    validate_block(data, 0x0025, "I&M5")?;
    if data.len() < 8 {
        return Err("I&M5 record did not contain its entry count.".into());
    }
    let count = read_be16(data, 6)? as usize;
    let mut offset = 8;
    let mut blocks = Vec::new();
    let mut im5_data = Vec::new();
    let mut asset_management_blocks = Vec::new();
    for _ in 0..count {
        let (block_type, block_length, _, _) = block_header(&data[offset..])?;
        let end = offset
            .checked_add(usize::from(block_length) + 4)
            .ok_or_else(|| "I&M5 block length overflowed.".to_string())?;
        if end > data.len() {
            return Err("I&M5 contained a truncated embedded block.".into());
        }
        let raw = hex(&data[offset..end]);
        blocks.push(json!({
            "blockType": block_type,
            "blockLength": block_length,
            "raw": raw,
        }));
        match block_type {
            0x0034 => im5_data.push(parse_im5_data(&data[offset..end])?),
            0x0036..=0x0038 => asset_management_blocks.push(json!({
                "blockType": block_type,
                "raw": hex(&data[offset..end]),
            })),
            _ => {}
        }
        offset = end;
    }
    if offset != data.len() {
        return Err("I&M5 contained trailing bytes after its entries.".into());
    }
    Ok(json!({
        "blockType": 0x0025,
        "numberOfEntries": count,
        "im5Data": im5_data,
        "assetManagementBlocks": asset_management_blocks,
        "blocks": blocks,
    }))
}

fn parse_im5_data(data: &[u8]) -> Result<Value, String> {
    validate_block(data, 0x0034, "I&M5 data")?;
    if data.len() < 158 {
        return Err("I&M5 data entry was truncated.".into());
    }
    let vendor_id = read_be16(data, 134)?;
    let mut result = json!({
        "blockType": 0x0034,
        "imAnnotation": clean_text(&data[6..70]),
        "imOrderId": clean_text(&data[70..134]),
        "vendorId": format!("{:04X}", vendor_id),
        "imSerialNumber": clean_text(&data[136..152]),
        "imHardwareRevision": read_be16(data, 152)?.to_string(),
        "imSoftwareRevision": software_revision(&data[154..158]),
    });
    if let Some(name) = crate::profinet_database::manufacturer_name(vendor_id) {
        result["vendorName"] = json!(name);
    }
    Ok(result)
}

fn parse_api_record(data: &[u8], expected_type: u16) -> Result<Value, String> {
    if expected_type == 0x0013 {
        validate_block_version(data, expected_type, 1, 1, "PROFINET identification")?;
    } else {
        validate_block(data, expected_type, "PROFINET identification")?;
    }
    let apis = if expected_type == 0x001A {
        parse_api_list(&data[6..])?
    } else {
        parse_api_payload(&data[6..])?.0
    };
    Ok(json!({
        "blockType": expected_type,
        "apis": apis,
    }))
}

fn parse_api_list(data: &[u8]) -> Result<Vec<Value>, String> {
    let count = usize::from(read_be16(data, 0)?);
    let expected = 2_usize
        .checked_add(
            count
                .checked_mul(4)
                .ok_or_else(|| "API count overflowed.".to_string())?,
        )
        .ok_or_else(|| "API record length overflowed.".to_string())?;
    if expected != data.len() {
        return Err("API data record contained a truncated or oversized API list.".into());
    }
    (0..count)
        .map(|index| Ok(json!({ "api": read_be32(data, 2 + index * 4)? })))
        .collect()
}

fn parse_filter_record(data: &[u8]) -> Result<Value, String> {
    let mut offset = 0;
    let mut blocks = Vec::new();
    let mut apis = Vec::new();
    while offset < data.len() {
        let (block_type, block_length, version_high, version_low) = block_header(&data[offset..])?;
        if !matches!(block_type, 0x0030..=0x0032) {
            return Err(format!(
                "I&M0 filter contained unexpected block type 0x{block_type:04X}."
            ));
        }
        if (version_high, version_low) != (1, 0) {
            return Err("I&M0 filter contained an unsupported block version.".into());
        }
        let end = offset
            .checked_add(usize::from(block_length) + 4)
            .ok_or_else(|| "I&M0 filter block length overflowed.".to_string())?;
        if end > data.len() {
            return Err("I&M0 filter contained a truncated block.".into());
        }
        let (block_apis, _) = parse_api_payload(&data[offset + 6..end])?;
        apis.extend(block_apis.iter().cloned());
        blocks.push(json!({
            "blockType": block_type,
            "apis": block_apis,
        }));
        offset = end;
    }
    if blocks.is_empty() {
        return Err("I&M0 filter contained no blocks.".into());
    }
    Ok(json!({ "blocks": blocks, "apis": apis }))
}

fn parse_api_payload(data: &[u8]) -> Result<(Vec<Value>, usize), String> {
    let count = usize::from(read_be16(data, 0)?);
    let mut offset = 2;
    let mut apis = Vec::with_capacity(count.min(256));
    for _ in 0..count {
        let api = read_be32(data, offset)?;
        offset += 4;
        let modules = usize::from(read_be16(data, offset)?);
        offset += 2;
        let mut module_values = Vec::with_capacity(modules.min(256));
        for _ in 0..modules {
            let slot = read_be16(data, offset)?;
            let module_id = read_be32(data, offset + 2)?;
            let submodules = usize::from(read_be16(data, offset + 6)?);
            offset += 8;
            let mut submodule_values = Vec::with_capacity(submodules.min(256));
            for _ in 0..submodules {
                submodule_values.push(json!({
                    "subslot": read_be16(data, offset)?,
                    "identNumber": read_be32(data, offset + 2)?,
                }));
                offset += 6;
            }
            module_values.push(json!({
                "slot": slot,
                "identNumber": module_id,
                "submodules": submodule_values,
            }));
        }
        apis.push(json!({
            "api": api,
            "modules": module_values,
        }));
    }
    if offset != data.len() {
        return Err("PROFINET identification record contained trailing bytes.".into());
    }
    Ok((apis, offset))
}

fn validate_fixed_block(
    data: &[u8],
    expected_type: u16,
    expected_length: u16,
    label: &str,
) -> Result<(), String> {
    validate_block(data, expected_type, label)?;
    if data.len() != usize::from(expected_length) + 4 {
        return Err(format!("{label} record has an invalid length."));
    }
    Ok(())
}

fn validate_block(data: &[u8], expected_type: u16, label: &str) -> Result<(), String> {
    validate_block_version(data, expected_type, 1, 0, label)
}

fn validate_block_version(
    data: &[u8],
    expected_type: u16,
    expected_version_high: u8,
    expected_version_low: u8,
    label: &str,
) -> Result<(), String> {
    let (block_type, block_length, version_high, version_low) = block_header(data)?;
    if block_type != expected_type {
        return Err(format!(
            "{label} record contained block type 0x{block_type:04X}."
        ));
    }
    if version_high != expected_version_high || version_low != expected_version_low {
        return Err(format!("{label} record has an unsupported block version."));
    }
    let end = usize::from(block_length)
        .checked_add(4)
        .ok_or_else(|| format!("{label} block length overflowed."))?;
    if end > data.len() {
        return Err(format!("{label} record is truncated."));
    }
    Ok(())
}

fn block_header(data: &[u8]) -> Result<(u16, u16, u8, u8), String> {
    if data.len() < 6 {
        return Err("PROFINET record is shorter than its block header.".into());
    }
    Ok((read_be16(data, 0)?, read_be16(data, 2)?, data[4], data[5]))
}

fn parse_rpc_header(packet: &[u8]) -> Result<RpcHeader, String> {
    if packet.len() < RPC_HEADER_LENGTH {
        return Err("DCE/RPC packet was truncated before its header.".into());
    }
    if packet[0] != 4 || packet[5] != 0 || packet[6] != 0 || packet[78] != 0 {
        return Err("DCE/RPC packet used an unsupported version or serial format.".into());
    }
    let data_representation = packet[4];
    if data_representation & 0x0F != 0 {
        return Err("DCE/RPC packet used a non-ASCII character representation.".into());
    }
    let big_endian = match data_representation & 0xF0 {
        0x00 => true,
        0x10 => false,
        _ => return Err("DCE/RPC packet used an unsupported data representation.".into()),
    };
    let body_length = read_u16(packet, 74, big_endian)?;
    let end = RPC_HEADER_LENGTH
        .checked_add(usize::from(body_length))
        .ok_or_else(|| "DCE/RPC body length overflowed.".to_string())?;
    if end != packet.len() {
        return Err("DCE/RPC fragment length did not match the captured packet.".into());
    }
    Ok(RpcHeader {
        packet_type: packet[1] & 0x1F,
        flags: packet[2],
        big_endian,
        object_uuid: parse_uuid(&packet[8..24], big_endian)?,
        interface_uuid: parse_uuid(&packet[24..40], big_endian)?,
        activity_uuid: parse_uuid(&packet[40..56], big_endian)?,
        interface_version: read_u32(packet, 60, big_endian)?,
        sequence: read_u32(packet, 64, big_endian)?,
        operation: read_u16(packet, 68, big_endian)?,
        body_length,
        fragment_number: read_u16(packet, 76, big_endian)?,
        serial_high: packet[7],
        serial_low: packet[79],
    })
}

fn encode_rpc_header(header: &RpcHeader) -> Vec<u8> {
    let mut packet = Vec::with_capacity(RPC_HEADER_LENGTH);
    packet.extend([4, header.packet_type, header.flags, 0]);
    packet.extend([
        if header.big_endian { 0 } else { 0x10 },
        0,
        0,
        header.serial_high,
    ]);
    put_uuid(&mut packet, header.object_uuid, header.big_endian);
    put_uuid(&mut packet, header.interface_uuid, header.big_endian);
    put_uuid(&mut packet, header.activity_uuid, header.big_endian);
    put_u32(&mut packet, 0, header.big_endian);
    put_u32(&mut packet, header.interface_version, header.big_endian);
    put_u32(&mut packet, header.sequence, header.big_endian);
    put_u16(&mut packet, header.operation, header.big_endian);
    put_u16(&mut packet, 0xFFFF, header.big_endian);
    put_u16(&mut packet, 0xFFFF, header.big_endian);
    put_u16(&mut packet, header.body_length, header.big_endian);
    put_u16(&mut packet, header.fragment_number, header.big_endian);
    packet.extend([0, header.serial_low]);
    packet
}

struct Tower {
    interface_uuid: Uuid,
    port: Option<u16>,
    ip_address: Option<Ipv4Addr>,
}

fn parse_tower(cursor: &mut Cursor<'_>, big_endian: bool) -> Result<Tower, String> {
    let _referent = cursor.u32(big_endian)?;
    let _annotation_offset = cursor.u32(big_endian)?;
    let annotation_length = cursor.u32(big_endian)? as usize;
    if annotation_length > 256 {
        return Err("DCE/RPC EPM annotation was oversized.".into());
    }
    cursor.bytes(annotation_length)?;
    let floor_length = cursor.u32(big_endian)? as usize;
    let floor_length_copy = cursor.u32(big_endian)? as usize;
    if floor_length != floor_length_copy || floor_length > 256 {
        return Err("DCE/RPC EPM tower length was invalid.".into());
    }
    let floor_start = cursor.position();
    let floor_count = cursor.u16(big_endian)?;
    if floor_count != 5 {
        return Err("DCE/RPC EPM tower did not contain five floors.".into());
    }
    let floor1 = parse_uuid_floor(cursor, big_endian)?;
    let _floor2 = parse_uuid_floor(cursor, big_endian)?;
    let _floor3 = parse_scalar_floor(cursor, big_endian)?;
    let port = parse_port_floor(cursor, big_endian)?;
    let ip_address = parse_ip_floor(cursor, big_endian)?;
    if cursor.position() - floor_start != floor_length {
        return Err("DCE/RPC EPM tower floor length did not match its contents.".into());
    }
    Ok(Tower {
        interface_uuid: floor1,
        port,
        ip_address,
    })
}

fn parse_uuid_floor(cursor: &mut Cursor<'_>, big_endian: bool) -> Result<Uuid, String> {
    let lhs_length = usize::from(cursor.u16(big_endian)?);
    if lhs_length < 19 {
        return Err("DCE/RPC EPM UUID floor was truncated.".into());
    }
    let protocol = cursor.byte()?;
    let uuid = cursor.uuid(big_endian)?;
    let _version_major = cursor.u16(big_endian)?;
    if lhs_length > 19 {
        cursor.bytes(lhs_length - 19)?;
    }
    let rhs_length = cursor.u16(big_endian)? as usize;
    if rhs_length < 2 {
        return Err("DCE/RPC EPM UUID floor version was truncated.".into());
    }
    let _version_minor = cursor.u16(big_endian)?;
    if rhs_length > 2 {
        cursor.bytes(rhs_length - 2)?;
    }
    if protocol != 0x0D {
        return Err("DCE/RPC EPM tower did not use UUID protocol floors.".into());
    }
    Ok(uuid)
}

fn parse_scalar_floor(cursor: &mut Cursor<'_>, big_endian: bool) -> Result<u8, String> {
    let lhs_length = usize::from(cursor.u16(big_endian)?);
    if lhs_length < 1 {
        return Err("DCE/RPC EPM scalar floor was truncated.".into());
    }
    let protocol = cursor.byte()?;
    if lhs_length > 1 {
        cursor.bytes(lhs_length - 1)?;
    }
    let rhs_length = usize::from(cursor.u16(big_endian)?);
    if rhs_length < 2 {
        return Err("DCE/RPC EPM scalar floor version was truncated.".into());
    }
    cursor.bytes(rhs_length)?;
    Ok(protocol)
}

fn parse_port_floor(cursor: &mut Cursor<'_>, big_endian: bool) -> Result<Option<u16>, String> {
    let protocol = parse_floor_prefix(cursor, big_endian, 2)?;
    let port = u16::from_be_bytes(cursor.bytes(2)?.try_into().expect("two-byte port"));
    Ok((protocol == 0x08).then_some(port))
}

fn parse_ip_floor(cursor: &mut Cursor<'_>, big_endian: bool) -> Result<Option<Ipv4Addr>, String> {
    let protocol = parse_floor_prefix(cursor, big_endian, 4)?;
    let bytes = cursor.bytes(4)?;
    Ok((protocol == 0x09).then_some(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])))
}

fn parse_floor_prefix(
    cursor: &mut Cursor<'_>,
    big_endian: bool,
    expected_rhs_length: u16,
) -> Result<u8, String> {
    let lhs_length = usize::from(cursor.u16(big_endian)?);
    if lhs_length < 1 {
        return Err("DCE/RPC EPM floor was truncated.".into());
    }
    let protocol = cursor.byte()?;
    if lhs_length > 1 {
        cursor.bytes(lhs_length - 1)?;
    }
    let rhs_length = cursor.u16(big_endian)?;
    if rhs_length != expected_rhs_length {
        return Err("DCE/RPC EPM floor value length was invalid.".into());
    }
    Ok(protocol)
}

struct Cursor<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    fn position(&self) -> usize {
        self.position
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.position)
    }

    fn bytes(&mut self, length: usize) -> Result<&'a [u8], String> {
        let end = self
            .position
            .checked_add(length)
            .ok_or_else(|| "PROFINET packet offset overflowed.".to_string())?;
        if end > self.data.len() {
            return Err("PROFINET packet was truncated.".into());
        }
        let result = &self.data[self.position..end];
        self.position = end;
        Ok(result)
    }

    fn byte(&mut self) -> Result<u8, String> {
        Ok(self.bytes(1)?[0])
    }

    fn u16(&mut self, big_endian: bool) -> Result<u16, String> {
        let position = self.position;
        let value = read_u16(self.data, position, big_endian)?;
        self.position += 2;
        Ok(value)
    }

    fn u32(&mut self, big_endian: bool) -> Result<u32, String> {
        let position = self.position;
        let value = read_u32(self.data, position, big_endian)?;
        self.position += 4;
        Ok(value)
    }

    fn uuid(&mut self, big_endian: bool) -> Result<Uuid, String> {
        parse_uuid(self.bytes(16)?, big_endian)
    }

    fn align(&mut self, alignment: usize) -> Result<(), String> {
        let padding = (alignment - self.position % alignment) % alignment;
        self.bytes(padding).map(|_| ())
    }
}

fn put_uuid(target: &mut Vec<u8>, value: Uuid, big_endian: bool) {
    let bytes = value.into_bytes();
    if big_endian {
        target.extend(bytes);
    } else {
        target.extend([bytes[3], bytes[2], bytes[1], bytes[0]]);
        target.extend([bytes[5], bytes[4], bytes[7], bytes[6]]);
        target.extend(&bytes[8..]);
    }
}

fn parse_uuid(bytes: &[u8], big_endian: bool) -> Result<Uuid, String> {
    if bytes.len() != 16 {
        return Err("UUID was truncated.".into());
    }
    if big_endian {
        return Uuid::from_slice(bytes).map_err(|_| "UUID was invalid.".to_string());
    }
    let mut value = [0; 16];
    value[..4].copy_from_slice(&[bytes[3], bytes[2], bytes[1], bytes[0]]);
    value[4..6].copy_from_slice(&[bytes[5], bytes[4]]);
    value[6..8].copy_from_slice(&[bytes[7], bytes[6]]);
    value[8..].copy_from_slice(&bytes[8..]);
    Ok(Uuid::from_bytes(value))
}

fn uuid(value: &str) -> Uuid {
    Uuid::parse_str(value).expect("valid protocol UUID")
}

fn put_u16(target: &mut Vec<u8>, value: u16, big_endian: bool) {
    target.extend(if big_endian {
        value.to_be_bytes()
    } else {
        value.to_le_bytes()
    });
}

fn put_u32(target: &mut Vec<u8>, value: u32, big_endian: bool) {
    target.extend(if big_endian {
        value.to_be_bytes()
    } else {
        value.to_le_bytes()
    });
}

fn read_u16(data: &[u8], offset: usize, big_endian: bool) -> Result<u16, String> {
    let bytes = data
        .get(offset..offset + 2)
        .ok_or_else(|| "PROFINET packet was truncated.".to_string())?;
    Ok(if big_endian {
        u16::from_be_bytes(bytes.try_into().expect("two-byte slice"))
    } else {
        u16::from_le_bytes(bytes.try_into().expect("two-byte slice"))
    })
}

fn read_u32(data: &[u8], offset: usize, big_endian: bool) -> Result<u32, String> {
    let bytes = data
        .get(offset..offset + 4)
        .ok_or_else(|| "PROFINET packet was truncated.".to_string())?;
    Ok(if big_endian {
        u32::from_be_bytes(bytes.try_into().expect("four-byte slice"))
    } else {
        u32::from_le_bytes(bytes.try_into().expect("four-byte slice"))
    })
}

fn read_be16(data: &[u8], offset: usize) -> Result<u16, String> {
    read_u16(data, offset, true)
}

fn read_be32(data: &[u8], offset: usize) -> Result<u32, String> {
    read_u32(data, offset, true)
}

fn clean_text(data: &[u8]) -> String {
    data.iter()
        .filter(|byte| **byte != 0)
        .map(|byte| {
            if byte.is_ascii_graphic() || *byte == b' ' {
                *byte as char
            } else {
                ' '
            }
        })
        .collect::<String>()
        .trim()
        .to_string()
}

fn software_revision(data: &[u8]) -> String {
    if data[0].is_ascii_graphic() {
        format!("{}{}.{}.{}", data[0] as char, data[1], data[2], data[3])
    } else {
        format!("{}.{}.{}", data[1], data[2], data[3])
    }
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|byte| format!("{byte:02X}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(big_endian: bool) -> RpcEndpoint {
        RpcEndpoint {
            object_uuid: uuid("dea00000-6c97-11d1-8271-0001002a0007"),
            interface_uuid: uuid(PNIO_INTERFACE),
            activity_uuid: uuid("ffddee11-b010-c020-e010-116655443322"),
            port: PNIO_PORT,
            ip_address: Ipv4Addr::new(192, 0, 2, 1),
            big_endian,
        }
    }

    fn response_packet(
        request: &RecordTarget,
        endpoint: &RpcEndpoint,
        record: &[u8],
        sequence: u32,
    ) -> Vec<u8> {
        let mut body = Vec::new();
        let args_length = 64 + record.len();
        put_u32(&mut body, 0, endpoint.big_endian);
        put_u32(&mut body, args_length as u32, endpoint.big_endian);
        put_u32(&mut body, args_length as u32, endpoint.big_endian);
        put_u32(&mut body, 0, endpoint.big_endian);
        put_u32(&mut body, args_length as u32, endpoint.big_endian);
        put_u16(&mut body, 0x8009, true);
        put_u16(&mut body, 60, true);
        body.extend([1, 0]);
        put_u16(&mut body, 0, true);
        put_uuid(&mut body, uuid(NIL_UUID), true);
        put_u32(&mut body, request.api, true);
        put_u16(&mut body, request.slot, true);
        put_u16(&mut body, request.subslot, true);
        put_u16(&mut body, 0, true);
        put_u16(&mut body, request.index, true);
        put_u32(&mut body, record.len() as u32, true);
        put_u16(&mut body, 0, true);
        put_u16(&mut body, 0, true);
        body.extend([0; 20]);
        body.extend(record);
        let header = RpcHeader::new(
            2,
            0x02,
            endpoint.big_endian,
            endpoint.object_uuid,
            endpoint.interface_uuid,
            endpoint.activity_uuid,
            1,
            sequence,
            5,
            body.len(),
        )
        .unwrap();
        let mut packet = encode_rpc_header(&header);
        packet.extend(body);
        packet
    }

    fn block_record(block_type: u16, version: (u8, u8), payload: &[u8]) -> Vec<u8> {
        let block_length = u16::try_from(payload.len() + 2).unwrap();
        let mut record = Vec::with_capacity(payload.len() + 6);
        record.extend(block_type.to_be_bytes());
        record.extend(block_length.to_be_bytes());
        record.extend([version.0, version.1]);
        record.extend(payload);
        record
    }

    fn api_list_record() -> Vec<u8> {
        let mut payload = vec![0, 1];
        payload.extend(0_u32.to_be_bytes());
        block_record(0x001A, (1, 0), &payload)
    }

    fn module_record(block_type: u16, version: (u8, u8)) -> Vec<u8> {
        let mut payload = vec![0, 1];
        payload.extend(0_u32.to_be_bytes());
        payload.extend(1_u16.to_be_bytes());
        payload.extend(1_u16.to_be_bytes());
        payload.extend(0x1111_u32.to_be_bytes());
        payload.extend(1_u16.to_be_bytes());
        payload.extend(1_u16.to_be_bytes());
        payload.extend(0x2222_u32.to_be_bytes());
        block_record(block_type, version, &payload)
    }

    fn im0_record() -> Vec<u8> {
        let mut payload = [0_u8; 54];
        payload[0..2].copy_from_slice(&0x1234_u16.to_be_bytes());
        payload[2..7].copy_from_slice(b"ORD-1");
        payload[22..28].copy_from_slice(b"SERIAL");
        payload[38..40].copy_from_slice(&3_u16.to_be_bytes());
        payload[40..44].copy_from_slice(b"V\x01\x02\x03");
        payload[44..46].copy_from_slice(&4_u16.to_be_bytes());
        payload[46..48].copy_from_slice(&0x0102_u16.to_be_bytes());
        payload[48..50].copy_from_slice(&7_u16.to_be_bytes());
        payload[50..52].copy_from_slice(&[1, 2]);
        payload[52..54].copy_from_slice(&0x003E_u16.to_be_bytes());
        block_record(0x0020, (1, 0), &payload)
    }

    fn im1_record() -> Vec<u8> {
        let mut payload = [b' '; 54];
        payload[..8].copy_from_slice(b"FUNCTION");
        payload[32..40].copy_from_slice(b"LOCATION");
        block_record(0x0021, (1, 0), &payload)
    }

    fn im2_record() -> Vec<u8> {
        let mut payload = [b' '; 16];
        payload[..10].copy_from_slice(b"2026-10-01");
        block_record(0x0022, (1, 0), &payload)
    }

    fn im3_record() -> Vec<u8> {
        let mut payload = [b' '; 54];
        payload[..10].copy_from_slice(b"DESCRIPTOR");
        block_record(0x0023, (1, 0), &payload)
    }

    fn im4_record() -> Vec<u8> {
        let mut payload = [0_u8; 54];
        payload[..4].copy_from_slice(b"crc1");
        for (index, value) in (1_u32..=10).enumerate() {
            let offset = 4 + index * 4;
            payload[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        }
        block_record(0x0024, (1, 0), &payload)
    }

    fn im5_record() -> Vec<u8> {
        let mut im5_payload = [b' '; 152];
        im5_payload[0..64].fill(b'A');
        im5_payload[64..128].fill(b'B');
        im5_payload[128..130].copy_from_slice(&0x1234_u16.to_be_bytes());
        im5_payload[130..146].fill(b'C');
        im5_payload[146..148].copy_from_slice(&3_u16.to_be_bytes());
        im5_payload[148..152].copy_from_slice(b"V\x01\x02\x03");
        let im5_data = block_record(0x0034, (1, 0), &im5_payload);
        let asset_a = block_record(0x0036, (1, 0), &[]);
        let asset_b = block_record(0x0037, (1, 0), &[]);
        let asset_c = block_record(0x0038, (1, 0), &[]);
        let mut payload = vec![0, 4];
        payload.extend(im5_data);
        payload.extend(asset_a);
        payload.extend(asset_b);
        payload.extend(asset_c);
        block_record(0x0025, (1, 0), &payload)
    }

    fn record_for_index(index: u16) -> Vec<u8> {
        match index {
            0xF821 => api_list_record(),
            0xF840 => module_record(0x0030, (1, 0)),
            0xF000 => module_record(0x0013, (1, 1)),
            0xAFF0 => im0_record(),
            0xAFF1 => im1_record(),
            0xAFF2 => im2_record(),
            0xAFF3 => im3_record(),
            0xAFF4 => im4_record(),
            0xAFF5 => im5_record(),
            _ => panic!("unexpected test record index 0x{index:04X}"),
        }
    }

    fn uuid_floor(value: Uuid) -> Vec<u8> {
        let mut floor = Vec::new();
        put_u16(&mut floor, 19, false);
        floor.push(0x0D);
        put_uuid(&mut floor, value, false);
        put_u16(&mut floor, 1, false);
        put_u16(&mut floor, 2, false);
        put_u16(&mut floor, 1, false);
        floor
    }

    fn epm_response_packet(
        request: &RpcHeader,
        endpoint: Option<&RpcEndpoint>,
        handle: &EpmHandle,
    ) -> Vec<u8> {
        let mut floors =
            uuid_floor(endpoint.map_or(uuid(PNIO_INTERFACE), |value| value.interface_uuid));
        floors.extend(uuid_floor(uuid("8a885d04-1ceb-11c9-9fe8-08002b104860")));
        put_u16(&mut floors, 1, false);
        floors.push(0x0A);
        put_u16(&mut floors, 2, false);
        put_u16(&mut floors, 0, false);
        put_u16(&mut floors, 1, false);
        floors.push(0x08);
        put_u16(&mut floors, 2, false);
        put_u16(
            &mut floors,
            endpoint.map_or(PNIO_PORT, |value| value.port),
            true,
        );
        put_u16(&mut floors, 1, false);
        floors.push(0x09);
        put_u16(&mut floors, 4, false);
        floors.extend(
            endpoint
                .map_or(Ipv4Addr::new(192, 0, 2, 1), |value| value.ip_address)
                .octets(),
        );

        let mut body = Vec::new();
        put_u32(&mut body, handle.entry, false);
        put_uuid(&mut body, handle.uuid, false);
        let actual = if endpoint.is_some() { 1 } else { 0 };
        put_u32(&mut body, actual, false);
        put_u32(&mut body, actual, false);
        put_u32(&mut body, 0, false);
        put_u32(&mut body, actual, false);
        if let Some(endpoint) = endpoint {
            put_uuid(&mut body, endpoint.object_uuid, false);
            put_u32(&mut body, 1, false);
            put_u32(&mut body, 0, false);
            put_u32(&mut body, 0, false);
            let floor_length = floors.len() + 2;
            put_u32(&mut body, floor_length as u32, false);
            put_u32(&mut body, floor_length as u32, false);
            put_u16(&mut body, 5, false);
            body.extend(floors);
        }
        if body.len() % 2 != 0 {
            body.push(0);
        }
        put_u32(&mut body, 0, false);
        let header = RpcHeader::new(
            2,
            0x02,
            false,
            uuid(NIL_UUID),
            uuid(EPM_INTERFACE),
            request.activity_uuid,
            3,
            request.sequence,
            2,
            body.len(),
        )
        .unwrap();
        let mut packet = encode_rpc_header(&header);
        packet.extend(body);
        packet
    }

    #[test]
    fn reads_epm_and_all_supported_records_with_a_continuation_handle() {
        let cancelled = AtomicBool::new(false);
        let endpoint = endpoint(false);
        let mut epm_calls = 0;
        let records = read_records(
            Duration::from_millis(10),
            &cancelled,
            |port, request, _, _| {
                let header = parse_rpc_header(request)?;
                if header.operation == 2 {
                    assert_eq!(port, EPM_PORT);
                    epm_calls += 1;
                    let handle = EpmHandle {
                        entry: 7,
                        uuid: uuid("11111111-2222-3333-4444-555555555555"),
                    };
                    let packet = epm_response_packet(
                        &header,
                        (epm_calls == 2).then_some(&endpoint),
                        &handle,
                    );
                    parse_rpc_fragment(&packet)
                } else {
                    assert_eq!(port, PNIO_PORT);
                    let target = RecordTarget {
                        api: read_u32(request, 124, true)?,
                        slot: read_u16(request, 128, true)?,
                        subslot: read_u16(request, 130, true)?,
                        index: read_u16(request, 134, true)?,
                        data_length: read_u32(request, 136, true)?,
                    };
                    let mut response_endpoint = endpoint.clone();
                    response_endpoint.activity_uuid = header.activity_uuid;
                    let packet = response_packet(
                        &target,
                        &response_endpoint,
                        &record_for_index(target.index),
                        header.sequence,
                    );
                    parse_rpc_fragment(&packet)
                }
            },
        )
        .unwrap();

        assert_eq!(epm_calls, 2);
        assert_eq!(records.len(), 15);
        assert!(records.iter().any(|record| record.target.index == 0xF821));
        assert!(records.iter().any(|record| record.target.index == 0xF840));
        assert!(records.iter().any(|record| record.target.index == 0xF000));
        assert!(records.iter().any(|record| {
            record.target.slot == 1 && record.target.subslot == 1 && record.target.index == 0xAFF5
        }));
    }

    #[test]
    fn parses_all_im_records_and_asset_management_entries() {
        assert_eq!(
            parse_record(0xAFF1, &im1_record()).unwrap()["function"],
            "FUNCTION"
        );
        assert_eq!(
            parse_record(0xAFF2, &im2_record()).unwrap()["installationDate"],
            "2026-10-01"
        );
        assert_eq!(
            parse_record(0xAFF3, &im3_record()).unwrap()["descriptor"],
            "DESCRIPTOR"
        );
        assert_eq!(
            parse_record(0xAFF4, &im4_record()).unwrap()["checkWorkingSubs"],
            9
        );
        let parsed = parse_record(0xAFF5, &im5_record()).unwrap();
        assert_eq!(parsed["im5Data"][0]["vendorId"], "1234");
        assert_eq!(parsed["assetManagementBlocks"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn exchanges_fragmented_rpc_frames_and_sends_a_fragment_ack() {
        let source_mac = [0, 1, 2, 3, 4, 5];
        let target_mac = [6, 7, 8, 9, 10, 11];
        let source_ip = Ipv4Addr::new(192, 0, 2, 2);
        let target_ip = Ipv4Addr::new(192, 0, 2, 1);
        let endpoint = endpoint(false);
        let target = RecordTarget {
            api: 0,
            slot: 0,
            subslot: 1,
            index: 0xAFF0,
            data_length: 128,
        };
        let request = build_read_request(&endpoint, &target, 4).unwrap();
        let response = response_packet(&target, &endpoint, &im0_record(), 4);
        let (first_header, first_body) = parse_rpc_fragment(&response).unwrap();
        let split = first_body.len() / 2;
        let mut first_header = first_header;
        first_header.flags = 0x04;
        first_header.fragment_number = 0;
        first_header.body_length = split as u16;
        let mut second_header = first_header.clone();
        second_header.flags = 0x06;
        second_header.fragment_number = 1;
        second_header.body_length = (first_body.len() - split) as u16;
        let mut first = encode_rpc_header(&first_header);
        first.extend(&first_body[..split]);
        let mut second = encode_rpc_header(&second_header);
        second.extend(&first_body[split..]);

        let wrong_frame = ethernet_ipv4_udp_frame(
            source_mac,
            target_mac,
            Ipv4Addr::new(192, 0, 2, 99),
            source_ip,
            PNIO_PORT,
            rpc_port(),
            &first,
        )
        .unwrap();
        let first_frame = ethernet_ipv4_udp_frame(
            target_mac,
            source_mac,
            target_ip,
            source_ip,
            PNIO_PORT,
            rpc_port(),
            &first,
        )
        .unwrap();
        let second_frame = ethernet_ipv4_udp_frame(
            target_mac,
            source_mac,
            target_ip,
            source_ip,
            PNIO_PORT,
            rpc_port(),
            &second,
        )
        .unwrap();
        assert!(parse_ipv4_udp_frame(&first_frame).is_some());
        assert!(parse_rpc_fragment(&first).is_ok());
        let mut incoming = vec![wrong_frame, first_frame, second_frame];
        let mut sent = Vec::new();
        let mut send = |frame: &[u8]| {
            sent.push(frame.to_vec());
            Ok(())
        };
        let mut receive = || {
            Ok(if incoming.is_empty() {
                None
            } else {
                Some(incoming.remove(0))
            })
        };
        let cancelled = AtomicBool::new(false);
        let (header, body) = exchange(
            source_mac,
            source_ip,
            target_mac,
            target_ip,
            PNIO_PORT,
            &request,
            Duration::from_millis(100),
            &cancelled,
            &mut send,
            &mut receive,
        )
        .unwrap();

        assert_eq!(header.packet_type, 2);
        assert_eq!(body, first_body);
        assert_eq!(sent.len(), 2);
        let ack = parse_ipv4_udp_frame(&sent[1]).unwrap();
        let (ack_header, ack_body) = parse_rpc_fragment(ack.payload).unwrap();
        assert_eq!(ack_header.packet_type, 9);
        assert!(ack_body.is_empty());
    }

    #[test]
    fn builds_read_request_with_the_documented_ndr_and_iod_layout() {
        let target = RecordTarget {
            api: 0,
            slot: 0,
            subslot: 1,
            index: 0xAFF0,
            data_length: DEFAULT_RECORD_DATA_LENGTH,
        };
        let packet = build_read_request(&endpoint(false), &target, 7).unwrap();
        assert_eq!(packet.len(), 164);
        assert_eq!(packet[0..8], [4, 0, 0x20, 0, 0x10, 0, 0, 0]);
        assert_eq!(u16::from_le_bytes([packet[74], packet[75]]), 84);
        assert_eq!(
            u32::from_le_bytes(packet[80..84].try_into().unwrap()),
            32_832
        );
        assert_eq!(&packet[100..104], &[0, 9, 0, 60]);
        assert_eq!(u16::from_be_bytes([packet[134], packet[135]]), 0xAFF0);
        assert_eq!(
            u32::from_be_bytes(packet[136..140].try_into().unwrap()),
            32_768
        );
    }

    #[test]
    fn parses_and_reassembles_little_and_big_endian_rpc_fragments() {
        let target = RecordTarget {
            api: 3,
            slot: 2,
            subslot: 1,
            index: 0xAFF0,
            data_length: 256,
        };
        let record = vec![0x20, 0, 0, 0, 1, 0];
        let packet = response_packet(&target, &endpoint(false), &record, 11);
        let split = 96;
        let (first_header, first_body) = parse_rpc_fragment(&packet).unwrap();
        let mut first_header = first_header;
        first_header.flags = 0x04;
        first_header.body_length = (split - RPC_HEADER_LENGTH) as u16;
        let mut second_header = first_header.clone();
        second_header.fragment_number = 1;
        second_header.flags = 0x02 | 0x04;
        second_header.body_length = (first_body.len() - (split - RPC_HEADER_LENGTH)) as u16;
        let mut first = encode_rpc_header(&first_header);
        first.extend(&first_body[..split - RPC_HEADER_LENGTH]);
        let mut second = encode_rpc_header(&second_header);
        second.extend(&first_body[split - RPC_HEADER_LENGTH..]);
        let fragments = vec![
            parse_rpc_fragment(&first).unwrap(),
            parse_rpc_fragment(&second).unwrap(),
        ];
        let (header, body) = reassemble_rpc_fragments(fragments).unwrap();
        assert_eq!(header.sequence, 11);
        assert_eq!(body, first_body);

        let big = response_packet(&target, &endpoint(true), &record, 12);
        let (header, body) = parse_rpc_fragment(&big).unwrap();
        assert!(header.big_endian);
        assert_eq!(
            parse_read_response(&header, &body, &target).unwrap().data,
            record
        );
    }

    #[test]
    fn preserves_rpc_serial_bytes_in_their_header_fields() {
        let mut header = RpcHeader::new(
            2,
            0,
            false,
            endpoint(false).object_uuid,
            endpoint(false).interface_uuid,
            endpoint(false).activity_uuid,
            1,
            1,
            5,
            0,
        )
        .unwrap();
        header.serial_high = 0x12;
        header.serial_low = 0x34;
        let packet = encode_rpc_header(&header);
        assert_eq!(packet[7], 0x12);
        assert_eq!(packet[78], 0);
        assert_eq!(packet[79], 0x34);
        let parsed = parse_rpc_header(&packet).unwrap();
        assert_eq!((parsed.serial_high, parsed.serial_low), (0x12, 0x34));
    }

    #[test]
    fn parses_im0_and_rejects_truncated_records() {
        let mut record = vec![0; 60];
        record[..6].copy_from_slice(&[0, 0x20, 0, 56, 1, 0]);
        record[6..8].copy_from_slice(&0x1234_u16.to_be_bytes());
        record[8..13].copy_from_slice(b"ORD-1");
        record[28..34].copy_from_slice(b"SERIAL");
        record[44..46].copy_from_slice(&3_u16.to_be_bytes());
        record[46..50].copy_from_slice(b"A\x01\x02\x03");
        record[50..52].copy_from_slice(&4_u16.to_be_bytes());
        record[52..54].copy_from_slice(&0x3B00_u16.to_be_bytes());
        record[54..56].copy_from_slice(&7_u16.to_be_bytes());
        record[56..58].copy_from_slice(&[1, 2]);
        record[58..60].copy_from_slice(&0x002E_u16.to_be_bytes());
        let parsed = parse_record(0xAFF0, &record).unwrap();
        assert_eq!(parsed["manufacturerId"], "1234");
        assert_eq!(
            parsed["manufacturerName"],
            "Chengdu Zongheng Intelligence Control Technology Co., Ltd."
        );
        assert_eq!(parsed["profileName"], "Robot and Numeric Controls");
        assert_eq!(parsed["softwareRevision"], "A1.2.3");
        assert_eq!(parsed["imSupported"], 0x2E);
        assert!(parse_record(0xAFF0, &record[..59]).is_err());
    }

    #[test]
    fn parses_api_real_identification_filter_and_im5_records() {
        let mut api_record = vec![0, 0x1A, 0, 12, 1, 0, 0, 2];
        api_record.extend(7_u32.to_be_bytes());
        api_record.extend(9_u32.to_be_bytes());
        let parsed = parse_record(0xF821, &api_record).unwrap();
        assert_eq!(parsed["apis"][1]["api"], 9);

        let mut real_identification = vec![0, 0x13, 0, 24, 1, 1, 0, 1];
        real_identification.extend(7_u32.to_be_bytes());
        real_identification.extend(1_u16.to_be_bytes());
        real_identification.extend(2_u16.to_be_bytes());
        real_identification.extend(8_u32.to_be_bytes());
        real_identification.extend(1_u16.to_be_bytes());
        real_identification.extend(3_u16.to_be_bytes());
        real_identification.extend(4_u32.to_be_bytes());
        let parsed = parse_record(0xF000, &real_identification).unwrap();
        assert_eq!(
            parsed["apis"][0]["modules"][0]["submodules"][0]["subslot"],
            3
        );

        let mut filter_block = vec![0, 0x30, 0, 24, 1, 0, 0, 1];
        filter_block.extend(7_u32.to_be_bytes());
        filter_block.extend(1_u16.to_be_bytes());
        filter_block.extend(2_u16.to_be_bytes());
        filter_block.extend(3_u32.to_be_bytes());
        filter_block.extend(1_u16.to_be_bytes());
        filter_block.extend(4_u16.to_be_bytes());
        filter_block.extend(5_u32.to_be_bytes());
        let parsed = parse_record(0xF840, &filter_block).unwrap();
        assert_eq!(parsed["apis"][0]["modules"][0]["slot"], 2);

        let mut im5_data = vec![0, 0x34, 0, 154, 1, 0];
        im5_data.extend([b'A'; 64]);
        im5_data.extend([b'B'; 64]);
        im5_data.extend(0x1234_u16.to_be_bytes());
        im5_data.extend([b'C'; 16]);
        im5_data.extend(3_u16.to_be_bytes());
        im5_data.extend([b'V', 1, 2, 3]);
        let mut im5_record = vec![0, 0x25, 0, 162, 1, 0, 0, 1];
        im5_record.extend(im5_data);
        let parsed = parse_record(0xAFF5, &im5_record).unwrap();
        assert_eq!(parsed["im5Data"][0]["imSoftwareRevision"], "V1.2.3");
        assert_eq!(
            parsed["im5Data"][0]["vendorName"],
            "Chengdu Zongheng Intelligence Control Technology Co., Ltd."
        );
    }

    #[test]
    fn resolves_manufacturer_and_profile_names() {
        assert_eq!(
            crate::profinet_database::manufacturer_name(42),
            Some("SIEMENS AG")
        );
        assert_eq!(crate::profinet_database::manufacturer_name(0xFDE8), None);
        assert_eq!(
            crate::profinet_database::profile_name(0x3B00),
            Some("Robot and Numeric Controls")
        );
        assert_eq!(
            crate::profinet_database::profile_name(0),
            Some("Unspecified")
        );

        let mut record = vec![0; 60];
        record[..6].copy_from_slice(&[0, 0x20, 0, 56, 1, 0]);
        record[6..8].copy_from_slice(&0xFDE8_u16.to_be_bytes());
        record[52..54].copy_from_slice(&0xFFFF_u16.to_be_bytes());
        let parsed = parse_record(0xAFF0, &record).unwrap();
        assert!(parsed.get("manufacturerName").is_none());
        assert_eq!(
            parsed["profileName"],
            "PROFIBUS: reserved for Device IDs; PROFINET: reserved for Profile IDs"
        );
    }

    #[test]
    fn validates_rpc_lengths_and_targets() {
        let target = RecordTarget {
            api: 0,
            slot: 0,
            subslot: 1,
            index: 0xAFF0,
            data_length: 128,
        };
        let packet = response_packet(&target, &endpoint(false), &[], 1);
        let mut malformed = packet.clone();
        malformed[74..76].copy_from_slice(&85_u16.to_le_bytes());
        assert!(parse_rpc_fragment(&malformed).is_err());
        let (header, body) = parse_rpc_fragment(&packet).unwrap();
        let wrong = RecordTarget {
            index: 0xF000,
            ..target
        };
        assert!(parse_read_response(&header, &body, &wrong).is_err());
    }
}
