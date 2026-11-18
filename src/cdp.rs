use crate::contract::{
    Device, Endpoint, Observation, Source, TopologyLink, format_mac, hex, mac_bytes,
};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub const CAPTURE_WINDOW: Duration = Duration::from_secs(30);
const MAX_NEIGHBORS: usize = 512;
const MAX_TLVS: usize = 64;
type Neighbors = BTreeMap<String, (Device, TopologyLink, Instant)>;

pub struct CaptureResult {
    pub devices: Vec<Device>,
    pub links: Vec<TopologyLink>,
    pub warnings: Vec<String>,
}

pub fn scan(
    interface: &str,
    local_mac: &str,
    cancelled: &AtomicBool,
) -> Result<CaptureResult, String> {
    if cancelled.load(Ordering::Relaxed) {
        return Ok(CaptureResult {
            devices: Vec::new(),
            links: Vec::new(),
            warnings: Vec::new(),
        });
    }
    mac_bytes(local_mac).ok_or("CDP requires the selected interface MAC")?;
    let mut neighbors = BTreeMap::new();
    let started = Instant::now();
    let mut limited = false;
    let result = crate::lldp::capture_passive(interface, CAPTURE_WINDOW, cancelled, |frame| {
        if is_cdp_frame(frame) {
            limited |= !retain_frame(&mut neighbors, frame, local_mac, Instant::now());
        }
    });
    let mut warnings = Vec::new();
    if let Err(error) = result {
        warnings.push(format!("Passive CDP capture: {error}"));
    }
    if limited {
        warnings.push(
            "Passive CDP neighbor limit reached (512); additional neighbors were omitted.".into(),
        );
    }
    warnings.push(format!(
        "Passive CDP observed the selected link for {} ms; absence of advertisements does not prove absence of neighbors.",
        started.elapsed().as_millis()
    ));
    expire(&mut neighbors, Instant::now());
    let (devices, links) = neighbors
        .into_values()
        .map(|(device, link, _)| (device, link))
        .unzip();
    Ok(CaptureResult {
        devices,
        links,
        warnings,
    })
}

fn expire(neighbors: &mut Neighbors, now: Instant) {
    neighbors.retain(|_, (device, _, seen)| {
        now.saturating_duration_since(*seen).as_secs()
            < device.observations[0].raw["ttl"].as_u64().unwrap_or(0)
    });
}

fn retain_frame(neighbors: &mut Neighbors, frame: &[u8], local_mac: &str, now: Instant) -> bool {
    let Some((device, link)) = parse(frame, local_mac) else {
        return true;
    };
    expire(neighbors, now);
    let raw = &device.observations[0].raw;
    let key = format!("{}:{}", device.mac_address, raw["portId"]);
    if raw["ttl"] == 0 {
        neighbors.remove(&key);
    } else if neighbors.len() < MAX_NEIGHBORS || neighbors.contains_key(&key) {
        neighbors.insert(key, (device, link, now));
    } else {
        return false;
    }
    true
}

pub(crate) fn is_cdp_frame(frame: &[u8]) -> bool {
    if frame.len() < 22 || frame[..6] != [1, 0, 0x0c, 0xcc, 0xcc, 0xcc] {
        return false;
    }
    let mut offset = 12;
    for _ in 0..2 {
        match frame.get(offset..offset + 2) {
            Some([0x81, 0x00] | [0x88, 0xa8]) => offset += 4,
            _ => break,
        }
    }
    let Some(length) = frame
        .get(offset..offset + 2)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u16::from_be_bytes)
    else {
        return false;
    };
    let length = usize::from(length);
    if !(12..=1500).contains(&length) {
        return false;
    }
    let payload_start = offset + 2;
    let Some(payload) = payload_start
        .checked_add(length)
        .and_then(|end| frame.get(payload_start..end))
    else {
        return false;
    };
    payload.starts_with(&[0xaa, 0xaa, 0x03, 0, 0, 0x0c, 0x20, 0])
}

fn parse(frame: &[u8], local_mac: &str) -> Option<(Device, TopologyLink)> {
    if frame.len() < 14
        || frame[..6] != [1, 0, 0x0c, 0xcc, 0xcc, 0xcc]
        || frame[6] & 1 != 0
        || frame[6..12] == [0; 6]
        || frame[6..12] == mac_bytes(local_mac)?
    {
        return None;
    }
    let mut offset = 12;
    let mut vlans = Vec::new();
    for _ in 0..2 {
        if matches!(frame.get(offset..offset + 2)?, [0x81, 0] | [0x88, 0xa8]) {
            vlans.push(
                u16::from_be_bytes(frame.get(offset + 2..offset + 4)?.try_into().ok()?) & 0x0fff,
            );
            offset += 4;
        }
    }
    let payload_length = usize::from(u16::from_be_bytes(
        frame.get(offset..offset + 2)?.try_into().ok()?,
    ));
    if payload_length > 1500 {
        return None;
    }
    let payload_start = offset.checked_add(2)?;
    let payload_end = payload_start.checked_add(payload_length)?;
    let payload = frame.get(payload_start..payload_end)?;
    if payload.len() < 12 || payload[..8] != [0xaa, 0xaa, 0x03, 0, 0, 0x0c, 0x20, 0] {
        return None;
    }
    let packet = &payload[8..];
    let version = *packet.first()?;
    let ttl = *packet.get(1)?;
    if !matches!(version, 1 | 2) || packet.len() < 4 || !valid_checksum(packet) {
        return None;
    }

    let mut offset = 4;
    let mut tlvs = Vec::new();
    let mut inventory = Map::new();
    let mut fields = BTreeMap::from([("protocols".into(), json!(["cdp"]))]);
    let mut device_id = None;
    let mut port_id = None;
    let mut platform = None;
    let mut system_name = None;
    while offset < packet.len() && tlvs.len() < MAX_TLVS {
        let header = packet.get(offset..offset + 4)?;
        let kind = u16::from_be_bytes(header[..2].try_into().ok()?);
        let length = usize::from(u16::from_be_bytes(header[2..4].try_into().ok()?));
        if length < 4 {
            return None;
        }
        let end = offset.checked_add(length)?;
        let value = packet.get(offset + 4..end)?;
        tlvs.push(json!({"type": kind, "length": length, "hex": hex(value)}));
        match kind {
            1 | 3 | 5 | 6 | 9 | 20 | 23 => {
                let text = std::str::from_utf8(value).ok()?.trim_end_matches('\0');
                if text.is_empty() {
                    return None;
                }
                let key = match kind {
                    1 => {
                        if device_id.replace(text.to_owned()).is_some() {
                            return None;
                        }
                        "deviceId"
                    }
                    3 => {
                        if port_id.replace(text.to_owned()).is_some() {
                            return None;
                        }
                        "portId"
                    }
                    5 => "softwareVersion",
                    6 => {
                        platform = Some(text.to_owned());
                        "platform"
                    }
                    9 => "vtpDomain",
                    20 => {
                        system_name = Some(text.to_owned());
                        "systemName"
                    }
                    _ => "location",
                };
                inventory.insert(key.into(), json!(text));
            }
            2 | 22 => {
                let addresses = decode_addresses(value)?;
                inventory.insert(
                    if kind == 2 {
                        "addresses"
                    } else {
                        "managementAddresses"
                    }
                    .into(),
                    json!(addresses),
                );
            }
            4 if value.len() == 4 => {
                inventory.insert(
                    "capabilities".into(),
                    json!(u32::from_be_bytes(value.try_into().ok()?)),
                );
            }
            10 if value.len() == 2 => {
                inventory.insert(
                    "nativeVlan".into(),
                    json!(u16::from_be_bytes(value.try_into().ok()?)),
                );
            }
            11 if value.len() == 1 && value[0] <= 1 => {
                inventory.insert(
                    "duplex".into(),
                    json!(if value[0] == 1 { "full" } else { "half" }),
                );
            }
            16 if value.len() == 2 => {
                inventory.insert(
                    "powerConsumption".into(),
                    json!(u16::from_be_bytes(value.try_into().ok()?)),
                );
            }
            17 if value.len() == 4 => {
                inventory.insert(
                    "mtu".into(),
                    json!(u32::from_be_bytes(value.try_into().ok()?)),
                );
            }
            21 => {
                inventory.insert("systemObjectIdHex".into(), json!(hex(value)));
            }
            25 | 26 => {
                inventory.insert(format!("tlv{kind}"), json!(hex(value)));
            }
            7 | 8 | 12..=15 | 18 | 19 | 24 => {
                inventory.insert(format!("tlv{kind}"), json!(hex(value)));
            }
            _ => {}
        }
        offset = end;
    }
    if offset != packet.len() {
        return None;
    }
    let device_id = device_id?;
    let port_id = port_id?;
    let name = system_name.as_deref().unwrap_or(&device_id);
    fields.insert("name".into(), json!(name));
    if let Some(platform) = &platform {
        fields.insert("model".into(), json!(platform));
    }
    let mac = format_mac(&frame[6..12]);
    let observed_at = crate::now();
    let raw = json!({
        "observationId": uuid::Uuid::new_v4().to_string(),
        "subject": {"kind": "device", "macAddress": mac},
        "acquisition": {"mechanism": "passive-announcement", "interfaceMac": local_mac},
        "protocol": "cdp",
        "version": version,
        "ttl": ttl,
        "deviceId": device_id,
        "portId": port_id,
        "platform": platform,
        "systemName": system_name,
        "vlans": vlans,
        "inventory": inventory,
        "tlvs": tlvs
    });
    let link = TopologyLink {
        source: Source::Cdp,
        observed_at: observed_at.clone(),
        local: Endpoint {
            mac_address: local_mac.into(),
            station_name: None,
            interface_key: None,
            port_id: None,
            port_mac: None,
        },
        remote: Endpoint {
            mac_address: mac.clone(),
            station_name: Some(name.to_owned()),
            interface_key: None,
            port_id: Some(port_id),
            port_mac: None,
        },
        raw: raw.clone(),
    };
    let device = Device {
        mac_address: mac.clone(),
        mac_addresses: vec![mac.clone()],
        observations: vec![Observation {
            source: Source::Cdp,
            observed_at,
            ip_address: None,
            mac_address: Some(mac),
            fields,
            raw,
            warnings: Vec::new(),
        }],
        ..Device::default()
    };
    Some((device, link))
}

fn valid_checksum(packet: &[u8]) -> bool {
    let sum = packet.chunks(2).fold(0_u32, |sum, chunk| {
        sum + u32::from(u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]))
    });
    let mut folded = (sum & 0xffff) + (sum >> 16);
    folded = (folded & 0xffff) + (folded >> 16);
    folded == 0xffff
}

fn decode_addresses(value: &[u8]) -> Option<Vec<Value>> {
    let count = usize::try_from(u32::from_be_bytes(value.get(..4)?.try_into().ok()?)).ok()?;
    if count > 64 {
        return None;
    }
    let mut offset = 4;
    let mut addresses = Vec::with_capacity(count);
    for _ in 0..count {
        let protocol_type = *value.get(offset)?;
        offset += 1;
        let protocol_length = usize::from(*value.get(offset)?);
        offset += 1;
        let protocol = value.get(offset..offset.checked_add(protocol_length)?)?;
        offset += protocol_length;
        let address_length = usize::from(u16::from_be_bytes(
            value.get(offset..offset + 2)?.try_into().ok()?,
        ));
        offset += 2;
        let address = value.get(offset..offset.checked_add(address_length)?)?;
        offset += address_length;
        addresses.push(json!({
            "protocolType": protocol_type,
            "protocol": hex(protocol),
            "address": hex(address)
        }));
    }
    (offset == value.len()).then_some(addresses)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tlv(kind: u16, value: &[u8], packet: &mut Vec<u8>) {
        packet.extend(kind.to_be_bytes());
        packet.extend(u16::try_from(value.len() + 4).unwrap().to_be_bytes());
        packet.extend(value);
    }

    fn advertisement(version: u8) -> Vec<u8> {
        advertisement_with(version, &[])
    }

    fn advertisement_with(version: u8, extra: &[(u16, &[u8])]) -> Vec<u8> {
        let mut packet = vec![version, 180, 0, 0];
        tlv(1, b"switch-1", &mut packet);
        tlv(3, b"GigabitEthernet1/1", &mut packet);
        tlv(6, b"Cisco IOS", &mut packet);
        tlv(10, &[0, 42], &mut packet);
        tlv(11, &[1], &mut packet);
        if version == 2 {
            tlv(20, b"switch-1.example", &mut packet);
        }
        for (kind, value) in extra {
            tlv(*kind, value, &mut packet);
        }
        let mut sum = packet.chunks(2).fold(0_u32, |sum, chunk| {
            sum + u32::from(u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]))
        });
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        let checksum = !(sum as u16);
        packet[2..4].copy_from_slice(&checksum.to_be_bytes());
        let mut frame = vec![1, 0, 0x0c, 0xcc, 0xcc, 0xcc, 2, 0, 0, 0, 0, 1];
        frame.extend(u16::try_from(packet.len() + 8).unwrap().to_be_bytes());
        frame.extend([0xaa, 0xaa, 3, 0, 0, 0x0c, 0x20, 0]);
        frame.extend(packet);
        frame
    }

    fn refresh_checksum(frame: &mut [u8]) {
        let packet = &mut frame[22..];
        packet[2..4].fill(0);
        let mut sum = packet.chunks(2).fold(0_u32, |sum, chunk| {
            sum + u32::from(u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]))
        });
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        packet[2..4].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    }

    #[test]
    fn parses_cdp_v1_and_v2_without_expanding_ip_scope() {
        for version in [1, 2] {
            let (device, link) = parse(&advertisement(version), "02:00:00:00:00:02").unwrap();
            let observation = &device.observations[0];
            assert_eq!(observation.raw["version"], version);
            assert_eq!(observation.fields["model"], "Cisco IOS");
            assert_eq!(observation.fields["protocols"], json!(["cdp"]));
            assert_eq!(device.ip_addresses, Vec::<String>::new());
            assert_eq!(link.source, Source::Cdp);
            assert_eq!(link.remote.port_id.as_deref(), Some("GigabitEthernet1/1"));
            assert_eq!(observation.raw["inventory"]["nativeVlan"], 42);
            assert_eq!(
                observation.raw["inventory"]["systemName"].as_str(),
                (version == 2).then_some("switch-1.example")
            );
        }
    }

    #[test]
    fn rejects_invalid_checksums_truncation_sources_and_malformed_tlvs() {
        let local = "02:00:00:00:00:02";
        let frame = advertisement(2);
        for end in 0..frame.len() {
            assert!(parse(&frame[..end], local).is_none(), "{end}");
        }
        let mut bad = frame.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(parse(&bad, local).is_none());
        bad = frame.clone();
        bad[6] |= 1;
        assert!(parse(&bad, local).is_none());
        bad = frame;
        bad[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        assert!(parse(&bad, local).is_none());
    }

    #[test]
    fn rejects_malformed_snap_and_tlv_data() {
        let local = "02:00:00:00:00:02";
        let mut bad_snap = advertisement(2);
        bad_snap[14] = 0xab;
        assert!(parse(&bad_snap, local).is_none());

        let mut short_tlv = advertisement(2);
        short_tlv[28..30].copy_from_slice(&3_u16.to_be_bytes());
        refresh_checksum(&mut short_tlv);
        assert!(parse(&short_tlv, local).is_none());

        let mut empty_identity = advertisement_with(2, &[(1, b"")]);
        refresh_checksum(&mut empty_identity);
        assert!(parse(&empty_identity, local).is_none());
    }

    #[test]
    fn rejects_duplicate_device_and_port_identifiers() {
        let local = "02:00:00:00:00:02";
        let mut duplicate_device = advertisement_with(2, &[(1, b"switch-2")]);
        refresh_checksum(&mut duplicate_device);
        assert!(parse(&duplicate_device, local).is_none());

        let mut duplicate_port = advertisement_with(2, &[(3, b"GigabitEthernet1/2")]);
        refresh_checksum(&mut duplicate_port);
        assert!(parse(&duplicate_port, local).is_none());
    }

    #[test]
    fn preserves_unknown_tlvs_and_rejects_excessive_tlv_counts() {
        let local = "02:00:00:00:00:02";
        let unknown = [0xde, 0xad];
        let frame = advertisement_with(2, &[(99, &unknown)]);
        let (device, _) = parse(&frame, local).unwrap();
        assert_eq!(
            device.observations[0].raw["tlvs"]
                .as_array()
                .unwrap()
                .last()
                .unwrap()["type"],
            99
        );

        let value = [0];
        let extra = vec![(99, value.as_slice()); MAX_TLVS + 1];
        let frame = advertisement_with(2, &extra);
        assert!(parse(&frame, local).is_none());
    }

    #[test]
    fn parses_supported_inventory_tlvs_and_addresses() {
        let mut address = 1_u32.to_be_bytes().to_vec();
        address.extend([1, 1, 0xcc, 0, 4, 192, 0, 2, 10]);
        let frame = advertisement_with(
            2,
            &[
                (2, &address),
                (4, &[0, 0, 0, 7]),
                (5, b"IOS-XE"),
                (9, b"engineering"),
                (16, &[0, 50]),
                (17, &[0, 0, 5, 220]),
                (21, &[1, 2, 3]),
                (22, &address),
                (23, b"cabinet 4"),
                (25, &[4, 5]),
                (26, &[6, 7]),
                (7, &[8]),
                (8, &[9]),
                (12, &[10]),
                (13, &[11]),
                (14, &[12]),
                (15, &[13]),
                (18, &[14]),
                (19, &[15]),
                (24, &[16]),
            ],
        );
        let (device, _) = parse(&frame, "02:00:00:00:00:02").unwrap();
        let inventory = &device.observations[0].raw["inventory"];

        assert_eq!(inventory["addresses"][0]["address"], "C000020A");
        assert_eq!(inventory["managementAddresses"][0]["protocol"], "CC");
        assert_eq!(inventory["capabilities"], 7);
        assert_eq!(inventory["softwareVersion"], "IOS-XE");
        assert_eq!(inventory["vtpDomain"], "engineering");
        assert_eq!(inventory["powerConsumption"], 50);
        assert_eq!(inventory["mtu"], 1500);
        assert_eq!(inventory["systemObjectIdHex"], "010203");
        assert_eq!(inventory["location"], "cabinet 4");
        assert_eq!(inventory["tlv25"], "0405");
        assert_eq!(inventory["tlv26"], "0607");
    }

    #[test]
    fn address_decoder_rejects_invalid_counts_and_lengths() {
        assert_eq!(decode_addresses(&[0, 0, 0, 0]), Some(Vec::new()));
        assert!(decode_addresses(&[0, 0, 0, 65]).is_none());
        assert!(decode_addresses(&[0, 0, 0, 1]).is_none());
        assert!(decode_addresses(&[0, 0, 0, 0, 0]).is_none());
    }

    #[test]
    fn validates_snap_envelope_and_vlan_tags() {
        let mut frame = advertisement(2);
        assert!(is_cdp_frame(&frame));
        frame.splice(12..12, [0x81, 0, 0, 42]);
        let length = u16::from_be_bytes(frame[16..18].try_into().unwrap());
        assert_eq!(length as usize, frame.len() - 18);
        assert!(parse(&frame, "02:00:00:00:00:02").is_some());
        assert!(is_cdp_frame(&frame));
        frame.splice(16..16, [0x88, 0xa8, 0, 7]);
        assert!(parse(&frame, "02:00:00:00:00:02").is_some());
    }

    #[test]
    fn rejects_non_cdp_snap_and_out_of_bounds_lengths() {
        assert!(!is_cdp_frame(&[]));

        let mut frame = advertisement(2);
        frame[0] = 2;
        assert!(!is_cdp_frame(&frame));

        let mut frame = advertisement(2);
        frame[12..14].copy_from_slice(&1501_u16.to_be_bytes());
        assert!(!is_cdp_frame(&frame));

        let mut frame = advertisement(2);
        frame[12..14].copy_from_slice(&1500_u16.to_be_bytes());
        assert!(!is_cdp_frame(&frame));
    }

    #[test]
    fn scan_reports_capture_setup_failures_and_honors_early_cancellation() {
        let cancelled = AtomicBool::new(true);
        let empty = scan("missing", "invalid", &cancelled).unwrap();
        assert!(empty.devices.is_empty() && empty.links.is_empty());

        let cancelled = AtomicBool::new(false);
        assert!(scan("missing", "invalid", &cancelled).is_err());

        let result = scan("otter-missing-interface", "02:00:00:00:00:02", &cancelled).unwrap();
        assert!(
            result
                .warnings
                .iter()
                .any(|warning| warning.starts_with("Passive CDP capture:"))
        );
        assert!(
            result
                .warnings
                .iter()
                .any(|warning| warning.contains("absence of advertisements"))
        );
    }

    #[test]
    fn cache_honors_ttl_withdrawal_updates_and_neighbor_limit() {
        let mut cache = Neighbors::new();
        let mut frame = advertisement(2);
        let local = "02:00:00:00:00:02";
        let now = Instant::now();
        assert!(retain_frame(&mut cache, &[], local, now));
        assert!(retain_frame(&mut cache, &frame, local, now));
        assert_eq!(cache.len(), 1);
        frame[23] = 0;
        let checksum = {
            let packet = &mut frame[22..];
            packet[2..4].fill(0);
            let mut sum = packet.chunks(2).fold(0_u32, |sum, chunk| {
                sum + u32::from(u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]))
            });
            while sum >> 16 != 0 {
                sum = (sum & 0xffff) + (sum >> 16);
            }
            !sum as u16
        };
        frame[24..26].copy_from_slice(&checksum.to_be_bytes());
        assert!(retain_frame(&mut cache, &frame, local, now));
        assert!(cache.is_empty());
        let frame = advertisement(2);
        for index in 0..MAX_NEIGHBORS {
            let mut distinct = frame.clone();
            distinct[10..12].copy_from_slice(&(index as u16 + 100).to_be_bytes());
            assert!(retain_frame(&mut cache, &distinct, local, now));
        }
        let mut extra = frame;
        extra[10..12].copy_from_slice(&999_u16.to_be_bytes());
        assert!(!retain_frame(&mut cache, &extra, local, now));
    }
}
