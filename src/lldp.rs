use crate::contract::{
    Device, Endpoint, Observation, Source, TopologyLink, format_mac, hex, mac_bytes,
};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub const CAPTURE_WINDOW: Duration = Duration::from_secs(30);
const MAX_NEIGHBORS: usize = 512;
type Neighbors = BTreeMap<String, (Device, TopologyLink, Instant)>;
pub struct CaptureResult {
    pub devices: Vec<Device>,
    pub links: Vec<TopologyLink>,
    pub warnings: Vec<String>,
}

/// Observe only the selected link. Advertised management addresses never expand IP probe scope.
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
    mac_bytes(local_mac).ok_or("LLDP requires the selected interface MAC")?;
    let mut neighbors = BTreeMap::new();
    let started = Instant::now();
    let mut limited = false;
    let result = capture(interface, CAPTURE_WINDOW, cancelled, |frame| {
        limited |= !retain_frame(&mut neighbors, frame, local_mac, Instant::now());
    });
    let mut warnings = Vec::new();
    if let Err(error) = result {
        warnings.push(format!("Passive LLDP capture: {error}"));
    }
    if limited {
        warnings.push(
            "Passive LLDP neighbor limit reached (512); additional neighbors were omitted.".into(),
        );
    }
    warnings.push(format!("Passive LLDP observed the selected link for {} ms; absence of advertisements does not prove absence of neighbors.", started.elapsed().as_millis()));
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
    let key = format!(
        "{}:{}:{}",
        device.mac_address, raw["chassisId"], raw["portId"]
    );
    if raw["ttl"] == 0 {
        neighbors.remove(&key);
    } else if neighbors.len() < MAX_NEIGHBORS || neighbors.contains_key(&key) {
        neighbors.insert(key, (device, link, now));
    } else {
        return false;
    }
    true
}

fn parse(frame: &[u8], local_mac: &str) -> Option<(Device, TopologyLink)> {
    if frame.len() < 14
        || !matches!(&frame[..6], [1, 0x80, 0xc2, 0, 0, 0x0e | 3 | 0])
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
                u16::from_be_bytes(frame.get(offset + 2..offset + 4)?.try_into().ok()?) & 0xfff,
            );
            offset += 4;
        }
    }
    if frame.get(offset..offset + 2)? != [0x88, 0xcc] {
        return None;
    }
    offset += 2;
    let mut mandatory = 1;
    let mut chassis = None;
    let mut port = None;
    let mut ttl = None;
    let mut fields = BTreeMap::from([("protocols".into(), json!(["lldp"]))]);
    let mut tlvs = Vec::new();
    let mut inventory = Map::new();
    let mut sources = Map::new();
    let mut ended = false;
    for _ in 0..64 {
        let header = u16::from_be_bytes(frame.get(offset..offset + 2)?.try_into().ok()?);
        offset += 2;
        let kind = (header >> 9) as u8;
        let length = usize::from(header & 0x1ff);
        let value = frame.get(offset..offset + length)?;
        offset += length;
        if kind == 0 {
            if length != 0 || mandatory != 4 {
                return None;
            }
            ended = true;
            break;
        }
        if mandatory < 4 {
            if kind != mandatory {
                return None;
            }
            mandatory += 1;
        } else if kind <= 3 {
            return None;
        }
        tlvs.push(json!({"type": kind, "hex": hex(value)}));
        match kind {
            1 | 2 => {
                let (&subtype, id) = value.split_first()?;
                if !(1..=7).contains(&subtype) || id.is_empty() || id.len() > 255 {
                    return None;
                }
                if (kind == 1 && subtype == 4 || kind == 2 && subtype == 3) && id.len() != 6 {
                    return None;
                }
                let identity = json!({"subtype": subtype, "hex": hex(id), "text": std::str::from_utf8(id).ok()});
                if kind == 1 {
                    chassis = Some(identity);
                } else {
                    port = Some(identity);
                }
            }
            3 => {
                if value.len() != 2 {
                    return None;
                }
                ttl = Some(u16::from_be_bytes(value.try_into().ok()?));
            }
            4..=6 => {
                let name = match kind {
                    4 => "portDescription",
                    5 => "name",
                    _ => "description",
                };
                if let Ok(text) = std::str::from_utf8(value) {
                    fields.insert(name.into(), json!(text));
                    sources.insert(name.into(), json!({"tlv": kind, "mutable": true}));
                }
            }
            7 if value.len() != 4 => return None,
            8 => {
                let size = usize::from(*value.first()?);
                if size < 2 || value.len() < size + 7 {
                    return None;
                }
                let oid_length = usize::from(value[size + 6]);
                if value.len() != size + 7 + oid_length {
                    return None;
                }
            }
            127 if value.len() >= 4 && value[..3] == [0, 0x12, 0xbb] => {
                if let Some((name, field)) = med_field(value[3]) {
                    if value.len() > 36 {
                        return None;
                    }
                    if let Ok(text) = std::str::from_utf8(&value[4..]) {
                        inventory.insert(name.into(), json!(text));
                        fields.insert(field.into(), json!(text));
                        sources.insert(
                            field.into(),
                            json!({"tlv":127, "oui":"0012BB", "subtype":value[3]}),
                        );
                    }
                }
            }
            _ => {}
        }
    }
    let ttl = ttl?;
    if !ended {
        return None;
    }
    let mac = format_mac(&frame[6..12]);
    let observed_at = crate::now();
    let raw = json!({"observationId": uuid::Uuid::new_v4().to_string(), "subject":{"kind":"device", "macAddress":mac}, "acquisition":{"mechanism":"passive-announcement", "interfaceMac": local_mac}, "chassisId": chassis?, "portId": port?, "ttl":ttl, "vlans":vlans, "tlvs":tlvs, "inventory":inventory, "fieldSources":sources});
    let link = TopologyLink {
        source: Source::Lldp,
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
            station_name: fields
                .get("name")
                .and_then(Value::as_str)
                .map(str::to_owned),
            interface_key: None,
            port_id: Some(raw["portId"]["hex"].as_str()?.to_owned()),
            port_mac: None,
        },
        raw: raw.clone(),
    };
    let device = Device {
        mac_address: mac.clone(),
        mac_addresses: vec![mac.clone()],
        observations: vec![Observation {
            source: Source::Lldp,
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

fn med_field(subtype: u8) -> Option<(&'static str, &'static str)> {
    match subtype {
        5 => Some(("hardwareRevision", "hardwareVersion")),
        6 => Some(("firmwareRevision", "firmwareVersion")),
        7 => Some(("softwareRevision", "softwareRevision")),
        8 => Some(("serialNumber", "serialNumber")),
        9 => Some(("manufacturer", "vendor")),
        10 => Some(("model", "model")),
        11 => Some(("assetId", "assetId")),
        _ => None,
    }
}

#[cfg(windows)]
fn capture(
    interface: &str,
    wait: Duration,
    cancelled: &AtomicBool,
    mut on_frame: impl FnMut(&[u8]),
) -> Result<(), String> {
    crate::profinet::npcap::capture_passive(interface, wait, cancelled, |frame| {
        on_frame(frame);
        Ok(())
    })
}

#[cfg(target_os = "linux")]
fn capture(
    interface: &str,
    wait: Duration,
    cancelled: &AtomicBool,
    mut on_frame: impl FnMut(&[u8]),
) -> Result<(), String> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let name = std::ffi::CString::new(interface).map_err(|_| "invalid interface name")?;
    // SAFETY: name is NUL-terminated; the returned index has no ownership.
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        return Err("LLDP interface not found".into());
    }
    // ETH_P_ALL retains VLAN headers; binding below restricts capture to the selected link.
    // SAFETY: socket returns a new owned descriptor or -1.
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            i32::from(3_u16.to_be()),
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    // SAFETY: fd is a newly allocated descriptor owned only here.
    let socket = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: zero is valid for all fields before initialization.
    let mut address: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    address.sll_family = libc::AF_PACKET as u16;
    address.sll_protocol = 3_u16.to_be();
    address.sll_ifindex = index as i32;
    // SAFETY: address is valid for the supplied length and the socket remains open.
    if unsafe {
        libc::bind(
            socket.as_raw_fd(),
            (&address as *const libc::sockaddr_ll).cast(),
            std::mem::size_of_val(&address) as u32,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().to_string());
    }
    // SAFETY: zero is a valid packet_mreq before setting its fields.
    let mut membership: libc::packet_mreq = unsafe { std::mem::zeroed() };
    membership.mr_ifindex = index as i32;
    membership.mr_type = libc::PACKET_MR_ALLMULTI as u16;
    // SAFETY: sets membership only for this socket, released when the descriptor closes.
    if unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_PACKET,
            libc::PACKET_ADD_MEMBERSHIP,
            (&membership as *const libc::packet_mreq).cast(),
            std::mem::size_of_val(&membership) as u32,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let start = Instant::now();
    let mut buffer = [0; 2048];
    while start.elapsed() < wait && !cancelled.load(Ordering::Relaxed) {
        let mut poll = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll points to one valid descriptor entry.
        if unsafe { libc::poll(&mut poll, 1, 50) } < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error.to_string());
        }
        // SAFETY: buffer is writable for its length, fd is open and nonblocking.
        let length = unsafe {
            libc::recv(
                fd,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                libc::MSG_TRUNC,
            )
        };
        if length < 0 {
            let error = std::io::Error::last_os_error();
            if matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
            ) {
                continue;
            }
            return Err(error.to_string());
        }
        if (length as usize) <= buffer.len() {
            on_frame(&buffer[..length as usize]);
        }
    }
    Ok(())
}

#[cfg(not(any(windows, target_os = "linux")))]
fn capture(_: &str, _: Duration, _: &AtomicBool, _: impl FnMut(&[u8])) -> Result<(), String> {
    Err("Passive LLDP requires Linux or Windows/Npcap".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn advertisement() -> Vec<u8> {
        let mut frame = vec![1, 0x80, 0xc2, 0, 0, 0x0e, 2, 0, 0, 0, 0, 1, 0x88, 0xcc];
        for (kind, value) in [
            (1_u16, &[4, 2, 0, 0, 0, 0, 1][..]),
            (2, b"\x05eth0"),
            (3, &[0, 120]),
            (5, b"PLC"),
            (127, b"\x00\x12\xbb\x08SERIAL"),
            (127, b"\x00\x12\xbb\x07APP"),
            (0, &[]),
        ] {
            frame.extend(((kind << 9) | value.len() as u16).to_be_bytes());
            frame.extend(value);
        }
        frame
    }
    #[test]
    fn advertisement_preserves_inventory_and_link_scope() {
        let (device, link) = parse(&advertisement(), "02:00:00:00:00:02").unwrap();
        let observation = &device.observations[0];
        assert_eq!(observation.fields["serialNumber"], "SERIAL");
        assert_eq!(observation.fields["softwareRevision"], "APP");
        assert!(!observation.fields.contains_key("firmwareVersion"));
        assert_eq!(link.remote.mac_address, "02:00:00:00:00:01");
        assert!(device.ip_addresses.is_empty());
        assert_eq!(
            observation.raw["acquisition"]["mechanism"],
            "passive-announcement"
        );
    }
    #[test]
    fn rejects_truncation_duplicate_mandatory_and_bad_source() {
        let frame = advertisement();
        for end in 0..frame.len() {
            assert!(parse(&frame[..end], "02:00:00:00:00:02").is_none(), "{end}");
        }
        let mut bad = frame.clone();
        bad[14] = 4; // Port ID cannot precede Chassis ID.
        assert!(parse(&bad, "02:00:00:00:00:02").is_none());
        assert!(parse(&frame, "02:00:00:00:00:01").is_none());
        bad = frame;
        bad[6] = 1;
        assert!(parse(&bad, "02:00:00:00:00:02").is_none());
    }
    #[test]
    fn vlan_and_non_mac_chassis_are_preserved_without_inventing_addresses() {
        let mut frame = advertisement();
        frame[16] = 7;
        frame.splice(12..12, [0x81, 0, 0, 42]);
        let (device, _) = parse(&frame, "02:00:00:00:00:02").unwrap();
        assert_eq!(device.observations[0].raw["chassisId"]["subtype"], 7);
        assert_eq!(device.observations[0].raw["vlans"], json!([42]));
        assert_eq!(device.mac_address, "02:00:00:00:00:01");
    }

    #[test]
    fn optional_tlvs_preserve_inventory_and_do_not_expand_ip_scope() {
        let mut frame = advertisement();
        frame.truncate(frame.len() - 2);
        for (kind, value) in [
            (7_u16, &[0, 0x14, 0, 0x14][..]),
            (8, &[5, 1, 192, 0, 2, 1, 2, 0, 0, 0, 1, 0][..]),
        ] {
            frame.extend(((kind << 9) | value.len() as u16).to_be_bytes());
            frame.extend(value);
        }
        for subtype in [5, 6, 9, 10, 11] {
            let value = [0, 0x12, 0xbb, subtype, b'A'];
            frame.extend(((127_u16 << 9) | value.len() as u16).to_be_bytes());
            frame.extend(value);
        }
        frame.extend([0, 0]);
        let (device, _) = parse(&frame, "02:00:00:00:00:02").unwrap();
        assert!(device.ip_addresses.is_empty());
        assert_eq!(device.observations[0].fields["vendor"], "A");
        assert_eq!(device.observations[0].fields["firmwareVersion"], "A");
        let mut bad = frame.clone();
        let management = bad
            .windows(2)
            .position(|value| value == [0x10, 12])
            .unwrap();
        bad[management + 2] = 1;
        assert!(parse(&bad, "02:00:00:00:00:02").is_none());
    }

    #[test]
    fn parser_retains_optional_text_and_rejects_invalid_mandatory_and_organizational_tlvs() {
        let mut frame = advertisement();
        let end = frame.len() - 2;
        frame.truncate(end);
        for (kind, value) in [(4_u16, b"port description".as_slice()), (6, b"switch")] {
            frame.extend(((kind << 9) | value.len() as u16).to_be_bytes());
            frame.extend(value);
        }
        frame.extend([0, 0]);
        let (device, _) = parse(&frame, "02:00:00:00:00:02").unwrap();
        assert_eq!(
            device.observations[0].fields["portDescription"],
            "port description"
        );
        assert_eq!(device.observations[0].fields["description"], "switch");

        let mut oversized_org = b"\x00\x12\xbb\x08".to_vec();
        oversized_org.extend([b'A'; 33]);
        for (kind, value) in [
            (1_u16, vec![0, b'x']),
            (3, vec![0]),
            (7, vec![0, 0, 0]),
            (8, vec![1, 2, 3]),
            (127, oversized_org),
        ] {
            let mut malformed = advertisement();
            let end = malformed.len() - 2;
            malformed.truncate(end);
            malformed.extend(((kind << 9) | value.len() as u16).to_be_bytes());
            malformed.extend(value);
            malformed.extend([0, 0]);
            assert!(
                parse(&malformed, "02:00:00:00:00:02").is_none(),
                "accepted malformed TLV type {kind}"
            );
        }
    }

    #[test]
    fn rejects_invalid_identifier_lengths_and_incomplete_tlv_sequences() {
        let local = "02:00:00:00:00:02";

        let mut short_mac_chassis = advertisement();
        short_mac_chassis.splice(22..23, []);
        short_mac_chassis[15] = 6;
        assert!(parse(&short_mac_chassis, local).is_none());

        let mut short_mac_port = advertisement();
        short_mac_port[25] = 3;
        assert!(parse(&short_mac_port, local).is_none());

        let mut unterminated = advertisement();
        unterminated.truncate(unterminated.len() - 2);
        assert!(parse(&unterminated, local).is_none());

        let mut too_many_tlvs = unterminated;
        for _ in 0..64 {
            too_many_tlvs.extend((9_u16 << 9).to_be_bytes());
        }
        assert!(parse(&too_many_tlvs, local).is_none());

        let mut unknown_med_subtype = advertisement();
        unknown_med_subtype.truncate(unknown_med_subtype.len() - 2);
        let value = [0, 0x12, 0xbb, 99];
        unknown_med_subtype.extend(((127_u16 << 9) | value.len() as u16).to_be_bytes());
        unknown_med_subtype.extend(value);
        unknown_med_subtype.extend([0, 0]);
        let (device, _) = parse(&unknown_med_subtype, local).unwrap();
        assert_eq!(
            device.observations[0].raw["inventory"]
                .as_object()
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn rejects_non_lldp_destination_and_multicast_source() {
        let mut frame = advertisement();
        frame[5] = 0x0f;
        assert!(parse(&frame, "02:00:00:00:00:02").is_none());

        let mut frame = advertisement();
        frame[6] |= 1;
        assert!(parse(&frame, "02:00:00:00:00:02").is_none());
    }
    #[test]
    fn cancelled_capture_does_not_open_an_interface() {
        let result = scan("absent", "invalid", &AtomicBool::new(true)).unwrap();
        assert!(result.devices.is_empty() && result.links.is_empty());
        assert!(scan("absent", "invalid", &AtomicBool::new(false)).is_err());
        assert!(
            scan("absent", "02:00:00:00:00:01", &AtomicBool::new(false))
                .unwrap()
                .warnings
                .iter()
                .any(|warning| warning.starts_with("Passive LLDP capture:"))
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn passive_linux_capture_stops_on_cancellation_without_transmitting() {
        let cancelled = std::sync::Arc::new(AtomicBool::new(false));
        let stop = std::sync::Arc::clone(&cancelled);
        let cancellation = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            stop.store(true, Ordering::Relaxed);
        });

        let result = scan("lo", "02:00:00:00:00:02", &cancelled).unwrap();

        cancellation.join().unwrap();
        assert!(
            result
                .warnings
                .iter()
                .any(|warning| warning.contains("observed the selected link"))
        );
        assert!(
            result
                .warnings
                .iter()
                .all(|warning| !warning.contains("neighbor limit reached"))
        );
    }

    #[test]
    fn cache_honors_withdrawal_expiry_updates_and_the_neighbor_limit() {
        let mut cache = Neighbors::new();
        let mut frame = advertisement();
        let local = "02:00:00:00:00:02";
        let now = Instant::now();
        assert!(retain_frame(&mut cache, &frame, local, now));
        assert_eq!(cache.len(), 1);
        assert!(retain_frame(&mut cache, &frame, local, now));
        assert_eq!(cache.len(), 1);
        let ttl = frame
            .windows(4)
            .position(|value| value == [6, 2, 0, 120])
            .unwrap();
        frame[ttl + 3] = 0;
        retain_frame(&mut cache, &frame, local, now);
        assert!(cache.is_empty());
        frame[ttl + 3] = 120;
        retain_frame(&mut cache, &frame, local, now);
        expire(&mut cache, now + Duration::from_secs(120));
        assert!(cache.is_empty());
        for index in 0..MAX_NEIGHBORS {
            frame[10..12].copy_from_slice(&(index as u16 + 100).to_be_bytes());
            assert!(retain_frame(&mut cache, &frame, local, now));
        }
        frame[10..12].copy_from_slice(&999_u16.to_be_bytes());
        assert!(!retain_frame(&mut cache, &frame, local, now));
        assert_eq!(cache.len(), MAX_NEIGHBORS);
    }
}
