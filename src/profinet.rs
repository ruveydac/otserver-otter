use crate::contract::{
    Device, Observation, Source, format_mac, hex, mac_bytes, normalize_mac, unique_ip_identities,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;
#[cfg(windows)]
#[path = "profinet_npcap.rs"]
pub(crate) mod npcap;
#[path = "profinet_pnio.rs"]
mod pnio;
use std::net::Ipv4Addr;
#[cfg(windows)]
use std::net::Ipv6Addr;
#[cfg(target_os = "linux")]
use std::time::Instant;
#[cfg(any(windows, target_os = "linux", test))]
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureInterface {
    pub name: String,
    pub friendly_name: String,
    pub description: String,
    pub addresses: Vec<String>,
}

#[cfg(any(windows, target_os = "linux", test))]
const DCP_MULTICAST: [u8; 6] = [0x01, 0x0e, 0xcf, 0x00, 0x00, 0x00];
const PROFINET_ETHERTYPE: [u8; 2] = [0x88, 0x92];
// Engineering tools must use a value from 0x0002 through 0x1900. A factor of 128 spreads
// device responses over at most 1.27 seconds. The collection window remains open independently
// for slow devices. Never use zero: it is reserved and can make non-conforming devices reply at once.
#[cfg(any(windows, target_os = "linux", test))]
const DCP_RESPONSE_DELAY_FACTOR: u16 = 0x0080;

/// Minimum time to collect replies after sending a PROFINET DCP Identify request.
pub const DCP_RESPONSE_WINDOW: Duration = Duration::from_secs(60);
const MAX_DCP_DEVICES: usize = 4_096;

#[cfg(windows)]
pub fn interfaces() -> Result<Vec<CaptureInterface>, String> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::Networking::WinSock::AF_UNSPEC;

    let mut size = 0_u32;
    // SAFETY: Initial call to get buffer size.
    unsafe {
        GetAdaptersAddresses(
            AF_UNSPEC as u32,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut size,
        );
    }
    if size == 0 {
        return Err("Could not query Windows network adapters.".into());
    }

    let mut buffer = vec![0_u8; size as usize];
    let adapter_addresses = buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;

    // SAFETY: Buffer is allocated with size returned by GetAdaptersAddresses.
    let status = unsafe {
        GetAdaptersAddresses(
            AF_UNSPEC as u32,
            0,
            std::ptr::null_mut(),
            adapter_addresses,
            &mut size,
        )
    };
    if status != 0 {
        return Err(format!(
            "Could not list Windows network interfaces (error code {status})."
        ));
    }

    let mut result = Vec::new();
    let mut current = adapter_addresses;
    while !current.is_null() {
        // SAFETY: current points to valid IP_ADAPTER_ADDRESSES_LH element.
        let adapter = unsafe { &*current };

        // Convert adapter name (GUID string or friendly name)
        let name = unsafe {
            std::ffi::CStr::from_ptr(adapter.AdapterName.cast())
                .to_string_lossy()
                .into_owned()
        };
        let friendly_name = if !adapter.FriendlyName.is_null() {
            let mut len = 0;
            while unsafe { *adapter.FriendlyName.add(len) } != 0 {
                len += 1;
            }
            let slice = unsafe { std::slice::from_raw_parts(adapter.FriendlyName, len) };
            String::from_utf16_lossy(slice)
        } else {
            name.clone()
        };
        let description = if !adapter.Description.is_null() {
            let mut len = 0;
            while unsafe { *adapter.Description.add(len) } != 0 {
                len += 1;
            }
            let slice = unsafe { std::slice::from_raw_parts(adapter.Description, len) };
            String::from_utf16_lossy(slice)
        } else {
            friendly_name.clone()
        };

        let mut addresses = Vec::new();
        if adapter.PhysicalAddressLength == 6 {
            addresses.push(format_mac(&adapter.PhysicalAddress[..6]));
        }

        let mut unicast = adapter.FirstUnicastAddress;
        while !unicast.is_null() {
            // SAFETY: unicast points to valid IP_ADAPTER_UNICAST_ADDRESS_LH.
            let item = unsafe { &*unicast };
            if !item.Address.lpSockaddr.is_null() {
                let family = unsafe { (*item.Address.lpSockaddr).sa_family as u32 };
                if family == windows_sys::Win32::Networking::WinSock::AF_INET as u32 {
                    let sockaddr = unsafe {
                        &*(item.Address.lpSockaddr
                            as *const windows_sys::Win32::Networking::WinSock::SOCKADDR_IN)
                    };
                    let s_addr = unsafe { sockaddr.sin_addr.S_un.S_addr };
                    let ip = std::net::Ipv4Addr::from(u32::from_be(s_addr));
                    addresses.push(ip.to_string());
                } else if family == windows_sys::Win32::Networking::WinSock::AF_INET6 as u32 {
                    let sockaddr = unsafe {
                        &*(item.Address.lpSockaddr
                            as *const windows_sys::Win32::Networking::WinSock::SOCKADDR_IN6)
                    };
                    let bytes = unsafe { sockaddr.sin6_addr.u.Byte };
                    addresses.push(Ipv6Addr::from(bytes).to_string());
                }
            }
            unicast = item.Next;
        }

        result.push(CaptureInterface {
            name,
            friendly_name,
            description,
            addresses,
        });

        current = adapter.Next;
    }

    Ok(result)
}

#[cfg(target_os = "linux")]
pub fn interfaces() -> Result<Vec<CaptureInterface>, String> {
    let entries = std::fs::read_dir("/sys/class/net")
        .map_err(|error| format!("Could not list Linux network interfaces: {error}"))?;
    let mut interfaces = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name().into_string().ok()?;
            let mac = std::fs::read_to_string(entry.path().join("address"))
                .ok()
                .map(|value| value.trim().to_ascii_uppercase())
                .filter(|value| normalize_mac(value).is_some());
            let mut addresses = mac.into_iter().collect::<Vec<_>>();
            addresses.extend(
                crate::discovery::interface_ip_addresses(&name)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|address| address.to_string()),
            );
            Some(CaptureInterface {
                name: name.clone(),
                friendly_name: name.clone(),
                description: name,
                addresses,
            })
        })
        .collect::<Vec<_>>();
    interfaces.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(interfaces)
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn interfaces() -> Result<Vec<CaptureInterface>, String> {
    Err("PROFINET capture is supported on Windows and Linux.".into())
}

#[cfg(windows)]
pub fn scan(
    interface: &str,
    source_mac: &str,
    wait: Duration,
    cancelled: &AtomicBool,
) -> Result<Vec<Device>, String> {
    if cancelled.load(Ordering::Relaxed) {
        return Ok(Vec::new());
    }
    let wait = dcp_response_window(wait);
    let selected = windows_scan_interface(interface)?;
    let source = mac_bytes(source_mac)
        .ok_or_else(|| "A valid source MAC address is required.".to_string())?;
    validate_source_mac(&selected, source_mac)?;
    let xid = new_xid();
    if npcap::available() {
        let request = identify_request(source, xid);
        let mut devices = BTreeMap::new();
        npcap::capture(&selected.name, &request, wait, cancelled, |frame| {
            collect_active_response(&mut devices, frame, source, xid)
        })?;
        return Ok(devices.into_values().collect());
    }
    let mut devices = BTreeMap::new();
    for frame in windows_capture::capture(wait, cancelled)? {
        if cancelled.load(Ordering::Relaxed) {
            break;
        }
        if !passive_frame_matches_interface(&frame, source) {
            continue;
        }
        if frame.len() >= 22
            && frame[14..16] == [0xfe, 0xff]
            && let Some(device) = parse_response(
                &frame,
                u32::from_be_bytes(frame[18..22].try_into().expect("four-byte slice")),
            )
        {
            insert_dcp_device(&mut devices, device)?;
            continue;
        }
        let mac = format_mac(&frame[6..12]);
        let Some(mac) = normalize_mac(&mac) else {
            continue;
        };
        let observed_at = crate::now();
        let fields = BTreeMap::from([
            ("lastSeen".into(), json!(observed_at)),
            ("macAddress".into(), json!(mac)),
            ("protocols".into(), json!(["profinet"])),
            ("status".into(), json!("online")),
        ]);
        let observation = Observation {
            source: Source::ProfinetDcp,
            observed_at,
            ip_address: None,
            mac_address: Some(mac.clone()),
            fields,
            raw: json!({
                "capture": "pktmon",
                "captureTarget": { "interface": selected.name, "macAddress": source_mac },
                "etherType": "0x8892",
                "passive": true,
            }),
            warnings: vec![
                "Observed passive PROFINET traffic addressed to the selected adapter; pktmon cannot transmit DCP Identify requests.".into(),
            ],
        };
        insert_passive_dcp_device(
            &mut devices,
            Device {
                mac_address: mac.clone(),
                mac_addresses: vec![mac],
                observations: vec![observation],
                ..Device::default()
            },
        )?;
    }
    Ok(devices.into_values().collect())
}

fn dcp_response_window(wait: Duration) -> Duration {
    wait.max(DCP_RESPONSE_WINDOW)
}

fn collect_active_response(
    devices: &mut BTreeMap<String, Device>,
    frame: &[u8],
    source: [u8; 6],
    xid: u32,
) -> Result<(), String> {
    if frame.len() >= 14
        && frame[6..12] != source
        && let Some(device) = parse_response(frame, xid)
    {
        insert_dcp_device(devices, device)?;
    }
    Ok(())
}

fn insert_dcp_device(devices: &mut BTreeMap<String, Device>, device: Device) -> Result<(), String> {
    if !devices.contains_key(&device.mac_address) && devices.len() >= MAX_DCP_DEVICES {
        return Err(format!(
            "PROFINET DCP discovery exceeded the bounded device limit of {MAX_DCP_DEVICES}."
        ));
    }
    devices.insert(device.mac_address.clone(), device);
    Ok(())
}

#[cfg(any(windows, test))]
fn insert_passive_dcp_device(
    devices: &mut BTreeMap<String, Device>,
    device: Device,
) -> Result<(), String> {
    if !devices.contains_key(&device.mac_address) {
        insert_dcp_device(devices, device)?;
    }
    Ok(())
}

#[cfg(any(windows, test))]
fn passive_frame_matches_interface(frame: &[u8], selected_mac: [u8; 6]) -> bool {
    frame.len() >= 14
        && frame[..6] == selected_mac
        && frame[6..12] != selected_mac
        && frame[12..14] == PROFINET_ETHERTYPE
}

pub fn enrich_pnio(
    interface: &str,
    source_mac: &str,
    devices: &mut [Device],
    targets: &BTreeSet<Ipv4Addr>,
    cancelled: &AtomicBool,
) -> Result<Vec<String>, String> {
    if devices.is_empty() || cancelled.load(Ordering::Relaxed) {
        return Ok(Vec::new());
    }
    let source = mac_bytes(source_mac)
        .ok_or_else(|| "A valid source MAC address is required for PNIO reads.".to_string())?;
    let source_ip = crate::discovery::source_ipv4(interface)?;
    #[cfg(windows)]
    {
        let selected = windows_scan_interface(interface)?;
        validate_source_mac(&selected, source_mac)?;
        if !npcap::interface_available(&selected.name) {
            return Err(
                "PNIO reads require Npcap bound to the selected adapter; pktmon is capture-only."
                    .into(),
            );
        }
        enrich_windows_pnio(
            &selected.name,
            source,
            source_ip,
            devices,
            targets,
            cancelled,
        )
    }
    #[cfg(target_os = "linux")]
    {
        enrich_linux_pnio(interface, source, source_ip, devices, targets, cancelled)
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = (source, source_ip, targets);
        Err("PROFINET PNIO reads are supported on Windows and Linux.".into())
    }
}

fn attach_pnio_records(device: &mut Device, target_ip: Ipv4Addr, scan: pnio::RecordScan) {
    let pnio::RecordScan { records, warnings } = scan;
    if records.is_empty() && warnings.is_empty() {
        return;
    }
    let observed_at = crate::now();
    let ip_address = Some(target_ip.to_string());
    let mut fields = BTreeMap::from([("macAddress".into(), json!(device.mac_address))]);
    if !records.is_empty() {
        fields.insert("lastSeen".into(), json!(observed_at));
        fields.insert("protocols".into(), json!(["profinet", "profinet-pnio"]));
        fields.insert("status".into(), json!("online"));
    }
    // Only the primary access point supplies these legacy device-level fields.
    let primary = records.iter().find(|record| {
        (
            record.target.api,
            record.target.slot,
            record.target.subslot,
            record.target.index,
        ) == (0, 0, 1, 0xAFF0)
    });
    if let Some(software_revision) =
        primary.and_then(|record| record.parsed["softwareRevision"].as_str())
    {
        fields.insert("softwareRevision".into(), json!(software_revision));
    }
    if let Some(manufacturer) =
        primary.and_then(|record| record.parsed["manufacturerName"].as_str())
    {
        fields.insert("manufacturer".into(), json!(manufacturer));
    }
    let raw_records = records
        .iter()
        .map(|record| {
            json!({
                "api": record.target.api,
                "slot": record.target.slot,
                "subslot": record.target.subslot,
                "index": format!("0x{:04X}", record.target.index),
                "parsed": record.parsed,
                "raw": hex(&record.data),
            })
        })
        .collect::<Vec<_>>();
    device.observations.push(Observation {
        source: Source::ProfinetDcp,
        observed_at,
        ip_address: ip_address.clone(),
        mac_address: Some(device.mac_address.clone()),
        fields,
        raw: json!({
            "observationId": uuid::Uuid::new_v4().to_string(),
            "subject": { "kind": "device", "macAddress": device.mac_address },
            "physicalEntities": pnio_physical_entities(&records),
            "pnioRecords": raw_records,
        }),
        warnings,
    });
}

fn read_device_records(
    devices: &mut [Device],
    targets: &BTreeSet<Ipv4Addr>,
    cancelled: &AtomicBool,
    mut transact: impl FnMut(
        [u8; 6],
        Ipv4Addr,
        u16,
        &[u8],
        Duration,
        &AtomicBool,
    ) -> Result<(pnio::RpcHeader, Vec<u8>), String>,
) -> Vec<String> {
    let identities = unique_ip_identities(devices);
    let mut warnings = Vec::new();
    for device in devices {
        if cancelled.load(Ordering::Relaxed) {
            break;
        }
        let Some(mac) =
            mac_bytes(&device.mac_address).filter(|mac| *mac != [0; 6] && mac[0] & 1 == 0)
        else {
            warnings.push(format!(
                "PROFINET PNIO skipped for {}: no valid unicast MAC address.",
                device.mac_address
            ));
            continue;
        };
        let ips = device
            .ip_addresses
            .iter()
            .filter_map(|ip| ip.parse::<Ipv4Addr>().ok())
            .filter(|ip| {
                !ip.is_unspecified()
                    && !ip.is_multicast()
                    && !ip.is_broadcast()
                    && !ip.is_loopback()
            })
            .collect::<BTreeSet<_>>();
        if ips.is_empty() {
            warnings.push(format!(
                "PROFINET PNIO skipped for {}: no usable device IPv4 address.",
                device.mac_address
            ));
        }
        for ip in ips {
            if cancelled.load(Ordering::Relaxed) {
                break;
            }
            if identities.get(&ip.to_string()) != Some(&device.mac_address) {
                warnings.push(format!(
                    "PROFINET PNIO skipped for {ip}: multiple MAC addresses claim this IP."
                ));
                continue;
            }
            if !targets.contains(&ip) {
                warnings.push(format!(
                    "PROFINET PNIO skipped for {ip}: outside the selected IP probe scope."
                ));
                continue;
            }
            match pnio::read_records(
                pnio::RESPONSE_TIMEOUT,
                cancelled,
                |port, request, timeout, cancelled| {
                    transact(mac, ip, port, request, timeout, cancelled)
                },
            ) {
                Ok(scan) => {
                    warnings.extend(
                        scan.warnings
                            .iter()
                            .map(|warning| format!("{ip}: {warning}")),
                    );
                    attach_pnio_records(device, ip, scan);
                }
                Err(error) => warnings.push(format!(
                    "PROFINET PNIO record scan failed for {ip}: {error}"
                )),
            }
        }
    }
    warnings
}

fn pnio_component(
    entities: &mut BTreeMap<String, Value>,
    api: u32,
    slot: u16,
    subslot: Option<u16>,
) -> &mut Value {
    let module_ref = format!("pnio:{api}:{slot}");
    let key = subslot.map_or_else(
        || module_ref.clone(),
        |subslot| format!("{module_ref}:{subslot}"),
    );
    entities.entry(key.clone()).or_insert_with(|| {
        json!({
            "ref": key,
            "parentRef": subslot.map(|_| module_ref),
            "parentPosition": subslot.unwrap_or(slot),
            "class": if subslot.is_some() { "submodule" } else { "module" },
            "api": api,
            "slot": slot,
            "subslot": subslot,
        })
    })
}

fn pnio_physical_entities(records: &[pnio::RecordRead]) -> Value {
    let mut entities = BTreeMap::new();
    // Identification records describe modules even when they provide no I&M identity.
    for record in records
        .iter()
        .filter(|record| record.target.index == 0xF000)
    {
        for api in record.parsed["apis"].as_array().into_iter().flatten() {
            let Some(api_id) = api["api"].as_u64().and_then(|id| u32::try_from(id).ok()) else {
                continue;
            };
            for module in api["modules"].as_array().into_iter().flatten() {
                let Some(slot) = module["slot"]
                    .as_u64()
                    .and_then(|slot| u16::try_from(slot).ok())
                else {
                    continue;
                };
                pnio_component(&mut entities, api_id, slot, None)["identNumber"] =
                    module["identNumber"].clone();
                for submodule in module["submodules"].as_array().into_iter().flatten() {
                    let Some(subslot) = submodule["subslot"]
                        .as_u64()
                        .and_then(|slot| u16::try_from(slot).ok())
                    else {
                        continue;
                    };
                    pnio_component(&mut entities, api_id, slot, Some(subslot))["identNumber"] =
                        submodule["identNumber"].clone();
                }
            }
        }
    }
    for record in records
        .iter()
        .filter(|record| matches!(record.target.index, 0xAFF0..=0xAFF5))
    {
        let target = &record.target;
        pnio_component(&mut entities, target.api, target.slot, None);
        let component =
            pnio_component(&mut entities, target.api, target.slot, Some(target.subslot));
        let parsed = &record.parsed;
        let mappings: &[(&str, &str)] = match target.index {
            0xAFF0 => &[
                ("manufacturerId", "manufacturerId"),
                ("manufacturerName", "manufacturer"),
                ("orderId", "catalogNumber"),
                ("hardwareRevision", "hardwareRevision"),
                ("softwareRevision", "softwareRevision"),
            ],
            0xAFF1 => &[("function", "function"), ("location", "location")],
            0xAFF2 => &[("installationDate", "installationDate")],
            0xAFF3 => &[("descriptor", "description")],
            _ => &[],
        };
        for &(source, field) in mappings {
            if let Some(value) = parsed
                .get(source)
                .filter(|value| value.as_str().is_some_and(|text| !text.trim().is_empty()))
            {
                component[field] = value.clone();
            }
        }
        if target.index == 0xAFF0
            && let Some(serial) = parsed["serialNumber"]
                .as_str()
                .filter(|serial| !serial.trim().is_empty())
        {
            component["serialClaim"] = json!({
                "scope": "submodule",
                "componentRef": component["ref"],
                "issuer": parsed.get("manufacturerName"),
                "manufacturerId": parsed.get("manufacturerId"),
                "original": serial,
                "encoding": "profinet-im-text",
                "normalizationVersion": 1,
            });
        }
    }
    entities.into_values().collect()
}

#[cfg(target_os = "linux")]
fn enrich_linux_pnio(
    interface: &str,
    source_mac: [u8; 6],
    source_ip: Ipv4Addr,
    devices: &mut [Device],
    targets: &BTreeSet<Ipv4Addr>,
    cancelled: &AtomicBool,
) -> Result<Vec<String>, String> {
    use std::io;
    use std::mem::size_of;
    use std::os::fd::AsRawFd;

    if devices.is_empty() {
        return Ok(Vec::new());
    }
    let (descriptor, mut address) = crate::discovery::open_raw_socket(interface, 0x0800)?;
    // SAFETY: address is initialized and remains valid for the duration of bind.
    let bound = unsafe {
        libc::bind(
            descriptor.as_raw_fd(),
            (&raw const address).cast(),
            size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if bound < 0 {
        return Err(format!(
            "Could not bind Linux PROFINET RPC interface {interface}: {}",
            io::Error::last_os_error()
        ));
    }
    let mut send = |frame: &[u8]| {
        if frame.len() < 6 {
            return Err("PROFINET RPC frame was shorter than an Ethernet address.".into());
        }
        address.sll_addr[..6].copy_from_slice(&frame[..6]);
        crate::discovery::send_with_retry(|| {
            crate::traffic::send_blocking(crate::traffic::Kind::Other, || {
                // SAFETY: frame and address remain valid during sendto.
                let sent = unsafe {
                    libc::sendto(
                        descriptor.as_raw_fd(),
                        frame.as_ptr().cast(),
                        frame.len(),
                        0,
                        (&raw const address).cast(),
                        size_of::<libc::sockaddr_ll>() as libc::socklen_t,
                    )
                };
                if sent == frame.len() as isize {
                    Ok(())
                } else if sent < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "short RPC frame send",
                    ))
                }
            })
        })
        .map_err(|error| format!("Could not send complete PROFINET RPC frame: {error}"))
    };
    let mut buffer = [0_u8; 65_536];
    let mut receive = || {
        // SAFETY: buffer is writable for its full length and descriptor remains owned.
        let received = unsafe {
            libc::recv(
                descriptor.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                0,
            )
        };
        if received > 0 {
            Ok(Some(buffer[..received as usize].to_vec()))
        } else {
            let error = io::Error::last_os_error();
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) {
                Ok(None)
            } else {
                Err(format!("Linux PROFINET RPC capture failed: {error}"))
            }
        }
    };

    Ok(read_device_records(
        devices,
        targets,
        cancelled,
        |target_mac, target_ip, target_port, request, timeout, cancelled| {
            pnio::exchange(
                source_mac,
                source_ip,
                target_mac,
                target_ip,
                target_port,
                request,
                timeout,
                cancelled,
                &mut send,
                &mut receive,
            )
        },
    ))
}

#[cfg(windows)]
fn enrich_windows_pnio(
    interface: &str,
    source_mac: [u8; 6],
    source_ip: Ipv4Addr,
    devices: &mut [Device],
    targets: &BTreeSet<Ipv4Addr>,
    cancelled: &AtomicBool,
) -> Result<Vec<String>, String> {
    Ok(read_device_records(
        devices,
        targets,
        cancelled,
        |target_mac, target_ip, target_port, request, timeout, cancelled| {
            let (request_header, _) = pnio::parse_rpc_fragment(request)?;
            let raw_request = pnio::ethernet_ipv4_udp_frame(
                source_mac,
                target_mac,
                source_ip,
                target_ip,
                pnio::rpc_port(),
                target_port,
                request,
            )?;
            let mut fragments = Vec::new();
            npcap::capture_raw(interface, &raw_request, timeout, cancelled, |frame| {
                let Some(udp) = pnio::parse_ipv4_udp_frame(frame) else {
                    return Ok(None);
                };
                if udp.source_mac != target_mac
                    || udp.destination_mac != source_mac
                    || udp.source_ip != target_ip
                    || udp.destination_ip != source_ip
                    || !pnio::response_source_port_matches(target_port, udp.source_port)
                    || udp.destination_port != pnio::rpc_port()
                {
                    return Ok(None);
                }
                let Ok((header, body)) = pnio::parse_rpc_fragment(udp.payload) else {
                    return Ok(None);
                };
                if header.packet_type != 2
                    || header.object_uuid != request_header.object_uuid
                    || header.interface_uuid != request_header.interface_uuid
                    || header.activity_uuid != request_header.activity_uuid
                    || header.sequence != request_header.sequence
                    || header.operation != request_header.operation
                {
                    return Ok(None);
                }
                let ack = if header.requires_fragment_ack() {
                    let payload = pnio::build_fragment_ack(&header);
                    Some(pnio::ethernet_ipv4_udp_frame(
                        source_mac,
                        target_mac,
                        source_ip,
                        target_ip,
                        pnio::rpc_port(),
                        target_port,
                        &payload,
                    )?)
                } else {
                    None
                };
                fragments.push((header, body));
                Ok(ack)
            })?;
            pnio::reassemble_rpc_fragments(fragments)
        },
    ))
}

#[cfg(windows)]
mod windows_capture {
    use std::path::Path;
    use std::process::{Command, Output};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    const CANCELLATION_POLL_INTERVAL: Duration = Duration::from_millis(100);

    pub fn capture(wait: Duration, cancelled: &AtomicBool) -> Result<Vec<Vec<u8>>, String> {
        let id = format!(
            "{}-{}",
            std::process::id(),
            crate::now().replace([':', '.'], "-")
        );
        let base = std::env::temp_dir();
        let etl = base.join(format!("otserver-{id}.etl"));
        let pcap = base.join(format!("otserver-{id}.pcapng"));
        let started = Command::new("pktmon")
            .args(["start", "--capture", "--comp", "nics", "--pkt-size", "0"])
            .arg("--file-name")
            .arg(&etl)
            .args(["--file-size", "32", "--log-mode", "circular"])
            .output()
            .map_err(|error| format!("Could not start pktmon: {error}"))?;
        command_result("Could not start pktmon capture", &started)?;
        let started_at = Instant::now();
        while !cancelled.load(Ordering::Relaxed) {
            let remaining = wait.saturating_sub(started_at.elapsed());
            if remaining.is_zero() {
                break;
            }
            std::thread::sleep(remaining.min(CANCELLATION_POLL_INTERVAL));
        }
        let stopped = Command::new("pktmon")
            .arg("stop")
            .output()
            .map_err(|error| format!("Could not stop pktmon: {error}"))?;
        command_result("Could not stop pktmon capture", &stopped)?;
        let converted = Command::new("pktmon")
            .arg("etl2pcap")
            .arg(&etl)
            .arg("--out")
            .arg(&pcap)
            .output()
            .map_err(|error| format!("Could not convert pktmon capture: {error}"))?;
        let conversion = command_result("Could not convert pktmon capture", &converted);
        let bytes = conversion.and_then(|()| {
            std::fs::read(&pcap).map_err(|error| format!("Could not read pktmon capture: {error}"))
        });
        remove_capture_file(&etl);
        remove_capture_file(&pcap);
        parse_pcapng(&bytes?)
    }

    fn command_result(context: &str, output: &Output) -> Result<(), String> {
        if output.status.success() {
            return Ok(());
        }
        let detail = String::from_utf8_lossy(if output.stderr.is_empty() {
            &output.stdout
        } else {
            &output.stderr
        });
        Err(format!(
            "{context}: {}. Run OTserver Otter as Administrator and ensure no other pktmon capture is active.",
            detail.trim()
        ))
    }

    fn remove_capture_file(path: &Path) {
        if let Err(error) = std::fs::remove_file(path)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            eprintln!("warning: could not remove {}: {error}", path.display());
        }
    }

    fn parse_pcapng(bytes: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        let mut packets = Vec::new();
        let mut offset = 0_usize;
        while offset + 12 <= bytes.len() {
            let block_type = le_u32(&bytes[offset..offset + 4]);
            let length = le_u32(&bytes[offset + 4..offset + 8]) as usize;
            if length < 12
                || offset
                    .checked_add(length)
                    .is_none_or(|end| end > bytes.len())
            {
                return Err("pktmon produced a malformed pcapng block.".into());
            }
            if le_u32(&bytes[offset + length - 4..offset + length]) as usize != length {
                return Err("pktmon produced a pcapng block with mismatched lengths.".into());
            }
            if block_type == 6 && length >= 32 {
                let captured = le_u32(&bytes[offset + 20..offset + 24]) as usize;
                let start = offset + 28;
                if start
                    .checked_add(captured)
                    .is_some_and(|end| end <= offset + length - 4)
                {
                    packets.push(bytes[start..start + captured].to_vec());
                }
            } else if block_type == 3 && length >= 16 {
                let original = le_u32(&bytes[offset + 8..offset + 12]) as usize;
                let captured = original.min(length - 16);
                packets.push(bytes[offset + 12..offset + 12 + captured].to_vec());
            }
            offset += length;
        }
        Ok(packets)
    }

    fn le_u32(value: &[u8]) -> u32 {
        u32::from_le_bytes(value.try_into().expect("four-byte slice"))
    }

    #[cfg(test)]
    mod tests {
        use super::parse_pcapng;

        #[test]
        fn reads_enhanced_packet_blocks_and_rejects_bad_lengths() {
            let frame = [1, 2, 3, 4, 5, 6, 6, 5, 4, 3, 2, 1, 0x88, 0x92];
            let mut block = vec![0_u8; 48];
            block[0..4].copy_from_slice(&6_u32.to_le_bytes());
            block[4..8].copy_from_slice(&48_u32.to_le_bytes());
            block[20..24].copy_from_slice(&(frame.len() as u32).to_le_bytes());
            block[24..28].copy_from_slice(&(frame.len() as u32).to_le_bytes());
            block[28..42].copy_from_slice(&frame);
            block[44..48].copy_from_slice(&48_u32.to_le_bytes());
            assert_eq!(parse_pcapng(&block).unwrap(), vec![frame]);

            block[44..48].copy_from_slice(&44_u32.to_le_bytes());
            assert!(parse_pcapng(&block).is_err());
        }
    }
}

#[cfg(target_os = "linux")]
pub fn scan(
    interface: &str,
    source_mac: &str,
    wait: Duration,
    cancelled: &AtomicBool,
) -> Result<Vec<Device>, String> {
    use std::io;
    use std::mem::size_of;
    use std::os::fd::AsRawFd;

    if cancelled.load(Ordering::Relaxed) {
        return Ok(Vec::new());
    }
    let wait = dcp_response_window(wait);
    let source = mac_bytes(source_mac)
        .ok_or_else(|| "A valid source MAC address is required.".to_string())?;
    let xid = new_xid();
    let (descriptor, mut address) =
        crate::discovery::open_raw_socket(interface, u16::from_be_bytes(PROFINET_ETHERTYPE))?;
    // SAFETY: address points to a fully initialized sockaddr_ll of the supplied size.
    let bound = unsafe {
        libc::bind(
            descriptor.as_raw_fd(),
            (&raw const address).cast(),
            size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if bound < 0 {
        return Err(format!(
            "Could not bind Linux interface {interface}: {}",
            io::Error::last_os_error()
        ));
    }

    address.sll_addr[..DCP_MULTICAST.len()].copy_from_slice(&DCP_MULTICAST);
    let request = identify_request(source, xid);
    let send_request = || {
        crate::discovery::send_with_retry(|| {
            crate::traffic::send_blocking(crate::traffic::Kind::Other, || {
                // SAFETY: request and address remain valid for the duration of sendto.
                let sent = unsafe {
                    libc::sendto(
                        descriptor.as_raw_fd(),
                        request.as_ptr().cast(),
                        request.len(),
                        0,
                        (&raw const address).cast(),
                        size_of::<libc::sockaddr_ll>() as libc::socklen_t,
                    )
                };
                if sent == request.len() as isize {
                    Ok(())
                } else if sent < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "short DCP frame send",
                    ))
                }
            })
        })
        .map_err(|error| format!("Could not send complete PROFINET DCP request: {error}"))
    };
    send_request()?;

    let deadline = Instant::now()
        .checked_add(wait)
        .ok_or_else(|| "PROFINET DCP response window is too large.".to_string())?;
    let mut buffer = [0_u8; 65_536];
    let mut devices = BTreeMap::new();
    while Instant::now() < deadline {
        if cancelled.load(Ordering::Relaxed) {
            break;
        }
        // SAFETY: buffer is writable for its full reported length and descriptor stays owned.
        let received = unsafe {
            libc::recv(
                descriptor.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                0,
            )
        };
        if received > 0 {
            collect_active_response(&mut devices, &buffer[..received as usize], source, xid)?;
            continue;
        }
        let error = io::Error::last_os_error();
        if matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
        ) {
            std::thread::sleep(Duration::from_millis(10));
            continue;
        }
        return Err(format!("Linux PROFINET capture failed: {error}"));
    }
    Ok(devices.into_values().collect())
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn scan(
    _interface: &str,
    _source_mac: &str,
    _wait: Duration,
    _cancelled: &AtomicBool,
) -> Result<Vec<Device>, String> {
    Err("PROFINET capture is supported on Windows and Linux.".into())
}

#[cfg(any(windows, target_os = "linux", test))]
fn identify_request(source: [u8; 6], xid: u32) -> Vec<u8> {
    let mut frame = Vec::with_capacity(64);
    frame.extend(DCP_MULTICAST);
    frame.extend(source);
    frame.extend(PROFINET_ETHERTYPE);
    frame.extend([0xfe, 0xfe, 0x05, 0x00]); // Identify request
    frame.extend(xid.to_be_bytes());
    frame.extend(DCP_RESPONSE_DELAY_FACTOR.to_be_bytes());
    frame.extend([0x00, 0x04, 0xff, 0xff, 0x00, 0x00]); // Identify all
    frame.resize(60, 0);
    frame
}

pub fn parse_response(frame: &[u8], expected_xid: u32) -> Option<Device> {
    if frame.len() < 26
        || frame[12..14] != PROFINET_ETHERTYPE
        || frame[14..16] != [0xfe, 0xff]
        || frame[16] != 0x05
        || frame[17] != 0x01
        || frame[18..22] != expected_xid.to_be_bytes()
        || frame[22..24] != [0, 0]
    {
        return None;
    }
    let mac = normalize_mac(&format_mac(&frame[6..12]))?;
    let data_length = u16::from_be_bytes([frame[24], frame[25]]) as usize;
    let end = 26_usize.checked_add(data_length)?;
    if data_length == 0 || end > frame.len() {
        return None;
    }
    let mut offset = 26;
    let mut fields = BTreeMap::new();
    let mut raw = BTreeMap::new();
    let mut raw_blocks = Vec::new();
    let mut warnings = Vec::new();
    fields.insert("macAddress".into(), json!(mac));
    fields.insert("status".into(), json!("online"));
    fields.insert("lastSeen".into(), json!(crate::now()));
    fields.insert("protocols".into(), json!(["profinet"]));

    while offset < end {
        if offset + 4 > end {
            return None;
        }
        let option = frame[offset];
        let suboption = frame[offset + 1];
        let length = u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]) as usize;
        offset += 4;
        let padded_length = length.checked_add(length % 2)?;
        if offset.checked_add(padded_length)? > end {
            return None;
        }
        let value = &frame[offset..offset + length];
        let has_block_info = matches!(option, 1 | 2 | 3 | 6 | 7);
        if has_block_info && length < 2 {
            return None;
        }
        let block_info = has_block_info.then(|| u16::from_be_bytes([value[0], value[1]]));
        let payload = if has_block_info { &value[2..] } else { value };
        raw_blocks.push(json!({
            "blockInfo": block_info,
            "option": option,
            "suboption": suboption,
            "value": hex(value),
        }));
        match (option, suboption) {
            (1, 1) => {
                if payload.len() < 6 {
                    return None;
                }
                let advertised_mac = normalize_mac(&format_mac(&payload[..6]))?;
                raw.insert("dcpMacAddress".into(), json!(advertised_mac));
                if advertised_mac != mac {
                    warnings.push(format!(
                        "DCP MAC {advertised_mac} differs from Ethernet source {mac}."
                    ));
                }
            }
            (1, 2) => {
                if payload.len() < 12 {
                    return None;
                }
                fields.insert("ipAddress".into(), json!(ipv4(&payload[0..4])));
                fields.insert("networkMask".into(), json!(ipv4(&payload[4..8])));
                fields.insert("gatewayAddress".into(), json!(ipv4(&payload[8..12])));
                raw.insert("ipBlockInfo".into(), json!(block_info?));
                if block_info? & 0x80 != 0 {
                    warnings.push("DCP reports an IP address conflict.".into());
                }
            }
            (1, 3) => {
                if payload.len() < 28 {
                    return None;
                }
                fields.insert("ipAddress".into(), json!(ipv4(&payload[0..4])));
                fields.insert("networkMask".into(), json!(ipv4(&payload[4..8])));
                fields.insert("gatewayAddress".into(), json!(ipv4(&payload[8..12])));
                raw.insert(
                    "dnsServers".into(),
                    json!([
                        ipv4(&payload[12..16]),
                        ipv4(&payload[16..20]),
                        ipv4(&payload[20..24]),
                        ipv4(&payload[24..28]),
                    ]),
                );
                raw.insert("ipBlockInfo".into(), json!(block_info?));
            }
            (2, 1) => insert_string(&mut fields, "model", payload),
            (2, 2) => {
                insert_string(&mut fields, "name", payload);
            }
            (2, 3) => {
                if payload.len() < 4 {
                    return None;
                }
                let vendor_id = u16::from_be_bytes([payload[0], payload[1]]);
                let device_id = u16::from_be_bytes([payload[2], payload[3]]);
                fields.insert("vendorId".into(), json!(vendor_id));
                fields.insert("deviceId".into(), json!(device_id));
                raw.insert("vendorId".into(), json!(vendor_id));
                raw.insert("deviceId".into(), json!(device_id));
            }
            (2, 4) => {
                if payload.len() < 2 {
                    return None;
                }
                let value = payload[0];
                let roles = [
                    (0x01, "io-device"),
                    (0x02, "io-controller"),
                    (0x04, "io-multidevice"),
                    (0x08, "pn-supervisor"),
                ]
                .into_iter()
                .filter_map(|(mask, label)| (value & mask != 0).then_some(label))
                .collect::<Vec<_>>();
                raw.insert(
                    "deviceRole".into(),
                    json!({ "roles": roles, "value": value }),
                );
            }
            (2, 5) => {
                if payload.len() % 2 != 0 {
                    return None;
                }
                raw.insert(
                    "deviceOptions".into(),
                    json!(
                        payload
                            .as_chunks::<2>()
                            .0
                            .iter()
                            .map(|pair| json!({ "option": pair[0], "suboption": pair[1] }))
                            .collect::<Vec<_>>()
                    ),
                );
            }
            (2, 6) => insert_string(&mut raw, "aliasName", payload),
            (2, 7) => {
                if payload.len() < 2 {
                    return None;
                }
                raw.insert(
                    "deviceInstance".into(),
                    json!(u16::from_be_bytes([payload[0], payload[1]])),
                );
            }
            (2, 8) => {
                if payload.len() < 4 {
                    return None;
                }
                raw.insert(
                    "oemVendorId".into(),
                    json!(u16::from_be_bytes([payload[0], payload[1]])),
                );
                raw.insert(
                    "oemDeviceId".into(),
                    json!(u16::from_be_bytes([payload[2], payload[3]])),
                );
            }
            (2, 10) | (2, 11) => {
                if payload.len() < 2 {
                    return None;
                }
                raw.insert(
                    if suboption == 10 {
                        "rsiProperties"
                    } else {
                        "protocolProperties"
                    }
                    .into(),
                    json!(u16::from_be_bytes([payload[0], payload[1]])),
                );
            }
            (3, 61) => {
                raw.insert("dhcpClientId".into(), json!(hex(payload)));
            }
            (3, 255) => {
                raw.insert("dhcpAddressResolution".into(), json!(hex(payload)));
            }
            (6, 1) => {
                if payload.len() < 2 {
                    return None;
                }
                raw.insert(
                    "deviceInitiative".into(),
                    json!(u16::from_be_bytes([payload[0], payload[1]])),
                );
            }
            (7, 1) => {
                if payload.len() < 16 {
                    return None;
                }
                raw.insert(
                    "configurationDomainUuid".into(),
                    json!(uuid(&payload[..16])),
                );
                insert_string(&mut raw, "configurationDomainName", &payload[16..]);
            }
            (7, 2) => {
                if payload.len() < 2 {
                    return None;
                }
                raw.insert(
                    "nmePriority".into(),
                    json!(u16::from_be_bytes([payload[0], payload[1]])),
                );
            }
            (7, 3) | (7, 4) => {
                if payload.len() < 16 {
                    return None;
                }
                raw.insert(
                    if suboption == 3 {
                        "nmeParameterUuid"
                    } else {
                        "nmeAgentUuid"
                    }
                    .into(),
                    json!(uuid(&payload[..16])),
                );
            }
            (7, 5) => {
                if payload.len() < 6 {
                    return None;
                }
                raw.insert(
                    "cimInterface".into(),
                    json!({
                        "deviceId": u16::from_be_bytes([payload[2], payload[3]]),
                        "instance": u16::from_be_bytes([payload[4], payload[5]]),
                        "vendorId": u16::from_be_bytes([payload[0], payload[1]]),
                    }),
                );
            }
            _ => {}
        }
        offset += padded_length;
    }
    if let Some(vendor_id) = fields.get("vendorId").and_then(Value::as_u64)
        && let Some(vendor) = crate::profinet_database::manufacturer_name(vendor_id as u16)
    {
        fields.insert("vendor".into(), json!(vendor));
    }
    raw.insert("blocks".into(), json!(raw_blocks));
    fields.entry("name".into()).or_insert_with(|| json!(mac));
    let ip = fields
        .get("ipAddress")
        .and_then(Value::as_str)
        .map(str::to_owned);
    Some(Device {
        mac_address: mac.clone(),
        mac_addresses: vec![mac.clone()],
        ip_addresses: ip.clone().into_iter().collect(),
        observations: vec![Observation {
            source: Source::ProfinetDcp,
            observed_at: crate::now(),
            ip_address: ip,
            mac_address: Some(mac),
            fields,
            raw: Value::Object(raw.into_iter().collect()),
            warnings,
        }],
        interfaces: vec![],
        ports: vec![],
    })
}

#[cfg(any(windows, target_os = "linux", test))]
fn new_xid() -> u32 {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    (elapsed.as_nanos() as u32) ^ std::process::id().rotate_left(16)
}

#[cfg(windows)]
pub fn npcap_available() -> bool {
    npcap::available()
}

pub fn npcap_version() -> Option<String> {
    #[cfg(windows)]
    {
        npcap::version()
    }
    #[cfg(not(windows))]
    {
        None
    }
}

#[cfg(windows)]
pub fn npcap_interface_available(interface: &str) -> bool {
    windows_scan_interface(interface)
        .is_ok_and(|selected| npcap::interface_available(&selected.name))
}

#[cfg(windows)]
pub(crate) fn windows_scan_interface(interface: &str) -> Result<CaptureInterface, String> {
    let selected = interfaces()?
        .into_iter()
        .find(|item| {
            item.name.eq_ignore_ascii_case(interface)
                || item.friendly_name.eq_ignore_ascii_case(interface)
        })
        .ok_or_else(|| format!("Windows network interface {interface} was not found."))?;
    if is_obsolete_bridge(&selected) {
        return Err(
            "The selected interface is the obsolete Windows Network Bridge left by the previous TAP backend. Remove that bridge, refresh interfaces, and select the physical Ethernet adapter; Npcap does not require a bridge."
                .into(),
        );
    }
    Ok(selected)
}

pub fn interface_mac(interface: &CaptureInterface) -> Option<String> {
    interface
        .addresses
        .iter()
        .find_map(|address| normalize_mac(address))
}

#[cfg(any(windows, test))]
pub(crate) fn validate_source_mac(
    interface: &CaptureInterface,
    source_mac: &str,
) -> Result<(), String> {
    let actual = interface_mac(interface).ok_or_else(|| {
        format!(
            "Windows did not report a hardware MAC address for interface {}. Active Layer-2 discovery was not started.",
            interface.friendly_name
        )
    })?;
    let configured = normalize_mac(source_mac)
        .ok_or_else(|| "A valid source MAC address is required.".to_string())?;
    if configured != actual {
        return Err(format!(
            "Source MAC {configured} does not belong to selected interface {} ({actual}). Active Layer-2 discovery was not started because spoofing a source MAC can trigger switch port security and interrupt the network.",
            interface.friendly_name
        ));
    }
    Ok(())
}

#[cfg(any(windows, test))]
fn is_obsolete_bridge(interface: &CaptureInterface) -> bool {
    interface
        .description
        .eq_ignore_ascii_case("Microsoft Network Adapter Multiplexor Driver")
        || interface
            .friendly_name
            .eq_ignore_ascii_case("Network Bridge")
}

fn ipv4(value: &[u8]) -> String {
    format!("{}.{}.{}.{}", value[0], value[1], value[2], value[3])
}
fn insert_string(target: &mut BTreeMap<String, Value>, key: &str, value: &[u8]) {
    let value = String::from_utf8_lossy(value)
        .trim_matches(char::from(0))
        .trim()
        .to_string();
    if !value.is_empty() {
        target.insert(key.into(), json!(value));
    }
}
fn uuid(value: &[u8]) -> String {
    uuid::Uuid::from_slice(value)
        .expect("sixteen-byte UUID")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforces_a_one_minute_dcp_response_window() {
        assert_eq!(
            dcp_response_window(Duration::from_secs(4)),
            DCP_RESPONSE_WINDOW
        );
    }

    #[test]
    fn deduplicates_active_identify_responses() {
        let xid = 42;
        let frame = response(xid, &[2, 2, 0, 5, 0, 0, b'p', b'l', b'c', 0]);
        let mut devices = BTreeMap::new();
        collect_active_response(&mut devices, &frame, [0, 1, 2, 3, 4, 5], xid).unwrap();
        collect_active_response(&mut devices, &frame, [0, 1, 2, 3, 4, 5], xid).unwrap();
        assert_eq!(devices.len(), 1);
    }

    #[test]
    fn rejects_dcp_devices_beyond_the_memory_bound() {
        let mut devices = BTreeMap::new();
        for index in 0..MAX_DCP_DEVICES {
            insert_dcp_device(
                &mut devices,
                Device {
                    mac_address: index.to_string(),
                    ..Device::default()
                },
            )
            .unwrap();
        }
        let error = insert_dcp_device(
            &mut devices,
            Device {
                mac_address: "overflow".into(),
                ..Device::default()
            },
        )
        .unwrap_err();
        assert!(error.contains("bounded device limit"));
    }

    #[test]
    fn passive_profinet_traffic_keeps_a_parsed_dcp_identity() {
        let mac = "00:11:22:33:44:55".to_string();
        let mut devices = BTreeMap::new();
        insert_dcp_device(
            &mut devices,
            Device {
                mac_address: mac.clone(),
                ip_addresses: vec!["192.0.2.1".into()],
                ..Device::default()
            },
        )
        .unwrap();
        insert_passive_dcp_device(
            &mut devices,
            Device {
                mac_address: mac.clone(),
                ..Device::default()
            },
        )
        .unwrap();
        assert_eq!(devices[&mac].ip_addresses, ["192.0.2.1"]);
    }

    #[test]
    fn pktmon_passive_frames_require_the_selected_adapter_as_destination() {
        let selected = [0, 1, 2, 3, 4, 5];
        let remote = [6, 7, 8, 9, 10, 11];
        let frame = |destination: [u8; 6], source: [u8; 6], ether_type: [u8; 2]| {
            let mut packet = vec![0; 14];
            packet[..6].copy_from_slice(&destination);
            packet[6..12].copy_from_slice(&source);
            packet[12..14].copy_from_slice(&ether_type);
            packet
        };

        assert!(passive_frame_matches_interface(
            &frame(selected, remote, PROFINET_ETHERTYPE),
            selected,
        ));
        assert!(!passive_frame_matches_interface(
            &frame([12, 13, 14, 15, 16, 17], remote, PROFINET_ETHERTYPE),
            selected,
        ));
        assert!(!passive_frame_matches_interface(
            &frame(selected, selected, PROFINET_ETHERTYPE),
            selected,
        ));
        assert!(!passive_frame_matches_interface(
            &frame(selected, remote, [0x08, 0x00]),
            selected,
        ));
        assert!(!passive_frame_matches_interface(&[0; 13], selected));
    }

    fn pnio_record(
        api: u32,
        slot: u16,
        subslot: u16,
        index: u16,
        parsed: Value,
    ) -> pnio::RecordRead {
        pnio::RecordRead {
            target: pnio::RecordTarget {
                api,
                slot,
                subslot,
                index,
                data_length: 32_768,
            },
            data: vec![0x12, 0x34],
            parsed,
        }
    }

    #[test]
    fn pnio_components_preserve_identity_containment_and_observation_scope() {
        let module = json!({
            "manufacturerId": "002A", "manufacturerName": "Module vendor",
            "orderId": "MODULE-1", "serialNumber": "MODULE-SERIAL",
            "hardwareRevision": "2", "softwareRevision": "V2.0.0",
        });
        let records = vec![
            pnio_record(0, 1, 1, 0xAFF0, module.clone()),
            pnio_record(7, 1, 1, 0xAFF0, module),
            pnio_record(
                0,
                0,
                1,
                0xAFF0,
                json!({
                    "manufacturerName": "Primary vendor", "serialNumber": "DAP-SERIAL",
                    "softwareRevision": "V1.0.0", "hardwareRevision": "1",
                }),
            ),
            pnio_record(
                0,
                1,
                1,
                0xAFF1,
                json!({ "function": "Input", "location": "Cell 1" }),
            ),
            pnio_record(0, 1, 1, 0xAFF2, json!({ "installationDate": "2026-01-01" })),
            pnio_record(0, 1, 1, 0xAFF3, json!({ "descriptor": "Input module" })),
            pnio_record(0, 1, 1, 0xAFF4, json!({ "imSignature": "AB" })),
            pnio_record(0, 1, 1, 0xAFF5, json!({ "im5Data": [] })),
            pnio_record(
                0,
                0,
                1,
                0xF000,
                json!({ "apis": [{
                "api": 0, "modules": [{
                    "slot": 1, "identNumber": 10,
                    "submodules": [{ "subslot": 1, "identNumber": 11 }],
                }, {
                    "slot": 2, "identNumber": 20,
                    "submodules": [{ "subslot": 1, "identNumber": 21 }],
                }],
            }] }),
            ),
        ];
        let mut device = Device {
            mac_address: "00:11:22:33:44:55".into(),
            ..Device::default()
        };
        let target_ip = Ipv4Addr::new(192, 0, 2, 10);
        for _ in 0..2 {
            attach_pnio_records(
                &mut device,
                target_ip,
                pnio::RecordScan {
                    records: records.clone(),
                    warnings: vec![
                        "PNIO record 0xAFF1 (API 0, slot 0, subslot 1) failed: timeout".into(),
                    ],
                },
            );
        }
        let observation = &device.observations[0];
        assert_eq!(observation.ip_address.as_deref(), Some("192.0.2.10"));
        assert!(observation.warnings[0].contains("0xAFF1"));
        assert_eq!(observation.fields["manufacturer"], "Primary vendor");
        assert_eq!(observation.fields["softwareRevision"], "V1.0.0");
        assert!(!observation.fields.contains_key("serialNumber"));
        assert_eq!(observation.raw["pnioRecords"][0]["raw"], "1234");
        assert_eq!(observation.raw["pnioRecords"].as_array().unwrap().len(), 9);
        assert_ne!(
            observation.raw["observationId"],
            device.observations[1].raw["observationId"]
        );
        assert_eq!(observation.raw["subject"]["macAddress"], device.mac_address);
        let components = observation.raw["physicalEntities"].as_array().unwrap();
        let by_ref = |key| {
            components
                .iter()
                .find(|entity| entity["ref"] == key)
                .unwrap()
        };
        assert_eq!(components.len(), 8);
        assert_eq!(by_ref("pnio:0:1")["identNumber"], 10);
        let module = by_ref("pnio:0:1:1");
        assert_eq!(module["identNumber"], 11);
        assert_eq!(module["parentRef"], "pnio:0:1");
        assert_eq!(module["parentPosition"], 1);
        assert_eq!(module["catalogNumber"], "MODULE-1");
        assert_eq!(module["hardwareRevision"], "2");
        assert_eq!(module["softwareRevision"], "V2.0.0");
        assert_eq!(module["location"], "Cell 1");
        assert_eq!(module["installationDate"], "2026-01-01");
        assert_eq!(module["description"], "Input module");
        assert_eq!(module["serialClaim"]["scope"], "submodule");
        assert_eq!(module["serialClaim"]["componentRef"], module["ref"]);
        assert_eq!(
            by_ref("pnio:7:1:1")["serialClaim"]["original"],
            "MODULE-SERIAL"
        );
        assert!(by_ref("pnio:0:2:1").get("serialClaim").is_none());
        let restored: Observation =
            serde_json::from_value(serde_json::to_value(observation).unwrap()).unwrap();
        assert_eq!(restored.raw, observation.raw);
    }

    #[test]
    fn pnio_module_only_and_empty_records_do_not_supply_device_identity() {
        let mut device = Device::default();
        let target_ip = Ipv4Addr::new(192, 0, 2, 10);
        attach_pnio_records(&mut device, target_ip, pnio::RecordScan::default());
        assert!(device.observations.is_empty());
        attach_pnio_records(
            &mut device,
            target_ip,
            pnio::RecordScan {
                records: vec![pnio_record(
                    0,
                    1,
                    1,
                    0xAFF0,
                    json!({
                        "serialNumber": " ", "orderId": "", "manufacturerName": "Module vendor",
                        "softwareRevision": "V2.0.0",
                    }),
                )],
                warnings: vec![],
            },
        );
        let observation = &device.observations[0];
        assert!(!observation.fields.contains_key("manufacturer"));
        assert!(!observation.fields.contains_key("softwareRevision"));
        let module = &observation.raw["physicalEntities"][1];
        assert!(module.get("serialClaim").is_none());
        assert!(module.get("catalogNumber").is_none());
        assert_eq!(module["manufacturer"], "Module vendor");
    }

    #[test]
    fn pnio_attempts_every_scoped_unambiguous_ip_without_requiring_dcp() {
        let device = |mac: &str, ips: &[&str]| Device {
            mac_address: mac.into(),
            ip_addresses: ips.iter().map(|ip| ip.to_string()).collect(),
            ..Device::default()
        };
        let mut devices = vec![
            device(
                "00:11:22:33:44:55",
                &["192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.2"],
            ),
            device("00:11:22:33:44:66", &["192.0.2.1"]),
            device(
                "00:11:22:33:44:77",
                &["::1", "0.0.0.0", "224.0.0.1", "255.255.255.255"],
            ),
            device("invalid", &["192.0.2.7"]),
            device("00:11:22:33:44:88", &["192.0.2.8"]),
        ];
        let targets = [1, 2, 3, 7]
            .map(|last| Ipv4Addr::new(192, 0, 2, last))
            .into();
        let mut attempted = Vec::new();
        let warnings = read_device_records(
            &mut devices,
            &targets,
            &AtomicBool::new(false),
            |mac, ip, port, _, timeout, _| {
                assert_eq!(port, 34964);
                assert_eq!(timeout, Duration::from_secs(2));
                attempted.push((mac, ip));
                Err("no EPM response".into())
            },
        );
        assert_eq!(
            attempted,
            [2, 3].map(|last| ([0, 17, 34, 51, 68, 85], Ipv4Addr::new(192, 0, 2, last)))
        );
        for detail in [
            "multiple MAC",
            "no usable device IPv4",
            "no valid unicast MAC",
            "outside the selected",
            "no EPM response",
        ] {
            assert!(
                warnings.iter().any(|warning| warning.contains(detail)),
                "{warnings:?}"
            );
        }
        assert!(devices.iter().all(|device| device.observations.is_empty()));
        assert!(
            read_device_records(
                &mut devices,
                &targets,
                &AtomicBool::new(true),
                |_, _, _, _, _, _| panic!("cancelled scans must not transmit")
            )
            .is_empty()
        );
        assert!(
            enrich_pnio(
                "invalid-interface",
                "00:11:22:33:44:55",
                &mut devices,
                &targets,
                &AtomicBool::new(false)
            )
            .is_err()
        );
        assert!(
            enrich_pnio(
                "invalid-interface",
                "invalid",
                &mut devices,
                &targets,
                &AtomicBool::new(true)
            )
            .unwrap()
            .is_empty()
        );
    }

    #[test]
    fn pnio_failed_records_export_diagnostics_without_claiming_online_identity() {
        let mut device = Device {
            mac_address: "00:11:22:33:44:55".into(),
            ..Device::default()
        };
        attach_pnio_records(
            &mut device,
            Ipv4Addr::new(192, 0, 2, 1),
            pnio::RecordScan {
                records: vec![],
                warnings: vec!["PNIO record 0xAFF0 failed".into()],
            },
        );
        let exported = serde_json::to_value(&device.observations[0]).unwrap();
        assert_eq!(exported["warnings"][0], "PNIO record 0xAFF0 failed");
        assert_eq!(exported["raw"]["pnioRecords"], json!([]));
        assert_eq!(
            exported["fields"],
            json!({ "macAddress": "00:11:22:33:44:55" })
        );
    }

    #[cfg(any(windows, target_os = "linux"))]
    #[test]
    fn cancelled_dcp_scan_skips_capture() {
        let cancelled = AtomicBool::new(true);
        assert!(
            scan(
                "invalid-interface",
                "invalid-mac",
                Duration::ZERO,
                &cancelled
            )
            .unwrap()
            .is_empty()
        );
    }

    #[test]
    fn parses_identity_and_ip_blocks() {
        let xid = 0x1234_5678;
        let mut frame = identify_request([0, 1, 2, 3, 4, 5], xid);
        frame[6..12].copy_from_slice(&[0, 17, 34, 51, 68, 85]);
        frame[15] = 0xff;
        frame[17] = 0x01;
        frame[22..24].fill(0);
        let blocks = [
            2, 1, 0, 9, 0, 0, b'E', b'T', b'2', b'0', b'0', b'S', b'P', 0, 2, 2, 0, 5, 0, 0, b'p',
            b'l', b'c', 0, 1, 2, 0, 14, 0, 0, 192, 0, 2, 1, 255, 255, 255, 0, 192, 0, 2, 254,
        ];
        frame[24..26].copy_from_slice(&(blocks.len() as u16).to_be_bytes());
        frame.truncate(26);
        frame.extend(blocks);
        let device = parse_response(&frame, xid).unwrap();
        assert_eq!(device.mac_address, "00:11:22:33:44:55");
        assert_eq!(device.observations[0].fields["ipAddress"], "192.0.2.1");
        assert_eq!(device.observations[0].fields["model"], "ET200SP");
    }

    #[test]
    fn rejects_unrelated_and_malformed_responses() {
        let xid = 0x1234_5678;
        let frame = response(xid, &[2, 2, 0, 5, 0, 0, b'p', b'l', b'c', 0]);
        assert!(parse_response(&frame, xid.wrapping_add(1)).is_none());
        for (offset, value) in [(12, 0), (14, 0), (16, 3), (17, 5), (22, 1)] {
            let mut invalid = frame.clone();
            invalid[offset] = value;
            assert!(parse_response(&invalid, xid).is_none());
        }
        let mut truncated = frame.clone();
        truncated[24..26].copy_from_slice(&100_u16.to_be_bytes());
        assert!(parse_response(&truncated, xid).is_none());
        assert!(parse_response(&response(xid, &[2, 2, 0, 6, 0, 0, b'p']), xid).is_none());
    }

    #[test]
    fn decodes_identify_all_device_metadata() {
        let xid = 9;
        let mut blocks = Vec::new();
        add_block(
            &mut blocks,
            1,
            3,
            &[
                192, 0, 2, 1, 255, 255, 255, 0, 192, 0, 2, 254, 192, 0, 2, 53, 192, 0, 2, 54, 0, 0,
                0, 0, 0, 0, 0, 0,
            ],
        );
        add_block(&mut blocks, 2, 3, &[0, 42, 0, 7]);
        add_block(&mut blocks, 2, 4, &[3, 0]);
        add_block(&mut blocks, 2, 6, b"port-001.plc");
        add_block(&mut blocks, 2, 7, &[0x12, 0x34]);
        add_block(&mut blocks, 2, 8, &[0, 42, 0, 7]);
        add_block(&mut blocks, 2, 10, &[0, 3]);
        add_block(&mut blocks, 2, 11, &[0, 0x21]);

        let observation = &parse_response(&response(xid, &blocks), xid)
            .unwrap()
            .observations[0];
        assert_eq!(observation.fields["ipAddress"], "192.0.2.1");
        assert_eq!(observation.fields["vendorId"], 42);
        assert_eq!(observation.fields["deviceId"], 7);
        let exported = serde_json::to_value(observation).unwrap();
        assert_eq!(exported["fields"]["vendorId"], 42);
        assert_eq!(exported["fields"]["vendor"], "SIEMENS AG");
        assert_eq!(exported["fields"]["deviceId"], 7);
        assert_eq!(observation.raw["dnsServers"][0], "192.0.2.53");
        assert_eq!(observation.raw["deviceRole"]["roles"][1], "io-controller");
        assert_eq!(observation.raw["aliasName"], "port-001.plc");
        assert_eq!(observation.raw["deviceInstance"], 0x1234);
        assert_eq!(observation.raw["oemVendorId"], 42);
        assert_eq!(observation.raw["rsiProperties"], 3);
        assert_eq!(observation.raw["protocolProperties"], 0x21);
    }

    #[test]
    fn resolves_vendor_from_the_final_device_identity_block() {
        for (vendor_ids, expected) in [
            (vec![2_u16], Some("Rockwell Automation")),
            (vec![0xFDE8], None),
            (vec![42, 0xFDE8], None),
            (vec![42, 2], Some("Rockwell Automation")),
            (vec![], None),
        ] {
            let mut blocks = Vec::new();
            add_block(&mut blocks, 2, 2, b"plc");
            for id in &vendor_ids {
                let [high, low] = id.to_be_bytes();
                add_block(&mut blocks, 2, 3, &[high, low, 0, 7]);
            }
            let device = parse_response(&response(9, &blocks), 9).unwrap();
            let exported = serde_json::to_value(&device.observations[0]).unwrap();
            assert_eq!(
                exported["fields"].get("vendor"),
                expected.map(|name| json!(name)).as_ref()
            );
            assert_eq!(
                exported["fields"].get("vendorId"),
                vendor_ids.last().map(|id| json!(id)).as_ref()
            );
            assert_eq!(
                exported["raw"].get("vendorId"),
                exported["fields"].get("vendorId")
            );
        }
    }

    #[test]
    fn preserves_repeated_blocks_and_reports_ip_conflicts() {
        let xid = 7;
        let blocks = [
            1, 2, 0, 14, 0, 0x81, 192, 0, 2, 1, 255, 255, 255, 0, 192, 0, 2, 254, 0x80, 1, 0, 3,
            0xaa, 0xcc, 0xdd, 0, 0x80, 1, 0, 3, 0xbb, 0xee, 0xff, 0,
        ];
        let device = parse_response(&response(xid, &blocks), xid).unwrap();
        let observation = &device.observations[0];
        assert_eq!(observation.raw["blocks"].as_array().unwrap().len(), 3);
        assert_eq!(
            observation.warnings,
            ["DCP reports an IP address conflict."]
        );
    }

    #[test]
    fn builds_identify_all_request() {
        let request = identify_request([0, 1, 2, 3, 4, 5], 0x1234_5678);
        assert_eq!(
            &request[..30],
            &[
                1, 14, 207, 0, 0, 0, 0, 1, 2, 3, 4, 5, 0x88, 0x92, 0xfe, 0xfe, 5, 0, 0x12, 0x34,
                0x56, 0x78, 0, 0x80, 0, 4, 0xff, 0xff, 0, 0,
            ]
        );
    }

    #[test]
    fn rejects_a_source_mac_that_does_not_belong_to_the_selected_interface() {
        let interface = CaptureInterface {
            name: "{GUID}".into(),
            friendly_name: "Ethernet 2".into(),
            description: "Physical Ethernet".into(),
            addresses: vec!["40:8D:5C:B7:93:F4".into(), "192.0.2.10".into()],
        };
        assert!(validate_source_mac(&interface, "40-8d-5c-b7-93-f4").is_ok());
        let error = validate_source_mac(&interface, "00:11:22:33:44:55").unwrap_err();
        assert!(error.contains("was not started"));
        assert!(error.contains("port security"));

        let mut missing = interface;
        missing.addresses = vec!["192.0.2.10".into()];
        assert!(validate_source_mac(&missing, "00:11:22:33:44:55").is_err());
    }

    #[test]
    fn rejects_obsolete_windows_bridge_interfaces() {
        assert!(is_obsolete_bridge(&CaptureInterface {
            name: "{GUID}".into(),
            friendly_name: "Network Bridge".into(),
            description: "Microsoft Network Adapter Multiplexor Driver".into(),
            addresses: vec![],
        }));
        assert!(!is_obsolete_bridge(&CaptureInterface {
            name: "{GUID}".into(),
            friendly_name: "Ethernet 2".into(),
            description: "Intel(R) Ethernet Connection".into(),
            addresses: vec![],
        }));
    }

    #[test]
    fn decodes_remaining_blocks_and_platform_input_errors() {
        let cancelled = AtomicBool::new(false);
        let xid = 11;
        let mut blocks = Vec::new();
        add_block(&mut blocks, 1, 1, &[0, 1, 2, 3, 4, 6]);
        add_block(&mut blocks, 2, 3, &[0, 42, 0, 7]);
        add_block(&mut blocks, 2, 5, &[1, 2, 3, 4]);
        add_block(&mut blocks, 3, 61, &[1, 2]);
        add_block(&mut blocks, 3, 255, &[3, 4]);
        add_block(&mut blocks, 6, 1, &[0, 1]);
        add_block(&mut blocks, 7, 1, &[0; 16]);
        add_block(&mut blocks, 7, 2, &[0, 2]);
        add_block(&mut blocks, 7, 3, &[1; 16]);
        add_block(&mut blocks, 7, 4, &[2; 16]);
        add_block(&mut blocks, 7, 5, &[0, 42, 0, 7, 0, 1]);
        add_block(&mut blocks, 99, 99, &[1]);
        let device = parse_response(&response(xid, &blocks), xid).unwrap();
        let raw = &device.observations[0].raw;
        assert_eq!(device.observations[0].fields["vendorId"], 42);
        assert_eq!(device.observations[0].fields["deviceId"], 7);
        assert_eq!(raw["vendorId"], 42);
        assert_eq!(raw["deviceOptions"][1]["suboption"], 4);
        assert_eq!(raw["deviceInitiative"], 1);
        assert_eq!(raw["nmePriority"], 2);
        assert!(device.observations[0].warnings[0].contains("differs"));
        assert!(mac_bytes("invalid").is_none());
        assert!(mac_bytes("00-11-22-33-44-55").is_some());
        assert_ne!(new_xid(), 0);
        assert!(
            scan(
                "missing-otserver-interface",
                "00:11:22:33:44:55",
                Duration::ZERO,
                &cancelled,
            )
            .is_err()
        );
        assert!(scan("lo", "invalid", Duration::ZERO, &cancelled).is_err());
    }

    #[test]
    fn rejects_malformed_identify_blocks() {
        let xid = 12;
        assert!(parse_response(&[], xid).is_none());
        let mut empty = response(xid, &[]);
        empty[24..26].fill(0);
        assert!(parse_response(&empty, xid).is_none());
        assert!(parse_response(&response(xid, &[1, 1, 0]), xid).is_none());
        for (option, suboption, payload) in [
            (1, 1, vec![0; 5]),
            (1, 2, vec![0; 11]),
            (1, 3, vec![0; 27]),
            (2, 3, vec![0; 3]),
            (2, 4, vec![]),
            (2, 5, vec![1]),
            (2, 7, vec![0]),
            (2, 8, vec![0; 3]),
            (2, 10, vec![0]),
            (6, 1, vec![0]),
            (7, 1, vec![0; 15]),
            (7, 2, vec![0]),
            (7, 3, vec![0; 15]),
            (7, 5, vec![0; 5]),
        ] {
            let mut blocks = Vec::new();
            add_block(&mut blocks, option, suboption, &payload);
            assert!(parse_response(&response(xid, &blocks), xid).is_none());
        }
    }

    fn response(xid: u32, blocks: &[u8]) -> Vec<u8> {
        let mut frame = identify_request([0, 1, 2, 3, 4, 5], xid);
        frame[6..12].copy_from_slice(&[0, 17, 34, 51, 68, 85]);
        frame[15] = 0xff;
        frame[17] = 1;
        frame[22..24].fill(0);
        frame[24..26].copy_from_slice(&(blocks.len() as u16).to_be_bytes());
        frame.truncate(26);
        frame.extend(blocks);
        frame
    }

    fn add_block(blocks: &mut Vec<u8>, option: u8, suboption: u8, payload: &[u8]) {
        let length = payload.len() + 2;
        blocks.extend([option, suboption]);
        blocks.extend((length as u16).to_be_bytes());
        blocks.extend([0, 0]);
        blocks.extend(payload);
        if !length.is_multiple_of(2) {
            blocks.push(0);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn lists_linux_interfaces_without_privileges() {
        let interfaces = interfaces().unwrap();
        assert!(!interfaces.is_empty());
        let loopback = interfaces
            .iter()
            .find(|interface| interface.name == "lo")
            .unwrap();
        assert!(
            loopback
                .addresses
                .iter()
                .any(|address| address == "127.0.0.1")
        );
        assert!(loopback.addresses.iter().any(|address| address == "::1"));
        assert_eq!(
            crate::discovery::source_ipv4("lo").unwrap(),
            Ipv4Addr::LOCALHOST
        );
        assert!(
            crate::discovery::interface_ipv4_addresses("missing-otserver-interface")
                .unwrap()
                .is_empty()
        );
        assert!(crate::discovery::interface_ipv4_addresses("invalid\0interface").is_err());
    }

    #[cfg(windows)]
    #[test]
    fn tests_windows_interfaces() {
        let result = interfaces();
        assert!(result.is_ok());
        assert!(
            scan(
                "invalid-iface",
                "invalid-mac",
                Duration::ZERO,
                &AtomicBool::new(false)
            )
            .is_err()
        );
    }
}
