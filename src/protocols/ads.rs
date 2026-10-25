use super::{Finding, hex, port};
use crate::contract::Source;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{Instant, timeout, timeout_at};

const ADS_TCP_PORT: u16 = 48_898;
const ADS_UDP_PORT: u16 = 48_899;
const UDP_COOKIE: u32 = 0x7114_6603;
const SERVER_INFO: u32 = 1;
const RESPONSE: u32 = 0x8000_0000;
const READ_DEVICE_INFO: u16 = 1;
const READ_STATE: u16 = 4;
const AMS_REQUEST: u16 = 4;
const AMS_RESPONSE: u16 = 5;
const AMS_HEADER_LENGTH: usize = 32;
const MAX_UDP_RESPONSE: usize = 512;
const MAX_TCP_RESPONSE: usize = 4096;
const DEFAULT_AMS_PORTS: [u16; 3] = [10_000, 851, 801];
const MAX_AMS_PORTS: usize = 8;
const MAX_TARGET_NETIDS: usize = 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(2);
static NEXT_INVOKE_ID: AtomicU32 = AtomicU32::new(1);

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProbeSettings {
    pub source_net_id: Option<[u8; 6]>,
    pub target_net_ids: BTreeMap<Ipv4Addr, [u8; 6]>,
    pub ams_ports: Vec<u16>,
}

impl ProbeSettings {
    pub fn from_config(
        source_net_id: Option<&str>,
        target_net_ids: &BTreeMap<String, String>,
        ams_ports: &[u16],
    ) -> Result<Self, String> {
        let source_net_id = source_net_id.map(parse_net_id).transpose()?;
        if ams_ports.len() > MAX_AMS_PORTS
            || ams_ports.contains(&0)
            || ams_ports.iter().copied().collect::<BTreeSet<_>>().len() != ams_ports.len()
        {
            return Err(format!(
                "ADS AMS ports must be unique nonzero values (at most {MAX_AMS_PORTS})."
            ));
        }
        if target_net_ids.len() > MAX_TARGET_NETIDS {
            return Err(format!(
                "ADS target NetID map exceeds the {MAX_TARGET_NETIDS}-entry limit."
            ));
        }
        let mut normalized_targets = BTreeMap::new();
        for (target, net_id) in target_net_ids {
            let ip = target.parse::<Ipv4Addr>().map_err(|_| {
                format!("ADS target NetID map key {target:?} must be an IPv4 address.")
            })?;
            if normalized_targets
                .insert(ip, parse_net_id(net_id)?)
                .is_some()
            {
                return Err(format!("ADS target NetID map repeats IPv4 address {ip}."));
            }
        }
        Ok(Self {
            source_net_id,
            target_net_ids: normalized_targets,
            ams_ports: ams_ports.to_vec(),
        })
    }

    fn ports(&self) -> &[u16] {
        if self.ams_ports.is_empty() {
            &DEFAULT_AMS_PORTS
        } else {
            &self.ams_ports
        }
    }
}

fn parse_net_id(value: &str) -> Result<[u8; 6], String> {
    let mut bytes = [0; 6];
    let mut parts = value.split('.');
    for byte in &mut bytes {
        let part = parts
            .next()
            .ok_or_else(|| "ADS AMS NetID must contain six dot-separated octets.".to_string())?;
        if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err("ADS AMS NetID must contain six decimal octets from 0 to 255.".into());
        }
        *byte = part.parse::<u8>().map_err(|_| {
            "ADS AMS NetID must contain six decimal octets from 0 to 255.".to_string()
        })?;
    }
    if parts.next().is_some() {
        return Err("ADS AMS NetID must contain exactly six dot-separated octets.".into());
    }
    if bytes == [0; 6] {
        return Err("ADS AMS NetID must not be the all-zero sentinel.".into());
    }
    Ok(bytes)
}

#[derive(Clone, Copy, Debug)]
struct AmsHeader {
    target_net_id: [u8; 6],
    target_port: u16,
    source_net_id: [u8; 6],
    source_port: u16,
    command: u16,
    state_flags: u16,
    data_length: u32,
    error_code: u32,
    invoke_id: u32,
}

impl AmsHeader {
    fn encode(self) -> [u8; AMS_HEADER_LENGTH] {
        let mut bytes = [0; AMS_HEADER_LENGTH];
        bytes[..6].copy_from_slice(&self.target_net_id);
        bytes[6..8].copy_from_slice(&self.target_port.to_le_bytes());
        bytes[8..14].copy_from_slice(&self.source_net_id);
        bytes[14..16].copy_from_slice(&self.source_port.to_le_bytes());
        bytes[16..18].copy_from_slice(&self.command.to_le_bytes());
        bytes[18..20].copy_from_slice(&self.state_flags.to_le_bytes());
        bytes[20..24].copy_from_slice(&self.data_length.to_le_bytes());
        bytes[24..28].copy_from_slice(&self.error_code.to_le_bytes());
        bytes[28..32].copy_from_slice(&self.invoke_id.to_le_bytes());
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != AMS_HEADER_LENGTH {
            return Err("invalid AMS header length".into());
        }
        Ok(Self {
            target_net_id: bytes[..6]
                .try_into()
                .map_err(|_| "invalid AMS target NetID")?,
            target_port: u16::from_le_bytes(
                bytes[6..8]
                    .try_into()
                    .map_err(|_| "invalid AMS target port")?,
            ),
            source_net_id: bytes[8..14]
                .try_into()
                .map_err(|_| "invalid AMS source NetID")?,
            source_port: u16::from_le_bytes(
                bytes[14..16]
                    .try_into()
                    .map_err(|_| "invalid AMS source port")?,
            ),
            command: u16::from_le_bytes(
                bytes[16..18]
                    .try_into()
                    .map_err(|_| "invalid AMS command")?,
            ),
            state_flags: u16::from_le_bytes(
                bytes[18..20].try_into().map_err(|_| "invalid AMS flags")?,
            ),
            data_length: u32::from_le_bytes(
                bytes[20..24]
                    .try_into()
                    .map_err(|_| "invalid AMS data length")?,
            ),
            error_code: u32::from_le_bytes(
                bytes[24..28].try_into().map_err(|_| "invalid AMS error")?,
            ),
            invoke_id: u32::from_le_bytes(
                bytes[28..32]
                    .try_into()
                    .map_err(|_| "invalid AMS invoke ID")?,
            ),
        })
    }
}

#[derive(Clone, Debug)]
struct DeviceInfo {
    major: u8,
    minor: u8,
    build: u16,
    name_bytes: [u8; 16],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AdsResponseError {
    InvalidLength,
    Service(u32),
}

impl DeviceInfo {
    fn decode(data: &[u8]) -> Result<Self, AdsResponseError> {
        if data.len() < 4 {
            return Err(AdsResponseError::InvalidLength);
        }
        let result = u32::from_le_bytes(
            data[..4]
                .try_into()
                .map_err(|_| AdsResponseError::InvalidLength)?,
        );
        if result != 0 {
            return Err(AdsResponseError::Service(result));
        }
        if data.len() != 24 {
            return Err(AdsResponseError::InvalidLength);
        }
        Ok(Self {
            major: data[4],
            minor: data[5],
            build: u16::from_le_bytes(
                data[6..8]
                    .try_into()
                    .map_err(|_| AdsResponseError::InvalidLength)?,
            ),
            name_bytes: data[8..24]
                .try_into()
                .map_err(|_| AdsResponseError::InvalidLength)?,
        })
    }

    fn name(&self) -> Option<String> {
        let end = self
            .name_bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(self.name_bytes.len());
        let name = String::from_utf8_lossy(&self.name_bytes[..end])
            .trim()
            .to_owned();
        (!name.is_empty()).then_some(name)
    }

    fn version(&self) -> String {
        format!("{}.{}.{}", self.major, self.minor, self.build)
    }
}

#[derive(Clone, Copy, Debug)]
struct AdsState {
    ads: u16,
    device: u16,
}

impl AdsState {
    fn decode(data: &[u8]) -> Result<Self, AdsResponseError> {
        if data.len() < 4 {
            return Err(AdsResponseError::InvalidLength);
        }
        let result = u32::from_le_bytes(
            data[..4]
                .try_into()
                .map_err(|_| AdsResponseError::InvalidLength)?,
        );
        if result != 0 {
            return Err(AdsResponseError::Service(result));
        }
        if data.len() != 8 {
            return Err(AdsResponseError::InvalidLength);
        }
        Ok(Self {
            ads: u16::from_le_bytes(
                data[4..6]
                    .try_into()
                    .map_err(|_| AdsResponseError::InvalidLength)?,
            ),
            device: u16::from_le_bytes(
                data[6..8]
                    .try_into()
                    .map_err(|_| AdsResponseError::InvalidLength)?,
            ),
        })
    }
}

struct AdsReply {
    ams_error: u32,
    data: Vec<u8>,
    response_header_hex: String,
    response_data_hex: String,
}

struct Discovery {
    net_id: [u8; 6],
    response_hex: String,
}

pub async fn probe(
    target: Ipv4Addr,
    settings: &ProbeSettings,
    cancelled: &AtomicBool,
    mut checkpoint: impl FnMut(Option<Finding>),
) -> Result<Option<Finding>, String> {
    if cancelled.load(Ordering::Relaxed) {
        return Ok(None);
    }

    let configured_net_id = settings.target_net_ids.get(&target).copied();
    let (target_net_id, discovery) = match configured_net_id {
        Some(net_id) => (net_id, json!({"outcome": "configured"})),
        None => match discover(target, cancelled).await? {
            Some(discovery) => (
                discovery.net_id,
                json!({"outcome": "success", "responseHex": discovery.response_hex}),
            ),
            None => return Ok(None),
        },
    };

    let mut finding = new_finding(target_net_id, discovery);
    if configured_net_id.is_none() {
        finding.ports.push(port(
            "udp",
            ADS_UDP_PORT,
            Source::BeckhoffAds,
            json!({"state": "open", "operation": "server-info"}),
        ));
    }
    checkpoint(Some(finding.clone()));

    if cancelled.load(Ordering::Relaxed) {
        set_incomplete(&mut finding, "cancelled");
        checkpoint(Some(finding.clone()));
        return Ok(Some(finding));
    }

    let address = SocketAddr::V4(SocketAddrV4::new(target, ADS_TCP_PORT));
    crate::traffic::wait().await;
    let mut stream = match timeout(IO_TIMEOUT, TcpStream::connect(address)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => {
            add_probe_warning(&mut finding, format!("ADS TCP connection failed: {error}"));
            set_incomplete(&mut finding, "tcp-connect-failed");
            checkpoint(Some(finding.clone()));
            return Ok(Some(finding));
        }
        Err(_) => {
            add_probe_warning(&mut finding, "ADS TCP connection timed out".into());
            set_incomplete(&mut finding, "tcp-connect-timeout");
            checkpoint(Some(finding.clone()));
            return Ok(Some(finding));
        }
    };

    finding.ports.push(port(
        "tcp",
        ADS_TCP_PORT,
        Source::BeckhoffAds,
        json!({"state": "open", "transport": "ams-tcp"}),
    ));
    let source_net_id = match settings.source_net_id {
        Some(net_id) => net_id,
        None => match stream.local_addr().ok().and_then(|address| match address {
            SocketAddr::V4(address) => Some(net_id_from_ipv4(*address.ip())),
            SocketAddr::V6(_) => None,
        }) {
            Some(net_id) => net_id,
            None => {
                add_probe_warning(
                    &mut finding,
                    "Could not derive the local IPv4 AMS NetID".into(),
                );
                set_incomplete(&mut finding, "source-netid-unavailable");
                checkpoint(Some(finding.clone()));
                return Ok(Some(finding));
            }
        },
    };
    finding.raw["sourceNetId"] = json!(format_net_id(source_net_id));
    finding.raw["sourceNetIdOrigin"] = json!(if settings.source_net_id.is_some() {
        "configured"
    } else {
        "connection-local-ipv4"
    });
    checkpoint(Some(finding.clone()));

    let ports = settings.ports();
    for &ams_port in ports {
        if cancelled.load(Ordering::Relaxed) {
            set_incomplete(&mut finding, "cancelled");
            add_probe_warning(
                &mut finding,
                "ADS collection cancelled; completed results retained.".into(),
            );
            break;
        }
        let mut endpoint = json!({
            "amsPort": ams_port,
            "deviceInfo": {"outcome": "pending"},
            "readState": {"outcome": "not-attempted"},
        });
        if let Some(endpoints) = finding.raw["endpoints"].as_array_mut() {
            endpoints.push(endpoint.clone());
        }
        checkpoint(Some(finding.clone()));

        let mut stop_connection = false;
        match request(
            &mut stream,
            target_net_id,
            source_net_id,
            ams_port,
            READ_DEVICE_INFO,
            cancelled,
        )
        .await
        {
            Ok(reply) if reply.ams_error == 0 => match DeviceInfo::decode(&reply.data) {
                Ok(info) => {
                    endpoint["deviceInfo"] = json!({
                        "outcome": "success",
                        "name": info.name(),
                        "nameBytes": hex(&info.name_bytes),
                        "version": {"major": info.major, "minor": info.minor, "build": info.build},
                        "responseHeaderHex": reply.response_header_hex,
                        "responseDataHex": reply.response_data_hex,
                    });
                    add_device_info_raw(&mut finding, ams_port, &info);
                }
                Err(AdsResponseError::InvalidLength) => {
                    endpoint["deviceInfo"] = json!({
                        "outcome": "invalid-response",
                        "responseHeaderHex": reply.response_header_hex,
                        "responseDataHex": reply.response_data_hex,
                    });
                    add_probe_warning(
                        &mut finding,
                        format!(
                            "ADS AMS port {ams_port} returned an invalid ReadDeviceInfo payload."
                        ),
                    );
                }
                Err(AdsResponseError::Service(code)) => {
                    endpoint["deviceInfo"] = json!({
                        "outcome": "ads-error",
                        "code": code,
                        "responseHeaderHex": reply.response_header_hex,
                        "responseDataHex": reply.response_data_hex,
                    });
                    add_probe_warning(
                        &mut finding,
                        format!("ADS AMS port {ams_port} ReadDeviceInfo returned 0x{code:08X}."),
                    );
                }
            },
            Ok(reply) => {
                endpoint["deviceInfo"] = json!({
                    "outcome": "ams-error",
                    "code": reply.ams_error,
                    "responseHeaderHex": reply.response_header_hex,
                    "responseDataHex": reply.response_data_hex,
                });
                add_probe_warning(
                    &mut finding,
                    format!(
                        "ADS AMS port {ams_port} ReadDeviceInfo returned AMS error 0x{:08X}.",
                        reply.ams_error
                    ),
                );
            }
            Err(error) => {
                endpoint["deviceInfo"] = json!({"outcome": "error", "error": error});
                stop_connection = true;
                if !cancelled.load(Ordering::Relaxed) {
                    add_probe_warning(
                        &mut finding,
                        format!("ADS AMS port {ams_port} ReadDeviceInfo exchange failed."),
                    );
                }
            }
        }
        replace_endpoint(&mut finding, ams_port, endpoint.clone());
        checkpoint(Some(finding.clone()));

        if cancelled.load(Ordering::Relaxed) {
            endpoint["readState"] = json!({"outcome": "cancelled"});
            replace_endpoint(&mut finding, ams_port, endpoint);
            set_incomplete(&mut finding, "cancelled");
            add_probe_warning(
                &mut finding,
                "ADS collection cancelled; completed results retained.".into(),
            );
            checkpoint(Some(finding.clone()));
            break;
        }
        if stop_connection {
            set_incomplete(&mut finding, "transport-error");
            checkpoint(Some(finding.clone()));
            break;
        }

        match request(
            &mut stream,
            target_net_id,
            source_net_id,
            ams_port,
            READ_STATE,
            cancelled,
        )
        .await
        {
            Ok(reply) if reply.ams_error == 0 => match AdsState::decode(&reply.data) {
                Ok(state) => {
                    endpoint["readState"] = json!({
                        "outcome": "success",
                        "adsState": state.ads,
                        "adsStateName": ads_state_name(state.ads),
                        "deviceState": state.device,
                        "responseHeaderHex": reply.response_header_hex,
                        "responseDataHex": reply.response_data_hex,
                    })
                }
                Err(AdsResponseError::InvalidLength) => {
                    endpoint["readState"] = json!({
                        "outcome": "invalid-response",
                        "responseHeaderHex": reply.response_header_hex,
                        "responseDataHex": reply.response_data_hex,
                    });
                    add_probe_warning(
                        &mut finding,
                        format!("ADS AMS port {ams_port} returned an invalid ReadState payload."),
                    );
                }
                Err(AdsResponseError::Service(code)) => {
                    endpoint["readState"] = json!({
                        "outcome": "ads-error",
                        "code": code,
                        "responseHeaderHex": reply.response_header_hex,
                        "responseDataHex": reply.response_data_hex,
                    });
                    add_probe_warning(
                        &mut finding,
                        format!("ADS AMS port {ams_port} ReadState returned 0x{code:08X}."),
                    );
                }
            },
            Ok(reply) => {
                endpoint["readState"] = json!({
                    "outcome": "ams-error",
                    "code": reply.ams_error,
                    "responseHeaderHex": reply.response_header_hex,
                    "responseDataHex": reply.response_data_hex,
                });
                add_probe_warning(
                    &mut finding,
                    format!(
                        "ADS AMS port {ams_port} ReadState returned AMS error 0x{:08X}.",
                        reply.ams_error
                    ),
                );
            }
            Err(error) => {
                if cancelled.load(Ordering::Relaxed) {
                    endpoint["readState"] = json!({"outcome": "cancelled"});
                } else {
                    endpoint["readState"] = json!({"outcome": "error", "error": error});
                    stop_connection = true;
                    add_probe_warning(
                        &mut finding,
                        format!("ADS AMS port {ams_port} ReadState exchange failed."),
                    );
                }
            }
        }
        replace_endpoint(&mut finding, ams_port, endpoint);
        checkpoint(Some(finding.clone()));
        if cancelled.load(Ordering::Relaxed) {
            mark_cancelled(&mut finding);
            checkpoint(Some(finding.clone()));
            break;
        }
        if stop_connection {
            set_incomplete(&mut finding, "transport-error");
            checkpoint(Some(finding.clone()));
            break;
        }
    }

    finding.raw["collectionComplete"] = json!(finding.raw["collectionStatus"] == "complete");
    checkpoint(Some(finding.clone()));
    Ok(Some(finding))
}

fn new_finding(net_id: [u8; 6], discovery: Value) -> Finding {
    Finding {
        source: Source::BeckhoffAds,
        fields: BTreeMap::from([("protocols".into(), json!(["beckhoff-ads"]))]),
        raw: json!({
            "protocol": "beckhoff-ads",
            "amsNetId": format_net_id(net_id),
            "discovery": discovery,
            "endpoints": [],
            "fieldSources": {},
            "collectionStatus": "complete",
            "collectionComplete": true,
        }),
        ports: Vec::new(),
        warnings: Vec::new(),
    }
}

fn add_device_info_raw(finding: &mut Finding, port: u16, info: &DeviceInfo) {
    if port != 851 && port != 801 {
        return;
    }
    let endpoint = json!({"amsPort": port, "name": info.name(), "version": info.version()});
    if let Some(items) = finding.raw["runtimeCandidates"].as_array_mut() {
        items.push(endpoint);
    } else {
        finding.raw["runtimeCandidates"] = json!([endpoint]);
    }
    if finding.raw.get("runtimePrimaryAmsPort").is_none() {
        if let Some(name) = info.name() {
            finding.fields.insert("runtimeName".into(), json!(name));
            finding.raw["fieldSources"]["runtimeName"] =
                json!({"amsPort": port, "command": "ReadDeviceInfo"});
        }
        finding
            .fields
            .insert("runtimeVersion".into(), json!(info.version()));
        finding.raw["fieldSources"]["runtimeVersion"] =
            json!({"amsPort": port, "command": "ReadDeviceInfo"});
        finding.raw["runtimePrimaryAmsPort"] = json!(port);
    }
}

pub(super) fn mark_cancelled(finding: &mut Finding) {
    if let Some(endpoints) = finding.raw["endpoints"].as_array_mut() {
        for endpoint in endpoints {
            for operation in ["deviceInfo", "readState"] {
                if endpoint[operation]["outcome"] == "pending"
                    || endpoint[operation]["outcome"] == "not-attempted"
                {
                    endpoint[operation]["outcome"] = json!("cancelled");
                }
            }
        }
    }
    set_incomplete(finding, "cancelled");
    add_probe_warning(
        finding,
        "ADS collection cancelled; completed results retained.".into(),
    );
}

fn replace_endpoint(finding: &mut Finding, port: u16, endpoint: Value) {
    if let Some(endpoints) = finding.raw["endpoints"].as_array_mut()
        && let Some(existing) = endpoints
            .iter_mut()
            .find(|existing| existing["amsPort"].as_u64() == Some(u64::from(port)))
    {
        *existing = endpoint;
    }
}

fn set_incomplete(finding: &mut Finding, status: &str) {
    finding.raw["collectionStatus"] = json!(status);
    finding.raw["collectionComplete"] = json!(false);
}

fn add_probe_warning(finding: &mut Finding, warning: String) {
    if !finding.warnings.contains(&warning) {
        finding.warnings.push(warning);
    }
}

fn ads_state_name(state: u16) -> &'static str {
    match state {
        0 => "invalid",
        1 => "idle",
        2 => "reset",
        3 => "init",
        4 => "start",
        5 => "run",
        6 => "stop",
        7 => "save-config",
        8 => "load-config",
        9 => "power-failure",
        10 => "power-good",
        11 => "error",
        12 => "shutdown",
        13 => "suspend",
        14 => "resume",
        15 => "config",
        16 => "reconfig",
        17 => "stopping",
        18 => "incompatible",
        19 => "exception",
        _ => "unknown",
    }
}

fn net_id_from_ipv4(ip: Ipv4Addr) -> [u8; 6] {
    let octets = ip.octets();
    [octets[0], octets[1], octets[2], octets[3], 1, 1]
}

fn format_net_id(net_id: [u8; 6]) -> String {
    net_id.map(|octet| octet.to_string()).join(".")
}

async fn discover(target: Ipv4Addr, cancelled: &AtomicBool) -> Result<Option<Discovery>, String> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .map_err(|_| "could not bind ADS discovery socket".to_string())?;
    let address = SocketAddrV4::new(target, ADS_UDP_PORT);
    socket
        .connect(address)
        .await
        .map_err(|_| "could not connect ADS discovery socket".to_string())?;
    let request = server_info_request();
    crate::traffic::wait().await;
    if cancelled.load(Ordering::Relaxed) {
        return Ok(None);
    }
    let deadline = Instant::now() + IO_TIMEOUT;
    timeout_at(deadline, socket.send(&request))
        .await
        .map_err(|_| "ADS discovery send timed out".to_string())?
        .map_err(|_| "ADS discovery send failed".to_string())?;
    let mut response = [0; MAX_UDP_RESPONSE + 1];
    let length = match timeout_at(deadline, socket.recv(&mut response)).await {
        Ok(Ok(length)) => length,
        Ok(Err(_)) | Err(_) => return Ok(None),
    };
    let bytes = &response[..length];
    let net_id = parse_server_info_response(bytes)?;
    Ok(Some(Discovery {
        net_id,
        response_hex: hex(bytes),
    }))
}

fn server_info_request() -> [u8; 24] {
    let mut request = [0; 24];
    request[..4].copy_from_slice(&UDP_COOKIE.to_le_bytes());
    request[4..8].copy_from_slice(&0_u32.to_le_bytes());
    request[8..12].copy_from_slice(&SERVER_INFO.to_le_bytes());
    // AmsAddr is eight zero bytes for SERVERINFO. The final word is the empty tag count.
    request[20..24].copy_from_slice(&0_u32.to_le_bytes());
    request
}

fn parse_server_info_response(bytes: &[u8]) -> Result<[u8; 6], String> {
    if bytes.len() < 24 || bytes.len() > MAX_UDP_RESPONSE {
        return Err("invalid ADS ServerInfo response length".into());
    }
    if u32::from_le_bytes(bytes[..4].try_into().map_err(|_| "truncated ADS cookie")?) != UDP_COOKIE
        || u32::from_le_bytes(
            bytes[4..8]
                .try_into()
                .map_err(|_| "truncated ADS invoke ID")?,
        ) != 0
        || u32::from_le_bytes(
            bytes[8..12]
                .try_into()
                .map_err(|_| "truncated ADS service ID")?,
        ) != (RESPONSE | SERVER_INFO)
    {
        return Err("uncorrelated ADS ServerInfo response".into());
    }
    let net_id = bytes[12..18]
        .try_into()
        .map_err(|_| "truncated ADS NetID")?;
    if net_id == [0; 6] {
        return Err("ADS ServerInfo returned the all-zero NetID sentinel".into());
    }
    let tag_count = u32::from_le_bytes(
        bytes[20..24]
            .try_into()
            .map_err(|_| "truncated ADS tag count")?,
    ) as usize;
    if tag_count > 64 {
        return Err("ADS ServerInfo tag count exceeds limit".into());
    }
    let mut offset = 24_usize;
    for _ in 0..tag_count {
        let header_end = offset.checked_add(4).ok_or("ADS tag offset overflow")?;
        let header = bytes
            .get(offset..header_end)
            .ok_or("truncated ADS ServerInfo tag")?;
        let length = u16::from_le_bytes([header[2], header[3]]) as usize;
        offset = header_end
            .checked_add(length)
            .ok_or("ADS tag length overflow")?;
        if offset > bytes.len() {
            return Err("truncated ADS ServerInfo tag value".into());
        }
    }
    if offset != bytes.len() {
        return Err("ADS ServerInfo response has trailing bytes".into());
    }
    Ok(net_id)
}

async fn request(
    stream: &mut TcpStream,
    target_net_id: [u8; 6],
    source_net_id: [u8; 6],
    target_port: u16,
    command: u16,
    cancelled: &AtomicBool,
) -> Result<AdsReply, String> {
    if cancelled.load(Ordering::Relaxed) {
        return Err("cancelled".into());
    }
    let invoke_id = NEXT_INVOKE_ID.fetch_add(1, Ordering::Relaxed).max(1);
    let source_port = 32_768;
    let header = AmsHeader {
        target_net_id,
        target_port,
        source_net_id,
        source_port,
        command,
        state_flags: AMS_REQUEST,
        data_length: 0,
        error_code: 0,
        invoke_id,
    };
    let mut frame = Vec::with_capacity(6 + AMS_HEADER_LENGTH);
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(&(AMS_HEADER_LENGTH as u32).to_le_bytes());
    frame.extend_from_slice(&header.encode());
    crate::traffic::wait().await;
    if cancelled.load(Ordering::Relaxed) {
        return Err("cancelled".into());
    }
    let deadline = Instant::now() + IO_TIMEOUT;
    timeout_at(deadline, stream.write_all(&frame))
        .await
        .map_err(|_| "ADS request write timed out".to_string())?
        .map_err(|_| "ADS request write failed".to_string())?;
    let response = read_frame(stream, deadline).await?;
    validate_response(&header, &response.0)?;
    Ok(AdsReply {
        ams_error: response.0.error_code,
        response_header_hex: hex(&response.0.encode()),
        response_data_hex: hex(&response.1),
        data: response.1,
    })
}

async fn read_frame(
    stream: &mut TcpStream,
    deadline: Instant,
) -> Result<(AmsHeader, Vec<u8>), String> {
    let mut prefix = [0; 6];
    timeout_at(deadline, stream.read_exact(&mut prefix))
        .await
        .map_err(|_| "ADS response prefix timed out".to_string())?
        .map_err(|_| "ADS response prefix truncated".to_string())?;
    if prefix[..2] != [0, 0] {
        return Err("invalid AMS/TCP reserved field".into());
    }
    let length = u32::from_le_bytes(
        prefix[2..6]
            .try_into()
            .map_err(|_| "invalid AMS/TCP length")?,
    ) as usize;
    if !(AMS_HEADER_LENGTH..=MAX_TCP_RESPONSE).contains(&length) {
        return Err("AMS/TCP response length is outside bounds".into());
    }
    let mut bytes = vec![0; length];
    timeout_at(deadline, stream.read_exact(&mut bytes))
        .await
        .map_err(|_| "ADS response body timed out".to_string())?
        .map_err(|_| "ADS response body truncated".to_string())?;
    let header = AmsHeader::decode(&bytes[..AMS_HEADER_LENGTH])?;
    let data_length = header.data_length as usize;
    if data_length != bytes.len() - AMS_HEADER_LENGTH {
        return Err("AMS/TCP and AMS data lengths disagree".into());
    }
    Ok((header, bytes[AMS_HEADER_LENGTH..].to_vec()))
}

fn validate_response(request: &AmsHeader, response: &AmsHeader) -> Result<(), String> {
    if response.target_net_id != request.source_net_id
        || response.target_port != request.source_port
        || response.source_net_id != request.target_net_id
        || response.source_port != request.target_port
        || response.command != request.command
        || response.state_flags != AMS_RESPONSE
        || response.invoke_id != request.invoke_id
    {
        return Err("uncorrelated AMS response".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    fn server_info_response(net_id: [u8; 6]) -> Vec<u8> {
        let mut response = Vec::from(UDP_COOKIE.to_le_bytes());
        response.extend(0_u32.to_le_bytes());
        response.extend((RESPONSE | SERVER_INFO).to_le_bytes());
        response.extend(net_id);
        response.extend(0_u16.to_le_bytes());
        response.extend(0_u32.to_le_bytes());
        response
    }

    fn info_response(header: AmsHeader) -> Vec<u8> {
        let mut data = Vec::from(0_u32.to_le_bytes());
        data.extend([3, 1]);
        data.extend(4_021_u16.to_le_bytes());
        data.extend(info_response_data()[8..].iter().copied());
        let header = AmsHeader {
            target_net_id: header.source_net_id,
            target_port: header.source_port,
            source_net_id: header.target_net_id,
            source_port: header.target_port,
            state_flags: AMS_RESPONSE,
            data_length: data.len() as u32,
            error_code: 0,
            ..header
        };
        tcp_frame(header, &data)
    }

    fn tcp_frame(header: AmsHeader, data: &[u8]) -> Vec<u8> {
        let body_length = AMS_HEADER_LENGTH + data.len();
        let mut frame = Vec::with_capacity(6 + body_length);
        frame.extend_from_slice(&[0, 0]);
        frame.extend_from_slice(&(body_length as u32).to_le_bytes());
        frame.extend_from_slice(&header.encode());
        frame.extend_from_slice(data);
        frame
    }

    #[test]
    fn parses_configured_netids_and_rejects_bad_ports() {
        let settings = ProbeSettings::from_config(
            Some("192.168.1.2.1.1"),
            &BTreeMap::from([("192.0.2.10".into(), "10.0.0.1.1.1".into())]),
            &[851, 801],
        )
        .unwrap();
        assert_eq!(settings.source_net_id, Some([192, 168, 1, 2, 1, 1]));
        assert_eq!(
            settings.target_net_ids[&Ipv4Addr::new(192, 0, 2, 10)],
            [10, 0, 0, 1, 1, 1]
        );
        assert!(ProbeSettings::from_config(Some("192.168.1.1"), &BTreeMap::new(), &[]).is_err());
        assert!(ProbeSettings::from_config(Some("0.0.0.0.0.0"), &BTreeMap::new(), &[]).is_err());
        assert!(ProbeSettings::from_config(None, &BTreeMap::new(), &[851, 851]).is_err());
        assert!(ProbeSettings::from_config(None, &BTreeMap::new(), &[0]).is_err());
        assert!(ProbeSettings::from_config(None, &BTreeMap::new(), &[1; 9]).is_err());
        assert!(
            ProbeSettings::from_config(
                None,
                &BTreeMap::from([("not-an-ip".into(), "1.2.3.4.5.6".into())]),
                &[]
            )
            .is_err()
        );
        assert!(
            ProbeSettings::from_config(
                None,
                &BTreeMap::from([
                    ("192.0.2.10".into(), "1.2.3.4.5.6".into()),
                    ("192.000.002.010".into(), "1.2.3.4.5.7".into())
                ]),
                &[],
            )
            .is_err()
        );
        let defaults = ProbeSettings::from_config(
            None,
            &BTreeMap::from([("192.0.2.10".into(), "1.2.3.4.5.6".into())]),
            &[],
        )
        .unwrap();
        assert_eq!(defaults.ports(), &DEFAULT_AMS_PORTS);

        let oversized = (0..=MAX_TARGET_NETIDS)
            .map(|ip| (Ipv4Addr::from(ip as u32).to_string(), "1.2.3.4.5.6".into()))
            .collect();
        assert!(ProbeSettings::from_config(None, &oversized, &[]).is_err());

        for invalid in ["1..3.4.5.6", "1.2.3.4.5.256", "1.2.3.4.5.6.7"] {
            assert!(ProbeSettings::from_config(Some(invalid), &BTreeMap::new(), &[]).is_err());
        }
    }

    #[test]
    fn decodes_only_exact_read_device_info_and_state_payloads() {
        let info = DeviceInfo::decode(&info_response_data()).unwrap();
        assert_eq!(info.name().as_deref(), Some("TwinCAT PLC 1"));
        assert_eq!(info.version(), "3.1.4021");
        let state = AdsState::decode(&[0, 0, 0, 0, 5, 0, 7, 0]).unwrap();
        assert_eq!(state.ads, 5);
        assert_eq!(state.device, 7);
        assert!(DeviceInfo::decode(&[0; 23]).is_err());
        assert!(AdsState::decode(&[0; 9]).is_err());
        assert!(DeviceInfo::decode(&[0; 3]).is_err());
        assert!(AdsState::decode(&[0; 3]).is_err());
        assert_eq!(
            DeviceInfo::decode(&1_u32.to_le_bytes()).unwrap_err(),
            AdsResponseError::Service(1),
        );
        assert_eq!(
            AdsState::decode(&1_u32.to_le_bytes()).unwrap_err(),
            AdsResponseError::Service(1),
        );

        let mut padded = info_response_data();
        padded[8..24].copy_from_slice(b"  Runtime name  ");
        assert_eq!(
            DeviceInfo::decode(&padded).unwrap().name().as_deref(),
            Some("Runtime name")
        );
        padded[8..24].fill(b' ');
        assert!(DeviceInfo::decode(&padded).unwrap().name().is_none());
        padded[8..24].fill(b'X');
        assert_eq!(
            DeviceInfo::decode(&padded).unwrap().name().as_deref(),
            Some("XXXXXXXXXXXXXXXX")
        );
    }

    #[test]
    fn state_names_cover_ads_state_values_and_unknown_codes() {
        let names = [
            "invalid",
            "idle",
            "reset",
            "init",
            "start",
            "run",
            "stop",
            "save-config",
            "load-config",
            "power-failure",
            "power-good",
            "error",
            "shutdown",
            "suspend",
            "resume",
            "config",
            "reconfig",
            "stopping",
            "incompatible",
            "exception",
        ];
        for (state, name) in names.into_iter().enumerate() {
            assert_eq!(ads_state_name(state as u16), name);
        }
        assert_eq!(ads_state_name(20), "unknown");
        assert_eq!(ads_state_name(u16::MAX), "unknown");
        assert_eq!(
            net_id_from_ipv4(Ipv4Addr::new(192, 0, 2, 10)),
            [192, 0, 2, 10, 1, 1]
        );
        assert_eq!(format_net_id([192, 0, 2, 10, 1, 1]), "192.0.2.10.1.1");
    }

    fn info_response_data() -> [u8; 24] {
        let mut data = [0; 24];
        data[4] = 3;
        data[5] = 1;
        data[6..8].copy_from_slice(&4_021_u16.to_le_bytes());
        data[8..21].copy_from_slice(b"TwinCAT PLC 1");
        data
    }

    #[test]
    fn validates_serverinfo_cookie_service_tags_and_netid() {
        let expected = [192, 0, 2, 10, 1, 1];
        let mut response = server_info_response(expected);
        assert_eq!(parse_server_info_response(&response).unwrap(), expected);
        response[20..24].copy_from_slice(&1_u32.to_le_bytes());
        response.extend(7_u16.to_le_bytes());
        response.extend(1_u16.to_le_bytes());
        response.push(0xaa);
        assert_eq!(parse_server_info_response(&response).unwrap(), expected);
        response.pop();
        assert!(parse_server_info_response(&response).is_err());
        let mut response = server_info_response(expected);
        response[0] ^= 1;
        assert!(parse_server_info_response(&response).is_err());
        let mut response = server_info_response(expected);
        response[4] = 1;
        assert!(parse_server_info_response(&response).is_err());
        let mut response = server_info_response(expected);
        response[8] = 0;
        assert!(parse_server_info_response(&response).is_err());
        assert!(parse_server_info_response(&server_info_response([0; 6])).is_err());
        assert!(parse_server_info_response(&vec![0; MAX_UDP_RESPONSE + 1]).is_err());
        let mut response = server_info_response(expected);
        response[20..24].copy_from_slice(&65_u32.to_le_bytes());
        assert!(parse_server_info_response(&response).is_err());
        let mut response = server_info_response(expected);
        response.push(0);
        assert!(parse_server_info_response(&response).is_err());
    }

    #[test]
    fn response_correlation_requires_reversed_addresses_and_matching_invoke() {
        let request = AmsHeader {
            target_net_id: [1, 2, 3, 4, 1, 1],
            target_port: 851,
            source_net_id: [192, 0, 2, 10, 1, 1],
            source_port: 32_768,
            command: READ_DEVICE_INFO,
            state_flags: AMS_REQUEST,
            data_length: 0,
            error_code: 0,
            invoke_id: 1,
        };
        let response = AmsHeader {
            target_net_id: request.source_net_id,
            target_port: request.source_port,
            source_net_id: request.target_net_id,
            source_port: request.target_port,
            state_flags: AMS_RESPONSE,
            ..request
        };
        assert!(validate_response(&request, &response).is_ok());
        assert!(
            validate_response(
                &request,
                &AmsHeader {
                    invoke_id: 2,
                    ..response
                }
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn reads_one_correlated_ads_device_info_frame() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut prefix = [0; 6];
            stream.read_exact(&mut prefix).await.unwrap();
            let mut body = vec![0; u32::from_le_bytes(prefix[2..].try_into().unwrap()) as usize];
            stream.read_exact(&mut body).await.unwrap();
            let request = AmsHeader::decode(&body[..AMS_HEADER_LENGTH]).unwrap();
            let response = info_response(request);
            stream.write_all(&response).await.unwrap();
        });
        let mut stream = TcpStream::connect(address).await.unwrap();
        let request = AmsHeader {
            target_net_id: [10, 0, 0, 1, 1, 1],
            target_port: 851,
            source_net_id: [127, 0, 0, 1, 1, 1],
            source_port: 32_768,
            command: READ_DEVICE_INFO,
            state_flags: AMS_REQUEST,
            data_length: 0,
            error_code: 0,
            invoke_id: 9,
        };
        stream.write_all(&tcp_frame(request, &[])).await.unwrap();
        let (header, data) = read_frame(&mut stream, Instant::now() + IO_TIMEOUT)
            .await
            .unwrap();
        validate_response(&request, &header).unwrap();
        let info = DeviceInfo::decode(&data).unwrap();
        assert_eq!(info.name().as_deref(), Some("TwinCAT PLC 1"));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn probe_collects_device_info_and_state_from_a_configured_target() {
        let _network = crate::network_test_lock().await;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, ADS_TCP_PORT))
            .await
            .unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            for expected_command in [READ_DEVICE_INFO, READ_STATE] {
                let mut prefix = [0; 6];
                stream.read_exact(&mut prefix).await.unwrap();
                let length = u32::from_le_bytes(prefix[2..].try_into().unwrap()) as usize;
                let mut body = vec![0; length];
                stream.read_exact(&mut body).await.unwrap();
                let request = AmsHeader::decode(&body[..AMS_HEADER_LENGTH]).unwrap();
                assert_eq!(request.command, expected_command);

                let response = if expected_command == READ_DEVICE_INFO {
                    info_response(request)
                } else {
                    let data = [0, 0, 0, 0, 5, 0, 7, 0];
                    let response = AmsHeader {
                        target_net_id: request.source_net_id,
                        target_port: request.source_port,
                        source_net_id: request.target_net_id,
                        source_port: request.target_port,
                        state_flags: AMS_RESPONSE,
                        data_length: data.len() as u32,
                        error_code: 0,
                        ..request
                    };
                    tcp_frame(response, &data)
                };
                stream.write_all(&response).await.unwrap();
            }
        });

        let target = Ipv4Addr::LOCALHOST;
        let settings = ProbeSettings {
            target_net_ids: BTreeMap::from([(target, [10, 0, 0, 1, 1, 1])]),
            ams_ports: vec![851],
            ..ProbeSettings::default()
        };
        let finding = probe(target, &settings, &AtomicBool::new(false), |_| {})
            .await
            .unwrap()
            .unwrap();

        assert_eq!(finding.fields["runtimeName"], "TwinCAT PLC 1");
        assert_eq!(finding.fields["runtimeVersion"], "3.1.4021");
        assert_eq!(
            finding.raw["endpoints"][0]["readState"]["adsStateName"],
            "run"
        );
        assert_eq!(finding.raw["collectionStatus"], "complete");
        assert_eq!(finding.raw["discovery"]["outcome"], "configured");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn probe_retains_a_configured_identity_when_tcp_is_refused() {
        let target = "127.0.0.2".parse().unwrap();
        let settings = ProbeSettings {
            target_net_ids: BTreeMap::from([(target, [10, 0, 0, 1, 1, 1])]),
            ..ProbeSettings::default()
        };

        let finding = probe(target, &settings, &AtomicBool::new(false), |_| {})
            .await
            .unwrap()
            .unwrap();

        assert_eq!(finding.raw["collectionStatus"], "tcp-connect-failed");
        assert!(finding.ports.is_empty());
        assert!(finding.warnings[0].contains("ADS TCP connection failed"));
    }

    #[tokio::test]
    async fn probe_cancellation_before_discovery_sends_no_request() {
        let settings = ProbeSettings::default();
        let cancelled = AtomicBool::new(true);

        assert!(
            probe(Ipv4Addr::LOCALHOST, &settings, &cancelled, |_| {})
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn probe_retains_server_info_when_cancelled_before_tcp_reads() {
        let _network = crate::network_test_lock().await;
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, ADS_UDP_PORT))
            .await
            .unwrap();
        let responder = tokio::spawn(async move {
            let mut request = [0; 64];
            let (length, peer) = socket.recv_from(&mut request).await.unwrap();
            assert_eq!(&request[..length], &server_info_request());
            socket
                .send_to(&server_info_response([192, 0, 2, 10, 1, 1]), peer)
                .await
                .unwrap();
        });
        let cancelled = AtomicBool::new(false);
        let mut checkpoints = 0;
        let finding = probe(
            Ipv4Addr::LOCALHOST,
            &ProbeSettings::default(),
            &cancelled,
            |_| {
                checkpoints += 1;
                if checkpoints == 1 {
                    cancelled.store(true, Ordering::Relaxed);
                }
            },
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(checkpoints, 2);
        assert_eq!(finding.raw["discovery"]["outcome"], "success");
        assert_eq!(finding.raw["collectionStatus"], "cancelled");
        assert_eq!(finding.ports.len(), 1);
        assert_eq!(finding.ports[0].port_id.as_deref(), Some("48899"));
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn probe_preserves_ads_and_payload_errors_then_stops_on_transport_loss() {
        let _network = crate::network_test_lock().await;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, ADS_TCP_PORT))
            .await
            .unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            for (port, command) in [
                (851, READ_DEVICE_INFO),
                (851, READ_STATE),
                (801, READ_DEVICE_INFO),
                (801, READ_STATE),
                (10_000, READ_DEVICE_INFO),
                (10_000, READ_STATE),
            ] {
                let mut prefix = [0; 6];
                stream.read_exact(&mut prefix).await.unwrap();
                let length = u32::from_le_bytes(prefix[2..].try_into().unwrap()) as usize;
                let mut body = vec![0; length];
                stream.read_exact(&mut body).await.unwrap();
                let request = AmsHeader::decode(&body[..AMS_HEADER_LENGTH]).unwrap();
                assert_eq!((request.target_port, request.command), (port, command));
                if port == 10_000 && command == READ_STATE {
                    return;
                }
                let (ams_error, data): (u32, &[u8]) = match (port, command) {
                    (851, READ_DEVICE_INFO) => (0, &1_u32.to_le_bytes()),
                    (851, READ_STATE) => (0, &0_u32.to_le_bytes()),
                    (801, READ_DEVICE_INFO) => (0x1234, &[]),
                    (801, READ_STATE) => (0, &2_u32.to_le_bytes()),
                    (10_000, READ_DEVICE_INFO) => (0, &[]),
                    _ => unreachable!(),
                };
                let response = AmsHeader {
                    target_net_id: request.source_net_id,
                    target_port: request.source_port,
                    source_net_id: request.target_net_id,
                    source_port: request.target_port,
                    state_flags: AMS_RESPONSE,
                    data_length: data.len() as u32,
                    error_code: ams_error,
                    ..request
                };
                stream.write_all(&tcp_frame(response, data)).await.unwrap();
            }
        });
        let target = Ipv4Addr::LOCALHOST;
        let settings = ProbeSettings {
            source_net_id: Some([10, 0, 0, 1, 1, 1]),
            target_net_ids: BTreeMap::from([(target, [10, 0, 0, 2, 1, 1])]),
            ams_ports: vec![851, 801, 10_000],
        };

        let finding = probe(target, &settings, &AtomicBool::new(false), |_| {})
            .await
            .unwrap()
            .unwrap();

        let endpoints = finding.raw["endpoints"].as_array().unwrap();
        assert_eq!(endpoints[0]["deviceInfo"]["outcome"], "ads-error");
        assert_eq!(endpoints[0]["readState"]["outcome"], "invalid-response");
        assert_eq!(endpoints[1]["deviceInfo"]["outcome"], "ams-error");
        assert_eq!(endpoints[1]["readState"]["outcome"], "ads-error");
        assert_eq!(endpoints[2]["deviceInfo"]["outcome"], "invalid-response");
        assert_eq!(endpoints[2]["readState"]["outcome"], "error");
        assert_eq!(finding.raw["collectionStatus"], "transport-error");
        assert!(
            finding
                .warnings
                .iter()
                .any(|warning| warning.contains("ReadState exchange failed"))
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn read_frame_rejects_reserved_oversized_and_truncated_frames() {
        async fn read_error(frame: Vec<u8>) -> String {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                stream.write_all(&frame).await.unwrap();
                stream.shutdown().await.unwrap();
            });
            let mut stream = TcpStream::connect(address).await.unwrap();
            let error = read_frame(&mut stream, Instant::now() + IO_TIMEOUT)
                .await
                .unwrap_err();
            server.await.unwrap();
            error
        }

        assert!(
            read_error([vec![1, 0], 32_u32.to_le_bytes().to_vec(), vec![0; 32]].concat())
                .await
                .contains("reserved field")
        );
        assert!(
            read_error(
                [
                    vec![0; 2],
                    (MAX_TCP_RESPONSE as u32 + 1).to_le_bytes().to_vec()
                ]
                .concat()
            )
            .await
            .contains("outside bounds")
        );
        assert!(read_error(vec![0, 0]).await.contains("prefix truncated"));
        assert!(
            read_error([vec![0; 2], 32_u32.to_le_bytes().to_vec(), vec![0; 8]].concat())
                .await
                .contains("body truncated")
        );
        let header = AmsHeader {
            target_net_id: [1; 6],
            target_port: 851,
            source_net_id: [2; 6],
            source_port: 32_768,
            command: READ_DEVICE_INFO,
            state_flags: AMS_RESPONSE,
            data_length: 1,
            error_code: 0,
            invoke_id: 1,
        };
        assert!(
            read_error(
                [
                    vec![0; 2],
                    32_u32.to_le_bytes().to_vec(),
                    header.encode().to_vec()
                ]
                .concat()
            )
            .await
            .contains("lengths disagree")
        );
    }
}
