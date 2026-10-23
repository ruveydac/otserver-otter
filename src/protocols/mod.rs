use crate::contract::{Observation, Port, Source, hex};
use serde_json::Value;
use std::collections::BTreeMap;
use std::future::Future;
use std::net::Ipv4Addr;
use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};

mod ads;
mod bacnet;
mod dnp3;
mod enip;
mod fins;
mod fox;
mod http;
mod iec61850;
mod netbios;
mod ntlm;
mod opcua;
mod rpc;
mod s7;
mod smb;
mod smb1;

pub use ads::ProbeSettings as AdsSettings;
pub use opcua::{
    Credential as OpcuaCredential, Credentials as OpcuaCredentials, ProbeSettings as OpcuaSettings,
};

const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

pub struct ProbeResult {
    pub observations: Vec<Observation>,
    pub ports: Vec<Port>,
    pub warnings: Vec<String>,
    pub outcomes: Vec<ProbeOutcome>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeStatus {
    Success,
    Partial,
    NoResponse,
    Failure,
    Cancelled,
}

impl ProbeStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Success => "SUCCESS",
            Self::Partial => "PARTIAL",
            Self::NoResponse => "NO_RESPONSE",
            Self::Failure => "FAIL",
            Self::Cancelled => "CANCELLED",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeOutcome {
    pub source: Source,
    pub protocol: &'static str,
    pub status: ProbeStatus,
    pub endpoint: String,
    pub timeout: &'static str,
    pub stage: &'static str,
    pub messages: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Selection {
    pub s7: bool,
    pub enip: bool,
    pub bacnet: bool,
    pub fins: bool,
    pub fox: bool,
    pub dnp3: bool,
    pub iec61850: bool,
    pub netbios: bool,
    pub smb: bool,
    pub rpc: bool,
    pub http: bool,
    pub opcua: bool,
    pub ads: bool,
}

impl Selection {
    pub fn any(self) -> bool {
        self.s7
            || self.enip
            || self.bacnet
            || self.fins
            || self.fox
            || self.dnp3
            || self.iec61850
            || self.netbios
            || self.smb
            || self.rpc
            || self.http
            || self.opcua
            || self.ads
    }

    pub fn labels(self) -> Vec<&'static str> {
        [
            (self.s7, "S7"),
            (self.enip, "EtherNet/IP"),
            (self.bacnet, "BACnet"),
            (self.fins, "FINS"),
            (self.fox, "Fox"),
            (self.dnp3, "DNP3"),
            (self.iec61850, "IEC 61850"),
            (self.netbios, "NetBIOS"),
            (self.smb, "SMB"),
            (self.rpc, "RPC"),
            (self.http, "HTTP"),
            (self.http, "HTTPS"),
            (self.opcua, "OPC UA"),
            (self.ads, "Beckhoff ADS"),
        ]
        .into_iter()
        .filter_map(|(enabled, label)| enabled.then_some(label))
        .collect()
    }
}

impl Default for Selection {
    fn default() -> Self {
        Self {
            s7: true,
            enip: true,
            bacnet: true,
            fins: true,
            fox: true,
            dnp3: true,
            iec61850: true,
            netbios: true,
            smb: true,
            rpc: true,
            http: true,
            opcua: true,
            ads: true,
        }
    }
}

#[derive(Clone)]
struct Finding {
    source: Source,
    fields: BTreeMap<String, Value>,
    raw: Value,
    ports: Vec<Port>,
    warnings: Vec<String>,
}

pub async fn scan(
    target: Ipv4Addr,
    mac: Option<&str>,
    selection: Selection,
    opcua: &opcua::ProbeSettings,
) -> ProbeResult {
    scan_with_cancellation(
        target,
        mac,
        selection,
        opcua,
        &AdsSettings::default(),
        &AtomicBool::new(false),
    )
    .await
}

pub async fn scan_with_cancellation(
    target: Ipv4Addr,
    mac: Option<&str>,
    selection: Selection,
    opcua: &opcua::ProbeSettings,
    ads_settings: &AdsSettings,
    cancelled: &AtomicBool,
) -> ProbeResult {
    if selection.any() {
        crate::traffic::wait().await;
    }
    let completed = Mutex::new(Vec::new());
    let probes = async {
        tokio::join!(
            collect_probe(0, probe_if(selection.s7, s7::probe(target)), &completed),
            collect_probe(1, probe_if(selection.enip, enip::probe(target)), &completed),
            collect_probe(
                2,
                probe_if(selection.bacnet, bacnet::probe(target)),
                &completed
            ),
            collect_probe(3, probe_if(selection.fins, fins::probe(target)), &completed),
            collect_probe(4, probe_if(selection.fox, fox::probe(target)), &completed),
            collect_probe(5, probe_if(selection.dnp3, dnp3::probe(target)), &completed),
            collect_probe(
                6,
                probe_if(selection.iec61850, iec61850::probe(target, iec61850::PORT)),
                &completed
            ),
            collect_probe(
                7,
                probe_if(selection.netbios, netbios::probe(target)),
                &completed
            ),
            collect_probe(8, probe_if(selection.smb, smb::probe(target)), &completed),
            collect_probe(9, probe_if(selection.rpc, rpc::probe(target)), &completed),
            collect_probe(
                10,
                probe_if(selection.opcua, opcua::probe(target, opcua)),
                &completed
            ),
            collect_probe(
                11,
                probe_if(selection.http, http::probe(target, 80, false)),
                &completed
            ),
            collect_probe(
                12,
                probe_if(selection.http, http::probe(target, 443, true)),
                &completed
            ),
            collect_probe(
                13,
                async {
                    let checkpoint = |finding| store_probe_result(13, Ok(finding), &completed);
                    probe_if(
                        selection.ads,
                        ads::probe(target, ads_settings, cancelled, checkpoint),
                    )
                    .await
                },
                &completed,
            ),
        );
    };
    let cancellation = async {
        while !cancelled.load(Ordering::Relaxed) {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    };
    tokio::select! {biased; () = cancellation => {}, () = probes => {}}
    let mut completed = completed
        .into_inner()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut take = |index| {
        completed
            .iter()
            .position(|(key, _)| *key == index)
            .map(|position| completed.swap_remove(position).1)
            .unwrap_or(Ok(None))
    };
    let (s7, enip, bacnet, fins, fox, dnp3, iec61850, netbios, smb, rpc, ua) = (
        take(0),
        take(1),
        take(2),
        take(3),
        take(4),
        take(5),
        take(6),
        take(7),
        take(8),
        take(9),
        take(10),
    );
    let mut observations = Vec::new();
    let mut ports = Vec::new();
    let mut warnings = Vec::new();
    if cancelled.load(Ordering::Relaxed) {
        warnings.push("Protocol collection cancelled; completed findings retained.".into());
    }
    let mut outcomes = Vec::new();
    let results = [
        (selection.s7, Source::S7, "s7", s7),
        (selection.enip, Source::EthernetIp, "ethernet-ip", enip),
        (selection.bacnet, Source::Bacnet, "bacnet", bacnet),
        (selection.fins, Source::OmronFins, "omron-fins", fins),
        (selection.fox, Source::NiagaraFox, "niagara-fox", fox),
        (selection.dnp3, Source::Dnp3, "dnp3", dnp3),
        (selection.iec61850, Source::Iec61850, "iec61850", iec61850),
        (selection.netbios, Source::Netbios, "netbios", netbios),
        (selection.smb, Source::OsFingerprint, "smb", smb),
        (selection.rpc, Source::OsFingerprint, "rpc", rpc),
        (selection.opcua, Source::OpcUa, "opc-ua", ua),
        (selection.http, Source::Http, "http", take(11)),
        (selection.http, Source::Https, "https", take(12)),
        (selection.ads, Source::BeckhoffAds, "beckhoff-ads", take(13)),
    ];
    for (enabled, source, protocol, mut result) in results {
        if !enabled {
            continue;
        }
        if protocol == "beckhoff-ads"
            && cancelled.load(Ordering::Relaxed)
            && let Ok(Some(finding)) = &mut result
        {
            ads::mark_cancelled(finding);
        }
        let endpoint = endpoint(protocol, target, opcua, ads_settings);
        let (status, stage, messages) = match &result {
            Ok(Some(finding))
                if protocol == "beckhoff-ads" && cancelled.load(Ordering::Relaxed) =>
            {
                (
                    ProbeStatus::Cancelled,
                    "collection",
                    finding.warnings.clone(),
                )
            }
            Ok(Some(finding))
                if finding
                    .warnings
                    .iter()
                    .all(|warning| informational_warning(warning)) =>
            {
                (ProbeStatus::Success, "probe", finding.warnings.clone())
            }
            Ok(Some(finding)) => (ProbeStatus::Partial, "collection", finding.warnings.clone()),
            Ok(None) if cancelled.load(Ordering::Relaxed) => (
                ProbeStatus::Cancelled,
                "probe",
                vec!["Probe cancelled before a response was collected.".into()],
            ),
            Ok(None) => (
                ProbeStatus::NoResponse,
                "response",
                vec![format!(
                    "No response received from {endpoint} (timeout {}).",
                    timeout(protocol)
                )],
            ),
            Err(error) if connection_refused(error) || timed_out(error) || peer_closed(error) => (
                ProbeStatus::NoResponse,
                if connection_refused(error) {
                    "connect"
                } else {
                    "response"
                },
                vec![error.clone()],
            ),
            Err(error) if cancelled.load(Ordering::Relaxed) && error.contains("cancelled") => (
                ProbeStatus::Cancelled,
                diagnostic_stage(protocol, error),
                vec![error.clone()],
            ),
            Err(error) => (
                ProbeStatus::Failure,
                diagnostic_stage(protocol, error),
                vec![error.clone()],
            ),
        };
        outcomes.push(ProbeOutcome {
            source,
            protocol,
            status,
            endpoint,
            timeout: timeout(protocol),
            stage,
            messages,
        });
        match result {
            Ok(Some(mut finding)) => {
                let observed_at = crate::now();
                finding
                    .fields
                    .insert("ipAddress".into(), serde_json::json!(target));
                finding
                    .fields
                    .insert("lastSeen".into(), serde_json::json!(observed_at));
                if let Some(mac) = mac {
                    finding
                        .fields
                        .insert("macAddress".into(), serde_json::json!(mac));
                }
                finding
                    .fields
                    .entry("status".into())
                    .or_insert_with(|| serde_json::json!("online"));
                if let Value::Object(raw) = &mut finding.raw {
                    raw.insert("acquisition".into(), serde_json::json!({"mechanism": "active-query", "messageRole": "response", "transportPeer": target}));
                    raw.insert(
                        "observationId".into(),
                        serde_json::json!(uuid::Uuid::new_v4().to_string()),
                    );
                    raw.insert(
                        "subject".into(),
                        mac.map_or_else(
                            || serde_json::json!({ "kind": "endpoint", "ipAddress": target }),
                            |mac| serde_json::json!({ "kind": "device", "macAddress": mac }),
                        ),
                    );
                    raw.insert(
                        "listeners".into(),
                        Value::Array(
                            finding
                                .ports
                                .iter()
                                .map(|port| {
                                    let (transport, number) = port
                                        .key
                                        .split_once(':')
                                        .unwrap_or((port.source.as_str(), ""));
                                    serde_json::json!({
                                        "address": target,
                                        "transport": transport,
                                        "port": number.parse::<u16>().ok(),
                                        "route": [],
                                    })
                                })
                                .collect(),
                        ),
                    );
                    if let Some(serial) = finding.fields.get("serialNumber") {
                        raw.entry("serialClaim").or_insert_with(|| {
                            serde_json::json!({
                                "scope": "device",
                                "issuer": finding.fields.get("vendor"),
                                "original": serial,
                                "encoding": "protocol-text",
                                "normalizationVersion": 1,
                            })
                        });
                    }
                }
                ports.append(&mut finding.ports);
                observations.push(Observation {
                    source: finding.source,
                    observed_at,
                    ip_address: Some(target.to_string()),
                    mac_address: mac.map(str::to_owned),
                    fields: finding.fields,
                    raw: finding.raw,
                    warnings: finding.warnings,
                });
            }
            Ok(None) => {}
            Err(error) => warnings.push(error),
        }
    }
    ProbeResult {
        observations,
        ports,
        warnings,
        outcomes,
    }
}

fn endpoint(
    protocol: &str,
    target: Ipv4Addr,
    opcua: &opcua::ProbeSettings,
    ads: &AdsSettings,
) -> String {
    match protocol {
        "s7" => "tcp/102 (S7 TSAP candidates)".into(),
        "ethernet-ip" => "tcp+udp/44818".into(),
        "bacnet" => "udp/47808".into(),
        "omron-fins" => "tcp+udp/9600".into(),
        "niagara-fox" => "tcp/1911,4911".into(),
        "dnp3" => "tcp/20000".into(),
        "iec61850" => "tcp/102 (MMS)".into(),
        "netbios" => "udp/137".into(),
        "smb" => "tcp/445".into(),
        "rpc" => "tcp/135".into(),
        "opc-ua" => format!(
            "opc.tcp/{}",
            if opcua.ports.is_empty() {
                "4840,4841,48400".to_owned()
            } else {
                opcua
                    .ports
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            }
        ),
        "http" => "tcp/80".into(),
        "https" => "tcp/443".into(),
        "beckhoff-ads" if ads.target_net_ids.contains_key(&target) => {
            "tcp/48898 (AMS; configured target NetID)".into()
        }
        "beckhoff-ads" => "udp/48899 and tcp/48898 (AMS)".into(),
        _ => "configured endpoint".into(),
    }
}

fn timeout(protocol: &str) -> &'static str {
    match protocol {
        "s7" => "2s per TSAP connect; 2s per response; 4s per SZL exchange",
        "dnp3" => "2s connect; up to 4s per response exchange",
        "opc-ua" => "4s endpoint request; 5s session; 4s per service request",
        "beckhoff-ads" => "2s per UDP/TCP exchange",
        _ => "2s",
    }
}

fn informational_warning(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    message.contains("unencrypted channel") || message.contains("differs from")
}

fn diagnostic_stage(protocol: &str, message: &str) -> &'static str {
    let message = message.to_ascii_lowercase();
    if message.contains("tcp connection")
        || message.contains("connection to tcp")
        || message.contains("connect timed out")
    {
        return "connect";
    }
    match protocol {
        "s7" if message.contains("setup communication") => "setup-communication",
        "s7" if message.contains("szl") => "szl-read",
        "s7" if message.contains("tsap") || message.contains("cotp") => "tsap-negotiate",
        "ethernet-ip" if message.contains("cip") => "cip-read",
        "ethernet-ip" => "list-identity",
        "bacnet" if message.contains("property") => "read-property",
        "bacnet" => "device-instance",
        "omron-fins" if message.contains("node-address") => "node-address-negotiate",
        "omron-fins" => "fins-command",
        "niagara-fox" if message.contains("tls") => "tls-hello",
        "niagara-fox" => "fox-hello",
        "dnp3" => "dnp3-read",
        "iec61850" if message.contains("directory") => "mms-directory",
        "iec61850" => "mms-read",
        "netbios" => "node-status",
        "smb" if message.contains("identity") || message.contains("challenge") => "session-setup",
        "smb" => "negotiate",
        "rpc" => "endpoint-mapper-bind",
        "opc-ua" if message.contains("endpoint") => "get-endpoints",
        "opc-ua" if message.contains("session") || message.contains("authentication") => {
            "activate-session"
        }
        "opc-ua" if message.contains("buildinfo") => "read-build-info",
        "opc-ua" if message.contains("asset") || message.contains("alias") => "asset-discovery",
        "opc-ua" => "opc-ua-service",
        "http" | "https" if message.contains("body") => "read-response-body",
        "http" | "https" => "get-root",
        "beckhoff-ads" if message.contains("readstate") => "read-state",
        "beckhoff-ads" if message.contains("readdeviceinfo") => "read-device-info",
        "beckhoff-ads" => "ams-exchange",
        _ => "probe",
    }
}

fn connection_refused(message: &str) -> bool {
    message.to_ascii_lowercase().contains("connection refused")
}

fn timed_out(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    message.contains("timed out") || message.contains("timeout")
}

fn peer_closed(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    message.contains("connection reset")
        || message.contains("connection closed")
        || message.contains("peer closed")
}

type CompletedProbes = Mutex<Vec<(usize, Result<Option<Finding>, String>)>>;

async fn collect_probe(
    index: usize,
    probe: impl Future<Output = Result<Option<Finding>, String>>,
    completed: &CompletedProbes,
) {
    store_probe_result(index, probe.await, completed);
}

fn store_probe_result(
    index: usize,
    result: Result<Option<Finding>, String>,
    completed: &CompletedProbes,
) {
    let mut completed = completed
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some((_, current)) = completed.iter_mut().find(|(key, _)| *key == index) {
        *current = result;
    } else {
        completed.push((index, result));
    }
}

async fn probe_if(
    enabled: bool,
    probe: impl Future<Output = Result<Option<Finding>, String>>,
) -> Result<Option<Finding>, String> {
    if enabled { probe.await } else { Ok(None) }
}

fn port(protocol: &str, number: u16, source: Source, raw: Value) -> Port {
    Port {
        key: format!("{protocol}:{number}"),
        source: source.label().into(),
        interface_key: None,
        port_id: Some(number.to_string()),
        description: Some(source.label().into()),
        mac_address: None,
        vlans: vec![],
        raw,
    }
}

fn text(bytes: &[u8]) -> Option<String> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    let value = String::from_utf8_lossy(&bytes[..end]).trim().to_owned();
    (!value.is_empty()).then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, UdpSocket};

    // Windows itself can answer SMB, RPC, and NetBIOS on loopback, so only a
    // Linux loopback target is genuinely empty.
    fn loopback_selection() -> Selection {
        Selection {
            netbios: !cfg!(windows),
            smb: !cfg!(windows),
            rpc: !cfg!(windows),
            http: false,
            ads: false,
            ..Selection::default()
        }
    }

    #[tokio::test]
    async fn empty_loopback_scan_is_safe() {
        let _network = crate::network_test_lock().await;
        let selection = loopback_selection();
        let result = scan(
            Ipv4Addr::LOCALHOST,
            Some("00:11:22:33:44:55"),
            selection,
            &opcua::ProbeSettings::default(),
        )
        .await;
        assert!(result.observations.is_empty());
        assert!(result.ports.is_empty());
        assert_eq!(result.outcomes.len(), selection.labels().len());
        assert_eq!(
            result
                .outcomes
                .iter()
                .any(|outcome| outcome.protocol == "smb"),
            selection.smb
        );
        assert_eq!(
            result
                .outcomes
                .iter()
                .any(|outcome| outcome.protocol == "rpc"),
            selection.rpc
        );
        assert!(result.outcomes.iter().all(|outcome| {
            matches!(
                outcome.status,
                ProbeStatus::NoResponse | ProbeStatus::Failure
            ) && !outcome.messages.is_empty()
        }));
        assert!(
            result
                .outcomes
                .iter()
                .filter(|outcome| outcome.status == ProbeStatus::NoResponse)
                .all(|outcome| {
                    !outcome.messages.is_empty()
                        && (!outcome.messages[0].starts_with("No response received")
                            || outcome.messages[0].contains(&outcome.endpoint)
                                && outcome.messages[0].contains(outcome.timeout))
                })
        );
        assert!(text(b"  value\0ignored").as_deref() == Some("value"));
        assert_eq!(text(b" \0"), None);
        assert_eq!(hex(&[0xaa, 0x01]), "AA01");
    }

    #[tokio::test]
    async fn disabled_protocols_do_not_probe() {
        let selection = Selection {
            s7: false,
            enip: false,
            bacnet: false,
            fins: false,
            fox: false,
            dnp3: false,
            iec61850: false,
            netbios: false,
            smb: false,
            rpc: false,
            http: false,
            opcua: false,
            ads: false,
        };
        assert!(!selection.any());
        assert!(selection.labels().is_empty());
        let result = scan(
            Ipv4Addr::LOCALHOST,
            Some("00:11:22:33:44:55"),
            selection,
            &opcua::ProbeSettings::default(),
        )
        .await;
        assert!(result.observations.is_empty());
        assert!(result.ports.is_empty());
        assert!(result.warnings.is_empty());
        assert!(result.outcomes.is_empty());
    }

    #[tokio::test]
    async fn cancellation_retains_completed_protocols_while_dropping_silent_ones() {
        let _network = crate::network_test_lock().await;
        let fox = TcpListener::bind((Ipv4Addr::LOCALHOST, 1911))
            .await
            .unwrap();
        let fox_alt = TcpListener::bind((Ipv4Addr::LOCALHOST, 4911))
            .await
            .unwrap();
        let _silent = UdpSocket::bind((Ipv4Addr::LOCALHOST, 47808)).await.unwrap();
        let cancelled = AtomicBool::new(false);
        let responder = async {
            for listener in [&fox, &fox_alt] {
                let (mut stream, _) = listener.accept().await.unwrap();
                let hello = b"fox a 1 -1 fox hello\n{\nfox.version=s:1.0\nid=i:1\n};;\n";
                let mut request = vec![0; hello.len()];
                stream.read_exact(&mut request).await.unwrap();
                assert_eq!(request, hello);
                stream
                    .write_all(b"fox a 0\n{\nhostName=s:PLC\n};;\n")
                    .await
                    .unwrap();
                // Both client connections must close before cancelling: a sent reply
                // or a short sleep does not establish that the whole probe completed.
                assert_eq!(stream.read(&mut [0]).await.unwrap(), 0);
            }
            cancelled.store(true, Ordering::Relaxed);
        };
        let selection = Selection {
            s7: false,
            enip: false,
            bacnet: true,
            fins: false,
            fox: true,
            dnp3: false,
            iec61850: false,
            netbios: false,
            smb: false,
            rpc: false,
            http: false,
            opcua: false,
            ads: false,
        };
        let settings = opcua::ProbeSettings::default();
        let ads_settings = AdsSettings::default();
        let (result, ()) = tokio::time::timeout(TIMEOUT, async {
            tokio::join!(
                scan_with_cancellation(
                    Ipv4Addr::LOCALHOST,
                    None,
                    selection,
                    &settings,
                    &ads_settings,
                    &cancelled,
                ),
                responder
            )
        })
        .await
        .expect("scan did not cancel before the silent probe timeout");
        assert_eq!(result.observations.len(), 1);
        assert_eq!(result.observations[0].source, Source::NiagaraFox);
        assert_eq!(result.observations[0].fields["name"], "PLC");
        assert_eq!(result.ports.len(), 2);
        assert_eq!(result.outcomes[0].status, ProbeStatus::Cancelled);
        assert_eq!(result.outcomes[1].protocol, "niagara-fox");
        assert_eq!(result.outcomes[1].status, ProbeStatus::Success);
        assert!(
            result
                .warnings
                .iter()
                .any(|warning| warning.contains("cancelled"))
        );
    }

    #[tokio::test]
    async fn ads_cancellation_retains_completed_device_info_before_state_reply() {
        let _network = crate::network_test_lock().await;
        const TCP_PORT: u16 = 48_898;
        const UDP_PORT: u16 = 48_899;
        const COOKIE: u32 = 0x7114_6603;
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, UDP_PORT))
            .await
            .unwrap();
        let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, TCP_PORT))
            .await
            .unwrap();
        let cancelled = AtomicBool::new(false);
        let responder_cancelled = &cancelled;
        let responder = async {
            let mut request = [0; 24];
            let (length, peer) = udp.recv_from(&mut request).await.unwrap();
            assert_eq!(length, request.len());
            let mut discovery = Vec::from(COOKIE.to_le_bytes());
            discovery.extend(0_u32.to_le_bytes());
            discovery.extend(0x8000_0001_u32.to_le_bytes());
            discovery.extend([127, 0, 0, 1, 1, 1]);
            discovery.extend(0_u16.to_le_bytes());
            discovery.extend(0_u32.to_le_bytes());
            udp.send_to(&discovery, peer).await.unwrap();

            let (mut stream, _) = tcp.accept().await.unwrap();
            let mut prefix = [0; 6];
            stream.read_exact(&mut prefix).await.unwrap();
            let frame_length = u32::from_le_bytes(prefix[2..6].try_into().unwrap()) as usize;
            let mut request = vec![0; frame_length];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(u16::from_le_bytes(request[16..18].try_into().unwrap()), 1);

            let mut data = Vec::from(0_u32.to_le_bytes());
            data.extend([3, 1]);
            data.extend(4021_u16.to_le_bytes());
            data.extend(b"Test PLC".iter().copied());
            data.resize(24, 0);
            let mut frame = prefix.to_vec();
            frame.extend_from_slice(&request);
            let response = ads_test_response(&frame, &data);
            stream.write_all(&response).await.unwrap();

            stream.read_exact(&mut prefix).await.unwrap();
            let frame_length = u32::from_le_bytes(prefix[2..6].try_into().unwrap()) as usize;
            let mut request = vec![0; frame_length];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(u16::from_le_bytes(request[16..18].try_into().unwrap()), 4);
            responder_cancelled.store(true, Ordering::Relaxed);
        };
        let selection = Selection {
            s7: false,
            enip: false,
            bacnet: false,
            fins: false,
            fox: false,
            dnp3: false,
            iec61850: false,
            netbios: false,
            smb: false,
            rpc: false,
            http: false,
            opcua: false,
            ads: true,
        };
        let settings = opcua::ProbeSettings::default();
        let ads_settings = AdsSettings::from_config(None, &BTreeMap::new(), &[851]).unwrap();
        let (result, ()) = tokio::join!(
            scan_with_cancellation(
                Ipv4Addr::LOCALHOST,
                Some("00:11:22:33:44:55"),
                selection,
                &settings,
                &ads_settings,
                &cancelled,
            ),
            responder,
        );
        assert_eq!(result.observations.len(), 1);
        let observation = &result.observations[0];
        assert_eq!(observation.source, Source::BeckhoffAds);
        assert_eq!(observation.fields["runtimeName"], "Test PLC");
        assert_eq!(observation.fields["runtimeVersion"], "3.1.4021");
        assert_eq!(observation.raw["runtimePrimaryAmsPort"], 851);
        assert_eq!(observation.raw["collectionStatus"], "cancelled");
        assert_eq!(
            observation.raw["endpoints"][0]["readState"]["outcome"],
            "cancelled"
        );
    }

    fn ads_test_response(request: &[u8], data: &[u8]) -> Vec<u8> {
        let request_header = &request[6..38];
        let mut header = Vec::from(&request_header[8..14]);
        header.extend_from_slice(&request_header[14..16]);
        header.extend_from_slice(&request_header[..6]);
        header.extend_from_slice(&request_header[6..8]);
        header.extend_from_slice(&request_header[16..18]);
        header.extend(5_u16.to_le_bytes());
        header.extend((data.len() as u32).to_le_bytes());
        header.extend(0_u32.to_le_bytes());
        header.extend_from_slice(&request_header[28..32]);
        let body_length = header.len() + data.len();
        let mut frame = vec![0, 0];
        frame.extend((body_length as u32).to_le_bytes());
        frame.extend(header);
        frame.extend_from_slice(data);
        frame
    }

    #[tokio::test]
    async fn loopback_scan_collects_findings_and_protocol_errors() {
        let _network = crate::network_test_lock().await;
        let fox = TcpListener::bind((Ipv4Addr::LOCALHOST, 1911))
            .await
            .unwrap();
        let fox_task = tokio::spawn(async move {
            let (mut stream, _) = fox.accept().await.unwrap();
            let mut request = [0; 128];
            assert!(stream.read(&mut request).await.unwrap() > 0);
            stream
                .write_all(b"fox a 0\n{\nhostName=s:station\n};;\n")
                .await
                .unwrap();
        });
        let bacnet = UdpSocket::bind((Ipv4Addr::LOCALHOST, 47808)).await.unwrap();
        let bacnet_task = tokio::spawn(async move {
            let mut request = [0; 17];
            let (_, peer) = bacnet.recv_from(&mut request).await.unwrap();
            bacnet.send_to(&[0; 9], peer).await.unwrap();
        });
        let result = scan(
            Ipv4Addr::LOCALHOST,
            None,
            loopback_selection(),
            &opcua::ProbeSettings::default(),
        )
        .await;
        assert_eq!(result.observations.len(), 1);
        assert_eq!(result.observations[0].fields["name"], "station");
        assert_eq!(result.observations[0].mac_address, None);
        assert_eq!(result.observations[0].raw["subject"]["kind"], "endpoint");
        assert_eq!(result.observations[0].raw["listeners"][0]["port"], 1911);
        assert_eq!(result.ports.len(), 1);
        let outcomes: std::collections::BTreeMap<&str, ProbeStatus> = result
            .outcomes
            .iter()
            .map(|outcome| (outcome.protocol, outcome.status))
            .collect();
        assert_eq!(outcomes["niagara-fox"], ProbeStatus::Success);
        assert!(matches!(
            outcomes["s7"],
            ProbeStatus::NoResponse | ProbeStatus::Failure
        ));
        assert!(
            result
                .warnings
                .iter()
                .any(|warning| warning.contains("BACnet"))
        );
        fox_task.await.unwrap();
        bacnet_task.await.unwrap();
    }
}
