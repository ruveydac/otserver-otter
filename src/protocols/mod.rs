use crate::contract::{Observation, Port, Source, hex};
use serde_json::Value;
use std::collections::BTreeMap;
use std::future::Future;
use std::net::Ipv4Addr;
use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};

mod bacnet;
mod dnp3;
mod enip;
mod fins;
mod fox;
mod iec61850;
mod netbios;
mod ntlm;
mod opcua;
mod rpc;
mod s7;
mod smb;
mod smb1;

pub use opcua::{
    Credential as OpcuaCredential, Credentials as OpcuaCredentials, ProbeSettings as OpcuaSettings,
};

const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

pub struct ProbeResult {
    pub observations: Vec<Observation>,
    pub ports: Vec<Port>,
    pub warnings: Vec<String>,
    pub outcomes: Vec<(Source, bool)>,
    /// Transport protocol labels aligned with outcomes (separate from export source).
    pub outcome_protocols: Vec<&'static str>,
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
    pub opcua: bool,
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
            || self.opcua
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
            (self.opcua, "OPC UA"),
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
            opcua: true,
        }
    }
}

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
    scan_with_cancellation(target, mac, selection, opcua, &AtomicBool::new(false)).await
}

pub async fn scan_with_cancellation(
    target: Ipv4Addr,
    mac: Option<&str>,
    selection: Selection,
    opcua: &opcua::ProbeSettings,
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
    let mut outcome_protocols = Vec::new();
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
    ];
    for (enabled, source, protocol, result) in results {
        if !enabled {
            continue;
        }
        outcomes.push((source, matches!(result, Ok(Some(_)))));
        outcome_protocols.push(protocol);
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
        outcome_protocols,
    }
}

type CompletedProbes = Mutex<Vec<(usize, Result<Option<Finding>, String>)>>;

async fn collect_probe(
    index: usize,
    probe: impl Future<Output = Result<Option<Finding>, String>>,
    completed: &CompletedProbes,
) {
    let result = probe.await;
    completed
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push((index, result));
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
        assert_eq!(result.outcome_protocols.len(), result.outcomes.len());
        assert_eq!(result.outcome_protocols.contains(&"smb"), selection.smb);
        assert_eq!(result.outcome_protocols.contains(&"rpc"), selection.rpc);
        assert!(result.outcomes.iter().all(|(_, success)| !success));
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
            opcua: false,
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
        assert!(result.outcome_protocols.is_empty());
    }

    #[tokio::test]
    async fn cancellation_retains_completed_protocols_while_dropping_silent_ones() {
        let _network = crate::network_test_lock().await;
        let fins = UdpSocket::bind((Ipv4Addr::LOCALHOST, 9600)).await.unwrap();
        let _silent = UdpSocket::bind((Ipv4Addr::LOCALHOST, 47808)).await.unwrap();
        let cancelled = AtomicBool::new(false);
        let responder = async {
            let mut request = [0; 13];
            let (_, peer) = fins.recv_from(&mut request).await.unwrap();
            let mut response = vec![0; 106];
            response[0] = 0xc0;
            response[4] = 0x63;
            response[9..12].copy_from_slice(&[0xef, 5, 1]);
            response[14..17].copy_from_slice(b"PLC");
            fins.send_to(&response, peer).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
            cancelled.store(true, Ordering::Relaxed);
        };
        let selection = Selection {
            s7: false,
            enip: false,
            bacnet: true,
            fins: true,
            fox: false,
            dnp3: false,
            iec61850: false,
            netbios: false,
            smb: false,
            rpc: false,
            opcua: false,
        };
        let settings = opcua::ProbeSettings::default();
        let (result, ()) = tokio::join!(
            scan_with_cancellation(Ipv4Addr::LOCALHOST, None, selection, &settings, &cancelled),
            responder
        );
        assert_eq!(result.observations.len(), 1);
        assert_eq!(result.observations[0].fields["model"], "PLC");
        assert!(
            result
                .warnings
                .iter()
                .any(|warning| warning.contains("cancelled"))
        );
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
        let outcomes: std::collections::BTreeMap<Source, bool> =
            result.outcomes.iter().copied().collect();
        assert!(outcomes[&Source::NiagaraFox]);
        assert!(!outcomes[&Source::S7]);
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
