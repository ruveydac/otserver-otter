use super::{Finding, hex};
use crate::contract::Source;
use iec61850_client::{ClientError, IedConnection};
use iec61850_mms::mms::client::MmsClientBuilder;
use iec61850_model::{Dbpos, FC, MmsValue};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

pub(crate) const PORT: u16 = 102;
const CONNECT_TIMEOUT_MS: u64 = 2_000;
const REQUEST_TIMEOUT_MS: u64 = 2_000;
const MAX_LOGICAL_DEVICES: usize = 64;
const MAX_LOGICAL_NODES: usize = 256;
const MAX_VARIABLES_PER_NODE: usize = 4096;

#[derive(Clone, Copy)]
enum ValueKind {
    String,
    Boolean,
    Integer,
    Health,
    DoublePoint,
}

struct Evidence {
    raw_values: Map<String, Value>,
    warnings: Vec<String>,
}

pub async fn probe(target: Ipv4Addr, port: u16) -> Result<Option<Finding>, String> {
    crate::traffic::wait().await;
    let client = MmsClientBuilder::new()
        .connect_timeout_ms(CONNECT_TIMEOUT_MS)
        .request_timeout_ms(REQUEST_TIMEOUT_MS)
        .max_outstanding(1)
        .build();
    let connection = IedConnection::with_mms_client(client);
    let host = target.to_string();
    if let Err(error) = connection.connect(&host, port).await {
        if no_service(&error) {
            return Ok(None);
        }
        return Err(format!("IEC 61850 {target}:{port}: {error}"));
    }

    let result = collect(&connection, target, port).await;
    if result.is_ok() {
        let _ = connection.disconnect().await;
    } else {
        let _ = connection.abort().await;
    }
    result.map(Some)
}

async fn collect(
    connection: &IedConnection,
    target: Ipv4Addr,
    port: u16,
) -> Result<Finding, String> {
    crate::traffic::wait().await;
    let logical_devices = connection
        .get_server_directory(false)
        .await
        .map_err(|error| format!("IEC 61850 {target}: server directory: {error}"))?;
    if logical_devices.is_empty() || logical_devices.len() > MAX_LOGICAL_DEVICES {
        return Err(format!(
            "IEC 61850 {target}: invalid logical-device count {}",
            logical_devices.len()
        ));
    }

    let mut variables = BTreeMap::<(String, String), BTreeSet<String>>::new();
    let mut logical_nodes = Map::new();
    for logical_device in &logical_devices {
        crate::traffic::wait().await;
        let nodes = connection
            .get_logical_device_directory(logical_device)
            .await
            .map_err(|error| {
                format!("IEC 61850 {target}: logical-device {logical_device} directory: {error}")
            })?;
        if nodes.len() > MAX_LOGICAL_NODES {
            return Err(format!(
                "IEC 61850 {target}: logical-device {logical_device} has too many logical nodes"
            ));
        }

        let mut node_values = Map::new();
        for node in nodes {
            let reference = format!("{logical_device}/{node}");
            crate::traffic::wait().await;
            let node_variables = connection
                .get_logical_node_variables(&reference)
                .await
                .map_err(|error| format!("IEC 61850 {target}: {reference} directory: {error}"))?;
            if node_variables.len() > MAX_VARIABLES_PER_NODE {
                return Err(format!(
                    "IEC 61850 {target}: {reference} advertises too many variables"
                ));
            }
            let node_variables = node_variables.into_iter().collect::<BTreeSet<_>>();
            node_values.insert(node.clone(), json!(node_variables));
            variables.insert((logical_device.clone(), node), node_variables);
        }
        logical_nodes.insert(logical_device.clone(), Value::Object(node_values));
    }

    let mut fields = BTreeMap::from([("protocols".into(), json!(["iec61850"]))]);
    let mut evidence = Evidence {
        raw_values: Map::new(),
        warnings: Vec::new(),
    };

    for (logical_node, object, attribute, field) in [
        ("LPHD1", "PhyNam", "vendor", "vendor"),
        ("LPHD1", "PhyNam", "model", "model"),
        ("LPHD1", "PhyNam", "serNum", "serialNumber"),
        ("LPHD1", "PhyNam", "hwRev", "hardwareVersion"),
        ("LPHD1", "PhyNam", "swRev", "firmwareVersion"),
        ("LPHD1", "PhyNam", "location", "location"),
        ("LLN0", "NamPlt", "vendor", "vendor"),
        ("LLN0", "NamPlt", "model", "model"),
        ("LLN0", "NamPlt", "serNum", "serialNumber"),
        ("LLN0", "NamPlt", "swRev", "firmwareVersion"),
        ("LLN0", "NamPlt", "location", "location"),
    ] {
        for logical_device in &logical_devices {
            let Some(node_variables) =
                variables.get(&(logical_device.clone(), logical_node.to_owned()))
            else {
                continue;
            };
            if let Some(value) = read_value(
                connection,
                &format!("{logical_device}/{logical_node}"),
                node_variables,
                &format!("{object}.{attribute}"),
                FC::Dc,
                ValueKind::String,
                &mut evidence,
            )
            .await
            {
                fields.entry(field.into()).or_insert(value);
            }
        }
    }

    for ((logical_device, logical_node), node_variables) in &variables {
        let node_reference = format!("{logical_device}/{logical_node}");
        for (object, field, kind) in [
            ("Health.stVal", "health", ValueKind::Health),
            ("PhyHealth.stVal", "physicalHealth", ValueKind::Boolean),
            ("BlkOpn.stVal", "blockedOpen", ValueKind::Boolean),
            ("BlkCls.stVal", "blockedClose", ValueKind::Boolean),
            ("Pos.stVal", "position", ValueKind::DoublePoint),
            // IEC 61850-7-3 INS carries actVal; libiec61850 builds it as stVal.
            ("OpCnt.actVal", "operationCount", ValueKind::Integer),
            ("OpCnt.stVal", "operationCount", ValueKind::Integer),
        ] {
            if let Some(value) = read_value(
                connection,
                &node_reference,
                node_variables,
                object,
                FC::St,
                kind,
                &mut evidence,
            )
            .await
            {
                fields.entry(field.into()).or_insert(value);
            }
        }
    }

    if let Some(model) = fields.get("model").cloned() {
        fields.entry("name".into()).or_insert(model);
    } else if let Some(vendor) = fields.get("vendor").cloned() {
        fields.entry("name".into()).or_insert(vendor);
    }

    let raw = Value::Object(Map::from_iter([
        ("logicalDevices".into(), json!(logical_devices)),
        ("logicalNodes".into(), Value::Object(logical_nodes)),
        ("values".into(), Value::Object(evidence.raw_values)),
    ]));
    Ok(Finding {
        source: Source::Iec61850,
        fields,
        raw,
        ports: vec![super::port(
            "tcp",
            port,
            Source::Iec61850,
            json!({ "state": "open" }),
        )],
        warnings: evidence.warnings,
    })
}

async fn read_value(
    connection: &IedConnection,
    node: &str,
    variables: &BTreeSet<String>,
    object: &str,
    fc: FC,
    kind: ValueKind,
    evidence: &mut Evidence,
) -> Option<Value> {
    let tail = variable_tail(object, fc);
    if !variables.contains(&tail) {
        return None;
    }
    let reference = format!("{node}.{object}");
    crate::traffic::wait().await;
    let key = format!("{reference}[{}]", fc.as_str());
    let value = match connection.read_object(&reference, fc).await {
        Ok(value) => value,
        Err(error) => {
            evidence
                .warnings
                .push(format!("IEC 61850 read {key}: {error}"));
            return None;
        }
    };
    evidence
        .raw_values
        .insert(key.clone(), value_to_json(&value));
    match decode(&value, kind) {
        Some(output) => Some(output),
        None => {
            evidence.warnings.push(format!(
                "IEC 61850 read {key} returned {}, expected {}",
                value.type_name(),
                expected(kind)
            ));
            None
        }
    }
}

fn decode(value: &MmsValue, kind: ValueKind) -> Option<Value> {
    match kind {
        ValueKind::String => match value {
            MmsValue::VisibleString(value) | MmsValue::MmsString(value) => Some(json!(value)),
            _ => None,
        },
        ValueKind::Boolean => match value {
            MmsValue::Boolean(value) => Some(json!(value)),
            _ => None,
        },
        ValueKind::Integer => match value {
            MmsValue::Integer(value) => Some(json!(value)),
            MmsValue::Unsigned(value) => Some(json!(value)),
            _ => None,
        },
        ValueKind::Health => match value {
            MmsValue::Integer(value) => health(*value),
            MmsValue::Unsigned(value) => health(i64::try_from(*value).unwrap_or(i64::MAX)),
            _ => None,
        },
        ValueKind::DoublePoint => Dbpos::from_mms_bit_string(value)
            .ok()
            .map(|value| json!(double_point_label(value))),
    }
}

fn health(value: i64) -> Option<Value> {
    match value {
        1 => Some(json!("ok")),
        2 => Some(json!("warning")),
        3 => Some(json!("alarm")),
        _ => None,
    }
}

fn expected(kind: ValueKind) -> &'static str {
    match kind {
        ValueKind::String => "a string",
        ValueKind::Boolean => "a boolean",
        ValueKind::Integer => "an integer",
        ValueKind::Health => "health 1 (ok), 2 (warning), or 3 (alarm)",
        ValueKind::DoublePoint => "a double point",
    }
}

fn variable_tail(object: &str, fc: FC) -> String {
    format!("{}${}", fc.as_str(), object.replace('.', "$"))
}

fn double_point_label(value: Dbpos) -> &'static str {
    match value {
        Dbpos::Intermediate => "intermediate",
        Dbpos::Off => "off",
        Dbpos::On => "on",
        Dbpos::BadState => "bad-state",
    }
}

fn value_to_json(value: &MmsValue) -> Value {
    match value {
        MmsValue::Boolean(value) => json!(value),
        MmsValue::Integer(value) => json!(value),
        MmsValue::Unsigned(value) => json!(value),
        MmsValue::Float32(value) => json!(value),
        MmsValue::Float64(value) => json!(value),
        MmsValue::BitString { padding, data } => {
            json!({ "padding": padding, "data": hex(data) })
        }
        MmsValue::OctetString(value) => json!(hex(value)),
        MmsValue::VisibleString(value) | MmsValue::MmsString(value) => json!(value),
        MmsValue::UtcTime(value) => json!(hex(value)),
        MmsValue::BinaryTime(value) => json!(hex(value)),
        MmsValue::Array(values) | MmsValue::Structure(values) => {
            Value::Array(values.iter().map(value_to_json).collect())
        }
    }
}

fn no_service(error: &ClientError) -> bool {
    match error {
        ClientError::SessionRefused { .. } => true,
        ClientError::Mms(message) => {
            let message = message.to_ascii_lowercase();
            [
                "connection refused",
                "connection reset",
                "connect timeout",
                "timed out",
                "network is unreachable",
                "no route to host",
                "transport connection was lost",
                "cotp input ended unexpectedly",
            ]
            .iter()
            .any(|text| message.contains(text))
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iec61850_model::{
        CdcOptions, DataAttribute, DataAttributeType, DataObjectBuilder, DoChild, IedModel,
        IedModelBuilder, LogicalDeviceBuilder, LogicalNodeBuilder, TrgOps, cdc,
    };
    use iec61850_server::{IedServer, IedServerConfig, ServerHandle};
    use std::sync::Arc;
    use tokio::net::TcpListener;

    fn attribute<'a>(
        model: &'a IedModel,
        node: &str,
        object: &str,
        name: &str,
    ) -> &'a DataAttribute {
        let DoChild::Da(attribute) = model
            .ld_by_inst("LD0")
            .unwrap()
            .ln_by_name(node)
            .unwrap()
            .do_by_name(object)
            .unwrap()
            .child_by_name(name)
            .unwrap()
        else {
            panic!("{node}.{object}.{name} is not a data attribute");
        };
        attribute
    }

    fn lab_model(standard_health: bool) -> Arc<IedModel> {
        let mut lln0 = LogicalNodeBuilder::lln0().add_do(cdc::lpl("NamPlt", CdcOptions::NONE));
        lln0 = if standard_health {
            lln0.add_do(cdc::ens("Health", CdcOptions::NONE))
        } else {
            lln0.add_do(cdc::sps("Health", CdcOptions::NONE))
        };
        let lphd1 = LogicalNodeBuilder::new("", "LPHD", "1")
            .add_do(cdc::dpl(
                "PhyNam",
                CdcOptions::DPL_HWREV
                    | CdcOptions::DPL_SWREV
                    | CdcOptions::DPL_SERNUM
                    | CdcOptions::DPL_MODEL
                    | CdcOptions::DPL_LOCATION,
            ))
            .add_do(cdc::sps("PhyHealth", CdcOptions::NONE))
            .build()
            .unwrap();
        let xcbr1 = LogicalNodeBuilder::new("", "XCBR", "1")
            .add_do(cdc::dps("Pos", CdcOptions::NONE))
            .add_do(cdc::sps("BlkOpn", CdcOptions::NONE))
            .add_do(cdc::sps("BlkCls", CdcOptions::NONE))
            .add_do(
                DataObjectBuilder::scalar("OpCnt")
                    .add_da(
                        "actVal",
                        FC::St,
                        DataAttributeType::Int32,
                        TrgOps::DCHG,
                        MmsValue::Integer(42),
                    )
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();
        let logical_device = LogicalDeviceBuilder::new("LD0")
            .add_ln(lln0.build().unwrap())
            .add_ln(lphd1)
            .add_ln(xcbr1)
            .build()
            .unwrap();
        let model = IedModelBuilder::new("TESTIED")
            .add_ld(logical_device)
            .unwrap()
            .build()
            .unwrap();

        attribute(&model, "LLN0", "NamPlt", "vendor")
            .store(MmsValue::VisibleString("NamPlt Vendor".into()));
        attribute(&model, "LLN0", "NamPlt", "swRev")
            .store(MmsValue::VisibleString("SW-LLN0".into()));
        if standard_health {
            attribute(&model, "LLN0", "Health", "stVal").store(MmsValue::Integer(1));
        } else {
            attribute(&model, "LLN0", "Health", "stVal").store(MmsValue::Boolean(true));
        }
        for (name, value) in [
            ("vendor", "Lab Vendor"),
            ("model", "Lab Breaker IED"),
            ("serNum", "SN-0001"),
            ("hwRev", "HW-2"),
            ("swRev", "SW-3"),
            ("location", "Lab / Bay 1"),
        ] {
            attribute(&model, "LPHD1", "PhyNam", name).store(MmsValue::VisibleString(value.into()));
        }
        attribute(&model, "LPHD1", "PhyHealth", "stVal").store(MmsValue::Boolean(true));
        attribute(&model, "XCBR1", "Pos", "stVal").store(Dbpos::On.to_mms_bit_string());
        attribute(&model, "XCBR1", "BlkOpn", "stVal").store(MmsValue::Boolean(false));
        attribute(&model, "XCBR1", "BlkCls", "stVal").store(MmsValue::Boolean(false));
        Arc::new(model)
    }

    async fn spawn_server(model: Arc<IedModel>) -> (ServerHandle, u16) {
        let server = IedServer::builder()
            .model(model)
            .bind("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
            .config(IedServerConfig {
                max_mms_connections: 2,
                ..Default::default()
            })
            .build()
            .unwrap();
        let handle = server.start().await.unwrap();
        let port = handle.bound_addr.port();
        (handle, port)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn probe_collects_asset_information_from_live_server() {
        let (handle, port) = spawn_server(lab_model(true)).await;
        let finding = probe(Ipv4Addr::LOCALHOST, port).await.unwrap().unwrap();

        assert_eq!(finding.source, Source::Iec61850);
        assert!(finding.warnings.is_empty());
        let fields = &finding.fields;
        assert_eq!(fields["protocols"], json!(["iec61850"]));
        assert_eq!(fields["vendor"], "Lab Vendor");
        assert_eq!(fields["model"], "Lab Breaker IED");
        assert_eq!(fields["name"], "Lab Breaker IED");
        assert_eq!(fields["serialNumber"], "SN-0001");
        assert_eq!(fields["hardwareVersion"], "HW-2");
        assert_eq!(fields["firmwareVersion"], "SW-3");
        assert_eq!(fields["location"], "Lab / Bay 1");
        assert_eq!(fields["health"], "ok");
        assert_eq!(fields["physicalHealth"], true);
        assert_eq!(fields["position"], "on");
        assert_eq!(fields["blockedOpen"], false);
        assert_eq!(fields["blockedClose"], false);
        assert_eq!(fields["operationCount"], 42);

        assert_eq!(finding.raw["logicalDevices"], json!(["TESTIEDLD0"]));
        let nodes = &finding.raw["logicalNodes"]["TESTIEDLD0"];
        assert_eq!(
            nodes.as_object().unwrap().keys().collect::<Vec<_>>(),
            ["LLN0", "LPHD1", "XCBR1"]
        );
        assert!(
            nodes["LPHD1"]
                .as_array()
                .unwrap()
                .contains(&json!("DC$PhyNam$vendor"))
        );
        let values = &finding.raw["values"];
        assert_eq!(values["TESTIEDLD0/LPHD1.PhyNam.vendor[DC]"], "Lab Vendor");
        assert_eq!(values["TESTIEDLD0/LLN0.Health.stVal[ST]"], 1);
        assert_eq!(
            values["TESTIEDLD0/XCBR1.Pos.stVal[ST]"],
            json!({ "padding": 6, "data": "80" })
        );
        assert_eq!(finding.ports.len(), 1);
        assert_eq!(finding.ports[0].key, format!("tcp:{port}"));
        assert_eq!(finding.ports[0].source, "iec61850");
        handle.stop().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mismatched_attribute_keeps_finding_and_warns() {
        let (handle, port) = spawn_server(lab_model(false)).await;
        let finding = probe(Ipv4Addr::LOCALHOST, port).await.unwrap().unwrap();

        assert!(!finding.fields.contains_key("health"));
        assert_eq!(finding.fields["vendor"], "Lab Vendor");
        assert_eq!(finding.fields["physicalHealth"], true);
        assert!(
            finding
                .warnings
                .iter()
                .any(|warning| warning.contains("LLN0.Health.stVal[ST]")
                    && warning.contains("expected health"))
        );
        handle.stop().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn closed_port_probes_as_absent_service() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        assert!(probe(Ipv4Addr::LOCALHOST, port).await.unwrap().is_none());
    }

    #[test]
    fn builds_mms_variable_tail() {
        assert_eq!(variable_tail("NamPlt.vendor", FC::Dc), "DC$NamPlt$vendor");
        assert_eq!(variable_tail("Pos.stVal", FC::St), "ST$Pos$stVal");
    }

    #[test]
    fn decodes_health_enumerations() {
        assert_eq!(
            decode(&MmsValue::Integer(1), ValueKind::Health),
            Some(json!("ok"))
        );
        assert_eq!(
            decode(&MmsValue::Unsigned(2), ValueKind::Health),
            Some(json!("warning"))
        );
        assert_eq!(
            decode(&MmsValue::Integer(3), ValueKind::Health),
            Some(json!("alarm"))
        );
        assert_eq!(decode(&MmsValue::Integer(4), ValueKind::Health), None);
        assert_eq!(decode(&MmsValue::Boolean(true), ValueKind::Health), None);
    }

    #[test]
    fn decodes_each_value_kind_strictly() {
        assert_eq!(
            decode(&MmsValue::VisibleString("IED".into()), ValueKind::String),
            Some(json!("IED"))
        );
        assert_eq!(decode(&MmsValue::Boolean(true), ValueKind::String), None);
        assert_eq!(
            decode(&MmsValue::Boolean(false), ValueKind::Boolean),
            Some(json!(false))
        );
        assert_eq!(
            decode(&MmsValue::Integer(-7), ValueKind::Integer),
            Some(json!(-7))
        );
        assert_eq!(
            decode(&MmsValue::Unsigned(7), ValueKind::Integer),
            Some(json!(7))
        );
        assert_eq!(decode(&MmsValue::Boolean(true), ValueKind::Integer), None);
        assert_eq!(
            decode(&Dbpos::BadState.to_mms_bit_string(), ValueKind::DoublePoint),
            Some(json!("bad-state"))
        );
        assert_eq!(
            decode(&MmsValue::Boolean(true), ValueKind::DoublePoint),
            None
        );
    }

    #[test]
    fn labels_every_double_point() {
        assert_eq!(double_point_label(Dbpos::Intermediate), "intermediate");
        assert_eq!(double_point_label(Dbpos::Off), "off");
        assert_eq!(double_point_label(Dbpos::On), "on");
        assert_eq!(double_point_label(Dbpos::BadState), "bad-state");
    }

    #[test]
    fn decodes_read_values_without_lossy_text() {
        assert_eq!(value_to_json(&MmsValue::VisibleString("IED".into())), "IED");
        assert_eq!(value_to_json(&MmsValue::Boolean(true)), true);
        assert_eq!(value_to_json(&MmsValue::Integer(-2)), -2);
        assert_eq!(value_to_json(&MmsValue::Unsigned(3)), 3);
        assert_eq!(value_to_json(&MmsValue::Float32(1.5)), 1.5);
        assert_eq!(value_to_json(&MmsValue::Float64(2.5)), 2.5);
        assert_eq!(
            value_to_json(&Dbpos::On.to_mms_bit_string()),
            json!({"padding": 6, "data": "80"})
        );
        assert_eq!(
            value_to_json(&MmsValue::OctetString(vec![0xde, 0xad])),
            "DEAD"
        );
        assert_eq!(
            value_to_json(&MmsValue::UtcTime([1, 2, 3, 4, 5, 6, 7, 8])),
            "0102030405060708"
        );
        assert_eq!(value_to_json(&MmsValue::BinaryTime(vec![3])), "03");
        assert_eq!(
            value_to_json(&MmsValue::Structure(vec![
                MmsValue::Boolean(true),
                MmsValue::Array(vec![MmsValue::Integer(1)]),
            ])),
            json!([true, [1]])
        );
    }

    #[test]
    fn classifies_unavailable_transport_but_not_malformed_mms() {
        assert!(no_service(&ClientError::Mms(
            "i/o error: Connection refused".into()
        )));
        assert!(no_service(&ClientError::SessionRefused {
            reason_code: None,
            transport_disconnect: None,
            provider_reason: None,
        }));
        assert!(!no_service(&ClientError::Mms("invalid tpkt header".into())));
    }
}
