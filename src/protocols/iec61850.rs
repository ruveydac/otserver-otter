use super::{Finding, hex, port};
use crate::contract::Source;
use iec61850_client::{ClientError, IedConnection};
use iec61850_mms::mms::client::MmsClientBuilder;
use iec61850_model::{Dbpos, FC, MmsValue};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

const PORT: u16 = 102;
const CONNECT_TIMEOUT_MS: u64 = 2_000;
const REQUEST_TIMEOUT_MS: u64 = 2_000;
const MAX_LOGICAL_DEVICES: usize = 64;
const MAX_LOGICAL_NODES: usize = 256;
const MAX_VARIABLES_PER_NODE: usize = 4096;

#[derive(Clone, Copy)]
enum ValueKind {
    String,
    Boolean,
    DoublePoint,
}

pub async fn probe(target: Ipv4Addr) -> Result<Option<Finding>, String> {
    crate::traffic::wait().await;
    let client = MmsClientBuilder::new()
        .connect_timeout_ms(CONNECT_TIMEOUT_MS)
        .request_timeout_ms(REQUEST_TIMEOUT_MS)
        .max_outstanding(1)
        .build();
    let connection = IedConnection::with_mms_client(client);
    let host = target.to_string();
    if let Err(error) = connection.connect(&host, PORT).await {
        if no_service(&error) {
            return Ok(None);
        }
        return Err(format!("IEC 61850 {target}:{PORT}: {error}"));
    }

    let result = collect(&connection, target).await;
    if result.is_ok() {
        let _ = connection.disconnect().await;
    } else {
        let _ = connection.abort().await;
    }
    result.map(Some)
}

async fn collect(connection: &IedConnection, target: Ipv4Addr) -> Result<Finding, String> {
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
    let mut raw_values = Map::new();

    for (logical_node, object, attribute, field) in [
        ("LPHD1", "PhyNam", "vendor", "vendor"),
        ("LPHD1", "PhyNam", "model", "model"),
        ("LPHD1", "PhyNam", "serNum", "serialNumber"),
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
            if let Some(value) = read_known(
                connection,
                logical_device,
                logical_node,
                node_variables,
                &format!("{object}.{attribute}"),
                FC::Dc,
                ValueKind::String,
                &mut raw_values,
            )
            .await?
            {
                fields.entry(field.into()).or_insert(value);
            }
        }
    }

    for ((logical_device, logical_node), node_variables) in &variables {
        for (object, field, kind) in [
            ("Health.stVal", "health", ValueKind::Boolean),
            ("PhyHealth.stVal", "physicalHealth", ValueKind::Boolean),
            ("BlkOpn.stVal", "blockedOpen", ValueKind::Boolean),
            ("BlkCls.stVal", "blockedClose", ValueKind::Boolean),
            ("Pos.stVal", "position", ValueKind::DoublePoint),
        ] {
            if let Some(value) = read_known(
                connection,
                logical_device,
                logical_node,
                node_variables,
                object,
                FC::St,
                kind,
                &mut raw_values,
            )
            .await?
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
        ("values".into(), Value::Object(raw_values)),
    ]));
    Ok(Finding {
        source: Source::Iec61850,
        fields,
        raw,
        ports: vec![port(
            "tcp",
            PORT,
            Source::Iec61850,
            json!({ "state": "open" }),
        )],
        warnings: vec![],
    })
}

async fn read_known(
    connection: &IedConnection,
    logical_device: &str,
    logical_node: &str,
    variables: &BTreeSet<String>,
    object: &str,
    fc: FC,
    kind: ValueKind,
    raw_values: &mut Map<String, Value>,
) -> Result<Option<Value>, String> {
    let tail = variable_tail(object, fc);
    if !variables.contains(&tail) {
        return Ok(None);
    }
    let reference = format!("{logical_device}/{logical_node}.{object}");
    crate::traffic::wait().await;
    let value = connection
        .read_object(&reference, fc)
        .await
        .map_err(|error| format!("IEC 61850 read {reference}[{}]: {error}", fc.as_str()))?;
    let output = match kind {
        ValueKind::String => match &value {
            MmsValue::VisibleString(value) | MmsValue::MmsString(value) => json!(value),
            other => {
                return Err(format!(
                    "IEC 61850 read {reference}[{}] returned {}, expected string",
                    fc.as_str(),
                    other.type_name()
                ));
            }
        },
        ValueKind::Boolean => match value {
            MmsValue::Boolean(value) => json!(value),
            other => {
                return Err(format!(
                    "IEC 61850 read {reference}[{}] returned {}, expected boolean",
                    fc.as_str(),
                    other.type_name()
                ));
            }
        },
        ValueKind::DoublePoint => match Dbpos::from_mms_bit_string(&value) {
            Ok(value) => json!(double_point_label(value)),
            Err(error) => {
                return Err(format!(
                    "IEC 61850 read {reference}[{}] returned invalid double point: {error}",
                    fc.as_str()
                ));
            }
        },
    };
    raw_values.insert(
        format!("{reference}[{}]", fc.as_str()),
        value_to_json(&value),
    );
    Ok(Some(output))
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

    #[test]
    fn builds_mms_variable_tail() {
        assert_eq!(variable_tail("NamPlt.vendor", FC::Dc), "DC$NamPlt$vendor");
        assert_eq!(variable_tail("Pos.stVal", FC::St), "ST$Pos$stVal");
    }

    #[test]
    fn decodes_read_values_without_lossy_text() {
        assert_eq!(value_to_json(&MmsValue::VisibleString("IED".into())), "IED");
        assert_eq!(value_to_json(&MmsValue::Boolean(true)), true);
        assert_eq!(
            value_to_json(&Dbpos::On.to_mms_bit_string()),
            json!({"padding": 6, "data": "80"})
        );
        assert_eq!(
            value_to_json(&MmsValue::OctetString(vec![0xde, 0xad])),
            "DEAD"
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
