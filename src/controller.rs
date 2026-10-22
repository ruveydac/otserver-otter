//! Outbound controller v1 client. Local scans still use the shared safety/pacing path.
mod install;
mod store;
#[cfg(test)]
mod tests;

use crate::{HttpOptions, LogOutput, ScanArgs, ScanOptions, ScannerConfig, resolve_scan, scan};
use clap::Args;
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::time::Instant;

#[derive(Args)]
pub struct ControllerArgs {
    /// Controller URL (HTTPS, or HTTP loopback). Reuses the enrolled URL when omitted.
    #[arg(long, default_value = "", hide_default_value = true)]
    server_url: String,
    /// Read the single-use enrollment token from stdin (never from process arguments).
    #[arg(long)]
    enroll: bool,
    /// Install and start a background controller for this OS user, then exit.
    #[arg(long)]
    install: bool,
    /// Enroll and save credentials without polling (also used by the GUI).
    #[arg(long, requires = "enroll", conflicts_with = "install")]
    enroll_only: bool,
    #[arg(long)]
    state_dir: Option<PathBuf>,
    /// Replace saved enrollment and run state after enrolling with a new controller; retained exports are kept.
    #[arg(long, requires = "enroll")]
    overwrite_state_dir: bool,
    /// Minimum idle polling interval in seconds (default: saved value, initially 30).
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..=300))]
    poll_seconds: Option<u64>,
    #[arg(long, required = true, action = clap::ArgAction::SetTrue)]
    ack_authorized: bool,
    /// Use the permission-restricted credential file instead of the OS secret store.
    #[arg(long)]
    file_credentials: bool,
    /// Request queued imports (must be enabled in the manager's Application settings).
    #[arg(long)]
    queued_imports: bool,
    /// Disable TLS certificate and hostname validation for HTTP clients.
    #[arg(long)]
    ignore_self_signed: bool,
    /// Proxy HTTP requests through URL. HTTPS requests remain direct unless --https-proxy is supplied.
    #[arg(long, value_name = "URL")]
    http_proxy: Option<String>,
    /// Proxy HTTPS requests through URL. HTTP requests remain direct unless --http-proxy is supplied.
    #[arg(long, value_name = "URL")]
    https_proxy: Option<String>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
struct Settings {
    poll_seconds: u64,
    file_credentials: bool,
    queued_imports: bool,
    http: HttpOptions,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            poll_seconds: 30,
            file_credentials: false,
            queued_imports: false,
            http: HttpOptions::default(),
        }
    }
}

#[cfg(feature = "gui")]
pub(super) struct EnrollmentInfo {
    pub server_url: String,
    pub name: String,
    pub site: String,
    pub http: HttpOptions,
}

#[cfg(feature = "gui")]
pub(super) fn enrollment_info(
    directory: Option<PathBuf>,
) -> Result<Option<EnrollmentInfo>, String> {
    let directory = store::Store::directory(directory).map_err(|e| e.to_string())?;
    let state = store::Store::read_state(&directory).map_err(|e| e.to_string())?;
    Ok(state.scanner.map(|scanner| EnrollmentInfo {
        server_url: state.server_url,
        name: scanner.name,
        site: scanner.site,
        http: state.settings.http,
    }))
}

// No Debug on objects containing controller or protocol credentials.
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Credential {
    credential: String,
    credential_expires_at: String,
}

#[derive(Deserialize, Serialize)]
struct Scanner {
    id: String,
    name: String,
    site: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Enrollment {
    #[serde(flatten)]
    credential: Credential,
    scanner: Scanner,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ScannerReport {
    version: &'static str,
    capabilities: [&'static str; 2],
    interfaces: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    computer_name: Option<String>,
    network_adapters: Vec<NetworkAdapterReport>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NetworkAdapterReport {
    name: String,
    friendly_name: String,
    description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    mac_address: Option<String>,
    ip_addresses: Vec<String>,
}

fn network_adapter_report(
    adapter: otserver_otter::profinet::CaptureInterface,
) -> NetworkAdapterReport {
    NetworkAdapterReport {
        mac_address: otserver_otter::profinet::interface_mac(&adapter),
        ip_addresses: adapter
            .addresses
            .iter()
            .filter_map(|address| address.parse::<IpAddr>().ok())
            .map(|address| address.to_string())
            .take(16)
            .collect(),
        name: adapter.name,
        friendly_name: adapter.friendly_name,
        description: adapter.description,
    }
}

fn scanner_report() -> Result<ScannerReport, Error> {
    let adapters =
        otserver_otter::profinet::interfaces().map_err(|_| Error::InterfacesUnavailable)?;
    let computer_name = ["COMPUTERNAME", "HOSTNAME"]
        .into_iter()
        .find_map(|key| std::env::var(key).ok())
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok())
        .map(|name| name.trim().to_owned())
        .filter(|name| !name.is_empty() && name.len() <= 256);
    let interfaces = adapters
        .iter()
        .map(|adapter| adapter.name.clone())
        .take(32)
        .collect();
    let network_adapters = adapters
        .into_iter()
        .take(32)
        .map(network_adapter_report)
        .collect();
    Ok(ScannerReport {
        version: otserver_otter::VERSION,
        capabilities: ["scan-v2", "controller-v1"],
        interfaces,
        computer_name,
        network_adapters,
    })
}

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "camelCase")]
enum Poll {
    Idle {
        #[serde(rename = "retryAfterSeconds")]
        retry_after_seconds: u64,
    },
    Run {
        run: Assignment,
    },
    Cancel {
        #[serde(rename = "runID")]
        run_id: String,
    },
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Assignment {
    id: String,
    configuration: Value,
    credentials: Value,
    upload_path: String,
    lease_expires_at: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Heartbeat {
    cancel_requested: bool,
    lease_expires_at: Option<String>,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
enum Phase {
    Assigned,
    Scanning,
    Ready,
    Finishing,
    Terminal,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct RunState {
    id: String,
    phase: Phase,
    status: String,
    import_id: Option<String>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    upload_attempts: u8,
}

#[derive(Deserialize, Serialize)]
struct PendingImport {
    id: String,
    status: String,
    #[serde(default)]
    retries: u8,
}

#[derive(Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct State {
    server_url: String,
    scanner: Option<Scanner>,
    credential_key: Option<String>,
    file_credential: Option<Credential>,
    credential_expires_at: String,
    assignment: Option<RunState>,
    #[serde(default)]
    pending_imports: Vec<PendingImport>,
    #[serde(default)]
    settings: Settings,
}

#[derive(Debug, PartialEq, Eq)]
enum Error {
    Retry,
    InterfacesUnavailable,
    UploadRetriesExhausted,
    Auth,
    Terminal,
    Invalid,
    Local(&'static str),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Retry => "Controller unavailable; retrying in 5 minutes.",
            Self::InterfacesUnavailable => "Could not enumerate capture interfaces; retrying in 5 minutes.",
            Self::UploadRetriesExhausted => "Scan result upload failed after the initial attempt and 5 retries. Local scan result retained.",
            Self::Auth => "Scanner credential is expired or not accepted. Verify --server-url, OS account, and --state-dir; re-enroll if the controller revoked it.",
            Self::Terminal => "Run is no longer active; local results retained.",
            Self::Invalid => "Controller response or configuration is invalid.",
            Self::Local(message) => message,
        })
    }
}

struct Api {
    base: Url,
    client: Client,
    credential: String,
    queued_imports: bool,
}

fn base_url(input: &str) -> Result<Url, Error> {
    let mut url = if input.contains("://") {
        Url::parse(input)
    } else {
        Url::parse(&format!("http://{input}"))
    }
    .map_err(|_| {
        Error::Local(
            "Controller URL is invalid; use https://otserver.example or http://127.0.0.1:3000.",
        )
    })?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.cannot_be_a_base()
        || !(url.scheme() == "https"
            || url.scheme() == "http"
                && matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]")))
    {
        return Err(Error::Local(
            "Controller URL requires HTTPS (HTTP is limited to loopback) and must not contain credentials, a query, or a fragment.",
        ));
    }
    url.set_path(&format!("{}/", url.path().trim_end_matches('/')));
    Ok(url)
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn expires_at(input: &str) -> Result<OffsetDateTime, Error> {
    OffsetDateTime::parse(input, &Rfc3339).map_err(|_| Error::Invalid)
}

fn validate_credential(credential: &Credential) -> Result<(), Error> {
    if !(40..=512).contains(&credential.credential.len())
        || !credential
            .credential
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        || expires_at(&credential.credential_expires_at)? <= OffsetDateTime::now_utc()
    {
        return Err(Error::Invalid);
    }
    Ok(())
}

fn lease_deadline(input: &str) -> Result<Instant, Error> {
    let remaining = expires_at(input)? - OffsetDateTime::now_utc();
    // Fail closed before the server deadline; never trust a lease longer than v1's 30 minutes.
    let seconds = remaining.as_seconds_f64().min(30.0 * 60.0) - 5.0;
    if seconds <= 0.0 {
        return Err(Error::Terminal);
    }
    Ok(Instant::now() + Duration::from_secs_f64(seconds))
}

impl Api {
    fn new(base: Url, http: &HttpOptions) -> Result<Self, Error> {
        let client = http
            .apply(
                Client::builder()
                    .connect_timeout(Duration::from_secs(10))
                    .timeout(Duration::from_secs(10))
                    // Never forward machine credentials or enrollment data to a redirect target.
                    .redirect(reqwest::redirect::Policy::none()),
            )
            .map_err(Error::Local)?
            .build()
            .map_err(|_| Error::Local("Could not initialize controller TLS client."))?;
        Ok(Self {
            base,
            credential: String::new(),
            queued_imports: false,
            client,
        })
    }

    fn request(
        &self,
        method: reqwest::Method,
        path: &str,
    ) -> Result<reqwest::RequestBuilder, Error> {
        let url = self
            .base
            .join(path.trim_start_matches('/'))
            .map_err(|_| Error::Invalid)?;
        let mut request = self.client.request(method, url);
        if !self.credential.is_empty() {
            let mut header =
                reqwest::header::HeaderValue::from_str(&format!("Otter {}", self.credential))
                    .map_err(|_| Error::Invalid)?;
            header.set_sensitive(true);
            request = request.header(reqwest::header::AUTHORIZATION, header);
        }
        Ok(request)
    }

    async fn post<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: Value,
    ) -> Result<T, Error> {
        let response = self
            .request(reqwest::Method::POST, path)?
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body.to_string())
            .send()
            .await
            .map_err(|_| Error::Retry)?;
        decode(response).await
    }

    async fn heartbeat(&self, id: &str, progress: u8) -> Result<Instant, Error> {
        let response: Heartbeat = self
            .post(
                &format!("api/otter/v1/runs/{id}/heartbeat"),
                json!({"progress": progress}),
            )
            .await?;
        if response.cancel_requested {
            return Err(Error::Local("cancelled"));
        }
        lease_deadline(response.lease_expires_at.as_deref().ok_or(Error::Invalid)?)
    }

    async fn upload(
        &self,
        id: &str,
        path: &std::path::Path,
        queued: bool,
    ) -> Result<crate::ImportDocument, Error> {
        let data = tokio::fs::read(path)
            .await
            .map_err(|_| Error::Local("Could not read retained scan result."))?;
        let metadata = import_metadata(id, queued);
        let form = reqwest::multipart::Form::new()
            .text("_payload", metadata.to_string())
            .part(
                "file",
                reqwest::multipart::Part::bytes(data)
                    .file_name("otserver-scan.json")
                    .mime_str("application/json")
                    .map_err(|_| Error::Invalid)?,
            );
        let response = self
            .request(reqwest::Method::POST, "api/asset-imports")?
            .timeout(Duration::from_secs(300))
            .multipart(form)
            .send()
            .await
            .map_err(|_| Error::Retry)?;
        let response: crate::CreateImportResponse = decode(response).await?;
        Ok(response.doc)
    }
}

fn import_metadata(id: &str, queued: bool) -> Value {
    json!({"source": "otserver-otter", "sourceVersion": otserver_otter::VERSION,
        "otterRun": id, "executionMode": if queued { "queued" } else { "sync" }})
}

async fn decode<T: serde::de::DeserializeOwned>(
    mut response: reqwest::Response,
) -> Result<T, Error> {
    let status = response.status();
    if !status.is_success() {
        return Err(match status.as_u16() {
            401 | 403 => Error::Auth,
            404 | 409 | 410 => Error::Terminal,
            408 | 425 | 429 | 500..=599 => Error::Retry,
            _ => Error::Invalid,
        });
    }
    let max = crate::MAX_IMPORT_RESPONSE_BYTES;
    if response
        .content_length()
        .is_some_and(|len| len > max as u64)
    {
        return Err(Error::Invalid);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| Error::Retry)? {
        if chunk.len() > max - body.len() {
            return Err(Error::Invalid);
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(body.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&body))
        .map_err(|_| Error::Invalid)
}

// Managed scans deliberately suppress scan/probe output: even protocol errors may contain secrets.
struct Quiet;
impl LogOutput for Quiet {
    fn write(&self, _msg: String) {}
}

fn mapped_config(
    assignment: &Assignment,
    api: &Api,
    scanner: &Scanner,
) -> Result<ScannerConfig, Error> {
    if !valid_id(&assignment.id) || assignment.upload_path != "/api/asset-imports" {
        return Err(Error::Local(
            "The controller supplied an invalid run ID or upload path.",
        ));
    }
    let configuration = assignment.configuration.as_object().ok_or(Error::Local(
        "Managed scan configuration must be an object.",
    ))?;
    const FIELDS: &[&str] = &[
        "name",
        "targets",
        "interface",
        "sourceMac",
        "serverUrl",
        "site",
        "noProtocols",
        "noArp",
        "noProfinet",
        "allowDcpSource",
        "noS7",
        "noEnip",
        "noBacnet",
        "noFins",
        "noFox",
        "noDnp3",
        "noIec61850",
        "noNetbios",
        "noSmb",
        "noRpc",
        "noHttp",
        "noAds",
        "noOpcua",
        "noSnmp",
        "noLldp",
        "opcuaPorts",
        "adsSourceNetId",
        "adsTargetNetIds",
        "adsPorts",
    ];
    if configuration
        .keys()
        .any(|key| !FIELDS.contains(&key.as_str()))
    {
        return Err(Error::Local(
            "Managed scan configuration contains an unsupported option. Check that the scanner and controller versions are compatible.",
        ));
    }
    if configuration.values().any(Value::is_null) {
        return Err(Error::Local(
            "Managed scan configuration contains a null option. Optional unset fields must be omitted.",
        ));
    }
    if configuration.get("site").and_then(Value::as_str) != Some(&scanner.site) {
        return Err(Error::Local(
            "The managed scan site does not match this scanner's enrolled site.",
        ));
    }
    let server_url = configuration
        .get("serverUrl")
        .and_then(Value::as_str)
        .ok_or(Error::Local(
            "Managed scan configuration is missing its controller URL.",
        ))?;
    if base_url(server_url)? != api.base {
        return Err(Error::Local(
            "The managed scan controller URL does not match --server-url. Use the same scheme, host, port, and base path as OTSERVER_PUBLIC_URL.",
        ));
    }
    let mut config: ScannerConfig =
        serde_json::from_value(assignment.configuration.clone()).map_err(|_| Error::Local("Managed scan configuration has invalid option types. Targets and AMS NetIDs must be text, protocol toggles booleans, and ports integers."))?;
    if config.interface.as_ref().is_some_and(|value| {
        value.trim().is_empty() || value.len() > 256 || value.chars().any(char::is_control)
    }) || config.name.as_ref().is_some_and(|value| {
        value.trim().is_empty() || value.len() > 120 || value.chars().any(char::is_control)
    }) {
        return Err(Error::Local(
            "The managed profile name or network interface is empty, too long, or contains control characters.",
        ));
    }
    let targets = config
        .targets
        .as_ref()
        .ok_or(Error::Local("The managed scan is missing its targets."))?;
    if targets.is_empty() || targets.len() > 1024 || targets.iter().any(|t| t.len() > 64) {
        return Err(Error::Local(
            "Managed scan targets must contain 1 to 1,024 IPv4 addresses or CIDR ranges.",
        ));
    }
    otserver_otter::discovery::expand_targets(targets).map_err(|_| {
        Error::Local("Managed scan targets are invalid or exceed the 65,536-address limit.")
    })?;
    if config
        .opcua_ports
        .as_ref()
        .is_some_and(|ports| ports.len() > 64 || ports.contains(&0))
        || config
            .source_mac
            .as_deref()
            .is_some_and(|mac| otserver_otter::contract::normalize_mac(mac).is_none())
    {
        return Err(Error::Local(
            "Managed OPC UA ports or source MAC are invalid. Ports must be 1–65535 (at most 64); source MAC must contain six colon-separated hexadecimal bytes.",
        ));
    }
    if config
        .ads_target_net_ids
        .as_ref()
        .is_some_and(|net_ids| net_ids.len() > 1024)
    {
        return Err(Error::Local(
            "Managed ADS target NetID map exceeds the 1,024-entry limit.",
        ));
    }
    let empty_net_ids = std::collections::BTreeMap::new();
    otserver_otter::protocols::AdsSettings::from_config(
        config.ads_source_net_id.as_deref(),
        config.ads_target_net_ids.as_ref().unwrap_or(&empty_net_ids),
        config.ads_ports.as_deref().unwrap_or_default(),
    )
    .map_err(|_| Error::Local("Managed ADS AMS NetID or port settings are invalid."))?;
    let credentials = assignment.credentials.as_object().ok_or(Error::Local(
        "Managed protocol credentials must be an object.",
    ))?;
    if credentials.keys().any(|key| {
        !["snmp", "opcuaCredentials", "opcuaUsername", "opcuaPassword"].contains(&key.as_str())
    }) {
        return Err(Error::Local(
            "Managed protocol credentials contain an unsupported credential option.",
        ));
    }
    let secrets: ScannerConfig = serde_json::from_value(assignment.credentials.clone())
        .map_err(|_| Error::Local("Managed protocol credentials have invalid field types."))?;
    for (key, value) in credentials {
        if matches!(key.as_str(), "snmp" | "opcuaCredentials") {
            let entries: Vec<&Value> = match value {
                Value::Array(entries) => entries.iter().collect(),
                entry => vec![entry],
            };
            if entries.len() > 32
                || entries.iter().any(|entry| {
                    entry.as_object().is_none_or(|fields| {
                        fields
                            .iter()
                            .any(|(field, value)| !bounded_secret(field, value))
                    })
                })
            {
                return Err(Error::Local(
                    "Managed SNMP or OPC UA credentials contain invalid entries or exceed their size limits.",
                ));
            }
        } else if !bounded_secret(key, value) {
            return Err(Error::Local(
                "Managed OPC UA fallback credentials must be text within the supported size limits.",
            ));
        }
    }
    config.snmp = secrets.snmp;
    config.opcua_credentials = secrets.opcua_credentials;
    config.opcua_username = secrets.opcua_username;
    config.opcua_password = secrets.opcua_password;
    if let Some(settings) = &config.snmp {
        let settings = settings.to_vec();
        if settings.len() > 32
            || settings.iter().any(|s| {
                otserver_otter::snmp::attempt_description(s).is_err()
                    || !otserver_otter::snmp::resolved_version(s).eq_ignore_ascii_case("auto")
                        && otserver_otter::snmp::auth(s).is_err()
            })
        {
            return Err(Error::Local(
                "Managed SNMP credentials are invalid. Check the version, SNMPv3 username, authentication/privacy algorithms, and required passwords.",
            ));
        }
    }
    if config
        .opcua_credentials
        .as_ref()
        .is_some_and(|c| c.to_vec().len() > 32)
    {
        return Err(Error::Local(
            "Managed OPC UA credentials exceed the 32-entry limit.",
        ));
    }
    config.server_url = None;
    config.site = None;
    Ok(config)
}

fn bounded_secret(key: &str, value: &Value) -> bool {
    value.as_str().is_some_and(|value| {
        value.len()
            <= if key.to_ascii_lowercase().contains("password") {
                4096
            } else {
                512
            }
    })
}

fn scan_options(mut config: ScannerConfig, output: PathBuf) -> Result<ScanOptions, Error> {
    let interfaces = otserver_otter::profinet::interfaces()
        .map_err(|_| Error::Local("Could not enumerate capture interfaces."))?;
    // An omitted interface is only unambiguous on a host with a single capture adapter.
    if config.interface.is_none() {
        let candidates: Vec<_> = interfaces
            .iter()
            .filter(|i| otserver_otter::profinet::interface_mac(i).is_some())
            .collect();
        if candidates.len() != 1 {
            return Err(Error::Local(
                "Select an explicit interface in the managed profile.",
            ));
        }
        config.interface = Some(candidates[0].name.clone());
    }
    let selected = crate::selected_interface(
        config.interface.as_deref().ok_or(Error::Invalid)?,
        &interfaces,
    )
    .ok_or(Error::Local(
        "The selected network interface is not available on this scanner.",
    ))?;
    if config.source_mac.is_none() {
        config.source_mac = otserver_otter::profinet::interface_mac(selected);
    }
    if config.source_mac.is_none() {
        return Err(Error::Local(
            "Could not determine the selected interface's source MAC address.",
        ));
    }
    config.output = Some(output);
    resolve_scan(
        ScanArgs {
            ack_authorized: true,
            ..ScanArgs::default()
        },
        config,
        None,
    )
    .map_err(|_| Error::Local("Could not resolve the managed scan options."))
}

// Never forward arbitrary discovery/protocol text: it may contain managed credentials.
fn scan_failure_reason(error: &str) -> &'static str {
    if error.contains("Permission denied") || error.contains("Operation not permitted") {
        "Discovery or export access was denied. Check capture privileges and scanner state-directory permissions. Linux raw capture requires root or CAP_NET_RAW."
    } else if error.starts_with("Could not determine the current MAC of interface") {
        "Could not determine the selected interface's current MAC address. Check that the adapter is available."
    } else if error.starts_with("Could not write export:") {
        "Could not write the scan export to the scanner's private state directory. Check disk space and directory permissions."
    } else if error.starts_with("Could not finalize export:") {
        "Could not finalize the scan export in the scanner's private state directory. Check disk space and directory permissions."
    } else {
        "Discovery or scan-export validation failed before a usable result could be saved."
    }
}

fn save(store: &store::Store, state: &State) -> Result<(), Error> {
    store.save(state)
}

async fn finish(
    api: &Api,
    store: &store::Store,
    state: &mut State,
    status: &str,
    message: Option<&str>,
) -> Result<(), Error> {
    let run = state.assignment.as_mut().ok_or(Error::Invalid)?;
    run.phase = Phase::Finishing;
    run.status = status.into();
    if let Some(message) = message {
        run.message.get_or_insert_with(|| message.into());
    }
    save(store, state)?;
    let run = state.assignment.as_ref().ok_or(Error::Invalid)?;
    if run.status == "failed"
        && let Some(message) = &run.message
    {
        eprintln!("Managed scan failed: {message}");
    }
    let response: Value = api
        .post(
            &format!("api/otter/v1/runs/{}/finish", run.id),
            json!({"status": run.status, "importID": run.import_id, "message": run.message}),
        )
        .await?;
    let status = response["status"].as_str().ok_or(Error::Invalid)?;
    if !matches!(status, "completed" | "partial" | "failed" | "cancelled") {
        return Err(Error::Invalid);
    }
    let run = state.assignment.as_mut().ok_or(Error::Invalid)?;
    run.phase = Phase::Terminal;
    run.status = status.into();
    save(store, state)
}

async fn leased<T>(
    api: &Api,
    id: &str,
    mut deadline: Instant,
    progress: u8,
    future: impl std::future::Future<Output = Result<T, Error>>,
) -> Result<T, Error> {
    if Instant::now() >= deadline {
        return Err(Error::Terminal);
    }
    match tokio::time::timeout_at(deadline, api.heartbeat(id, progress)).await {
        Ok(Ok(next)) => deadline = next,
        Ok(Err(Error::Retry)) => {}
        Ok(Err(error)) => return Err(error),
        Err(_) => return Err(Error::Terminal),
    }
    tokio::pin!(future);
    let mut tick = tokio::time::interval_at(
        Instant::now() + Duration::from_secs(15),
        Duration::from_secs(15),
    );
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        if Instant::now() >= deadline {
            return Err(Error::Terminal);
        }
        tokio::select! {
            biased;
            () = tokio::time::sleep_until(deadline) => return Err(Error::Terminal),
            _ = tick.tick() => {
                match tokio::time::timeout_at(deadline, api.heartbeat(id, progress)).await {
                    Ok(Ok(next)) => deadline = next,
                    Ok(Err(Error::Retry)) => {},
                    Ok(Err(error)) => return Err(error),
                    Err(_) => return Err(Error::Terminal),
                }
            }
            result = &mut future => return if Instant::now() < deadline { result } else { Err(Error::Terminal) },
        }
    }
}

async fn upload_with_retries<F>(
    store: &store::Store,
    state: &mut State,
    mut upload: impl FnMut() -> F,
) -> Result<crate::ImportDocument, Error>
where
    F: std::future::Future<Output = Result<crate::ImportDocument, Error>>,
{
    loop {
        let run = state.assignment.as_mut().ok_or(Error::Invalid)?;
        let attempts = run.upload_attempts;
        if attempts >= 6 {
            return Err(Error::UploadRetriesExhausted);
        }
        if attempts > 0 {
            eprintln!("Retrying scan result upload in 2 minutes (retry {attempts} of 5).");
            tokio::time::sleep(Duration::from_secs(120)).await;
        }
        // Reserve the attempt before sending so restarts cannot reset the retry limit.
        run.upload_attempts = attempts + 1;
        save(store, state)?;
        match upload().await {
            Err(Error::Retry) => continue,
            result => return result,
        }
    }
}

async fn execute(
    api: &Api,
    store: &store::Store,
    state: &mut State,
    assignment: Assignment,
) -> Result<(), Error> {
    let deadline = lease_deadline(&assignment.lease_expires_at)?;
    let id = &assignment.id;
    if !valid_id(id) {
        return Err(Error::Invalid);
    }
    if state.assignment.as_ref().is_none_or(|run| run.id != *id) {
        state.assignment = Some(RunState {
            id: id.clone(),
            phase: Phase::Assigned,
            status: "failed".into(),
            import_id: None,
            message: None,
            upload_attempts: 0,
        });
        save(store, state)?;
    }
    let phase = state
        .assignment
        .as_ref()
        .ok_or(Error::Invalid)?
        .phase
        .clone();
    if matches!(phase, Phase::Terminal | Phase::Finishing) {
        let status = state
            .assignment
            .as_ref()
            .ok_or(Error::Invalid)?
            .status
            .clone();
        return finish(api, store, state, &status, None).await;
    }
    if phase == Phase::Scanning {
        // A crash during discovery is uncertain work. Never replay active probes for this ID.
        return finish(api, store, state, "failed", Some("Scanner restarted during discovery. The interrupted scan was not replayed to avoid duplicate probes.")).await;
    }
    let path = store.result_path(id);
    if phase == Phase::Assigned {
        let config = match mapped_config(
            &assignment,
            api,
            state.scanner.as_ref().ok_or(Error::Invalid)?,
        ) {
            Ok(config) => config,
            Err(error) => {
                return finish(api, store, state, "failed", Some(&error.to_string())).await;
            }
        };
        let name = config.name.clone().unwrap_or_else(|| "Managed scan".into());
        let options = match scan_options(config, path.clone()) {
            Ok(options) => options,
            Err(error) => {
                return finish(api, store, state, "failed", Some(&error.to_string())).await;
            }
        };
        state.assignment.as_mut().ok_or(Error::Invalid)?.phase = Phase::Scanning;
        save(store, state)?;
        let start: Value = api
            .post(&format!("api/otter/v1/runs/{id}/start"), json!({}))
            .await?;
        if start["status"] != "running" {
            return Err(Error::Terminal);
        }
        let cancelled = Arc::new(AtomicBool::new(false));
        let scan_future = scan(&name, &options, &Quiet, &cancelled);
        tokio::pin!(scan_future);
        let mut completed = false;
        let outcome = leased(api, id, deadline, 0, async {
            let result = scan_future.as_mut().await;
            completed = true;
            Ok(result)
        })
        .await;
        let partial = match outcome {
            Ok(Ok(partial)) => partial,
            Ok(Err(error)) => {
                return finish(
                    api,
                    store,
                    state,
                    "failed",
                    Some(scan_failure_reason(&error)),
                )
                .await;
            }
            Err(error) => {
                cancelled.store(true, Ordering::Relaxed);
                // Raw discovery uses blocking tasks; wait for their cooperative safe stop.
                if !completed {
                    let _ = scan_future.as_mut().await;
                }
                return Err(error);
            }
        };
        store.sync_result(id)?;
        let run = state.assignment.as_mut().ok_or(Error::Invalid)?;
        run.phase = Phase::Ready;
        run.status = if partial { "partial" } else { "completed" }.into();
        save(store, state)?;
    }
    let deadline = api.heartbeat(id, 90).await?;
    if state
        .assignment
        .as_ref()
        .ok_or(Error::Invalid)?
        .import_id
        .is_none()
    {
        let imported = match leased(
            api,
            id,
            deadline,
            90,
            upload_with_retries(store, state, || api.upload(id, &path, api.queued_imports)),
        )
        .await
        {
            Err(Error::UploadRetriesExhausted) => {
                return finish(
                    api,
                    store,
                    state,
                    "failed",
                    Some(&Error::UploadRetriesExhausted.to_string()),
                )
                .await;
            }
            result => result?,
        };
        let import_id = imported
            .id
            .as_str()
            .filter(|id| valid_id(id))
            .ok_or(Error::Invalid)?
            .to_owned();
        state.assignment.as_mut().ok_or(Error::Invalid)?.import_id = Some(import_id.clone());
        if !matches!(
            imported.status.as_str(),
            "pending" | "running" | "completed" | "failed"
        ) {
            return Err(Error::Invalid);
        }
        eprintln!(
            "Scanner result uploaded; import status: {}.",
            imported.status
        );
        if api.queued_imports && imported.status != "completed" {
            state.pending_imports.push(PendingImport {
                id: import_id,
                status: imported.status,
                retries: 0,
            });
        }
        // Scanner outcome is deliberately independent of import processing success.
        save(store, state)?;
    }
    let status = state
        .assignment
        .as_ref()
        .ok_or(Error::Invalid)?
        .status
        .clone();
    finish(api, store, state, &status, None).await
}

async fn imports(api: &Api, store: &store::Store, state: &mut State) -> Result<(), Error> {
    for index in 0..state.pending_imports.len() {
        let response = api
            .request(
                reqwest::Method::GET,
                &format!("api/asset-imports/{}", state.pending_imports[index].id),
            )?
            .send()
            .await
            .map_err(|_| Error::Retry)?;
        let mut document: crate::ImportDocument = decode(response).await?;
        if document.status == "failed" && state.pending_imports[index].retries == 0 {
            // One bounded queued retry using the known ID; never re-upload a terminal run.
            state.pending_imports[index].retries = 1;
            save(store, state)?;
            let response: crate::CreateImportResponse = api
                .post(
                    &format!(
                        "api/asset-imports/{}/retry",
                        state.pending_imports[index].id
                    ),
                    json!({}),
                )
                .await?;
            document = response.doc;
        }
        if !matches!(
            document.status.as_str(),
            "pending" | "running" | "completed" | "failed"
        ) {
            return Err(Error::Invalid);
        }
        if document.status != state.pending_imports[index].status {
            eprintln!("Import processing status: {}.", document.status);
        }
        state.pending_imports[index].status = document.status;
    }
    state
        .pending_imports
        .retain(|i| matches!(i.status.as_str(), "pending" | "running"));
    save(store, state)
}

pub async fn run(args: ControllerArgs) -> Result<(), String> {
    run_inner(args).await.map_err(|error| error.to_string())
}

async fn run_inner(args: ControllerArgs) -> Result<(), Error> {
    let (store, mut state, mut api) = initialize(&args, None).await?;
    if args.install {
        let directory = store.path().to_owned();
        drop(store);
        let message = install::install(Some(directory), false).map_err(|message| {
            eprintln!("{message}");
            Error::Local(
                "Controller installation failed; enrollment and retained exports are kept.",
            )
        })?;
        eprintln!("{message}");
        return Ok(());
    }
    if args.enroll_only {
        eprintln!("Scanner enrolled; credentials saved. Install or start the controller to poll.");
        return Ok(());
    }
    eprintln!("Polling controller.");
    let settings = state.settings.clone();
    loop {
        let delay = poll_once(
            &mut api,
            &store,
            &mut state,
            settings.poll_seconds,
            settings.file_credentials,
        )
        .await?;
        tokio::time::sleep(delay).await;
    }
}

async fn initialize(
    args: &ControllerArgs,
    supplied_token: Option<&str>,
) -> Result<(store::Store, State, Api), Error> {
    if !args.ack_authorized {
        return Err(Error::Local("Managed scanning requires --ack-authorized."));
    }
    let requested_base = if args.server_url.is_empty() {
        None
    } else {
        Some(base_url(&args.server_url)?)
    };
    let store = store::Store::open(args.state_dir.clone())?;
    let mut state = store.load()?;
    let base = match requested_base {
        Some(base) => base,
        None => base_url(&state.server_url)?,
    };
    if !state.server_url.is_empty()
        && state.server_url != base.as_str()
        && !(args.enroll && args.overwrite_state_dir)
    {
        return Err(Error::Local(
            "State directory belongs to a different controller URL. To replace its saved enrollment and run state, re-enroll with --enroll --overwrite-state-dir. Retained scan exports will be kept.",
        ));
    }
    let mut settings = state.settings.clone();
    settings.poll_seconds = args.poll_seconds.unwrap_or(settings.poll_seconds);
    if !(1..=300).contains(&settings.poll_seconds) {
        return Err(Error::Invalid);
    }
    settings.file_credentials |= args.file_credentials;
    settings.queued_imports |= args.queued_imports;
    if supplied_token.is_some() {
        settings.http = HttpOptions::default();
    }
    settings.http.ignore_self_signed |= args.ignore_self_signed;
    if let Some(proxy) = &args.http_proxy {
        settings.http.http_proxy = Some(proxy.clone());
    }
    if let Some(proxy) = &args.https_proxy {
        settings.http.https_proxy = Some(proxy.clone());
    }
    let mut api = Api::new(base, &settings.http)?;
    api.queued_imports = settings.queued_imports;
    if args.enroll {
        use std::io::{BufRead, Read};
        let mut token = String::new();
        let token = if let Some(token) = supplied_token {
            token
        } else {
            eprintln!("Paste the single-use enrollment token, then press Enter:");
            std::io::stdin()
                .lock()
                .take(513)
                .read_line(&mut token)
                .map_err(|_| Error::Local("Could not read enrollment token from stdin."))?;
            &token
        };
        let token = token.trim();
        if !(40..=512).contains(&token.len())
            || !token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(Error::Local(
                "Enrollment token is invalid; copy a fresh single-use token from OTserver > Otter Scanners.",
            ));
        }
        let report = scanner_report()?;
        let mut enrollment_request = serde_json::to_value(report).map_err(|_| Error::Invalid)?;
        enrollment_request["token"] = json!(token);
        let enrollment: Enrollment = api.post("api/otter/v1/enroll", enrollment_request).await
            .map_err(|error| if error == Error::Retry {
                Error::Local("Could not complete enrollment. Check the controller connection and retry; request a new token if the server already consumed it.")
            } else { error })?;
        validate_credential(&enrollment.credential)?;
        if !valid_id(&enrollment.scanner.id) || !valid_id(&enrollment.scanner.site) {
            return Err(Error::Invalid);
        }
        state.server_url = api.base.to_string();
        state.scanner = Some(enrollment.scanner);
        state.assignment = None;
        state.pending_imports.clear();
        state.settings = settings.clone();
        store.persist_credential(
            &mut state,
            &enrollment.credential,
            settings.file_credentials,
        )?;
        api.credential = enrollment.credential.credential;
        eprintln!("Scanner enrolled.");
    } else {
        api.credential = store.credential(&state)?;
    }
    if state.scanner.is_none() {
        return Err(Error::Local("Enroll this scanner before polling."));
    }
    state.settings = settings;
    store.save(&state)?;
    Ok((store, state, api))
}

#[cfg(feature = "gui")]
pub(super) async fn enroll_from_gui(
    server_url: String,
    token: String,
    overwrite: bool,
    http: HttpOptions,
) -> Result<(), String> {
    let args = ControllerArgs {
        server_url,
        enroll: true,
        enroll_only: true,
        install: false,
        state_dir: None,
        overwrite_state_dir: overwrite,
        poll_seconds: None,
        ack_authorized: true,
        file_credentials: false,
        queued_imports: false,
        ignore_self_signed: http.ignore_self_signed,
        http_proxy: http.http_proxy,
        https_proxy: http.https_proxy,
    };
    initialize(&args, Some(&token))
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

#[cfg(feature = "gui")]
pub(super) fn install_from_gui() -> Result<String, String> {
    install::install(None, true)
}

async fn poll_once(
    api: &mut Api,
    store: &store::Store,
    state: &mut State,
    poll_seconds: u64,
    file_credentials: bool,
) -> Result<Duration, Error> {
    let result = async {
        let expiry = expires_at(&state.credential_expires_at)?;
        if expiry <= OffsetDateTime::now_utc() {
            return Err(Error::Auth);
        }
        if expiry - OffsetDateTime::now_utc() < time::Duration::days(30) {
            let rotated: Credential = api
                .post("api/otter/v1/credentials/rotate", json!({}))
                .await?;
            validate_credential(&rotated)?;
            // Persist first. Any storage failure exits; never fall back to the revoked credential.
            store.persist_credential(state, &rotated, file_credentials)?;
            api.credential = rotated.credential;
        }
        let report = scanner_report()?;
        let poll: Poll = api.post("api/otter/v1/poll", json!(report)).await?;
        match poll {
            Poll::Idle {
                retry_after_seconds,
            } => {
                if let Some(run) = &mut state.assignment {
                    run.phase = Phase::Terminal;
                }
                imports(api, store, state).await?;
                Ok(retry_after_seconds.clamp(poll_seconds, 300))
            }
            Poll::Cancel { run_id } => {
                if !valid_id(&run_id) {
                    return Err(Error::Invalid);
                }
                if state.assignment.as_ref().is_none_or(|r| r.id != run_id) {
                    state.assignment = Some(RunState {
                        id: run_id,
                        phase: Phase::Finishing,
                        status: "cancelled".into(),
                        import_id: None,
                        message: None,
                        upload_attempts: 0,
                    });
                }
                finish(api, store, state, "cancelled", None).await?;
                Ok(poll_seconds)
            }
            Poll::Run { run } => {
                let id = run.id.clone();
                match execute(api, store, state, run).await {
                    Err(Error::Local("cancelled")) => {
                        finish(api, store, state, "cancelled", None).await?
                    }
                    Err(Error::Invalid)
                        if state.assignment.as_ref().is_some_and(|run| run.id == id) =>
                    {
                        finish(
                            api,
                            store,
                            state,
                            "failed",
                            Some("Controller response or managed scan configuration is invalid."),
                        )
                        .await?
                    }
                    other => other?,
                }
                Ok(poll_seconds)
            }
        }
    }
    .await;
    match result {
        Ok(seconds) => Ok(Duration::from_secs(seconds)),
        Err(error @ (Error::Retry | Error::InterfacesUnavailable)) => {
            eprintln!("{error}");
            Ok(Duration::from_secs(300))
        }
        Err(Error::Terminal) => {
            if let Some(run) = &mut state.assignment {
                run.phase = Phase::Terminal;
            }
            save(store, state)?;
            Ok(Duration::from_secs(poll_seconds))
        }
        Err(error) => Err(error),
    }
}
