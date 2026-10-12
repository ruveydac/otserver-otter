//! Outbound controller v1 client. Local scans still use the shared safety/pacing path.
mod store;
#[cfg(test)]
mod tests;

use crate::{LogOutput, ScanArgs, ScanOptions, ScannerConfig, resolve_scan, scan};
use clap::Args;
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::time::Instant;

#[derive(Args)]
pub struct ControllerArgs {
    #[arg(long)]
    server_url: String,
    /// Read the single-use enrollment token from stdin (never from process arguments).
    #[arg(long)]
    enroll: bool,
    #[arg(long)]
    state_dir: Option<PathBuf>,
    #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..=300))]
    poll_seconds: u64,
    #[arg(long, required = true, action = clap::ArgAction::SetTrue)]
    ack_authorized: bool,
    /// Use the permission-restricted credential file instead of the OS secret store.
    #[arg(long)]
    file_credentials: bool,
    /// Request queued imports (requires OTSERVER_QUEUED_IMPORTS=on on the manager).
    #[arg(long)]
    queued_imports: bool,
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
}

#[derive(Debug, PartialEq, Eq)]
enum Error {
    Retry,
    Auth,
    Terminal,
    Invalid,
    Local(&'static str),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Retry => "Controller unavailable; retrying with backoff.",
            Self::Auth => "Scanner authentication rejected; re-enroll this scanner.",
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
    let mut url = Url::parse(input).map_err(|_| Error::Invalid)?;
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
            "Controller URL requires HTTPS (HTTP is limited to loopback).",
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
    // Fail closed before the server deadline; never trust a lease longer than v1's two minutes.
    let seconds = remaining.as_seconds_f64().min(120.0) - 5.0;
    if seconds <= 0.0 {
        return Err(Error::Terminal);
    }
    Ok(Instant::now() + Duration::from_secs_f64(seconds))
}

fn backoff(attempt: u32, jitter: u64) -> Duration {
    let ceiling = (2u64.saturating_pow(attempt.min(8))).min(300);
    Duration::from_millis(ceiling * 500 + jitter % (ceiling * 500 + 1))
}

impl Api {
    fn new(base: Url) -> Result<Self, Error> {
        Ok(Self {
            base,
            credential: String::new(),
            queued_imports: false,
            client: Client::builder()
                .connect_timeout(Duration::from_secs(10))
                .timeout(Duration::from_secs(10))
                // Never forward machine credentials or enrollment data to a redirect target.
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(|_| Error::Local("Could not initialize controller TLS client."))?,
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
        return Err(Error::Invalid);
    }
    let configuration = assignment.configuration.as_object().ok_or(Error::Invalid)?;
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
        "noOpcua",
        "noSnmp",
        "noLldp",
        "opcuaPorts",
    ];
    if configuration
        .keys()
        .any(|key| !FIELDS.contains(&key.as_str()))
        || configuration.values().any(Value::is_null)
        || configuration.get("site").and_then(Value::as_str) != Some(&scanner.site)
        || base_url(
            configuration
                .get("serverUrl")
                .and_then(Value::as_str)
                .ok_or(Error::Invalid)?,
        )? != api.base
    {
        return Err(Error::Invalid);
    }
    let mut config: ScannerConfig =
        serde_json::from_value(assignment.configuration.clone()).map_err(|_| Error::Invalid)?;
    if config.interface.as_ref().is_some_and(|value| {
        value.trim().is_empty() || value.len() > 256 || value.chars().any(char::is_control)
    }) || config.name.as_ref().is_some_and(|value| {
        value.trim().is_empty() || value.len() > 120 || value.chars().any(char::is_control)
    }) {
        return Err(Error::Invalid);
    }
    let targets = config.targets.as_ref().ok_or(Error::Invalid)?;
    if targets.is_empty() || targets.len() > 1024 || targets.iter().any(|t| t.len() > 64) {
        return Err(Error::Invalid);
    }
    otserver_otter::discovery::expand_targets(targets).map_err(|_| Error::Invalid)?;
    if config
        .opcua_ports
        .as_ref()
        .is_some_and(|ports| ports.len() > 64 || ports.contains(&0))
        || config
            .source_mac
            .as_deref()
            .is_some_and(|mac| otserver_otter::contract::normalize_mac(mac).is_none())
    {
        return Err(Error::Invalid);
    }
    let credentials = assignment.credentials.as_object().ok_or(Error::Invalid)?;
    if credentials.keys().any(|key| {
        !["snmp", "opcuaCredentials", "opcuaUsername", "opcuaPassword"].contains(&key.as_str())
    }) {
        return Err(Error::Invalid);
    }
    let secrets: ScannerConfig =
        serde_json::from_value(assignment.credentials.clone()).map_err(|_| Error::Invalid)?;
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
                return Err(Error::Invalid);
            }
        } else if !bounded_secret(key, value) {
            return Err(Error::Invalid);
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
            return Err(Error::Invalid);
        }
    }
    if config
        .opcua_credentials
        .as_ref()
        .is_some_and(|c| c.to_vec().len() > 32)
    {
        return Err(Error::Invalid);
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
    .ok_or(Error::Invalid)?;
    if config.source_mac.is_none() {
        config.source_mac = otserver_otter::profinet::interface_mac(selected);
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
    .map_err(|_| Error::Invalid)
}

fn save(store: &store::Store, state: &State) -> Result<(), Error> {
    store.save(state)
}

async fn finish(
    api: &Api,
    store: &store::Store,
    state: &mut State,
    status: &str,
) -> Result<(), Error> {
    let run = state.assignment.as_mut().ok_or(Error::Invalid)?;
    run.phase = Phase::Finishing;
    run.status = status.into();
    save(store, state)?;
    let run = state.assignment.as_ref().ok_or(Error::Invalid)?;
    let response: Value = api
        .post(
            &format!("api/otter/v1/runs/{}/finish", run.id),
            json!({"status": run.status, "importID": run.import_id}),
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
        return finish(api, store, state, &status).await;
    }
    if phase == Phase::Scanning {
        // A crash during discovery is uncertain work. Never replay active probes for this ID.
        return finish(api, store, state, "failed").await;
    }
    let path = store.result_path(id);
    if phase == Phase::Assigned {
        let config = mapped_config(
            &assignment,
            api,
            state.scanner.as_ref().ok_or(Error::Invalid)?,
        )?;
        let name = config.name.clone().unwrap_or_else(|| "Managed scan".into());
        let options = scan_options(config, path.clone())?;
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
            Ok(Err(_)) => return finish(api, store, state, "failed").await,
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
        let imported = leased(
            api,
            id,
            deadline,
            90,
            api.upload(id, &path, api.queued_imports),
        )
        .await?;
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
    finish(api, store, state, &status).await
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
    if !args.ack_authorized {
        return Err(Error::Local("Managed scanning requires --ack-authorized."));
    }
    let base = base_url(&args.server_url)?;
    let store = store::Store::open(args.state_dir)?;
    let mut state = store.load()?;
    if !state.server_url.is_empty() && state.server_url != base.as_str() {
        return Err(Error::Local(
            "State directory belongs to a different controller URL.",
        ));
    }
    let mut api = Api::new(base)?;
    api.queued_imports = args.queued_imports;
    if args.enroll {
        use std::io::{BufRead, Read};
        let mut token = String::new();
        std::io::stdin()
            .lock()
            .take(513)
            .read_line(&mut token)
            .map_err(|_| Error::Local("Could not read enrollment token from stdin."))?;
        let token = token.trim();
        if !(40..=512).contains(&token.len())
            || !token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(Error::Invalid);
        }
        let enrollment: Enrollment = api
            .post("api/otter/v1/enroll", json!({"token": token}))
            .await?;
        validate_credential(&enrollment.credential)?;
        if !valid_id(&enrollment.scanner.id) || !valid_id(&enrollment.scanner.site) {
            return Err(Error::Invalid);
        }
        state.server_url = api.base.to_string();
        state.scanner = Some(enrollment.scanner);
        state.assignment = None;
        state.pending_imports.clear();
        store.persist_credential(&mut state, &enrollment.credential, args.file_credentials)?;
        api.credential = enrollment.credential.credential;
    } else {
        api.credential = store.credential(&state)?;
    }
    if state.scanner.is_none() {
        return Err(Error::Local("Enroll this scanner before polling."));
    }
    let mut attempt = 0;
    loop {
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
                store.persist_credential(&mut state, &rotated, args.file_credentials)?;
                api.credential = rotated.credential;
            }
            let interfaces = otserver_otter::profinet::interfaces()
                .map_err(|_| Error::Local("Could not enumerate capture interfaces."))?
                .into_iter()
                .map(|i| i.name)
                .take(128)
                .collect::<Vec<_>>();
            let poll: Poll = api
                .post(
                    "api/otter/v1/poll",
                    json!({"version": otserver_otter::VERSION,
                "capabilities": ["scan-v2", "controller-v1"], "interfaces": interfaces}),
                )
                .await?;
            match poll {
                Poll::Idle {
                    retry_after_seconds,
                } => {
                    if let Some(run) = &mut state.assignment {
                        run.phase = Phase::Terminal;
                    }
                    imports(&api, &store, &mut state).await?;
                    Ok(retry_after_seconds.clamp(args.poll_seconds, 300))
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
                        });
                    }
                    finish(&api, &store, &mut state, "cancelled").await?;
                    Ok(args.poll_seconds)
                }
                Poll::Run { run } => {
                    let id = run.id.clone();
                    match execute(&api, &store, &mut state, run).await {
                        Err(Error::Local("cancelled")) => {
                            finish(&api, &store, &mut state, "cancelled").await?
                        }
                        Err(Error::Invalid)
                            if state.assignment.as_ref().is_some_and(|run| run.id == id) =>
                        {
                            finish(&api, &store, &mut state, "failed").await?
                        }
                        other => other?,
                    }
                    Ok(args.poll_seconds)
                }
            }
        }
        .await;
        let delay = match result {
            Ok(seconds) => {
                attempt = 0;
                Duration::from_secs(seconds)
            }
            Err(Error::Retry) => {
                attempt += 1;
                eprintln!("{}", Error::Retry);
                backoff(attempt, uuid::Uuid::new_v4().as_u128() as u64)
            }
            Err(Error::Terminal) => {
                if let Some(run) = &mut state.assignment {
                    run.phase = Phase::Terminal;
                }
                save(&store, &state)?;
                Duration::from_secs(args.poll_seconds)
            }
            Err(error) => return Err(error),
        };
        tokio::time::sleep(delay).await;
    }
}
