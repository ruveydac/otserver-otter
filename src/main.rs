mod controller;
#[cfg(feature = "gui")]
pub mod gui;
use clap::{ArgAction, Args, Parser, Subcommand};
use otserver_otter::contract::{
    Device, InterfaceRef, ScanExport, ScanInfo, ScannerInfo, Source, merge_devices,
    unique_ip_identities, validate,
};
use otserver_otter::{discovery, profinet, protocols, snmp};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use uuid::Uuid;

#[cfg(test)]
pub(crate) static CONFIG_FILE_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub trait LogOutput: Send + Sync {
    fn write(&self, msg: String);

    fn log(&self, msg: String) {
        self.write(format_log_line(&msg));
    }

    fn devices(&self, _configuration: &str, _devices: &[Device]) {}
}

pub struct StdoutLogger;
impl LogOutput for StdoutLogger {
    fn write(&self, msg: String) {
        println!("{msg}");
    }
}

#[derive(Parser)]
#[command(
    name = "otserver-otter",
    version = env!("OTTER_BUILD_VERSION"),
    about = "Read-only OT discovery for OTserver — https://otserver.org"
)]
#[cfg_attr(not(feature = "gui"), command(subcommand_required = true))]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    Doctor,
    Interfaces {
        #[arg(long)]
        json: bool,
    },
    Scan(ScanArgs),
    /// Run an outbound-only, centrally managed scanner.
    Controller(controller::ControllerArgs),
    Validate {
        file: PathBuf,
    },
    #[cfg(feature = "gui")]
    Gui,
}

#[derive(Args, Clone, Default)]
pub struct ScanArgs {
    #[arg(long = "target")]
    pub targets: Vec<String>,
    #[arg(long)]
    pub interface: Option<String>,
    #[arg(long)]
    pub source_mac: Option<String>,
    #[arg(short, long)]
    pub output: Option<PathBuf>,
    #[arg(long, action = ArgAction::SetTrue, required = true)]
    pub ack_authorized: bool,
    #[arg(long, hide = true)]
    pub no_protocols: bool,
    #[arg(long)]
    pub no_arp: bool,
    #[arg(long)]
    pub no_profinet: bool,
    #[arg(long)]
    pub allow_dcp_source: bool,
    #[arg(long)]
    pub no_s7: bool,
    #[arg(long)]
    pub no_enip: bool,
    #[arg(long)]
    pub no_bacnet: bool,
    #[arg(long)]
    pub no_fins: bool,
    #[arg(long)]
    pub no_fox: bool,
    #[arg(long)]
    pub no_dnp3: bool,
    #[arg(long)]
    pub no_iec61850: bool,
    #[arg(long)]
    pub no_netbios: bool,
    #[arg(long)]
    pub no_smb: bool,
    #[arg(long)]
    pub no_rpc: bool,
    #[arg(long)]
    pub no_http: bool,
    #[arg(long)]
    pub no_ads: bool,
    #[arg(long)]
    pub no_opcua: bool,
    #[arg(long)]
    pub no_snmp: bool,
    #[arg(long)]
    pub no_lldp: bool,
    #[arg(long)]
    pub server_url: Option<String>,
    #[arg(long)]
    pub site: Option<String>,
    /// Disable TLS certificate and hostname validation for HTTP clients.
    #[arg(long)]
    pub ignore_self_signed: bool,
    /// Proxy HTTP requests through URL. HTTPS requests remain direct unless --https-proxy is supplied.
    #[arg(long, value_name = "URL")]
    pub http_proxy: Option<String>,
    /// Proxy HTTPS requests through URL. HTTP requests remain direct unless --http-proxy is supplied.
    #[arg(long, value_name = "URL")]
    pub https_proxy: Option<String>,
    #[arg(long, value_name = "NETID")]
    pub ads_source_net_id: Option<String>,
    #[arg(long = "ads-target-netid", value_name = "IP=NETID")]
    pub ads_target_netids: Vec<String>,
    #[arg(long = "ads-port", value_name = "AMS_PORT")]
    pub ads_ports: Vec<u16>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct HttpOptions {
    pub ignore_self_signed: bool,
    pub http_proxy: Option<String>,
    pub https_proxy: Option<String>,
}

impl HttpOptions {
    pub fn validate(&self) -> Result<(), &'static str> {
        if let Some(proxy) = self.http_proxy.as_deref() {
            reqwest::Proxy::http(proxy).map_err(|_| "HTTP proxy URL is invalid.")?;
        }
        if let Some(proxy) = self.https_proxy.as_deref() {
            reqwest::Proxy::https(proxy).map_err(|_| "HTTPS proxy URL is invalid.")?;
        }
        Ok(())
    }

    pub fn apply(
        &self,
        mut builder: reqwest::ClientBuilder,
    ) -> Result<reqwest::ClientBuilder, &'static str> {
        self.validate()?;
        if self.ignore_self_signed {
            builder = builder.tls_danger_accept_invalid_certs(true);
        }
        if let Some(proxy) = self.http_proxy.as_deref() {
            builder = builder
                .proxy(reqwest::Proxy::http(proxy).map_err(|_| "HTTP proxy URL is invalid.")?);
        }
        if let Some(proxy) = self.https_proxy.as_deref() {
            builder = builder
                .proxy(reqwest::Proxy::https(proxy).map_err(|_| "HTTPS proxy URL is invalid.")?);
        }
        Ok(builder)
    }
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct ScannerConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub targets: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_mac: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snmp: Option<snmp::Credentials>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_protocols: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_arp: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_profinet: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_dcp_source: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_s7: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_enip: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_bacnet: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_fins: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_fox: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_dnp3: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_iec61850: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_netbios: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_smb: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_rpc: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_http: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_ads: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_opcua: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_snmp: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_lldp: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opcua_ports: Option<Vec<u16>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opcua_credentials: Option<otserver_otter::protocols::OpcuaCredentials>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opcua_username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opcua_password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ads_source_net_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ads_target_net_ids: Option<BTreeMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ads_ports: Option<Vec<u16>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub site: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum ScannerConfigs {
    Multiple(Vec<ScannerConfig>),
    Single(Box<ScannerConfig>),
}

impl Default for ScannerConfigs {
    fn default() -> Self {
        Self::Single(Box::default())
    }
}

impl ScannerConfigs {
    pub fn configs(&self) -> &[ScannerConfig] {
        match self {
            Self::Single(config) => std::slice::from_ref(config.as_ref()),
            Self::Multiple(configs) => configs,
        }
    }

    pub fn configs_mut(&mut self) -> &mut [ScannerConfig] {
        match self {
            Self::Single(config) => std::slice::from_mut(config.as_mut()),
            Self::Multiple(configs) => configs,
        }
    }

    pub fn is_multiple(&self) -> bool {
        matches!(self, Self::Multiple(_))
    }

    fn validate(&self) -> Result<(), String> {
        if self.configs().is_empty() {
            return Err("Configuration list must contain at least one entry.".into());
        }

        let mut names = BTreeSet::new();
        for (index, config) in self.configs().iter().enumerate() {
            let Some(name) = config.name.as_deref() else {
                if self.is_multiple() {
                    return Err(format!("Configuration {} requires a name.", index + 1));
                }
                continue;
            };
            if name.is_empty() || name.trim() != name || name.chars().any(char::is_control) {
                return Err(format!(
                    "Configuration {} name must be non-empty, trimmed, and contain no control characters.",
                    index + 1
                ));
            }
            if self.is_multiple() && !names.insert(name) {
                return Err(format!("Configuration name {name:?} must be unique."));
            }
        }
        Ok(())
    }

    pub fn named_configs(&self) -> Vec<(String, ScannerConfig)> {
        self.configs()
            .iter()
            .enumerate()
            .map(|(index, config)| {
                let name = config.name.clone().unwrap_or_else(|| {
                    if self.is_multiple() {
                        format!("Configuration {}", index + 1)
                    } else {
                        "Configuration".into()
                    }
                });
                (name, config.clone())
            })
            .collect()
    }
}

pub struct UploadOptions {
    pub endpoint: reqwest::Url,
    pub site: String,
    pub api_key: String,
    pub http: HttpOptions,
}

pub struct ScanOptions {
    pub targets: Vec<String>,
    pub interface: String,
    pub source_mac: String,
    pub output: PathBuf,
    pub protocols: ProtocolOptions,
    pub allow_dcp_source: bool,
    pub snmp: Vec<snmp::Settings>,
    pub opcua: otserver_otter::protocols::OpcuaSettings,
    pub ads: otserver_otter::protocols::AdsSettings,
    pub upload: Option<UploadOptions>,
}

pub struct ConfiguredScan {
    pub name: String,
    pub options: ScanOptions,
}

#[derive(Default, Debug, PartialEq, Eq)]
pub struct BatchResult {
    pub completed: usize,
    pub partial: usize,
    pub failures: Vec<String>,
    pub cancelled: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProtocolOptions {
    pub arp: bool,
    pub profinet: bool,
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
    pub snmp: bool,
    pub lldp: bool,
    pub ads: bool,
}

impl Default for ProtocolOptions {
    fn default() -> Self {
        Self {
            arp: true,
            profinet: true,
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
            snmp: true,
            lldp: true,
            ads: true,
        }
    }
}

#[derive(Deserialize)]
struct CreateImportResponse {
    doc: ImportDocument,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImportDocument {
    id: serde_json::Value,
    status: String,
    created_assets: Option<u64>,
    updated_assets: Option<u64>,
    skipped_assets: Option<u64>,
    error: Option<String>,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    run_cli(Cli::parse()).await
}

async fn run_cli(cli: Cli) -> Result<(), String> {
    run_cli_with_configs(cli, None).await
}

async fn run_cli_with_configs(
    cli: Cli,
    scanner_configs: Option<ScannerConfigs>,
) -> Result<(), String> {
    match cli.command {
        Some(Commands::Controller(args)) => controller::run(args).await,
        Some(Commands::Doctor) => doctor(),
        Some(Commands::Interfaces { json }) => {
            let devices = profinet::interfaces()?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&devices).map_err(|error| error.to_string())?
                );
                return Ok(());
            }
            for device in devices {
                let addresses = device.addresses.join(", ");
                println!("{}\t{}\t{}", device.name, device.description, addresses);
            }
            Ok(())
        }
        Some(Commands::Validate { file }) => {
            let value: serde_json::Value = serde_json::from_slice(
                &tokio::fs::read(file)
                    .await
                    .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
            if value["format"] != "otserver-scan" || value["schemaVersion"] != 2 {
                return Err(
                    "Unsupported scanner file. Expected otserver-scan schemaVersion 2. Run a new scan with OTserver Otter."
                        .into(),
                );
            }
            let scan: ScanExport =
                serde_json::from_value(value).map_err(|error| error.to_string())?;
            validate(&scan)?;
            println!(
                "Valid otserver-scan v2 file with {} device(s).",
                scan.devices.len()
            );
            Ok(())
        }
        Some(Commands::Scan(args)) => {
            let configs = match scanner_configs {
                Some(configs) => configs,
                None => load_config()?,
            };
            let logger = StdoutLogger;
            let cancelled = Arc::new(AtomicBool::new(false));
            let (scans, mut failures) = prepare_scans(
                args,
                configs.named_configs(),
                std::env::var("OTSERVER_API_KEY").ok(),
            )?;
            for failure in &failures {
                logger.log(failure.clone());
            }
            let result = run_scan_batch(&scans, &logger, &cancelled).await;
            failures.extend(result.failures);
            if !failures.is_empty() {
                return Err(format!(
                    "{} configuration(s) failed: {}",
                    failures.len(),
                    failures.join("; ")
                ));
            }
            if result.partial > 0 {
                std::process::exit(2);
            }
            Ok(())
        }
        #[cfg(feature = "gui")]
        Some(Commands::Gui) | None => gui::run_gui(),
        #[cfg(not(feature = "gui"))]
        None => Err("A command is required; run otserver-otter --help.".into()),
    }
}

pub fn get_config_path() -> Result<PathBuf, String> {
    if let Ok(exe) = std::env::current_exe() {
        Ok(exe.with_file_name("otter.json"))
    } else {
        Ok(PathBuf::from("otter.json"))
    }
}

fn config_load_path(path: &Path) -> PathBuf {
    if path.exists() {
        return path.to_owned();
    }
    let legacy = path.with_file_name("otscanner.json");
    if legacy.exists() {
        legacy
    } else {
        path.to_owned()
    }
}

pub fn load_config() -> Result<ScannerConfigs, String> {
    let path = config_load_path(&get_config_path()?);
    match std::fs::read(&path) {
        Ok(data) => parse_config(&data)
            .map_err(|error| format!("Could not read {}: {error}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(ScannerConfigs::default()),
        Err(error) => Err(format!("Could not read {}: {error}", path.display())),
    }
}

pub fn save_config_sync(configs: &ScannerConfigs) -> Result<(), String> {
    configs.validate()?;
    let path = get_config_path()?;
    let data = serde_json::to_vec_pretty(configs)
        .map_err(|error| format!("Could not serialize config: {error}"))?;
    std::fs::write(&path, data)
        .map_err(|error| format!("Could not write {}: {error}", path.display()))
}

pub fn parse_config(data: &[u8]) -> Result<ScannerConfigs, String> {
    let configs: ScannerConfigs =
        serde_json::from_slice(data).map_err(|error| error.to_string())?;
    configs.validate()?;
    Ok(configs)
}

pub fn prepare_scans(
    args: ScanArgs,
    configs: Vec<(String, ScannerConfig)>,
    environment_api_key: Option<String>,
) -> Result<(Vec<ConfiguredScan>, Vec<String>), String> {
    let mut scans = Vec::new();
    let mut failures = Vec::new();
    let mut outputs = BTreeMap::<PathBuf, String>::new();

    for (name, config) in configs {
        match resolve_scan(args.clone(), config, environment_api_key.clone()) {
            Ok(options) => {
                if let Some(existing) = outputs.insert(options.output.clone(), name.clone()) {
                    return Err(format!(
                        "Configurations {existing:?} and {name:?} resolve to the same output path {}.",
                        options.output.display()
                    ));
                }
                scans.push(ConfiguredScan { name, options });
            }
            Err(error) => failures.push(format!("Configuration {name:?}: {error}")),
        }
    }

    if scans.is_empty() {
        return Err(if failures.is_empty() {
            "No configurations are available to scan.".into()
        } else {
            failures.join("; ")
        });
    }
    Ok((scans, failures))
}

pub fn resolve_scan(
    args: ScanArgs,
    config: ScannerConfig,
    environment_api_key: Option<String>,
) -> Result<ScanOptions, String> {
    let ads = ads_probe_settings(&args, &config)?;
    let http = HttpOptions {
        ignore_self_signed: args.ignore_self_signed,
        http_proxy: args.http_proxy,
        https_proxy: args.https_proxy,
    };
    http.validate().map_err(str::to_owned)?;
    let no_native_protocols = args.no_protocols || config.no_protocols.unwrap_or(false);
    let protocols = ProtocolOptions {
        arp: !(args.no_arp || config.no_arp.unwrap_or(false)),
        profinet: !(args.no_profinet || config.no_profinet.unwrap_or(false)),
        s7: !(no_native_protocols || args.no_s7 || config.no_s7.unwrap_or(false)),
        enip: !(no_native_protocols || args.no_enip || config.no_enip.unwrap_or(false)),
        bacnet: !(no_native_protocols || args.no_bacnet || config.no_bacnet.unwrap_or(false)),
        fins: !(no_native_protocols || args.no_fins || config.no_fins.unwrap_or(false)),
        fox: !(no_native_protocols || args.no_fox || config.no_fox.unwrap_or(false)),
        dnp3: !(no_native_protocols || args.no_dnp3 || config.no_dnp3.unwrap_or(false)),
        iec61850: !(no_native_protocols || args.no_iec61850 || config.no_iec61850.unwrap_or(false)),
        netbios: !(no_native_protocols || args.no_netbios || config.no_netbios.unwrap_or(false)),
        smb: !(no_native_protocols || args.no_smb || config.no_smb.unwrap_or(false)),
        rpc: !(no_native_protocols || args.no_rpc || config.no_rpc.unwrap_or(false)),
        http: !(no_native_protocols || args.no_http || config.no_http.unwrap_or(false)),
        ads: !(no_native_protocols || args.no_ads || config.no_ads.unwrap_or(false)),
        opcua: !(no_native_protocols || args.no_opcua || config.no_opcua.unwrap_or(false)),
        snmp: !(args.no_snmp || config.no_snmp.unwrap_or(false)),
        lldp: !(args.no_lldp || config.no_lldp.unwrap_or(false)),
    };
    let opcua = opcua_probe_settings(&config);
    let targets = if args.targets.is_empty() {
        config.targets.unwrap_or_default()
    } else {
        args.targets
    };
    if targets.is_empty() {
        return Err("At least one --target or config targets entry is required.".into());
    }

    let interface = nonempty(args.interface.or(config.interface), "interface")?;
    let source_mac = nonempty(args.source_mac.or(config.source_mac), "sourceMac")?;
    let server_url = optional_nonempty(args.server_url.or(config.server_url), "serverUrl")?;
    let site = optional_nonempty(args.site.or(config.site), "site")?;
    let api_key = optional_nonempty(environment_api_key.or(config.api_key), "apiKey")?;
    let upload = match (server_url, site, api_key) {
        (None, None, None) => None,
        (Some(server_url), Some(site), Some(api_key)) => Some(UploadOptions {
            endpoint: import_endpoint(&server_url)?,
            site,
            api_key,
            http,
        }),
        _ => {
            return Err(
                "Upload requires serverUrl, site, and OTSERVER_API_KEY or config apiKey.".into(),
            );
        }
    };

    Ok(ScanOptions {
        targets,
        interface,
        source_mac,
        output: args
            .output
            .or(config.output)
            .unwrap_or_else(|| PathBuf::from("otserver-scan.json")),
        protocols,
        allow_dcp_source: args.allow_dcp_source || config.allow_dcp_source.unwrap_or(false),
        snmp: config
            .snmp
            .as_ref()
            .map(snmp::Credentials::to_vec)
            .filter(|settings| !settings.is_empty())
            .unwrap_or_else(|| vec![snmp::Settings::default()]),
        opcua,
        ads,
        upload,
    })
}

fn ads_probe_settings(
    args: &ScanArgs,
    config: &ScannerConfig,
) -> Result<otserver_otter::protocols::AdsSettings, String> {
    let mut target_net_ids = config.ads_target_net_ids.clone().unwrap_or_default();
    let mut cli_targets = BTreeSet::new();
    for mapping in &args.ads_target_netids {
        let (target, net_id) = mapping
            .split_once('=')
            .ok_or("--ads-target-netid must use IP=NETID.")?;
        if target.is_empty() || net_id.is_empty() {
            return Err("--ads-target-netid must use IP=NETID.".into());
        }
        if !cli_targets.insert(target.to_owned()) {
            return Err(format!(
                "ADS target NetID for {target} was specified more than once."
            ));
        }
        target_net_ids.insert(target.to_owned(), net_id.to_owned());
    }
    let ports = if args.ads_ports.is_empty() {
        config.ads_ports.as_deref().unwrap_or_default()
    } else {
        args.ads_ports.as_slice()
    };
    otserver_otter::protocols::AdsSettings::from_config(
        args.ads_source_net_id
            .as_deref()
            .or(config.ads_source_net_id.as_deref()),
        &target_net_ids,
        ports,
    )
}

fn opcua_probe_settings(config: &ScannerConfig) -> otserver_otter::protocols::OpcuaSettings {
    let config_value = |value: Option<&str>| {
        value
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    };
    let mut credentials = config
        .opcua_credentials
        .as_ref()
        .map(|credentials| credentials.to_vec())
        .unwrap_or_default();
    if credentials.is_empty()
        && let Some(username) = config_value(config.opcua_username.as_deref())
    {
        credentials.push(otserver_otter::protocols::OpcuaCredential {
            username: Some(username),
            password: config_value(config.opcua_password.as_deref()),
        });
    }
    otserver_otter::protocols::OpcuaSettings {
        // Empty means the probe falls back to its default ports.
        ports: config.opcua_ports.clone().unwrap_or_default(),
        credentials,
    }
}

fn timestamp() -> String {
    let now = time::OffsetDateTime::now_local().unwrap_or_else(|_| time::OffsetDateTime::now_utc());
    format!("[{:02}:{:02}]", now.hour(), now.minute())
}

pub fn format_log_line(message: &str) -> String {
    if let Some((target, remainder)) = message.split_once("] [")
        && (target.starts_with("[ip=") || target.starts_with("[mac="))
        && let Some((protocol, detail)) = remainder.split_once("] ")
    {
        format!("{target}] [{protocol}] {} {detail}", timestamp())
    } else {
        format!("{} {message}", timestamp())
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "keeps target and all standard diagnostic fields explicit at the formatting boundary"
)]
fn format_diagnostic(
    ip: &str,
    mac: Option<&str>,
    protocol: &str,
    status: &str,
    code: &str,
    endpoint: &str,
    stage: &str,
    message: &str,
) -> String {
    let target = match mac {
        Some(mac) => format!("[ip={ip} mac={mac}]"),
        None => format!("[ip={ip}]"),
    };
    format_target_diagnostic(&target, protocol, status, code, endpoint, stage, message)
}

fn format_mac_diagnostic(
    mac: &str,
    protocol: &str,
    status: &str,
    code: &str,
    endpoint: &str,
    stage: &str,
    message: &str,
) -> String {
    format_target_diagnostic(
        &format!("[mac={mac}]"),
        protocol,
        status,
        code,
        endpoint,
        stage,
        message,
    )
}

fn format_target_diagnostic(
    target: &str,
    protocol: &str,
    status: &str,
    code: &str,
    endpoint: &str,
    stage: &str,
    message: &str,
) -> String {
    let mut line = format!(
        "{target} [{protocol}] {status} code={code} endpoint={endpoint} stage={stage}: {}",
        safe_diagnostic_text(message)
    );
    if let Some(hint) = diagnostic_hint(code) {
        line.push_str(" Hint: ");
        line.push_str(hint);
    }
    line
}

fn diagnostic_hint(code: &str) -> Option<&'static str> {
    match code {
        "no-response" | "response-timeout" => Some(
            "Check reachability, VLAN/routing, filtering, and service availability; silence is inconclusive.",
        ),
        "connect-timeout" | "network-unreachable" => {
            Some("Check the operating-system route, link/VLAN, and filtering.")
        }
        "connection-refused" => Some("Confirm the reported service is enabled on this port."),
        "authentication-failed" => {
            Some("Verify the configured credentials and protocol security level.")
        }
        "authentication-required" => {
            Some("Configure a supported credential mode for this read-only probe.")
        }
        "authentication-mode-unsupported" | "security-policy-unsupported" => {
            Some("Compare the reported device modes with the configured probe capabilities.")
        }
        "access-denied" => Some("Check device authorization for this read operation."),
        "unsupported-operation" => Some(
            "The device does not support this read operation; other collected results are retained.",
        ),
        "response-mismatch" => Some(
            "Verify that replies come from the expected target and match the outstanding request.",
        ),
        "malformed-response" => {
            Some("Check device protocol/firmware compatibility; malformed data was rejected.")
        }
        "permission-denied" => Some(
            "Check scanner permissions and capture-driver availability for the selected interface.",
        ),
        "request-rejected" | "request-aborted" => {
            Some("Review the reported protocol status and whether the device permits this read.")
        }
        "device-status-error" => {
            Some("Use the reported device status/code to check support and access for this read.")
        }
        _ => None,
    }
}

fn safe_diagnostic_text(message: &str) -> String {
    const MAX_CHARS: usize = 512;
    let mut result = String::new();
    for (index, character) in message.chars().enumerate() {
        if index == MAX_CHARS {
            result.push_str("… (truncated)");
            break;
        }
        result.push(if character.is_control() {
            ' '
        } else {
            character
        });
    }
    result
}

fn diagnostic_code(message: &str, status: protocols::ProbeStatus) -> &'static str {
    let message = message.to_ascii_lowercase();
    if status == protocols::ProbeStatus::NoResponse {
        if message.contains("connection refused") {
            "connection-refused"
        } else if message.contains("connection reset")
            || message.contains("connection closed")
            || message.contains("peer closed")
        {
            "connection-closed"
        } else if message.contains("connect timed out") || message.contains("connection timed out")
        {
            "connect-timeout"
        } else if message.contains("timed out") || message.contains("timeout") {
            "response-timeout"
        } else {
            "no-response"
        }
    } else if status == protocols::ProbeStatus::Cancelled || message.contains("cancelled") {
        "cancelled"
    } else if message.contains("unencrypted channel") {
        "security-mode"
    } else if message.contains("differs from") {
        "identity-disagreement"
    } else if message.contains("no endpoint with securitypolicy") {
        "security-policy-unsupported"
    } else if message.contains("requires username authentication") {
        "authentication-required"
    } else if message.contains("no authentication mode supported")
        || message.contains("no usable authentication")
    {
        "authentication-mode-unsupported"
    } else if message.contains("need a username") || message.contains("configure opcuacredentials")
    {
        "authentication-required"
    } else if message.contains("unsupported snmp authentication")
        || message.contains("unsupported snmp privacy")
    {
        "authentication-mode-unsupported"
    } else if message.contains("connection refused") {
        "connection-refused"
    } else if message.contains("connection reset")
        || message.contains("connection closed")
        || message.contains("broken pipe")
    {
        "connection-closed"
    } else if message.contains("network is unreachable")
        || message.contains("host is unreachable")
        || message.contains("no route to host")
    {
        "network-unreachable"
    } else if message.contains("permission denied") || message.contains("operation not permitted") {
        "permission-denied"
    } else if message.contains("connect timed out") || message.contains("connection timed out") {
        "connect-timeout"
    } else if message.contains("timed out") || message.contains("timeout") {
        "response-timeout"
    } else if message.contains("authentication failed") || message.contains("credentials rejected")
    {
        "authentication-failed"
    } else if message.contains("access denied") || message.contains("access-denied") {
        "access-denied"
    } else if message.contains("bacnet error class")
        || message.contains("fins status")
        || message.contains("status 0x")
        || message.contains("returned 0x")
    {
        "device-status-error"
    } else if message.contains("rejected") {
        "request-rejected"
    } else if message.contains("aborted") {
        "request-aborted"
    } else if message.contains("unsupported") || message.contains("not implemented") {
        "unsupported-operation"
    } else if message.contains("mismatch") || message.contains("uncorrelated") {
        "response-mismatch"
    } else if message.contains("invalid")
        || message.contains("malformed")
        || message.contains("truncated")
        || message.contains("oversized")
    {
        "malformed-response"
    } else if status == protocols::ProbeStatus::Partial {
        "partial-collection"
    } else {
        "protocol-error"
    }
}

fn pnio_no_response(message: &str) -> bool {
    if !message.starts_with("PROFINET PNIO record scan failed for ") {
        return false;
    }
    let message = message.to_ascii_lowercase();
    [
        "timed out",
        "timeout",
        "connection refused",
        "connection reset",
        "connection closed",
        "peer closed",
    ]
    .iter()
    .any(|needle| message.contains(*needle))
}

fn pnio_warning_target(message: &str) -> Option<String> {
    let candidate = message
        .strip_prefix("PROFINET PNIO skipped for ")
        .or_else(|| message.strip_prefix("PROFINET PNIO record scan failed for "))
        .or_else(|| message.split_once(": ").map(|(target, _)| target))?;
    let target = candidate
        .split_once(": ")
        .map_or(candidate, |(target, _)| target)
        .trim();
    if target.parse::<Ipv4Addr>().is_ok() {
        Some(target.to_owned())
    } else {
        otserver_otter::contract::normalize_mac(target)
    }
}

pub fn nonempty(value: Option<String>, name: &str) -> Result<String, String> {
    optional_nonempty(value, name)?.ok_or_else(|| format!("--{name} or config {name} is required."))
}

pub fn optional_nonempty(value: Option<String>, name: &str) -> Result<Option<String>, String> {
    value
        .map(|value| {
            let value = value.trim().to_owned();
            if value.is_empty() {
                Err(format!("{name} must not be empty."))
            } else {
                Ok(value)
            }
        })
        .transpose()
}

pub fn nonempty_opt(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn import_endpoint(server_url: &str) -> Result<reqwest::Url, String> {
    let mut endpoint = reqwest::Url::parse(server_url)
        .map_err(|error| format!("serverUrl is invalid: {error}"))?;
    if !matches!(endpoint.scheme(), "http" | "https")
        || endpoint.cannot_be_a_base()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
    {
        return Err("serverUrl must be an HTTP(S) base URL without a query or fragment.".into());
    }
    endpoint.set_path(&format!(
        "{}/api/asset-imports",
        endpoint.path().trim_end_matches('/')
    ));
    Ok(endpoint)
}

fn doctor() -> Result<(), String> {
    println!("Capture interfaces: {}", profinet::interfaces()?.len());
    println!("Native ARP and OT protocol modules: available");
    #[cfg(windows)]
    if profinet::npcap_available() {
        println!(
            "Npcap active PROFINET backend: available (version {})",
            profinet::npcap_version()
                .as_deref()
                .unwrap_or("unavailable")
        );
    } else {
        println!("Npcap active PROFINET backend: not available (pktmon passive fallback only)");
    }
    Ok(())
}

pub async fn scan(
    configuration: &str,
    options: &ScanOptions,
    logger: &dyn LogOutput,
    cancelled: &Arc<AtomicBool>,
) -> Result<bool, String> {
    let started_at = otserver_otter::now();
    #[cfg(windows)]
    let npcap_active = options.protocols.profinet && profinet::npcap_available();
    #[cfg(windows)]
    let npcap_version = npcap_active.then(profinet::npcap_version).flatten();
    #[cfg(not(windows))]
    let npcap_version = None;
    let mut devices = Vec::new();
    let mut links = Vec::new();
    let mut unresolved = Vec::new();
    let mut warnings = Vec::new();
    let mut errors = Vec::new();
    let mut protocol_failed = false;
    let interfaces = if cancelled.load(Ordering::Relaxed) {
        Ok(Vec::new())
    } else {
        profinet::interfaces()
    };
    let source_mac =
        if (options.protocols.arp || options.protocols.profinet || options.protocols.lldp)
            && !cancelled.load(Ordering::Relaxed)
        {
            scan_source_mac(
                &options.interface,
                &options.source_mac,
                interfaces.as_ref().map_err(Clone::clone)?,
                logger,
            )?
        } else {
            options.source_mac.clone()
        };
    let interface = scan_interface_ref(
        &options.interface,
        &source_mac,
        interfaces.as_deref().unwrap_or_default(),
    );

    logger.log(format!(
        "Starting discovery for target(s): {}",
        options.targets.join(", ")
    ));
    logger.log(format!(
        "Interface: {}, Source MAC: {}",
        options.interface, source_mac
    ));
    logger.log(format!(
        "Traffic pacing: {} ARP requests/s, approximately {} discovery operations/s, shared across targets. OS-generated packets are not a hard-capped wire budget.",
        otserver_otter::traffic::ARP_REQUESTS_PER_SECOND,
        otserver_otter::traffic::OPERATIONS_PER_SECOND,
    ));

    let target_addresses = discovery::expand_targets(&options.targets)?;
    let lldp_capture = if options.protocols.lldp && !cancelled.load(Ordering::Relaxed) {
        let interface = options.interface.clone();
        let mac = source_mac.clone();
        let cancellation = Arc::clone(cancelled);
        Some(tokio::task::spawn_blocking(move || {
            otserver_otter::lldp::scan(&interface, &mac, &cancellation)
        }))
    } else {
        None
    };

    let dcp_first = options.allow_dcp_source && options.protocols.profinet;
    if dcp_first && !cancelled.load(Ordering::Relaxed) {
        match discover_profinet(&options.interface, &source_mac, logger, cancelled).await {
            Ok(found) => devices.extend(found),
            Err(error) => errors.push(error),
        }
    }

    let arp_targets = if dcp_first {
        dcp_arp_targets(&target_addresses, &devices)?
    } else {
        target_addresses.clone()
    };
    if options.protocols.arp && !cancelled.load(Ordering::Relaxed) {
        logger.log("Executing ARP discovery...".into());
        #[cfg(windows)]
        logger.log(if profinet::npcap_interface_available(&options.interface) {
            "Windows ARP uses Npcap: paced requests with reply collection during the sweep.".into()
        } else {
            "Windows ARP uses the driver-free SendARP fallback: each address waits for resolution or an OS timeout. Sparse ranges can be slow; install and bind Npcap to the selected adapter for paced sweeps.".into()
        });
        match discover(&options.interface, &source_mac, &arp_targets, cancelled).await {
            Ok(found) => {
                logger.log(format!("ARP discovery found {} device(s).", found.len()));
                for device in &found {
                    for ip in &device.ip_addresses {
                        logger.log(format_diagnostic(
                            ip,
                            Some(&device.mac_address),
                            "arp",
                            "SUCCESS",
                            "reply-correlated",
                            "ethernet broadcast (ff:ff:ff:ff:ff:ff)",
                            "arp-reply",
                            "Received and validated a reply matching the requested IPv4 target.",
                        ));
                    }
                }
                devices.extend(found);
            }
            Err(error) => {
                let message = format!(
                    "ARP sweep for {} IPv4 target(s) failed: {error}",
                    arp_targets.len()
                );
                let diagnostic = format_mac_diagnostic(
                    "ff:ff:ff:ff:ff:ff",
                    "arp",
                    "FAIL",
                    diagnostic_code(&message, protocols::ProbeStatus::Failure),
                    "ethernet broadcast; ARP response window 3s",
                    "sweep",
                    &message,
                );
                logger.log(diagnostic.clone());
                errors.push(diagnostic);
            }
        }
    } else if !options.protocols.arp {
        logger.log("ARP discovery disabled.".into());
    }

    if options.protocols.profinet && !dcp_first && !cancelled.load(Ordering::Relaxed) {
        match discover_profinet(&options.interface, &source_mac, logger, cancelled).await {
            Ok(found) => devices.extend(found),
            Err(error) => errors.push(error),
        }
    }
    devices = merge_devices(devices);
    logger.log(format!(
        "Unique devices after Layer 2 discovery: {}",
        devices.len()
    ));
    logger.devices(configuration, &devices);

    let probe_targets = ip_probe_targets(
        &target_addresses,
        &devices,
        options.protocols.arp,
        options.allow_dcp_source,
    );
    if options.protocols.profinet && !cancelled.load(Ordering::Relaxed) {
        logger.log("Reading PROFINET PNIO I&M records for discovered MAC/IP pairs...".into());
        let selected = options.interface.clone();
        let mac = source_mac.clone();
        let targets = probe_targets.clone();
        let cancellation = Arc::clone(cancelled);
        let (enriched, result) = tokio::task::spawn_blocking(move || {
            let result =
                profinet::enrich_pnio(&selected, &mac, &mut devices, &targets, &cancellation);
            (devices, result)
        })
        .await
        .map_err(|error| error.to_string())?;
        devices = enriched;
        let diagnostics =
            result.unwrap_or_else(|error| vec![format!("PROFINET PNIO scan skipped: {error}")]);
        let mut incomplete = false;
        for warning in &diagnostics {
            let status = if pnio_no_response(warning) {
                protocols::ProbeStatus::NoResponse
            } else {
                protocols::ProbeStatus::Partial
            };
            let formatted = if let Some(target) = pnio_warning_target(warning) {
                if let Ok(ip) = target.parse::<Ipv4Addr>() {
                    format_diagnostic(
                        &ip.to_string(),
                        None,
                        "profinet-pnio",
                        status.label(),
                        diagnostic_code(warning, status),
                        "udp/34964 or advertised PNIO endpoint; timeout 2s per RPC exchange",
                        "record-read",
                        warning,
                    )
                } else {
                    format_mac_diagnostic(
                        &target,
                        "profinet-pnio",
                        status.label(),
                        diagnostic_code(warning, status),
                        "udp/34964 or advertised PNIO endpoint; timeout 2s per RPC exchange",
                        "record-read",
                        warning,
                    )
                }
            } else {
                format_mac_diagnostic(
                    &source_mac,
                    "profinet-pnio",
                    "FAIL",
                    diagnostic_code(warning, protocols::ProbeStatus::Failure),
                    "selected interface; RPC timeout 2s",
                    "prepare",
                    &format!("Interface-scoped PNIO diagnostic: {warning}"),
                )
            };
            logger.log(formatted.clone());
            if status == protocols::ProbeStatus::NoResponse {
                continue;
            }
            incomplete = true;
            warnings.push(formatted);
        }
        protocol_failed |= incomplete;
        logger.devices(configuration, &devices);
    }
    logger.log(format!(
        "IP protocol targets: {} ({}).",
        probe_targets.len(),
        if options.protocols.arp {
            "discovered MAC/IP identities"
        } else {
            "ARP disabled; selected targets included"
        }
    ));
    let native_selection = protocols::Selection {
        s7: options.protocols.s7,
        enip: options.protocols.enip,
        bacnet: options.protocols.bacnet,
        fins: options.protocols.fins,
        fox: options.protocols.fox,
        dnp3: options.protocols.dnp3,
        iec61850: options.protocols.iec61850,
        netbios: options.protocols.netbios,
        smb: options.protocols.smb,
        rpc: options.protocols.rpc,
        http: options.protocols.http,
        opcua: options.protocols.opcua,
        ads: options.protocols.ads,
    };
    if native_selection.any() && !cancelled.load(Ordering::Relaxed) {
        logger.log(format!(
            "Probing native protocols ({})...",
            native_selection.labels().join(", ")
        ));
        protocol_failed |= probe_protocols(
            configuration,
            &probe_targets,
            &mut devices,
            &mut unresolved,
            &mut warnings,
            native_selection,
            &options.opcua,
            &options.ads,
            logger,
            cancelled,
        )
        .await;
        logger.devices(configuration, &devices);
    }

    if (options.protocols.snmp || options.protocols.lldp) && !cancelled.load(Ordering::Relaxed) {
        let snmp_selection = snmp::QuerySelection {
            inventory: options.protocols.snmp,
            lldp: options.protocols.lldp,
        };
        logger.log(format!(
            "Resolved SNMP inventory={} LLDP topology={}.",
            snmp_selection.inventory, snmp_selection.lldp
        ));
        let label = match (snmp_selection.inventory, snmp_selection.lldp) {
            (true, true) => "SNMP and LLDP",
            (true, false) => "SNMP",
            (false, true) => "LLDP",
            (false, false) => unreachable!("guard requires one query type"),
        };
        logger.log(format!("Querying {label}..."));
        let ips = probe_targets
            .iter()
            .map(Ipv4Addr::to_string)
            .collect::<BTreeSet<_>>();
        protocol_failed |= probe_snmp(
            configuration,
            ips,
            &mut devices,
            &mut links,
            &mut unresolved,
            &mut warnings,
            &options.snmp,
            snmp_selection,
            logger,
            cancelled,
        )
        .await;
    }

    if let Some(capture) = lldp_capture {
        match capture.await {
            Ok(Ok(result)) => {
                devices.extend(result.devices);
                links.extend(result.links);
                for warning in result.warnings {
                    let informational =
                        warning.starts_with("Passive LLDP observed the selected link");
                    protocol_failed |= !informational;
                    let status = if informational { "INFO" } else { "PARTIAL" };
                    let code = if informational {
                        "capture-window-complete"
                    } else {
                        diagnostic_code(&warning, protocols::ProbeStatus::Partial)
                    };
                    let diagnostic = format_mac_diagnostic(
                        "01:80:c2:00:00:0e",
                        "lldp-passive",
                        status,
                        code,
                        &format!(
                            "selected interface {}; capture window 30s",
                            options.interface
                        ),
                        "capture",
                        &warning,
                    );
                    logger.log(diagnostic.clone());
                    warnings.push(diagnostic);
                }
            }
            Ok(Err(error)) => {
                let diagnostic = format_mac_diagnostic(
                    "01:80:c2:00:00:0e",
                    "lldp-passive",
                    "FAIL",
                    diagnostic_code(&error, protocols::ProbeStatus::Failure),
                    &format!(
                        "selected interface {}; capture window 30s",
                        options.interface
                    ),
                    "capture",
                    &error,
                );
                logger.log(diagnostic.clone());
                errors.push(diagnostic);
            }
            Err(error) => {
                let diagnostic = format_mac_diagnostic(
                    "01:80:c2:00:00:0e",
                    "lldp-passive",
                    "FAIL",
                    "capture-task-failed",
                    &format!(
                        "selected interface {}; capture window 30s",
                        options.interface
                    ),
                    "capture",
                    &error.to_string(),
                );
                logger.log(diagnostic.clone());
                errors.push(diagnostic);
            }
        }
    }
    let stopped = cancelled.load(Ordering::Relaxed);
    if stopped {
        warnings
            .push("Scan stopped by user; this export contains results collected so far.".into());
        logger.log("Stopping scan and writing collected results...".into());
    }

    let devices = merge_devices(devices);
    logger.devices(configuration, &devices);

    let scan = ScanExport {
        format: "otserver-scan".into(),
        schema_version: 2,
        scanner: ScannerInfo {
            name: "OTserver Otter".into(),
            version: otserver_otter::VERSION.into(),
            npcap_version,
        },
        scan: ScanInfo {
            id: Uuid::new_v4().to_string(),
            started_at,
            finished_at: otserver_otter::now(),
            targets: options.targets.clone(),
            interface,
            partial: stopped || protocol_failed || !errors.is_empty(),
        },
        devices,
        links,
        unresolved,
        warnings,
        errors,
    };
    validate(&scan)?;
    write_atomic(
        &options.output,
        &serde_json::to_vec_pretty(&scan).map_err(|error| error.to_string())?,
    )
    .await?;
    logger.log(format!(
        "Wrote {} device(s) to {}.",
        scan.devices.len(),
        options.output.display()
    ));
    Ok(scan.scan.partial)
}

pub async fn run_scan_batch(
    scans: &[ConfiguredScan],
    logger: &dyn LogOutput,
    cancelled: &Arc<AtomicBool>,
) -> BatchResult {
    let mut result = BatchResult::default();
    for (index, configured) in scans.iter().enumerate() {
        if cancelled.load(Ordering::Relaxed) {
            result.cancelled = true;
            break;
        }

        logger.log(format!(
            "Starting configuration {:?} ({}/{}).",
            configured.name,
            index + 1,
            scans.len()
        ));
        match scan(&configured.name, &configured.options, logger, cancelled).await {
            Ok(_) if cancelled.load(Ordering::Relaxed) => {
                logger.log(format!("Configuration {:?} stopped.", configured.name));
                result.cancelled = true;
                break;
            }
            Ok(partial) => {
                if let Some(upload) = &configured.options.upload
                    && let Err(error) =
                        upload_scan(upload, &configured.options.output, logger).await
                {
                    let failure =
                        format!("Configuration {:?} upload failed: {error}", configured.name);
                    logger.log(failure.clone());
                    result.failures.push(failure);
                    continue;
                }
                if partial {
                    result.partial += 1;
                    logger.log(format!(
                        "Configuration {:?} completed with partial errors.",
                        configured.name
                    ));
                } else {
                    result.completed += 1;
                    logger.log(format!(
                        "Configuration {:?} completed successfully.",
                        configured.name
                    ));
                }
            }
            Err(error) => {
                let failure = format!("Configuration {:?} failed: {error}", configured.name);
                logger.log(failure.clone());
                result.failures.push(failure);
                if cancelled.load(Ordering::Relaxed) {
                    result.cancelled = true;
                    break;
                }
            }
        }
    }
    result
}

pub async fn upload_scan(
    options: &UploadOptions,
    path: &Path,
    logger: &dyn LogOutput,
) -> Result<(), String> {
    logger.log(format!(
        "Uploading export {} to OTserver at {}...",
        path.display(),
        options.endpoint
    ));
    let data = tokio::fs::read(path)
        .await
        .map_err(|error| format!("Could not read {} for upload: {error}", path.display()))?;
    let filename = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("otserver-scan.json");
    let imported = send_import(options, data, filename).await?;
    let id = match &imported.id {
        serde_json::Value::String(value) => value.clone(),
        value => value.to_string(),
    };
    logger.log(format!(
        "Imported as {id}: {} created, {} updated, {} skipped.",
        imported.created_assets.unwrap_or(0),
        imported.updated_assets.unwrap_or(0),
        imported.skipped_assets.unwrap_or(0)
    ));
    Ok(())
}

const MAX_IMPORT_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
#[cfg(not(test))]
const IMPORT_TIMEOUT: Duration = Duration::from_secs(300);
#[cfg(test)]
const IMPORT_TIMEOUT: Duration = Duration::from_secs(2);

async fn send_import(
    options: &UploadOptions,
    data: Vec<u8>,
    filename: &str,
) -> Result<ImportDocument, String> {
    let file = reqwest::multipart::Part::bytes(data)
        .file_name(filename.to_owned())
        .mime_str("application/json")
        .map_err(|error| error.to_string())?;
    let form = reqwest::multipart::Form::new()
        .text(
            "_payload",
            serde_json::json!({
                "site": options.site,
                "source": "otserver-otter",
                "sourceVersion": otserver_otter::VERSION,
                "status": "pending"
            })
            .to_string(),
        )
        .part("file", file);
    let client = options
        .http
        .apply(
            reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(10))
                .timeout(IMPORT_TIMEOUT),
        )
        .map_err(|error| format!("Could not initialize OTserver upload: {error}"))?
        .build()
        .map_err(|error| format!("Could not initialize OTserver upload: {error}"))?;
    let mut response = client
        .post(options.endpoint.clone())
        .header(
            reqwest::header::AUTHORIZATION,
            format!("users API-Key {}", options.api_key),
        )
        .multipart(form)
        .send()
        .await
        .map_err(|error| format!("Could not upload scan: {error}"))?;
    let status = response.status();
    if response
        .content_length()
        .is_some_and(|length| length > MAX_IMPORT_RESPONSE_BYTES as u64)
    {
        return Err("OTserver response exceeded the 16 MiB limit.".into());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| format!("Could not read OTserver response: {error}"))?
    {
        if chunk.len() > MAX_IMPORT_RESPONSE_BYTES - body.len() {
            return Err("OTserver response exceeded the 16 MiB limit.".into());
        }
        body.extend_from_slice(&chunk);
    }
    let body = body.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(&body);
    if !status.is_success() {
        return Err(format!(
            "OTserver import failed ({status}): {}",
            String::from_utf8_lossy(body)
                .chars()
                .take(500)
                .collect::<String>()
        ));
    }
    let response: CreateImportResponse = serde_json::from_slice(body)
        .map_err(|error| format!("OTserver returned an invalid import response: {error}"))?;
    if response.doc.status != "completed" {
        return Err(response.doc.error.clone().unwrap_or_else(|| {
            format!("OTserver import ended with status {}.", response.doc.status)
        }));
    }
    Ok(response.doc)
}

async fn discover(
    interface: &str,
    source_mac: &str,
    targets: &[Ipv4Addr],
    cancelled: &Arc<AtomicBool>,
) -> Result<Vec<otserver_otter::contract::Device>, String> {
    let interface = interface.to_owned();
    let source_mac = source_mac.to_owned();
    let targets = targets.to_vec();
    let cancelled = Arc::clone(cancelled);
    tokio::task::spawn_blocking(move || {
        discovery::scan(
            &interface,
            &source_mac,
            &targets,
            Duration::from_secs(3),
            &cancelled,
        )
    })
    .await
    .map_err(|error| error.to_string())?
}

async fn discover_profinet(
    interface: &str,
    source_mac: &str,
    logger: &dyn LogOutput,
    cancelled: &Arc<AtomicBool>,
) -> Result<Vec<Device>, String> {
    #[cfg(windows)]
    let npcap_active = profinet::npcap_available();
    #[cfg(windows)]
    let npcap_version = npcap_active.then(profinet::npcap_version).flatten();
    #[cfg(windows)]
    if npcap_active {
        logger.log(format!(
            "Using Npcap {} for active PROFINET DCP; the selected adapter will be bound directly by GUID.",
            npcap_version.as_deref().unwrap_or("(version unavailable)")
        ));
    } else {
        logger.log(
            "Npcap is not available. Windows will use passive pktmon PROFINET capture. Install Npcap explicitly from https://npcap.com/ to enable active DCP Identify. Driver installation is never a scan side effect."
                .into(),
        );
    }
    logger.log(format!(
        "Scanning PROFINET DCP; awaiting Identify replies for at least {} seconds...",
        profinet::DCP_RESPONSE_WINDOW.as_secs()
    ));
    let selected = interface.to_owned();
    let mac = source_mac.to_owned();
    let cancellation = Arc::clone(cancelled);
    let started = Instant::now();
    let result = tokio::task::spawn_blocking(move || {
        profinet::scan(
            &selected,
            &mac,
            profinet::DCP_RESPONSE_WINDOW,
            cancellation.as_ref(),
        )
    })
    .await
    .map_err(|error| error.to_string())
    .and_then(|result| result);
    match &result {
        Ok(found) => {
            let (status, code, message) = if cancelled.load(Ordering::Relaxed) {
                (
                    "CANCELLED",
                    "cancelled",
                    format!(
                        "Identify collection stopped after {}s; {} device(s) retained.",
                        started.elapsed().as_secs(),
                        found.len()
                    ),
                )
            } else if found.is_empty() {
                (
                    "NO_RESPONSE",
                    "no-identify-responses",
                    format!(
                        "No DCP Identify responses during the {}s selected-link window. No response does not establish that a device is absent.",
                        started.elapsed().as_secs()
                    ),
                )
            } else {
                (
                    "SUCCESS",
                    "identify-complete",
                    format!(
                        "Identify collection completed after {}s; found {} device(s).",
                        started.elapsed().as_secs(),
                        found.len()
                    ),
                )
            };
            logger.log(format_mac_diagnostic(
                "01:0e:cf:00:00:00",
                "profinet-dcp",
                status,
                code,
                "ethernet DCP multicast; response window 60s",
                "identify",
                &message,
            ));
        }
        Err(error) => logger.log(format_mac_diagnostic(
            "01:0e:cf:00:00:00",
            "profinet-dcp",
            "FAIL",
            diagnostic_code(error, protocols::ProbeStatus::Failure),
            "ethernet DCP multicast; response window 60s",
            "capture",
            error,
        )),
    }
    result.map_err(|error| {
        format_mac_diagnostic(
            "01:0e:cf:00:00:00",
            "profinet-dcp",
            "FAIL",
            diagnostic_code(&error, protocols::ProbeStatus::Failure),
            "ethernet DCP multicast; response window 60s",
            "capture",
            &error,
        )
    })
}

fn dcp_arp_targets(selected: &[Ipv4Addr], devices: &[Device]) -> Result<Vec<Ipv4Addr>, String> {
    let mut targets = selected.iter().copied().collect::<BTreeSet<_>>();
    for device in devices {
        if !device
            .observations
            .iter()
            .any(|observation| observation.source == Source::ProfinetDcp)
        {
            continue;
        }
        targets.extend(
            device
                .ip_addresses
                .iter()
                .filter_map(|ip| ip.parse::<Ipv4Addr>().ok()),
        );
    }
    if targets.len() > discovery::MAX_TARGETS {
        return Err(format!(
            "The scan contains more than {} IPv4 addresses. Split it into smaller scans.",
            discovery::MAX_TARGETS
        ));
    }
    Ok(targets.into_iter().collect())
}

fn scan_source_mac(
    selected: &str,
    configured: &str,
    interfaces: &[profinet::CaptureInterface],
    logger: &dyn LogOutput,
) -> Result<String, String> {
    let actual = selected_interface(selected, interfaces)
        .and_then(profinet::interface_mac)
        .ok_or_else(|| format!("Could not determine the current MAC of interface {selected}."))?;
    if otserver_otter::contract::normalize_mac(configured).as_deref() != Some(&actual) {
        logger.log(format!(
            "Using current interface MAC {actual}; configured source MAC {configured} differs."
        ));
    }
    Ok(actual)
}

fn selected_interface<'a>(
    selected: &str,
    interfaces: &'a [profinet::CaptureInterface],
) -> Option<&'a profinet::CaptureInterface> {
    interfaces.iter().find(|interface| {
        interface.name == selected
            || interface.friendly_name == selected
            || cfg!(windows)
                && (interface.name.eq_ignore_ascii_case(selected)
                    || interface.friendly_name.eq_ignore_ascii_case(selected))
    })
}

fn scan_interface_ref(
    selected: &str,
    source_mac: &str,
    interfaces: &[profinet::CaptureInterface],
) -> InterfaceRef {
    let addresses = selected_interface(selected, interfaces)
        .into_iter()
        .flat_map(|interface| &interface.addresses)
        .filter_map(|address| address.parse::<std::net::IpAddr>().ok())
        .map(|address| address.to_string())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    InterfaceRef {
        id: selected.into(),
        name: selected.into(),
        mac_address: otserver_otter::contract::normalize_mac(source_mac),
        addresses,
        ip_route_policy: Some("operating-system".into()),
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "keeps native result attachment in one bounded probe path"
)]
async fn probe_protocols(
    configuration: &str,
    targets: &BTreeSet<Ipv4Addr>,
    devices: &mut [otserver_otter::contract::Device],
    unresolved: &mut Vec<otserver_otter::contract::Observation>,
    warnings: &mut Vec<String>,
    selection: protocols::Selection,
    opcua: &otserver_otter::protocols::OpcuaSettings,
    ads: &otserver_otter::protocols::AdsSettings,
    logger: &dyn LogOutput,
    cancelled: &Arc<AtomicBool>,
) -> bool {
    let identities = unique_ip_identities(devices);
    let mut tasks = tokio::task::JoinSet::new();
    let mut failed = false;
    for &ip in targets {
        if cancelled.load(Ordering::Relaxed) {
            break;
        }
        if tasks.len() == 32 {
            let result = tokio::select! {
                () = wait_for_cancellation(cancelled) => break,
                result = tasks.join_next() => result,
            };
            failed |= apply_probe(configuration, devices, unresolved, warnings, logger, result);
        }
        let mac = identities.get(&ip.to_string()).cloned();
        let opcua = opcua.clone();
        let ads = ads.clone();
        let cancellation = Arc::clone(cancelled);
        tasks.spawn(async move {
            let result = protocols::scan_with_cancellation(
                ip,
                mac.as_deref(),
                selection,
                &opcua,
                &ads,
                &cancellation,
            )
            .await;
            (ip, mac, result)
        });
    }
    drain_tasks(&mut tasks, cancelled, |result| {
        failed |= apply_probe(configuration, devices, unresolved, warnings, logger, result);
    })
    .await;
    failed
}

fn ip_probe_targets(
    selected: &[Ipv4Addr],
    devices: &[Device],
    arp_enabled: bool,
    allow_dcp_source: bool,
) -> BTreeSet<Ipv4Addr> {
    let mut targets = unique_ip_identities(devices)
        .keys()
        .filter_map(|ip| ip.parse::<Ipv4Addr>().ok())
        .filter(|ip| allow_dcp_source || selected.contains(ip))
        .collect::<BTreeSet<_>>();
    if !arp_enabled {
        targets.extend(selected);
    }
    targets
}

async fn drain_tasks<T: 'static>(
    tasks: &mut tokio::task::JoinSet<T>,
    cancelled: &AtomicBool,
    mut apply: impl FnMut(Option<Result<T, tokio::task::JoinError>>),
) {
    while !tasks.is_empty() {
        let result = tokio::select! {
            () = wait_for_cancellation(cancelled) => break,
            result = tasks.join_next() => result,
        };
        apply(result);
    }
    while let Some(result) = tasks.try_join_next() {
        apply(Some(result));
    }
    let deadline = tokio::time::Instant::now() + Duration::from_millis(100);
    while !tasks.is_empty() {
        match tokio::time::timeout_at(deadline, tasks.join_next()).await {
            Ok(Some(result)) => apply(Some(result)),
            _ => break,
        }
    }
    tasks.abort_all();
}

#[expect(
    clippy::too_many_arguments,
    reason = "keeps scan result mutation in one bounded probe path"
)]
async fn probe_snmp(
    configuration: &str,
    ips: BTreeSet<String>,
    devices: &mut Vec<Device>,
    links: &mut Vec<otserver_otter::contract::TopologyLink>,
    unresolved: &mut Vec<otserver_otter::contract::Observation>,
    warnings: &mut Vec<String>,
    settings: &[snmp::Settings],
    selection: snmp::QuerySelection,
    logger: &dyn LogOutput,
    cancelled: &AtomicBool,
) -> bool {
    let identities = unique_ip_identities(devices);
    let mut tasks = tokio::task::JoinSet::new();
    let mut failed = false;
    for ip in ips {
        if cancelled.load(Ordering::Relaxed) {
            break;
        }
        if tasks.len() == 16 {
            let result = tokio::select! {
                () = wait_for_cancellation(cancelled) => break,
                result = tasks.join_next() => result,
            };
            failed |= apply_snmp_probe(
                configuration,
                devices,
                links,
                unresolved,
                warnings,
                logger,
                selection,
                result,
            );
        }
        let settings = settings.to_vec();
        let local_mac = identities.get(&ip).cloned();
        tasks.spawn(async move {
            let (attempts, result) =
                snmp::query_with_attempts(&ip, local_mac.as_deref(), &settings, selection).await;
            (ip, attempts, result)
        });
    }
    drain_tasks(&mut tasks, cancelled, |result| {
        failed |= apply_snmp_probe(
            configuration,
            devices,
            links,
            unresolved,
            warnings,
            logger,
            selection,
            result,
        );
    })
    .await;
    failed
}

async fn wait_for_cancellation(cancelled: &AtomicBool) {
    while !cancelled.load(Ordering::Relaxed) {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[expect(
    clippy::type_complexity,
    reason = "the join result carries the target and fallible SNMP response"
)]
#[expect(
    clippy::too_many_arguments,
    reason = "keeps live device snapshots in the single bounded probe path"
)]
fn apply_snmp_probe(
    configuration: &str,
    devices: &mut Vec<Device>,
    links: &mut Vec<otserver_otter::contract::TopologyLink>,
    unresolved: &mut Vec<otserver_otter::contract::Observation>,
    warnings: &mut Vec<String>,
    logger: &dyn LogOutput,
    selection: snmp::QuerySelection,
    result: Option<
        Result<
            (
                String,
                Vec<snmp::QueryAttempt>,
                Result<snmp::ResultData, snmp::QueryError>,
            ),
            tokio::task::JoinError,
        >,
    >,
) -> bool {
    let Some(result) = result else { return false };
    let Ok((ip, attempts, result)) = result else {
        warnings.push("An SNMP probe task failed.".into());
        return true;
    };
    let snmp_endpoint = "udp/161; timeout 30s";
    for (index, attempt) in attempts.into_iter().enumerate() {
        let (status, code, message) = if attempt.success {
            (
                "INFO",
                "credential-attempt-accepted",
                "SNMP version/security settings received a response.".to_owned(),
            )
        } else {
            let message = attempt
                .failure
                .unwrap_or_else(|| "SNMP version/security settings did not complete.".into());
            (
                "INFO",
                diagnostic_code(&message, protocols::ProbeStatus::Failure),
                message,
            )
        };
        logger.log(format_diagnostic(
            &ip,
            None,
            "snmp",
            status,
            code,
            snmp_endpoint,
            "authenticate",
            &format!("Attempt {} ({}): {message}", index + 1, attempt.description),
        ));
    }
    let mut result = match result {
        Ok(result) => result,
        Err(error) => {
            let message = error.to_string();
            let failed = !error.is_no_response();
            for (enabled, protocol, stage) in [
                (selection.inventory, "snmp", "inventory"),
                (selection.lldp, "lldp-snmp", "neighbor-inventory"),
            ] {
                if !enabled {
                    continue;
                }
                let diagnostic = format_diagnostic(
                    &ip,
                    None,
                    protocol,
                    if failed { "FAIL" } else { "NO_RESPONSE" },
                    diagnostic_code(&message, protocols::ProbeStatus::Failure),
                    snmp_endpoint,
                    stage,
                    &message,
                );
                logger.log(diagnostic.clone());
                if failed {
                    warnings.push(diagnostic);
                }
            }
            return failed;
        }
    };
    if selection.inventory {
        logger.log(format_diagnostic(
            &ip,
            result.identity_mac.as_deref(),
            "snmp",
            if result.inventory_complete {
                "SUCCESS"
            } else {
                "PARTIAL"
            },
            if result.inventory_complete {
                "inventory-complete"
            } else {
                "inventory-partial"
            },
            snmp_endpoint,
            "inventory",
            if result.inventory_complete {
                "SNMP inventory collection completed."
            } else {
                "SNMP inventory collection completed with read failures; successful rows retained."
            },
        ));
    }
    if selection.lldp {
        logger.log(format_diagnostic(
            &ip,
            result.identity_mac.as_deref(),
            "lldp-snmp",
            if result.lldp_complete {
                "SUCCESS"
            } else {
                "PARTIAL"
            },
            if result.lldp_complete {
                "neighbor-inventory-complete"
            } else {
                "neighbor-inventory-partial"
            },
            snmp_endpoint,
            "neighbor-inventory",
            if result.lldp_complete {
                "SNMP LLDP neighbor collection completed."
            } else {
                "SNMP LLDP neighbor collection was incomplete; successful rows retained."
            },
        ));
    }
    let mut incomplete = selection.inventory && !result.inventory_complete
        || selection.lldp && !result.lldp_complete;
    for warning in result.warnings.drain(..) {
        let protocol = if warning.contains("LLDP") || warning.contains("lldp") {
            "lldp-snmp"
        } else {
            "snmp"
        };
        let formatted = format_diagnostic(
            &ip,
            result.identity_mac.as_deref(),
            protocol,
            "PARTIAL",
            diagnostic_code(&warning, protocols::ProbeStatus::Partial),
            snmp_endpoint,
            "collection",
            &warning,
        );
        logger.log(formatted.clone());
        warnings.push(formatted);
        incomplete = true;
    }
    links.append(&mut result.links);
    if let Some(mac) = result.identity_mac {
        if let Some(device) = devices.iter_mut().find(|device| device.mac_address == mac) {
            device.ip_addresses.push(ip);
            if let Some(observation) = result.observation {
                device.observations.push(observation);
            }
            device.interfaces.append(&mut result.interfaces);
            device.ports.append(&mut result.ports);
        } else if let Some(observation) = result.observation {
            devices.push(Device {
                mac_address: mac.clone(),
                mac_addresses: vec![mac],
                ip_addresses: vec![ip],
                observations: vec![observation],
                interfaces: result.interfaces,
                ports: result.ports,
            });
        }
    } else if let Some(observation) = result.observation {
        unresolved.push(observation);
    }
    logger.devices(configuration, devices);
    incomplete
}

#[expect(
    clippy::type_complexity,
    reason = "the join result carries the target, optional MAC, and protocol response"
)]
fn apply_probe(
    configuration: &str,
    devices: &mut [otserver_otter::contract::Device],
    unresolved: &mut Vec<otserver_otter::contract::Observation>,
    warnings: &mut Vec<String>,
    logger: &dyn LogOutput,
    result: Option<
        Result<(Ipv4Addr, Option<String>, protocols::ProbeResult), tokio::task::JoinError>,
    >,
) -> bool {
    let Some(result) = result else { return false };
    let Ok((ip, mac, mut result)) = result else {
        warnings.push("A native protocol probe task failed.".into());
        return true;
    };
    let mut failed = false;
    for outcome in &result.outcomes {
        let messages = if outcome.messages.is_empty() {
            vec![match outcome.status {
                protocols::ProbeStatus::Success => "Probe completed successfully.".to_owned(),
                protocols::ProbeStatus::Partial => "Probe returned partial results.".to_owned(),
                protocols::ProbeStatus::NoResponse => {
                    "No correlated response was received.".to_owned()
                }
                protocols::ProbeStatus::Failure => "Probe failed.".to_owned(),
                protocols::ProbeStatus::Cancelled => "Probe was cancelled.".to_owned(),
            }]
        } else {
            outcome.messages.clone()
        };
        for message in messages {
            let endpoint = format!("{}; timeout {}", outcome.endpoint, outcome.timeout);
            let status = if outcome.status == protocols::ProbeStatus::Success
                && !outcome.messages.is_empty()
            {
                "INFO"
            } else {
                outcome.status.label()
            };
            let formatted = format_diagnostic(
                &ip.to_string(),
                mac.as_deref(),
                outcome.protocol,
                status,
                diagnostic_code(&message, outcome.status),
                &endpoint,
                outcome.stage,
                &message,
            );
            logger.log(formatted.clone());
            failed |= matches!(
                outcome.status,
                protocols::ProbeStatus::Failure | protocols::ProbeStatus::Partial
            );
            if matches!(
                outcome.status,
                protocols::ProbeStatus::Failure
                    | protocols::ProbeStatus::Partial
                    | protocols::ProbeStatus::Cancelled
            ) {
                warnings.push(formatted);
            }
        }
    }
    if let Some(device) = mac
        .as_deref()
        .and_then(|mac| devices.iter_mut().find(|device| device.mac_address == mac))
    {
        device.observations.append(&mut result.observations);
        device.ports.append(&mut result.ports);
    } else {
        unresolved.append(&mut result.observations);
    }
    logger.devices(configuration, devices);
    failed
}

async fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let temporary = path.with_extension(format!(
        "{}.tmp",
        path.extension()
            .and_then(|value| value.to_str())
            .unwrap_or("json")
    ));
    tokio::fs::write(&temporary, bytes)
        .await
        .map_err(|error| format!("Could not write export: {error}"))?;
    tokio::fs::rename(&temporary, path)
        .await
        .map_err(|error| format!("Could not finalize export: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[derive(Default)]
    struct DeviceLogger {
        snapshots: std::sync::Mutex<Vec<(String, usize)>>,
    }

    impl LogOutput for DeviceLogger {
        fn write(&self, _msg: String) {}

        fn devices(&self, configuration: &str, devices: &[Device]) {
            self.snapshots
                .lock()
                .unwrap()
                .push((configuration.to_string(), devices.len()));
        }
    }

    fn args() -> ScanArgs {
        ScanArgs {
            ack_authorized: true,
            ..ScanArgs::default()
        }
    }

    fn no_protocols() -> ProtocolOptions {
        ProtocolOptions {
            arp: false,
            profinet: false,
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
            snmp: false,
            lldp: false,
            ads: false,
        }
    }

    #[test]
    fn rejects_malformed_explicit_proxy_urls() {
        assert_eq!(
            HttpOptions {
                http_proxy: Some("not a URL".into()),
                ..HttpOptions::default()
            }
            .validate(),
            Err("HTTP proxy URL is invalid.")
        );
        assert_eq!(
            HttpOptions {
                https_proxy: Some("not a URL".into()),
                ..HttpOptions::default()
            }
            .validate(),
            Err("HTTPS proxy URL is invalid.")
        );
    }

    #[tokio::test]
    async fn validate_command_dispatch_accepts_contract_exports_and_rejects_bad_versions() {
        let valid =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("contracts/otserver-scan-v2-valid.json");
        assert!(
            run_cli(Cli {
                command: Some(Commands::Validate { file: valid }),
            })
            .await
            .is_ok()
        );

        let invalid = std::env::temp_dir().join(format!("{}.json", Uuid::new_v4()));
        tokio::fs::write(&invalid, br#"{"format":"otserver-scan","schemaVersion":1}"#)
            .await
            .unwrap();
        let error = run_cli(Cli {
            command: Some(Commands::Validate {
                file: invalid.clone(),
            }),
        })
        .await
        .unwrap_err();
        tokio::fs::remove_file(invalid).await.unwrap();
        assert!(error.contains("Expected otserver-scan schemaVersion 2"));
    }

    #[test]
    fn resolves_config_with_cli_and_environment_precedence() {
        let config = parse_config(
            br#"{
                "targets":["192.0.2.0/24"],
                "interface":"config-interface",
                "sourceMac":"00:11:22:33:44:55",
                "output":"configured.json",
                "snmp":[{"version":"3","username":"ops","authProtocol":"sha256","authPassword":"secret"}],
                "noProtocols":true,
                "allowDcpSource":true,
                "serverUrl":"https://otserver.example/base/",
                "site":"site-1",
                "apiKey":"config-key"
            }"#,
        )
        .unwrap();
        let config = config.configs()[0].clone();
        let mut cli = args();
        cli.interface = Some("cli-interface".into());
        cli.ignore_self_signed = true;
        cli.http_proxy = Some("http://proxy.example:8080".into());
        cli.https_proxy = Some("http://secure-proxy.example:8080".into());
        let resolved = resolve_scan(cli, config, Some("environment-key".into())).unwrap();

        assert_eq!(resolved.targets, ["192.0.2.0/24"]);
        assert_eq!(resolved.interface, "cli-interface");
        assert_eq!(resolved.output, PathBuf::from("configured.json"));
        assert!(resolved.protocols.arp);
        assert!(resolved.protocols.profinet);
        assert!(resolved.allow_dcp_source);
        assert!(!resolved.protocols.s7);
        assert!(!resolved.protocols.enip);
        assert!(!resolved.protocols.bacnet);
        assert!(!resolved.protocols.fins);
        assert!(!resolved.protocols.fox);
        assert!(!resolved.protocols.dnp3);
        assert!(!resolved.protocols.iec61850);
        assert!(!resolved.protocols.netbios);
        assert!(!resolved.protocols.opcua);
        assert!(resolved.protocols.snmp);
        assert!(resolved.protocols.lldp);
        assert_eq!(resolved.snmp[0].username.as_deref(), Some("ops"));
        assert_eq!(resolved.snmp[0].auth_password.as_deref(), Some("secret"));
        let upload = resolved.upload.unwrap();
        assert_eq!(
            upload.endpoint.as_str(),
            "https://otserver.example/base/api/asset-imports"
        );
        assert_eq!(upload.api_key, "environment-key");
        assert_eq!(upload.site, "site-1");
        assert_eq!(
            upload.http,
            HttpOptions {
                ignore_self_signed: true,
                http_proxy: Some("http://proxy.example:8080".into()),
                https_proxy: Some("http://secure-proxy.example:8080".into()),
            }
        );
    }

    #[test]
    fn serializes_and_deserializes_config_roundtrip() {
        let config = ScannerConfig {
            name: None,
            targets: Some(vec!["192.168.1.0/24".into()]),
            interface: Some("eth0".into()),
            source_mac: Some("00:11:22:33:44:55".into()),
            output: Some(PathBuf::from("output.json")),
            snmp: Some(snmp::Credentials::Single(snmp::Settings {
                version: Some("2c".into()),
                community: Some("lab-public".into()),
                ..snmp::Settings::default()
            })),
            no_protocols: None,
            no_arp: Some(true),
            no_profinet: None,
            allow_dcp_source: None,
            no_s7: Some(true),
            no_enip: None,
            no_bacnet: Some(true),
            no_fins: None,
            no_fox: Some(true),
            no_dnp3: Some(true),
            no_iec61850: Some(true),
            no_netbios: Some(true),
            no_smb: Some(true),
            no_rpc: Some(true),
            no_http: Some(true),
            no_ads: Some(true),
            no_opcua: Some(true),
            no_snmp: Some(true),
            no_lldp: Some(true),
            opcua_ports: Some(vec![4840, 4841]),
            opcua_credentials: None,
            opcua_username: Some("opc-user".into()),
            opcua_password: Some("opc-password".into()),
            ads_source_net_id: Some("10.0.0.1.1.1".into()),
            ads_target_net_ids: Some(BTreeMap::from([(
                "192.168.1.10".into(),
                "10.0.0.10.1.1".into(),
            )])),
            ads_ports: Some(vec![851, 801]),
            server_url: Some("https://otserver.example".into()),
            site: Some("site-1".into()),
            api_key: Some("key-123".into()),
        };
        let configs = ScannerConfigs::Single(Box::new(config));
        let bytes = serde_json::to_vec_pretty(&configs).unwrap();
        let parsed = parse_config(&bytes).unwrap();
        assert_eq!(configs, parsed);
    }

    #[test]
    fn parses_named_configuration_list_in_order() {
        let configs = parse_config(
            br#"[
                {"name":"Line A","targets":["192.0.2.1"]},
                {"name":"Line B","targets":["192.0.2.2"]}
            ]"#,
        )
        .unwrap();

        assert!(configs.is_multiple());
        assert_eq!(
            configs
                .configs()
                .iter()
                .filter_map(|config| config.name.as_deref())
                .collect::<Vec<_>>(),
            ["Line A", "Line B"]
        );
    }

    #[test]
    fn rejects_invalid_configuration_lists() {
        assert!(parse_config(br#"[]"#).is_err());
        assert!(parse_config(br#"[{"targets":["192.0.2.1"]}]"#).is_err());
        assert!(parse_config(br#"[{"name":" "}]"#).is_err());
        assert!(parse_config(br#"[{"name":"Line A"},{"name":"Line A"}]"#).is_err());
    }

    fn complete_config(name: &str, target: &str, output: &str) -> ScannerConfig {
        ScannerConfig {
            name: Some(name.into()),
            targets: Some(vec![target.into()]),
            interface: Some("test-interface".into()),
            source_mac: Some("00:11:22:33:44:55".into()),
            output: Some(output.into()),
            ..ScannerConfig::default()
        }
    }

    #[test]
    fn prepares_valid_configs_and_reports_invalid_entries() {
        let configs = vec![
            (
                "Invalid".into(),
                ScannerConfig {
                    name: Some("Invalid".into()),
                    ..ScannerConfig::default()
                },
            ),
            (
                "Valid".into(),
                complete_config("Valid", "192.0.2.1", "valid.json"),
            ),
        ];
        let (scans, failures) = prepare_scans(args(), configs, None).unwrap();

        assert_eq!(scans.len(), 1);
        assert_eq!(scans[0].name, "Valid");
        assert_eq!(failures.len(), 1);
    }

    #[test]
    fn prepare_scans_reports_empty_and_all_invalid_batches() {
        assert!(matches!(
            prepare_scans(args(), Vec::new(), None),
            Err(error) if error == "No configurations are available to scan."
        ));
        assert!(matches!(
            prepare_scans(args(), vec![("Invalid".into(), ScannerConfig::default())], None),
            Err(error) if error.starts_with("Configuration \"Invalid\":")
        ));
    }

    #[test]
    fn rejects_duplicate_batch_outputs() {
        let configs = vec![
            (
                "Line A".into(),
                complete_config("Line A", "192.0.2.1", "a.json"),
            ),
            (
                "Line B".into(),
                complete_config("Line B", "192.0.2.2", "b.json"),
            ),
        ];
        let mut cli = args();
        cli.output = Some("same.json".into());

        assert!(prepare_scans(cli, configs, None).is_err());
    }

    #[tokio::test]
    async fn batch_continues_after_scan_failure() {
        let configs = vec![
            (
                "Line A".into(),
                complete_config("Line A", "invalid-a", "a.json"),
            ),
            (
                "Line B".into(),
                complete_config("Line B", "invalid-b", "b.json"),
            ),
        ];
        let (scans, failures) = prepare_scans(args(), configs, None).unwrap();
        assert!(failures.is_empty());

        let result = run_scan_batch(&scans, &StdoutLogger, &Arc::new(AtomicBool::new(false))).await;

        assert_eq!(result.failures.len(), 2);
        assert!(!result.cancelled);
    }

    #[test]
    fn resolves_opcua_settings_from_config() {
        let config = ScannerConfig {
            opcua_ports: Some(vec![4841, 48400]),
            opcua_username: Some("opc-user".into()),
            opcua_password: Some("opc-password".into()),
            ..ScannerConfig::default()
        };
        let settings = opcua_probe_settings(&config);
        assert_eq!(settings.ports, [4841, 48400]);
        assert_eq!(settings.credentials.len(), 1);
        assert_eq!(
            settings.credentials[0].username.as_deref(),
            Some("opc-user")
        );
        assert_eq!(
            settings.credentials[0].password.as_deref(),
            Some("opc-password")
        );

        let settings = opcua_probe_settings(&ScannerConfig::default());
        assert!(settings.ports.is_empty());
        assert!(settings.credentials.is_empty());
    }

    #[test]
    fn resolves_opcua_credential_list_before_legacy_fields() {
        let config = parse_config(
            br#"{
                "opcuaCredentials":[
                    {"username":"first","password":"first-password"},
                    {"username":"second","password":"second-password"}
                ],
                "opcuaUsername":"legacy",
                "opcuaPassword":"legacy-password"
            }"#,
        )
        .unwrap();
        let settings = opcua_probe_settings(&config.configs()[0]);
        assert_eq!(settings.credentials.len(), 2);
        assert_eq!(settings.credentials[0].username.as_deref(), Some("first"));
        assert_eq!(settings.credentials[1].username.as_deref(), Some("second"));
    }

    #[test]
    fn rejects_unknown_or_incomplete_config() {
        assert!(parse_config(br#"{"unknown":true}"#).is_err());
        let mut cli = args();
        cli.targets.push("192.0.2.1".into());
        cli.interface = Some("eth0".into());
        cli.source_mac = Some("00:11:22:33:44:55".into());
        cli.server_url = Some("https://otserver.example".into());
        assert!(resolve_scan(cli, ScannerConfig::default(), None).is_err());
    }

    #[test]
    fn prefers_otter_config_and_falls_back_to_legacy_name() {
        let directory = std::env::temp_dir().join(format!("otserver-otter-{}", Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let current = directory.join("otter.json");
        let legacy = directory.join("otscanner.json");

        assert_eq!(config_load_path(&current), current);
        std::fs::write(&legacy, b"{}").unwrap();
        assert_eq!(config_load_path(&current), legacy);
        std::fs::write(&current, b"{}").unwrap();
        assert_eq!(config_load_path(&current), current);

        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn cli_exposes_individual_protocol_disable_flags() {
        let cli = Cli::try_parse_from([
            "otserver-otter",
            "scan",
            "--ack-authorized",
            "--allow-dcp-source",
            "--no-arp",
            "--no-profinet",
            "--no-s7",
            "--no-enip",
            "--no-bacnet",
            "--no-fins",
            "--no-fox",
            "--no-dnp3",
            "--no-iec61850",
            "--no-netbios",
            "--no-http",
            "--no-ads",
            "--no-opcua",
            "--no-snmp",
            "--no-lldp",
            "--ignore-self-signed",
            "--http-proxy",
            "http://proxy.example:8080",
            "--https-proxy",
            "http://secure-proxy.example:8080",
        ])
        .unwrap();
        let Some(Commands::Scan(args)) = cli.command else {
            panic!("expected scan command");
        };
        assert!(args.allow_dcp_source);
        assert!(args.no_arp);
        assert!(args.no_profinet);
        assert!(args.no_s7);
        assert!(args.no_enip);
        assert!(args.no_bacnet);
        assert!(args.no_fins);
        assert!(args.no_fox);
        assert!(args.no_dnp3);
        assert!(args.no_iec61850);
        assert!(args.no_netbios);
        assert!(args.no_http);
        assert!(args.no_ads);
        assert!(args.no_opcua);
        assert!(args.no_snmp);
        assert!(args.no_lldp);
        assert!(args.ignore_self_signed);
        assert_eq!(
            args.http_proxy.as_deref(),
            Some("http://proxy.example:8080")
        );
        assert_eq!(
            args.https_proxy.as_deref(),
            Some("http://secure-proxy.example:8080")
        );
    }

    #[cfg(not(feature = "gui"))]
    #[test]
    fn cli_requires_subcommand_without_gui() {
        assert!(Cli::try_parse_from(["otserver-otter"]).is_err());
    }

    #[test]
    fn netbios_can_be_disabled_by_cli_or_config() {
        for (cli_disabled, config_disabled) in [(false, false), (true, false), (false, true)] {
            let mut cli = args();
            cli.no_netbios = cli_disabled;
            let mut config = complete_config("Test", "192.0.2.1", "test.json");
            config.no_netbios = Some(config_disabled);
            let options = resolve_scan(cli, config, None).unwrap();
            assert_eq!(
                options.protocols.netbios,
                !(cli_disabled || config_disabled)
            );
            assert!(options.protocols.s7);
        }
    }

    #[test]
    fn http_honors_cli_config_and_legacy_disable() {
        for (cli_disabled, config_disabled, legacy) in [
            (false, false, false),
            (true, false, false),
            (false, true, false),
            (false, false, true),
        ] {
            let mut cli = args();
            cli.no_http = cli_disabled;
            let mut config = complete_config("Test", "192.0.2.1", "test.json");
            config.no_http = Some(config_disabled);
            config.no_protocols = Some(legacy);
            let options = resolve_scan(cli, config, None).unwrap();
            assert_eq!(
                options.protocols.http,
                !(cli_disabled || config_disabled || legacy)
            );
        }
    }

    #[test]
    fn ads_honors_cli_config_and_legacy_disable() {
        for (cli_disabled, config_disabled, legacy) in [
            (false, false, false),
            (true, false, false),
            (false, true, false),
            (false, false, true),
        ] {
            let mut cli = args();
            cli.no_ads = cli_disabled;
            let mut config = complete_config("Test", "192.0.2.1", "test.json");
            config.no_ads = Some(config_disabled);
            config.no_protocols = Some(legacy);
            let options = resolve_scan(cli, config, None).unwrap();
            assert_eq!(
                options.protocols.ads,
                !(cli_disabled || config_disabled || legacy)
            );
        }
    }

    #[test]
    fn ads_cli_settings_override_config_and_validate_netids_and_ports() {
        let mut cli = args();
        cli.ads_source_net_id = Some("192.0.2.2.1.1".into());
        cli.ads_target_netids
            .push("192.0.2.10=10.0.0.10.1.1".into());
        cli.ads_ports = vec![851];
        let config = ScannerConfig {
            ads_source_net_id: Some("192.0.2.1.1.1".into()),
            ads_target_net_ids: Some(BTreeMap::from([(
                "192.0.2.10".into(),
                "10.0.0.11.1.1".into(),
            )])),
            ads_ports: Some(vec![801]),
            ..complete_config("Test", "192.0.2.10", "test.json")
        };
        let settings = ads_probe_settings(&cli, &config).unwrap();
        assert_eq!(settings.source_net_id, Some([192, 0, 2, 2, 1, 1]));
        assert_eq!(
            settings.target_net_ids[&Ipv4Addr::new(192, 0, 2, 10)],
            [10, 0, 0, 10, 1, 1]
        );
        assert_eq!(settings.ams_ports, [851]);

        cli.ads_target_netids = vec!["not-an-ip=10.0.0.10.1.1".into()];
        assert!(ads_probe_settings(&cli, &config).is_err());
        cli.ads_target_netids.clear();
        cli.ads_source_net_id = Some("192.0.2.1".into());
        assert!(ads_probe_settings(&cli, &config).is_err());
        cli.ads_source_net_id = None;
        cli.ads_ports = vec![851, 851];
        assert!(ads_probe_settings(&cli, &config).is_err());
    }

    #[test]
    fn all_protocols_are_enabled_by_default() {
        let mut cli = args();
        cli.targets.push("192.0.2.1".into());
        cli.interface = Some("eth0".into());
        cli.source_mac = Some("00:11:22:33:44:55".into());
        let resolved = resolve_scan(cli, ScannerConfig::default(), None).unwrap();
        assert_eq!(resolved.protocols, ProtocolOptions::default());
        assert!(!resolved.allow_dcp_source);
        assert_eq!(resolved.snmp, vec![snmp::Settings::default()]);
        assert_eq!(snmp::resolved_version(&resolved.snmp[0]), "2c");
        assert!(snmp::auth(&resolved.snmp[0]).is_ok());
    }

    #[test]
    fn windows_probes_honor_cli_config_and_legacy_disables() {
        for (smb, rpc, legacy) in [
            (false, false, false),
            (true, false, false),
            (false, true, false),
            (false, false, true),
        ] {
            let mut cli = args();
            cli.no_smb = smb;
            cli.no_rpc = rpc;
            cli.no_protocols = legacy;
            let options =
                resolve_scan(cli, complete_config("Test", "192.0.2.1", "test.json"), None).unwrap();
            assert_eq!(
                (options.protocols.smb, options.protocols.rpc),
                (!(smb || legacy), !(rpc || legacy))
            );
            let mut config = complete_config("Test", "192.0.2.1", "test.json");
            config.no_smb = Some(smb);
            config.no_rpc = Some(rpc);
            config.no_protocols = Some(legacy);
            let options = resolve_scan(args(), config, None).unwrap();
            assert_eq!(
                (options.protocols.smb, options.protocols.rpc),
                (!(smb || legacy), !(rpc || legacy))
            );
        }
        let cli = Cli::try_parse_from([
            "otserver-otter",
            "scan",
            "--ack-authorized",
            "--no-smb",
            "--no-rpc",
        ])
        .unwrap();
        let Some(Commands::Scan(args)) = cli.command else {
            panic!("scan arguments");
        };
        assert!(args.no_smb && args.no_rpc);
    }

    #[test]
    fn all_ip_protocols_use_discovery_unless_arp_is_explicitly_disabled() {
        let selected = discovery::expand_targets(&["192.0.2.0/30".into()]).unwrap();
        let found = vec![Device {
            mac_address: "00:11:22:33:44:55".into(),
            ip_addresses: vec!["192.0.2.1".into()],
            ..Device::default()
        }];
        assert_eq!(
            ip_probe_targets(&selected, &found, true, false),
            [selected[0]].into()
        );
        assert!(ip_probe_targets(&selected, &[], true, false).is_empty());
        assert!(ip_probe_targets(&selected[1..], &found, true, false).is_empty());
        assert_eq!(
            ip_probe_targets(&selected, &found, false, false),
            selected.iter().copied().collect()
        );
        assert_eq!(
            ip_probe_targets(&selected, &[], false, false),
            selected.iter().copied().collect()
        );

        let conflict = Device {
            mac_address: "00:11:22:33:44:66".into(),
            ip_addresses: vec!["192.0.2.1".into()],
            ..Device::default()
        };
        assert!(ip_probe_targets(&selected, &[found[0].clone(), conflict], true, false).is_empty());
    }

    #[test]
    fn allow_dcp_source_adds_out_of_range_ip_to_arp_and_probe_targets() {
        let selected = [Ipv4Addr::new(12, 0, 0, 1)];
        let dcp = Device {
            mac_address: "00:11:22:33:44:55".into(),
            ip_addresses: vec!["13.1.1.1".into()],
            observations: vec![otserver_otter::contract::Observation {
                source: Source::ProfinetDcp,
                observed_at: String::new(),
                ip_address: Some("13.1.1.1".into()),
                mac_address: Some("00:11:22:33:44:55".into()),
                fields: BTreeMap::new(),
                raw: serde_json::Value::Null,
                warnings: vec![],
            }],
            ..Device::default()
        };
        assert_eq!(
            dcp_arp_targets(&selected, std::slice::from_ref(&dcp)).unwrap(),
            [Ipv4Addr::new(12, 0, 0, 1), Ipv4Addr::new(13, 1, 1, 1)]
        );
        assert!(ip_probe_targets(&selected, std::slice::from_ref(&dcp), true, false).is_empty());
        assert_eq!(
            ip_probe_targets(&selected, std::slice::from_ref(&dcp), true, true),
            [Ipv4Addr::new(13, 1, 1, 1)].into()
        );
    }

    #[test]
    fn dcp_discovered_addresses_cannot_overflow_the_arp_target_limit() {
        let selected: Vec<_> = (0..discovery::MAX_TARGETS)
            .map(|index| Ipv4Addr::from(index as u32))
            .collect();
        let dcp = Device {
            ip_addresses: vec![Ipv4Addr::from(discovery::MAX_TARGETS as u32).to_string()],
            observations: vec![otserver_otter::contract::Observation {
                source: Source::ProfinetDcp,
                observed_at: String::new(),
                ip_address: None,
                mac_address: None,
                fields: BTreeMap::new(),
                raw: serde_json::Value::Null,
                warnings: Vec::new(),
            }],
            ..Device::default()
        };

        assert!(dcp_arp_targets(&selected, &[dcp]).is_err());
    }

    #[test]
    fn scan_uses_current_interface_mac_instead_of_stale_saved_mac() {
        let interfaces = [profinet::CaptureInterface {
            name: "wlan-test".into(),
            friendly_name: "Wi-Fi".into(),
            description: "Wi-Fi".into(),
            addresses: vec!["192.0.2.17".into(), "F6:30:EA:29:58:EA".into()],
        }];
        assert_eq!(
            scan_source_mac("wlan-test", "F6:00:00:00:00:02", &interfaces, &StdoutLogger).unwrap(),
            "F6:30:EA:29:58:EA"
        );
        assert_eq!(
            scan_source_mac("Wi-Fi", "f6-30-ea-29-58-ea", &interfaces, &StdoutLogger).unwrap(),
            "F6:30:EA:29:58:EA"
        );
        assert!(
            scan_source_mac("missing", "F6:00:00:00:00:02", &interfaces, &StdoutLogger).is_err()
        );
    }

    #[test]
    fn resolves_snmp_credential_list_in_order() {
        let config = parse_config(
            br#"{
                "targets":["192.0.2.1"],
                "interface":"eth0",
                "sourceMac":"00:11:22:33:44:55",
                "snmp":[
                    {"version":"3","username":"ops","authProtocol":"sha256","authPassword":"auth-secret"},
                    {"version":"2c","community":"first"},
                    {"version":"2c","community":"second"}
                ]
            }"#,
        )
        .unwrap();
        let resolved = resolve_scan(args(), config.configs()[0].clone(), None).unwrap();
        assert_eq!(resolved.snmp.len(), 3);
        assert_eq!(resolved.snmp[0].username.as_deref(), Some("ops"));
        assert_eq!(resolved.snmp[1].community.as_deref(), Some("first"));
        assert_eq!(resolved.snmp[2].community.as_deref(), Some("second"));

        let empty = parse_config(br#"{"snmp":[]}"#).unwrap();
        let mut cli = args();
        cli.targets.push("192.0.2.1".into());
        cli.interface = Some("eth0".into());
        cli.source_mac = Some("00:11:22:33:44:55".into());
        let resolved = resolve_scan(cli, empty.configs()[0].clone(), None).unwrap();
        assert_eq!(resolved.snmp, vec![snmp::Settings::default()]);
    }

    #[test]
    fn snmp_probe_creates_device_only_from_derived_mac_identity() {
        let mut devices = vec![];
        let mut links = vec![];
        let mut unresolved = vec![];
        let mut warnings = vec![];
        let observation = otserver_otter::contract::Observation {
            source: Source::Snmp,
            observed_at: "2026-08-24T00:00:00Z".into(),
            ip_address: Some("192.0.2.10".into()),
            mac_address: Some("00:11:22:33:44:55".into()),
            fields: BTreeMap::new(),
            raw: serde_json::json!({}),
            warnings: vec![],
        };
        let result = snmp::ResultData {
            identity_mac: Some("00:11:22:33:44:55".into()),
            observation: Some(observation),
            interfaces: vec![],
            ports: vec![],
            links: vec![],
            warnings: vec![],
            inventory_complete: true,
            lldp_complete: true,
        };

        let logger = DeviceLogger::default();
        assert!(!apply_snmp_probe(
            "Line A",
            &mut devices,
            &mut links,
            &mut unresolved,
            &mut warnings,
            &logger,
            snmp::QuerySelection {
                inventory: true,
                lldp: false,
            },
            Some(Ok(("192.0.2.10".into(), vec![], Ok(result)))),
        ));
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].mac_address, "00:11:22:33:44:55");
        assert!(unresolved.is_empty());
        assert_eq!(*logger.snapshots.lock().unwrap(), [("Line A".into(), 1)]);
    }

    #[test]
    fn native_probe_without_mac_stays_unresolved() {
        let mut devices = vec![];
        let mut unresolved = vec![];
        let mut warnings = vec![];
        apply_probe(
            "Line A",
            &mut devices,
            &mut unresolved,
            &mut warnings,
            &DeviceLogger::default(),
            Some(Ok((
                "192.0.2.10".parse().unwrap(),
                None,
                protocols::ProbeResult {
                    observations: vec![otserver_otter::contract::Observation {
                        source: Source::EthernetIp,
                        observed_at: "2026-08-24T00:00:00Z".into(),
                        ip_address: Some("192.0.2.10".into()),
                        mac_address: None,
                        fields: BTreeMap::new(),
                        raw: serde_json::json!({}),
                        warnings: vec![],
                    }],
                    ports: vec![],
                    warnings: vec![],
                    outcomes: vec![protocols::ProbeOutcome {
                        source: Source::EthernetIp,
                        protocol: "ethernet-ip",
                        status: protocols::ProbeStatus::Success,
                        endpoint: "tcp+udp/44818".into(),
                        timeout: "2s",
                        stage: "probe",
                        messages: vec![],
                    }],
                },
            ))),
        );
        assert_eq!(unresolved.len(), 1);
        assert!(devices.is_empty());
    }

    #[tokio::test]
    async fn snmp_configuration_failure_marks_probe_failed() {
        let settings = snmp::Settings {
            version: Some("unsupported".into()),
            ..snmp::Settings::default()
        };
        let Err(error) = snmp::query(
            "127.0.0.1",
            None,
            &settings,
            snmp::QuerySelection {
                inventory: true,
                lldp: false,
            },
        )
        .await
        else {
            panic!("unsupported SNMP configuration unexpectedly succeeded")
        };
        let mut devices = vec![];
        let mut links = vec![];
        let mut unresolved = vec![];
        let mut warnings = vec![];

        let logger = DeviceLogger::default();
        assert!(apply_snmp_probe(
            "Line A",
            &mut devices,
            &mut links,
            &mut unresolved,
            &mut warnings,
            &logger,
            snmp::QuerySelection {
                inventory: true,
                lldp: false,
            },
            Some(Ok(("127.0.0.1".into(), vec![], Err(error)))),
        ));
        assert!(logger.snapshots.lock().unwrap().is_empty());
    }

    #[test]
    fn formats_per_ip_protocol_outcomes_with_timestamp() {
        #[derive(Default)]
        struct CapturingLogger {
            lines: std::sync::Mutex<Vec<String>>,
        }
        impl LogOutput for CapturingLogger {
            fn write(&self, msg: String) {
                self.lines.lock().unwrap().push(msg);
            }
        }
        let logger = CapturingLogger::default();
        logger.log(format_diagnostic(
            "192.0.2.10",
            None,
            "snmp",
            "SUCCESS",
            "probe-complete",
            "udp/161; timeout 30s",
            "inventory",
            "SNMP inventory collection completed.",
        ));
        logger.log(format_diagnostic(
            "192.0.2.11",
            None,
            "s7",
            "FAIL",
            "response-mismatch",
            "tcp/102; timeout 2s",
            "setup-communication",
            "S7 response did not match the outstanding request.",
        ));
        let lines = logger.lines.lock().unwrap();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("[ip=192.0.2.10] [snmp] ["));
        assert!(
            lines[0].contains(
                "SUCCESS code=probe-complete endpoint=udp/161; timeout 30s stage=inventory"
            )
        );
        assert!(lines[1].starts_with("[ip=192.0.2.11] [s7] ["));
        assert!(lines[1].contains("FAIL code=response-mismatch endpoint=tcp/102; timeout 2s"));
    }

    #[test]
    fn diagnostics_keep_target_protocol_and_one_line_safe_details() {
        let formatted = format_log_line(&format_diagnostic(
            "192.0.2.10",
            Some("00:11:22:33:44:55"),
            "s7",
            "PARTIAL",
            "response-mismatch",
            "tcp/102; timeout 2s",
            "setup-communication",
            "S7 response mismatch\nnext fake log entry",
        ));

        assert!(formatted.starts_with("[ip=192.0.2.10 mac=00:11:22:33:44:55] [s7] ["));
        assert!(formatted.contains("PARTIAL code=response-mismatch"));
        assert!(formatted.contains("endpoint=tcp/102; timeout 2s"));
        assert!(formatted.contains("Hint: Verify that replies come from the expected target"));
        assert!(!formatted.contains('\n'));
        assert_eq!(
            diagnostic_code("connection refused", protocols::ProbeStatus::Failure),
            "connection-refused"
        );
        assert_eq!(
            diagnostic_code("response timed out", protocols::ProbeStatus::Failure),
            "response-timeout"
        );
        assert_eq!(
            diagnostic_code("Authentication failed", protocols::ProbeStatus::Failure),
            "authentication-failed"
        );
    }

    #[test]
    fn diagnostic_codes_distinguish_transport_security_and_protocol_failures() {
        use protocols::ProbeStatus::{Cancelled, Failure, NoResponse, Partial, Success};

        for (message, status, expected) in [
            ("connection refused", NoResponse, "connection-refused"),
            ("peer closed", NoResponse, "connection-closed"),
            ("connection timed out", NoResponse, "connect-timeout"),
            ("response timeout", NoResponse, "response-timeout"),
            ("quiet", NoResponse, "no-response"),
            ("cancelled", Failure, "cancelled"),
            ("other", Cancelled, "cancelled"),
            ("unencrypted channel", Failure, "security-mode"),
            (
                "value differs from expected",
                Failure,
                "identity-disagreement",
            ),
            (
                "no endpoint with SecurityPolicy",
                Failure,
                "security-policy-unsupported",
            ),
            (
                "requires username authentication",
                Failure,
                "authentication-required",
            ),
            (
                "no usable authentication mode",
                Failure,
                "authentication-mode-unsupported",
            ),
            ("need a username", Failure, "authentication-required"),
            (
                "unsupported SNMP privacy",
                Failure,
                "authentication-mode-unsupported",
            ),
            ("connection reset", Failure, "connection-closed"),
            ("no route to host", Failure, "network-unreachable"),
            ("operation not permitted", Failure, "permission-denied"),
            ("connect timed out", Failure, "connect-timeout"),
            ("timed out", Failure, "response-timeout"),
            ("credentials rejected", Failure, "authentication-failed"),
            ("access-denied", Failure, "access-denied"),
            ("BACnet error class 2", Failure, "device-status-error"),
            ("request rejected", Failure, "request-rejected"),
            ("request aborted", Failure, "request-aborted"),
            ("not implemented", Failure, "unsupported-operation"),
            ("uncorrelated response", Failure, "response-mismatch"),
            ("oversized payload", Failure, "malformed-response"),
            ("other partial result", Partial, "partial-collection"),
            ("other failure", Failure, "protocol-error"),
            (
                "message text does not override success",
                Success,
                "protocol-error",
            ),
        ] {
            assert_eq!(diagnostic_code(message, status), expected, "{message}");
        }
    }

    #[test]
    fn diagnostic_hints_and_sanitization_are_bounded() {
        for code in [
            "no-response",
            "connect-timeout",
            "connection-refused",
            "authentication-failed",
            "authentication-required",
            "authentication-mode-unsupported",
            "access-denied",
            "unsupported-operation",
            "response-mismatch",
            "malformed-response",
            "permission-denied",
            "request-rejected",
            "device-status-error",
        ] {
            assert!(diagnostic_hint(code).is_some(), "missing hint for {code}");
        }
        assert!(diagnostic_hint("unknown").is_none());
        assert_eq!(safe_diagnostic_text("line\nnext\tentry"), "line next entry");
        assert!(safe_diagnostic_text(&"x".repeat(513)).ends_with("… (truncated)"));
    }

    #[test]
    fn pnio_warning_targets_are_normalized_without_accepting_arbitrary_text() {
        assert_eq!(
            pnio_warning_target("PROFINET PNIO skipped for 192.0.2.1: outside scope"),
            Some("192.0.2.1".into())
        );
        assert_eq!(
            pnio_warning_target("PROFINET PNIO record scan failed for 00:11:22:33:44:55: timeout"),
            Some("00:11:22:33:44:55".into())
        );
        assert_eq!(pnio_warning_target("unknown target: invalid"), None);
        assert_eq!(
            pnio_warning_target("PROFINET PNIO skipped for invalid"),
            None
        );
    }

    #[test]
    fn import_endpoint_appends_to_base_path_and_rejects_non_base_urls() {
        assert_eq!(
            import_endpoint("https://otserver.example/base/")
                .unwrap()
                .as_str(),
            "https://otserver.example/base/api/asset-imports"
        );
        for input in [
            "not a URL",
            "ftp://otserver.example",
            "https://otserver.example/?token=secret",
            "https://otserver.example/#fragment",
            "mailto:ops@example.com",
        ] {
            assert!(import_endpoint(input).is_err(), "accepted {input}");
        }
    }

    #[test]
    fn pnio_endpoint_timeout_is_expected_no_response() {
        assert!(pnio_no_response(
            "PROFINET PNIO record scan failed for 192.0.2.10: RPC response timed out"
        ));
    }

    #[test]
    fn pnio_record_timeout_remains_partial() {
        assert!(!pnio_no_response(
            "192.0.2.10: PNIO record 0xAFF0 (API 0, slot 0, subslot 1) failed: response timed out"
        ));
    }

    #[test]
    fn expected_no_response_is_logged_without_marking_scan_partial() {
        #[derive(Default)]
        struct CapturingLogger(std::sync::Mutex<Vec<String>>);

        impl LogOutput for CapturingLogger {
            fn write(&self, message: String) {
                self.0.lock().unwrap().push(message);
            }
        }

        let logger = CapturingLogger::default();
        let mut devices = Vec::new();
        let mut unresolved = Vec::new();
        let mut warnings = Vec::new();
        let partial = apply_probe(
            "Test",
            &mut devices,
            &mut unresolved,
            &mut warnings,
            &logger,
            Some(Ok((
                "192.0.2.10".parse().unwrap(),
                None,
                protocols::ProbeResult {
                    observations: Vec::new(),
                    ports: Vec::new(),
                    warnings: Vec::new(),
                    outcomes: vec![protocols::ProbeOutcome {
                        source: Source::S7,
                        protocol: "s7",
                        status: protocols::ProbeStatus::NoResponse,
                        endpoint: "tcp/102".into(),
                        timeout: "2s",
                        stage: "response",
                        messages: vec!["No response received from tcp/102 (timeout 2s).".into()],
                    }],
                },
            ))),
        );

        assert!(!partial);
        assert!(warnings.is_empty());
        assert!(logger.0.lock().unwrap()[0].starts_with("[ip=192.0.2.10] [s7] ["));
        assert!(logger.0.lock().unwrap()[0].contains("NO_RESPONSE code=response-timeout"));
    }

    #[tokio::test]
    async fn stopped_scan_writes_valid_partial_export() {
        let output = std::env::temp_dir().join(format!("{}.json", Uuid::new_v4()));
        let options = ScanOptions {
            targets: vec!["192.0.2.1".into()],
            interface: "test-interface".into(),
            source_mac: "00:11:22:33:44:55".into(),
            output: output.clone(),
            protocols: ProtocolOptions::default(),
            allow_dcp_source: false,
            snmp: vec![snmp::Settings::default()],
            opcua: protocols::OpcuaSettings::default(),
            ads: protocols::AdsSettings::default(),
            upload: None,
        };
        let cancelled = Arc::new(AtomicBool::new(true));

        assert!(
            scan("Test", &options, &StdoutLogger, &cancelled)
                .await
                .unwrap()
        );
        let export: ScanExport =
            serde_json::from_slice(&tokio::fs::read(&output).await.unwrap()).unwrap();
        tokio::fs::remove_file(output).await.unwrap();

        assert!(export.scan.partial);
        assert!(export.scan.interface.addresses.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn passive_lldp_capture_stops_before_ip_probes_and_keeps_partial_export() {
        #[derive(Default)]
        struct CancelAfterLayer2 {
            cancelled: Option<Arc<AtomicBool>>,
            messages: std::sync::Mutex<Vec<String>>,
        }

        impl LogOutput for CancelAfterLayer2 {
            fn write(&self, message: String) {
                if message.contains("Unique devices after Layer 2 discovery:")
                    && let Some(cancelled) = &self.cancelled
                {
                    cancelled.store(true, Ordering::Relaxed);
                }
                self.messages.lock().unwrap().push(message);
            }
        }

        let interfaces = profinet::interfaces().unwrap();
        let Some(interface) = interfaces
            .iter()
            .find(|interface| profinet::interface_mac(interface).is_some())
        else {
            return;
        };
        let output = std::env::temp_dir().join(format!("{}.json", Uuid::new_v4()));
        let mut protocols = no_protocols();
        protocols.lldp = true;
        let options = ScanOptions {
            targets: vec![Ipv4Addr::LOCALHOST.to_string()],
            interface: interface.name.clone(),
            source_mac: "02:00:00:00:00:01".into(),
            output: output.clone(),
            protocols,
            allow_dcp_source: false,
            snmp: Vec::new(),
            opcua: protocols::OpcuaSettings::default(),
            ads: protocols::AdsSettings::default(),
            upload: None,
        };
        let cancelled = Arc::new(AtomicBool::new(false));
        let logger = CancelAfterLayer2 {
            cancelled: Some(Arc::clone(&cancelled)),
            ..CancelAfterLayer2::default()
        };

        let partial = scan("Passive LLDP", &options, &logger, &cancelled)
            .await
            .unwrap();
        let export: ScanExport =
            serde_json::from_slice(&tokio::fs::read(&output).await.unwrap()).unwrap();
        tokio::fs::remove_file(output).await.unwrap();
        let messages = logger.messages.lock().unwrap();

        assert!(partial && export.scan.partial);
        assert!(cancelled.load(Ordering::Relaxed));
        assert!(
            export
                .warnings
                .iter()
                .any(|warning| warning.contains("stopped by user"))
        );
        assert!(
            messages
                .iter()
                .any(|message| message.contains("Unique devices after Layer 2 discovery:"))
        );
        assert!(
            !messages
                .iter()
                .any(|message| message.contains("Querying LLDP"))
        );
    }

    #[test]
    fn scan_metadata_keeps_only_selected_interface_ip_addresses() {
        let interfaces = [
            profinet::CaptureInterface {
                name: "eth0".into(),
                friendly_name: "Cell A".into(),
                description: String::new(),
                addresses: vec![
                    "00:11:22:33:44:55".into(),
                    "192.0.2.10".into(),
                    "192.0.2.10".into(),
                    "2001:db8::1".into(),
                    "invalid".into(),
                ],
            },
            profinet::CaptureInterface {
                name: "eth1".into(),
                friendly_name: "Cell B".into(),
                description: String::new(),
                addresses: vec!["198.51.100.10".into()],
            },
        ];
        let metadata = scan_interface_ref("Cell A", "00-11-22-33-44-55", &interfaces);
        assert_eq!(metadata.addresses, ["192.0.2.10", "2001:db8::1"]);
        assert_eq!(metadata.mac_address.as_deref(), Some("00:11:22:33:44:55"));
        assert_eq!(metadata.id, "Cell A");
        assert_eq!(
            metadata.ip_route_policy.as_deref(),
            Some("operating-system")
        );
        assert!(
            scan_interface_ref("missing", "00:11:22:33:44:55", &interfaces)
                .addresses
                .is_empty()
        );
    }

    #[test]
    fn named_configs_supplies_display_names_without_rewriting_configs() {
        let configs = ScannerConfigs::Multiple(vec![
            ScannerConfig {
                targets: Some(vec!["192.0.2.1".into()]),
                ..ScannerConfig::default()
            },
            ScannerConfig {
                name: Some("Cell B".into()),
                targets: Some(vec!["192.0.2.2".into()]),
                ..ScannerConfig::default()
            },
        ]);

        let named = configs.named_configs();

        assert_eq!(named[0].0, "Configuration 1");
        assert_eq!(named[1].0, "Cell B");
        assert!(configs.configs()[0].name.is_none());
    }

    #[test]
    fn configs_mut_updates_a_single_configuration() {
        let mut configs = ScannerConfigs::default();
        configs.configs_mut()[0].targets = Some(vec!["192.0.2.7".into()]);

        assert_eq!(
            configs.configs()[0].targets.as_deref(),
            Some(["192.0.2.7".into()].as_slice())
        );
    }

    #[test]
    fn mac_diagnostics_keep_target_scope_and_sanitize_text() {
        let line = format_mac_diagnostic(
            "01:80:c2:00:00:0e",
            "lldp-passive",
            "PARTIAL",
            "capture-error",
            "selected interface eth0",
            "capture",
            "bad\npacket\ttext",
        );

        assert!(line.starts_with("[mac=01:80:c2:00:00:0e] [lldp-passive] PARTIAL"));
        assert!(line.contains("endpoint=selected interface eth0 stage=capture"));
        assert!(line.contains("bad packet text"));
        assert!(!line.contains('\n'));
    }

    #[tokio::test]
    async fn dcp_capture_setup_failure_reports_the_multicast_endpoint() {
        struct CapturingLogger(std::sync::Mutex<Vec<String>>);
        impl LogOutput for CapturingLogger {
            fn write(&self, message: String) {
                self.0.lock().unwrap().push(message);
            }
        }

        let logger = CapturingLogger(std::sync::Mutex::new(Vec::new()));
        let interface = format!("missing-{}", Uuid::new_v4());
        let cancelled = Arc::new(AtomicBool::new(false));
        let result = discover_profinet(&interface, "00:11:22:33:44:55", &logger, &cancelled).await;

        assert!(result.is_err());
        let logs = logger.0.lock().unwrap();
        let diagnostic = logs
            .iter()
            .find(|line| line.contains("[profinet-dcp]") && line.contains(" FAIL"))
            .unwrap();
        assert!(diagnostic.starts_with("[mac=01:0e:cf:00:00:00]"));
        assert!(diagnostic.contains("endpoint=ethernet DCP multicast; response window 60s"));
        assert!(diagnostic.contains("stage=capture"));
    }

    struct CancelOnLog {
        trigger: &'static str,
        cancelled: Arc<AtomicBool>,
        messages: std::sync::Mutex<Vec<String>>,
    }

    impl LogOutput for CancelOnLog {
        fn write(&self, message: String) {
            if message.contains(self.trigger) {
                self.cancelled.store(true, Ordering::Relaxed);
            }
            self.messages.lock().unwrap().push(message);
        }
    }

    fn local_scan_options(output: PathBuf) -> ScanOptions {
        let (interface, source_mac) = profinet::interfaces()
            .unwrap()
            .into_iter()
            .find_map(|interface| {
                profinet::interface_mac(&interface).map(|mac| (interface.name, mac))
            })
            .expect("cancellation tests require a local interface with a MAC address");
        ScanOptions {
            targets: vec![Ipv4Addr::LOCALHOST.to_string()],
            interface,
            source_mac,
            output,
            protocols: no_protocols(),
            allow_dcp_source: false,
            snmp: Vec::new(),
            opcua: protocols::OpcuaSettings::default(),
            ads: protocols::AdsSettings::default(),
            upload: None,
        }
    }

    #[tokio::test]
    async fn arp_dispatch_retains_an_empty_result_when_cancelled_before_sending() {
        let output = std::env::temp_dir().join(format!("{}.json", Uuid::new_v4()));
        let cancelled = Arc::new(AtomicBool::new(false));
        let logger = CancelOnLog {
            trigger: "Executing ARP discovery...",
            cancelled: Arc::clone(&cancelled),
            messages: std::sync::Mutex::new(Vec::new()),
        };
        let mut options = local_scan_options(output.clone());
        options.protocols.arp = true;

        assert!(
            scan("ARP cancel", &options, &logger, &cancelled)
                .await
                .unwrap()
        );
        let export: ScanExport =
            serde_json::from_slice(&tokio::fs::read(&output).await.unwrap()).unwrap();
        {
            let messages = logger.messages.lock().unwrap();
            assert!(cancelled.load(Ordering::Relaxed));
            assert!(
                messages
                    .iter()
                    .any(|message| message.contains("ARP discovery found 0 device(s)."))
            );
        }
        assert!(export.scan.partial);
        assert!(export.devices.is_empty());
        tokio::fs::remove_file(output).await.unwrap();
    }

    #[tokio::test]
    async fn dcp_dispatch_stops_before_sending_when_cancelled_during_setup() {
        let output = std::env::temp_dir().join(format!("{}.json", Uuid::new_v4()));
        let cancelled = Arc::new(AtomicBool::new(false));
        let logger = CancelOnLog {
            trigger: "Scanning PROFINET DCP;",
            cancelled: Arc::clone(&cancelled),
            messages: std::sync::Mutex::new(Vec::new()),
        };
        let mut options = local_scan_options(output.clone());
        options.protocols.arp = true;
        options.protocols.profinet = true;
        options.allow_dcp_source = true;

        assert!(
            scan("DCP cancel", &options, &logger, &cancelled)
                .await
                .unwrap()
        );
        let export: ScanExport =
            serde_json::from_slice(&tokio::fs::read(&output).await.unwrap()).unwrap();
        {
            let messages = logger.messages.lock().unwrap();
            assert!(cancelled.load(Ordering::Relaxed));
            assert!(messages.iter().any(|message| {
                message.contains("[profinet-dcp]") && message.contains("CANCELLED code=cancelled")
            }));
        }
        assert!(export.scan.partial);
        assert!(export.devices.is_empty());
        tokio::fs::remove_file(output).await.unwrap();
    }

    #[tokio::test]
    async fn scan_runs_a_local_no_response_probe_and_writes_a_complete_export() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let output = std::env::temp_dir().join(format!("{}.json", Uuid::new_v4()));
        let protocols = ProtocolOptions {
            opcua: true,
            ..no_protocols()
        };
        let options = ScanOptions {
            targets: vec![Ipv4Addr::LOCALHOST.to_string()],
            interface: "not-bound-for-ip-probes".into(),
            source_mac: "00:11:22:33:44:55".into(),
            output: output.clone(),
            protocols,
            allow_dcp_source: false,
            snmp: Vec::new(),
            opcua: protocols::OpcuaSettings {
                ports: vec![port],
                credentials: Vec::new(),
            },
            ads: protocols::AdsSettings::default(),
            upload: None,
        };

        let partial = scan(
            "Local closed listener",
            &options,
            &StdoutLogger,
            &Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
        let export: ScanExport =
            serde_json::from_slice(&tokio::fs::read(&output).await.unwrap()).unwrap();
        tokio::fs::remove_file(output).await.unwrap();

        assert!(!partial);
        assert!(!export.scan.partial);
        assert!(export.devices.is_empty());
        assert!(export.errors.is_empty());
        assert_eq!(export.scan.targets, [Ipv4Addr::LOCALHOST.to_string()]);
    }

    #[tokio::test]
    async fn scan_retains_a_correlated_udp_identity_when_tcp_is_malformed() {
        // A closed port may time out on Windows instead of reporting connection refusal.
        let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 44818))
            .await
            .unwrap();
        let udp = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 44818))
            .await
            .unwrap();
        let tcp_responder = tokio::spawn(async move {
            let (mut stream, _) = tcp.accept().await.unwrap();
            let mut request = [0; 24];
            stream.read_exact(&mut request).await.unwrap();
            stream.write_all(&[0; 24]).await.unwrap();
        });
        let responder = tokio::spawn(async move {
            let mut request = [0; 24];
            let (_, peer) = udp.recv_from(&mut request).await.unwrap();
            let mut response = vec![0; 68];
            response[0] = 0x63;
            response[2..4].copy_from_slice(&44_u16.to_le_bytes());
            response[12..20].copy_from_slice(&request[12..20]);
            response[24..26].copy_from_slice(&1_u16.to_le_bytes());
            response[26..28].copy_from_slice(&0x000c_u16.to_le_bytes());
            response[28..30].copy_from_slice(&38_u16.to_le_bytes());
            response[30] = 1;
            response[32..34].copy_from_slice(&2_u16.to_be_bytes());
            response[36..40].copy_from_slice(&[127, 0, 0, 1]);
            response[48..50].copy_from_slice(&1_u16.to_le_bytes());
            response[50..52].copy_from_slice(&12_u16.to_le_bytes());
            response[52..54].copy_from_slice(&158_u16.to_le_bytes());
            response[54..56].copy_from_slice(&[3, 7]);
            response[58..62].copy_from_slice(&42_u32.to_le_bytes());
            response[62] = 4;
            response[63..67].copy_from_slice(b"PLC1");
            udp.send_to(&response, peer).await.unwrap();
        });

        let output = std::env::temp_dir().join(format!("{}.json", Uuid::new_v4()));
        let mut protocols = no_protocols();
        protocols.enip = true;
        let options = ScanOptions {
            targets: vec![Ipv4Addr::LOCALHOST.to_string()],
            interface: "not-bound-for-ip-probes".into(),
            source_mac: "00:11:22:33:44:55".into(),
            output: output.clone(),
            protocols,
            allow_dcp_source: false,
            snmp: Vec::new(),
            opcua: protocols::OpcuaSettings::default(),
            ads: protocols::AdsSettings::default(),
            upload: None,
        };

        let partial = scan(
            "Local EtherNet/IP responder",
            &options,
            &StdoutLogger,
            &Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
        let export: ScanExport =
            serde_json::from_slice(&tokio::fs::read(&output).await.unwrap()).unwrap();
        tokio::fs::remove_file(output).await.unwrap();
        tcp_responder.await.unwrap();
        responder.await.unwrap();

        assert!(partial);
        assert!(export.scan.partial);
        assert_eq!(export.unresolved.len(), 1);
        assert_eq!(export.unresolved[0].source, Source::EthernetIp);
        assert_eq!(export.unresolved[0].fields["model"], "PLC1");
        assert_eq!(export.unresolved[0].raw["serialClaim"]["scope"], "adapter");
        assert_eq!(
            export.unresolved[0].raw["serialClaim"]["original"],
            "0000002A"
        );
        assert!(
            export
                .warnings
                .iter()
                .any(|warning| warning.contains("tcp: invalid List Identity response"))
        );
    }

    #[tokio::test]
    async fn scan_exports_snmp_configuration_failures_as_partial_results() {
        let output = std::env::temp_dir().join(format!("{}.json", Uuid::new_v4()));
        let mut protocols = no_protocols();
        protocols.snmp = true;
        let options = ScanOptions {
            targets: vec![Ipv4Addr::LOCALHOST.to_string()],
            interface: "not-bound-for-ip-probes".into(),
            source_mac: "00:11:22:33:44:55".into(),
            output: output.clone(),
            protocols,
            allow_dcp_source: false,
            snmp: vec![snmp::Settings {
                version: Some("unsupported".into()),
                ..snmp::Settings::default()
            }],
            opcua: protocols::OpcuaSettings::default(),
            ads: protocols::AdsSettings::default(),
            upload: None,
        };

        let partial = scan(
            "Invalid SNMP configuration",
            &options,
            &StdoutLogger,
            &Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
        let export: ScanExport =
            serde_json::from_slice(&tokio::fs::read(&output).await.unwrap()).unwrap();
        tokio::fs::remove_file(output).await.unwrap();

        assert!(partial);
        assert!(export.scan.partial);
        assert!(export.devices.is_empty());
        assert!(
            export
                .warnings
                .iter()
                .any(|warning| warning.contains("Unsupported SNMP version"))
        );
    }

    #[tokio::test]
    async fn atomic_export_reports_a_missing_parent_directory() {
        let directory = std::env::temp_dir().join(format!("otter-missing-{}", Uuid::new_v4()));
        let error = write_atomic(&directory.join("scan.json"), b"{}")
            .await
            .unwrap_err();
        assert!(error.starts_with("Could not write export:"));
        assert!(!directory.exists());
    }

    #[tokio::test]
    async fn scan_reports_device_snapshots_with_the_configuration_name() {
        let output = std::env::temp_dir().join(format!("{}.json", Uuid::new_v4()));
        let options = ScanOptions {
            targets: vec!["192.0.2.1".into()],
            interface: "test-interface".into(),
            source_mac: "00:11:22:33:44:55".into(),
            output: output.clone(),
            protocols: ProtocolOptions::default(),
            allow_dcp_source: false,
            snmp: vec![snmp::Settings::default()],
            opcua: protocols::OpcuaSettings::default(),
            ads: protocols::AdsSettings::default(),
            upload: None,
        };
        let cancelled = Arc::new(AtomicBool::new(true));
        let logger = DeviceLogger::default();

        scan("Line A", &options, &logger, &cancelled).await.unwrap();
        tokio::fs::remove_file(output).await.unwrap();

        let snapshots = logger.snapshots.lock().unwrap();
        assert_eq!(snapshots.len(), 2);
        assert!(
            snapshots
                .iter()
                .all(|(name, count)| name == "Line A" && *count == 0)
        );
    }

    #[tokio::test]
    async fn disabled_probe_batch_writes_a_complete_empty_export() {
        let output = std::env::temp_dir().join(format!("{}.json", Uuid::new_v4()));
        let configured = ConfiguredScan {
            name: "Quiet line".into(),
            options: ScanOptions {
                targets: vec!["127.0.0.1".into()],
                interface: "lo".into(),
                source_mac: "00:11:22:33:44:55".into(),
                output: output.clone(),
                protocols: no_protocols(),
                allow_dcp_source: false,
                snmp: Vec::new(),
                opcua: protocols::OpcuaSettings::default(),
                ads: protocols::AdsSettings::default(),
                upload: None,
            },
        };
        let result = run_scan_batch(
            &[configured],
            &DeviceLogger::default(),
            &Arc::new(AtomicBool::new(false)),
        )
        .await;

        assert_eq!(
            result,
            BatchResult {
                completed: 1,
                ..BatchResult::default()
            }
        );
        let export: ScanExport =
            serde_json::from_slice(&tokio::fs::read(&output).await.unwrap()).unwrap();
        assert!(!export.scan.partial);
        assert!(export.devices.is_empty());
        assert_eq!(export.scan.targets, ["127.0.0.1"]);
        tokio::fs::remove_file(output).await.unwrap();
    }

    fn empty_batch_scan(name: &str, output: PathBuf) -> ConfiguredScan {
        ConfiguredScan {
            name: name.into(),
            options: ScanOptions {
                targets: vec!["127.0.0.1".into()],
                interface: "not-bound-for-ip-probes".into(),
                source_mac: "00:11:22:33:44:55".into(),
                output,
                protocols: no_protocols(),
                allow_dcp_source: false,
                snmp: Vec::new(),
                opcua: protocols::OpcuaSettings::default(),
                ads: protocols::AdsSettings::default(),
                upload: None,
            },
        }
    }

    #[tokio::test]
    async fn batch_stops_when_cancelled_during_discovery_and_keeps_export() {
        struct CancelAtDiscovery(Arc<AtomicBool>);
        impl LogOutput for CancelAtDiscovery {
            fn write(&self, message: String) {
                if message.contains("Starting discovery for target(s):") {
                    self.0.store(true, Ordering::Relaxed);
                }
            }
        }

        let output = std::env::temp_dir().join(format!("{}.json", Uuid::new_v4()));
        let cancelled = Arc::new(AtomicBool::new(false));
        let result = run_scan_batch(
            &[empty_batch_scan("Cell", output.clone())],
            &CancelAtDiscovery(Arc::clone(&cancelled)),
            &cancelled,
        )
        .await;

        assert!(result.cancelled);
        assert_eq!(result.completed, 0);
        let export: ScanExport =
            serde_json::from_slice(&tokio::fs::read(&output).await.unwrap()).unwrap();
        assert!(export.scan.partial);
        tokio::fs::remove_file(output).await.unwrap();
    }

    #[tokio::test]
    async fn batch_retains_partial_results_and_continues_after_upload_failure() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let endpoint = format!(
            "http://{}/api/asset-imports",
            listener.local_addr().unwrap()
        );
        drop(listener);

        let partial_output = std::env::temp_dir().join(format!("{}.json", Uuid::new_v4()));
        let failed_upload_output = std::env::temp_dir().join(format!("{}.json", Uuid::new_v4()));
        let complete_output = std::env::temp_dir().join(format!("{}.json", Uuid::new_v4()));
        let mut partial = empty_batch_scan("Partial", partial_output.clone());
        partial.options.protocols.snmp = true;
        partial.options.snmp = vec![snmp::Settings {
            version: Some("unsupported".into()),
            ..snmp::Settings::default()
        }];
        let mut failed_upload = empty_batch_scan("Upload failure", failed_upload_output.clone());
        failed_upload.options.upload = Some(UploadOptions {
            endpoint: reqwest::Url::parse(&endpoint).unwrap(),
            site: "site-1".into(),
            api_key: "test-key".into(),
            http: HttpOptions::default(),
        });
        let complete = empty_batch_scan("Complete", complete_output.clone());

        let result = run_scan_batch(
            &[partial, failed_upload, complete],
            &StdoutLogger,
            &Arc::new(AtomicBool::new(false)),
        )
        .await;

        assert_eq!(result.partial, 1);
        assert_eq!(result.completed, 1);
        assert_eq!(result.failures.len(), 1);
        assert!(result.failures[0].contains("upload failed"));
        assert!(partial_output.exists());
        assert!(failed_upload_output.exists());
        assert!(complete_output.exists());
        for path in [partial_output, failed_upload_output, complete_output] {
            tokio::fs::remove_file(path).await.unwrap();
        }
    }

    #[tokio::test]
    async fn uploads_payload_multipart_with_api_key_through_http_proxy() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            loop {
                let mut buffer = [0; 4096];
                let read = socket.read(&mut buffer).await.unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
                let Some(header_end) = request.windows(4).position(|value| value == b"\r\n\r\n")
                else {
                    continue;
                };
                let headers = String::from_utf8_lossy(&request[..header_end]);
                let length = headers
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .and_then(|value| value.trim().parse::<usize>().ok())
                    })
                    .unwrap();
                if request.len() >= header_end + 4 + length {
                    break;
                }
            }
            let request = String::from_utf8_lossy(&request);
            assert!(request.starts_with("POST http://127.0.0.1:"));
            assert!(request.contains("users API-Key secret-key"));
            assert!(request.contains("name=\"_payload\""));
            assert!(request.contains("\"site\":\"site-1\""));
            assert!(request.contains("\"source\":\"otserver-otter\""));
            assert!(request.contains("filename=\"scan.json\""));

            let body = r#"{"doc":{"id":"import-1","status":"completed","createdAssets":2,"updatedAssets":1,"skippedAssets":0}}"#;
            socket
                .write_all(
                    format!(
                        "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
        });
        let upload = UploadOptions {
            endpoint: reqwest::Url::parse(&format!("http://{address}/api/asset-imports")).unwrap(),
            site: "site-1".into(),
            api_key: "secret-key".into(),
            http: HttpOptions {
                http_proxy: Some(format!("http://{address}")),
                ..HttpOptions::default()
            },
        };

        let imported = send_import(
            &upload,
            br#"{"format":"otserver-scan"}"#.to_vec(),
            "scan.json",
        )
        .await
        .unwrap();
        assert_eq!(imported.status, "completed");
        assert_eq!(imported.created_assets, Some(2));
        server.await.unwrap();
    }

    async fn import_test_response(response: Vec<u8>) -> Result<ImportDocument, String> {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0; 4096];
            assert!(socket.read(&mut request).await.unwrap() > 0);
            // The client may stop reading as soon as the body limit is exceeded.
            let _ = socket.write_all(&response).await;
            tokio::time::sleep(Duration::from_secs(10)).await;
        });
        let result = send_import(
            &UploadOptions {
                endpoint: reqwest::Url::parse(&format!("http://{address}/api/asset-imports"))
                    .unwrap(),
                site: "site-1".into(),
                api_key: "test-key".into(),
                http: HttpOptions::default(),
            },
            b"{}".to_vec(),
            "scan.json",
        )
        .await;
        server.abort();
        result
    }

    #[tokio::test]
    async fn upload_rejects_announced_and_chunked_oversized_responses() {
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            MAX_IMPORT_RESPONSE_BYTES + 1
        );
        assert!(
            import_test_response(response.into_bytes())
                .await
                .err()
                .unwrap()
                .contains("16 MiB")
        );
        let mut response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        response.extend(format!("{:X}\r\n", MAX_IMPORT_RESPONSE_BYTES + 1).as_bytes());
        response.resize(response.len() + MAX_IMPORT_RESPONSE_BYTES + 1, b'x');
        response.extend(b"\r\n0\r\n\r\n");
        assert!(
            import_test_response(response)
                .await
                .err()
                .unwrap()
                .contains("16 MiB")
        );
    }

    #[tokio::test]
    async fn upload_deadline_and_error_responses_preserve_failure_diagnostics() {
        let started = Instant::now();
        assert!(
            import_test_response(vec![])
                .await
                .err()
                .unwrap()
                .contains("Could not upload scan")
        );
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(
            import_test_response(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n".to_vec())
                .await
                .err()
                .unwrap()
                .contains("Could not read OTserver response")
        );
        for (status, body, expected) in [
            ("403 Forbidden", "denied", "403 Forbidden"),
            ("200 OK", "not-json", "invalid import response"),
            (
                "200 OK",
                r#"{"doc":{"id":"1","status":"failed","error":"validation failed"}}"#,
                "validation failed",
            ),
        ] {
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            assert!(
                import_test_response(response.into_bytes())
                    .await
                    .err()
                    .unwrap()
                    .contains(expected)
            );
        }
    }

    #[tokio::test]
    async fn upload_accepts_chunked_json_with_a_utf8_bom() {
        let body = "\u{feff}{\"doc\":{\"id\":\"1\",\"status\":\"completed\"}}";
        let response = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:X}\r\n{body}\r\n0\r\n\r\n",
            body.len()
        );
        assert_eq!(
            import_test_response(response.into_bytes())
                .await
                .unwrap()
                .status,
            "completed"
        );
    }

    #[test]
    fn applies_native_outcomes_and_scopes_observations_to_correlated_devices() {
        #[derive(Default)]
        struct CapturingLogger(std::sync::Mutex<Vec<String>>);

        impl LogOutput for CapturingLogger {
            fn write(&self, message: String) {
                self.0.lock().unwrap().push(message);
            }
        }

        let observation = |source| otserver_otter::contract::Observation {
            source,
            observed_at: "2026-01-01T00:00:00Z".into(),
            ip_address: Some("192.0.2.10".into()),
            mac_address: None,
            fields: BTreeMap::new(),
            raw: serde_json::Value::Null,
            warnings: Vec::new(),
        };
        let outcome = |status, messages| protocols::ProbeOutcome {
            source: Source::S7,
            protocol: "s7",
            status,
            endpoint: "tcp/102".into(),
            timeout: "2s",
            stage: "read",
            messages,
        };
        let mac = "00:11:22:33:44:55";
        let logger = CapturingLogger::default();
        let mut devices = vec![Device {
            mac_address: mac.into(),
            ..Device::default()
        }];
        let mut unresolved = Vec::new();
        let mut warnings = Vec::new();

        let failed = apply_probe(
            "Line A",
            &mut devices,
            &mut unresolved,
            &mut warnings,
            &logger,
            Some(Ok((
                "192.0.2.10".parse().unwrap(),
                Some(mac.into()),
                protocols::ProbeResult {
                    observations: vec![observation(Source::S7)],
                    ports: Vec::new(),
                    warnings: Vec::new(),
                    outcomes: vec![
                        outcome(protocols::ProbeStatus::Success, Vec::new()),
                        outcome(
                            protocols::ProbeStatus::Success,
                            vec!["identity read completed".into()],
                        ),
                        outcome(protocols::ProbeStatus::Partial, Vec::new()),
                        outcome(protocols::ProbeStatus::NoResponse, Vec::new()),
                        outcome(protocols::ProbeStatus::Failure, Vec::new()),
                        outcome(protocols::ProbeStatus::Cancelled, Vec::new()),
                    ],
                },
            ))),
        );

        assert!(failed);
        assert_eq!(devices[0].observations.len(), 1);
        assert!(unresolved.is_empty());
        assert_eq!(warnings.len(), 3);
        let logs = logger.0.lock().unwrap();
        assert_eq!(logs.len(), 6);
        assert!(
            logs.iter()
                .any(|line| line.contains("INFO code=protocol-error"))
        );
        assert!(
            logs.iter()
                .any(|line| line.contains("NO_RESPONSE code=no-response"))
        );
        drop(logs);

        assert!(!apply_probe(
            "Line A",
            &mut devices,
            &mut unresolved,
            &mut warnings,
            &logger,
            Some(Ok((
                "192.0.2.10".parse().unwrap(),
                None,
                protocols::ProbeResult {
                    observations: vec![observation(Source::OpcUa)],
                    ports: Vec::new(),
                    warnings: Vec::new(),
                    outcomes: Vec::new(),
                },
            ))),
        ));
        assert_eq!(unresolved.len(), 1);
        assert!(!apply_probe(
            "Line A",
            &mut devices,
            &mut unresolved,
            &mut warnings,
            &logger,
            None,
        ));
    }

    #[tokio::test]
    async fn applies_snmp_success_partial_and_configuration_failure_results() {
        #[derive(Default)]
        struct CapturingLogger(std::sync::Mutex<Vec<String>>);

        impl LogOutput for CapturingLogger {
            fn write(&self, message: String) {
                self.0.lock().unwrap().push(message);
            }
        }

        let observation = || otserver_otter::contract::Observation {
            source: Source::Snmp,
            observed_at: "2026-01-01T00:00:00Z".into(),
            ip_address: Some("192.0.2.10".into()),
            mac_address: None,
            fields: BTreeMap::new(),
            raw: serde_json::Value::Null,
            warnings: Vec::new(),
        };
        let result = |identity_mac, warnings, inventory_complete, lldp_complete| snmp::ResultData {
            identity_mac,
            observation: Some(observation()),
            interfaces: Vec::new(),
            ports: Vec::new(),
            links: Vec::new(),
            warnings,
            inventory_complete,
            lldp_complete,
        };
        let logger = CapturingLogger::default();
        let mut devices = vec![Device {
            mac_address: "00:11:22:33:44:55".into(),
            ..Device::default()
        }];
        let mut links = Vec::new();
        let mut unresolved = Vec::new();
        let mut warnings = Vec::new();
        let attempts = vec![
            snmp::QueryAttempt {
                description: "version=3 security=user".into(),
                success: false,
                failure: Some("unsupported SNMP privacy".into()),
            },
            snmp::QueryAttempt {
                description: "version=2c security=community".into(),
                success: true,
                failure: None,
            },
            snmp::QueryAttempt {
                description: "version=1 security=community".into(),
                success: false,
                failure: None,
            },
        ];

        assert!(apply_snmp_probe(
            "Line A",
            &mut devices,
            &mut links,
            &mut unresolved,
            &mut warnings,
            &logger,
            snmp::QuerySelection {
                inventory: true,
                lldp: true,
            },
            Some(Ok((
                "192.0.2.10".into(),
                attempts,
                Ok(result(
                    Some("00:11:22:33:44:55".into()),
                    vec!["LLDP neighbor table was incomplete".into()],
                    false,
                    true,
                )),
            ))),
        ));
        assert_eq!(devices[0].observations.len(), 1);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("lldp-snmp"));
        assert!(logger.0.lock().unwrap().iter().any(|line| {
            line.contains("Attempt 1") && line.contains("authentication-mode-unsupported")
        }));
        assert!(
            logger
                .0
                .lock()
                .unwrap()
                .iter()
                .any(|line| line.contains("SNMP version/security settings did not complete."))
        );

        assert!(!apply_snmp_probe(
            "Line A",
            &mut devices,
            &mut links,
            &mut unresolved,
            &mut warnings,
            &logger,
            snmp::QuerySelection {
                inventory: false,
                lldp: false,
            },
            Some(Ok((
                "192.0.2.11".into(),
                Vec::new(),
                Ok(result(None, Vec::new(), true, true)),
            ))),
        ));
        assert_eq!(unresolved.len(), 1);

        assert!(!apply_snmp_probe(
            "Line A",
            &mut devices,
            &mut links,
            &mut unresolved,
            &mut warnings,
            &logger,
            snmp::QuerySelection {
                inventory: true,
                lldp: false,
            },
            Some(Ok((
                "192.0.2.12".into(),
                Vec::new(),
                Ok(result(
                    Some("00:11:22:33:44:66".into()),
                    Vec::new(),
                    true,
                    true,
                )),
            ))),
        ));
        assert_eq!(devices.len(), 2);
        assert_eq!(devices[1].mac_address, "00:11:22:33:44:66");
        assert!(!apply_snmp_probe(
            "Line A",
            &mut devices,
            &mut links,
            &mut unresolved,
            &mut warnings,
            &logger,
            snmp::QuerySelection {
                inventory: true,
                lldp: false,
            },
            None,
        ));

        let (attempts, error) = snmp::query_with_attempts(
            "192.0.2.20",
            None,
            &[snmp::Settings {
                version: Some("4".into()),
                ..snmp::Settings::default()
            }],
            snmp::QuerySelection {
                inventory: true,
                lldp: true,
            },
        )
        .await;
        let Err(error) = error else {
            panic!("unsupported SNMP version unexpectedly succeeded")
        };
        assert!(!error.is_no_response());
        assert!(apply_snmp_probe(
            "Line A",
            &mut devices,
            &mut links,
            &mut unresolved,
            &mut warnings,
            &logger,
            snmp::QuerySelection {
                inventory: true,
                lldp: true,
            },
            Some(Ok(("192.0.2.20".into(), attempts, Err(error)))),
        ));
        assert_eq!(warnings.len(), 3);
    }

    #[tokio::test]
    async fn cancelled_probe_workers_are_reported_without_panicking_the_scan() {
        let native = tokio::spawn(std::future::pending::<()>());
        native.abort();
        let native_error = native.await.unwrap_err();
        let snmp_task = tokio::spawn(std::future::pending::<()>());
        snmp_task.abort();
        let snmp_error = snmp_task.await.unwrap_err();
        let logger = DeviceLogger::default();
        let mut devices = Vec::new();
        let mut links = Vec::new();
        let mut unresolved = Vec::new();
        let mut warnings = Vec::new();

        assert!(apply_probe(
            "Line A",
            &mut devices,
            &mut unresolved,
            &mut warnings,
            &logger,
            Some(Err(native_error)),
        ));
        assert!(apply_snmp_probe(
            "Line A",
            &mut devices,
            &mut links,
            &mut unresolved,
            &mut warnings,
            &logger,
            snmp::QuerySelection {
                inventory: true,
                lldp: true,
            },
            Some(Err(snmp_error)),
        ));

        assert_eq!(
            warnings,
            [
                "A native protocol probe task failed.",
                "An SNMP probe task failed."
            ]
        );
    }

    #[tokio::test]
    async fn drain_tasks_keeps_ready_results_and_stops_waiting_after_cancellation() {
        let mut tasks = tokio::task::JoinSet::new();
        tasks.spawn(async { 7 });
        tasks.spawn(std::future::pending::<u8>());
        tokio::task::yield_now().await;

        let cancelled = AtomicBool::new(true);
        let mut completed = Vec::new();
        drain_tasks(&mut tasks, &cancelled, |result| {
            if let Some(Ok(value)) = result {
                completed.push(value);
            }
        })
        .await;

        assert_eq!(completed, [7]);
    }

    #[tokio::test]
    async fn configuration_loading_prefers_current_name_then_legacy_and_atomic_exports_replace() {
        let directory = std::env::temp_dir().join(format!("otter-config-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&directory).unwrap();
        let current = directory.join("otter.json");
        let legacy = directory.join("otscanner.json");
        std::fs::write(&legacy, b"legacy").unwrap();
        assert_eq!(config_load_path(&current), legacy);
        std::fs::write(&current, b"current").unwrap();
        assert_eq!(config_load_path(&current), current);
        std::fs::remove_file(&legacy).unwrap();

        let export = directory.join("scan.json");
        write_atomic(&export, b"first").await.unwrap();
        write_atomic(&export, b"replacement").await.unwrap();
        assert_eq!(tokio::fs::read(&export).await.unwrap(), b"replacement");
        assert!(
            write_atomic(&directory.join("missing/scan.json"), b"data")
                .await
                .unwrap_err()
                .starts_with("Could not write export:")
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn cli_dispatches_safe_local_information_commands_and_batch_cancellation() {
        for command in [
            Commands::Interfaces { json: true },
            Commands::Interfaces { json: false },
            Commands::Doctor,
        ] {
            assert!(
                run_cli(Cli {
                    command: Some(command),
                })
                .await
                .is_ok()
            );
        }

        let result = run_scan_batch(
            &[ConfiguredScan {
                name: "Pending line".into(),
                options: ScanOptions {
                    targets: vec!["127.0.0.1".into()],
                    interface: "lo".into(),
                    source_mac: "00:11:22:33:44:55".into(),
                    output: PathBuf::from("unused.json"),
                    protocols: ProtocolOptions {
                        arp: false,
                        profinet: false,
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
                        snmp: false,
                        lldp: false,
                        ads: false,
                    },
                    allow_dcp_source: false,
                    snmp: Vec::new(),
                    opcua: protocols::OpcuaSettings::default(),
                    ads: protocols::AdsSettings::default(),
                    upload: None,
                },
            }],
            &DeviceLogger::default(),
            &Arc::new(AtomicBool::new(true)),
        )
        .await;
        assert_eq!(
            result,
            BatchResult {
                cancelled: true,
                ..BatchResult::default()
            }
        );
    }

    #[tokio::test]
    async fn scan_command_dispatch_uses_supplied_config_without_reading_local_config() {
        let directory = std::env::temp_dir().join(format!("otter-cli-{}", Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let output = directory.join("scan.json");
        let mut scan = args();
        scan.targets = vec!["127.0.0.1".into()];
        scan.interface = Some("lo".into());
        scan.source_mac = Some("00:11:22:33:44:55".into());
        scan.output = Some(output.clone());
        scan.no_protocols = true;
        scan.no_arp = true;
        scan.no_profinet = true;
        scan.no_snmp = true;
        scan.no_lldp = true;

        let result = run_cli_with_configs(
            Cli {
                command: Some(Commands::Scan(scan)),
            },
            Some(ScannerConfigs::default()),
        )
        .await;

        assert!(result.is_ok(), "{result:?}");
        let export: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&output).unwrap()).unwrap();
        assert_eq!(export["format"], "otserver-scan");
        assert!(export["scan"].get("partial").is_none());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn scan_command_reports_invalid_configurations_after_running_valid_ones() {
        let directory = std::env::temp_dir().join(format!("otter-cli-{}", Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let output = directory.join("scan.json");
        let mut scan = args();
        scan.targets = vec!["127.0.0.1".into()];
        scan.interface = Some("lo".into());
        scan.source_mac = Some("00:11:22:33:44:55".into());
        scan.output = Some(output.clone());
        scan.no_protocols = true;
        scan.no_arp = true;
        scan.no_profinet = true;
        scan.no_snmp = true;
        scan.no_lldp = true;
        let configs = ScannerConfigs::Multiple(vec![
            ScannerConfig {
                name: Some("valid".into()),
                ..ScannerConfig::default()
            },
            ScannerConfig {
                name: Some("invalid".into()),
                ads_ports: Some(vec![0]),
                ..ScannerConfig::default()
            },
        ]);

        let error = run_cli_with_configs(
            Cli {
                command: Some(Commands::Scan(scan)),
            },
            Some(configs),
        )
        .await
        .unwrap_err();

        assert!(error.contains("1 configuration(s) failed"), "{error}");
        assert!(output.is_file());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn controller_command_dispatch_fails_before_network_or_default_state_access() {
        let directory = std::env::temp_dir().join(format!("otter-cli-{}", Uuid::new_v4()));
        let cli = Cli::try_parse_from([
            "otserver-otter",
            "controller",
            "--ack-authorized",
            "--state-dir",
            directory.to_str().unwrap(),
        ])
        .unwrap();

        let error = run_cli(cli).await.unwrap_err();

        assert!(error.contains("Controller URL is invalid"), "{error}");
        assert!(directory.is_dir());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn absent_executable_adjacent_config_uses_defaults_without_creating_a_file() {
        let _config_guard = CONFIG_FILE_TEST_LOCK.lock().unwrap();
        let path = get_config_path().unwrap();
        if path.exists() {
            return;
        }

        assert_eq!(load_config().unwrap(), ScannerConfigs::default());
        assert!(!path.exists());
    }
}
