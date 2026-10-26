use crate::{
    BatchResult, HttpOptions, LogOutput, ScanArgs, ScannerConfig, ScannerConfigs, controller,
    format_log_line, load_config, nonempty_opt, prepare_scans, run_scan_batch, save_config_sync,
};
use eframe::egui;
use otserver_otter::contract::Device;
use otserver_otter::profinet::{self, CaptureInterface};
use otserver_otter::protocols::{OpcuaCredential, OpcuaCredentials};
use otserver_otter::snmp::{Credentials as SnmpCredentials, Settings as SnmpSettings};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};

pub struct GuiLogger {
    sender: Sender<ScanMessage>,
}

enum ScanMessage {
    Log(String),
    Devices(Vec<Device>),
    Finished(BatchResult),
}

enum ControllerMessage {
    Enrolled,
    Installed(String),
}

fn local_scan_configs(configs: Vec<(String, ScannerConfig)>) -> Vec<(String, ScannerConfig)> {
    configs
        .into_iter()
        .map(|(name, mut config)| {
            config.server_url = None;
            config.site = None;
            config.api_key = None;
            (name, config)
        })
        .collect()
}

impl LogOutput for GuiLogger {
    fn write(&self, msg: String) {
        let _ = self.sender.send(ScanMessage::Log(msg));
    }

    fn devices(&self, _configuration: &str, devices: &[Device]) {
        let _ = self.sender.send(ScanMessage::Devices(devices.to_vec()));
    }
}

fn bound_ip_addresses(interfaces: &[CaptureInterface], selected: &str) -> Vec<String> {
    interfaces
        .iter()
        .find(|item| item.name == selected)
        .map(|item| {
            item.addresses
                .iter()
                .filter(|address| address.parse::<IpAddr>().is_ok())
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

fn with_added_configuration(
    configs: &ScannerConfigs,
    selected: usize,
    edited: ScannerConfig,
) -> ScannerConfigs {
    let mut values = configs.configs().to_vec();
    values[selected] = edited;
    if !configs.is_multiple() && values[0].name.is_none() {
        values[0].name = Some("Configuration 1".into());
    }

    let mut number = values.len() + 1;
    let name = loop {
        let candidate = format!("Configuration {number}");
        if values
            .iter()
            .all(|config| config.name.as_deref() != Some(&candidate))
        {
            break candidate;
        }
        number += 1;
    };

    let mut added = values[selected].clone();
    added.name = Some(name);
    let base = added
        .output
        .as_deref()
        .unwrap_or_else(|| Path::new("otserver-scan.json"));
    for suffix in 2.. {
        let stem = base
            .file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or("otserver-scan");
        let filename = match base.extension().and_then(|value| value.to_str()) {
            Some(extension) => format!("{stem}-{suffix}.{extension}"),
            None => format!("{stem}-{suffix}"),
        };
        let candidate = base.with_file_name(filename);
        if values.iter().all(|config| {
            config
                .output
                .as_deref()
                .unwrap_or_else(|| Path::new("otserver-scan.json"))
                != candidate
        }) {
            added.output = Some(candidate);
            break;
        }
    }
    values.push(added);
    ScannerConfigs::Multiple(values)
}

fn text_row(ui: &mut egui::Ui, label: &str, edit: egui::TextEdit) -> bool {
    ui.horizontal(|ui| {
        ui.label(label);
        ui.add(edit).changed()
    })
    .inner
}

fn protocol_combo(
    ui: &mut egui::Ui,
    id: &str,
    value: &mut String,
    options: &[(&str, &str)],
) -> bool {
    let selected = options
        .iter()
        .find(|(option, _)| *option == value.as_str())
        .map(|(_, label)| *label)
        .unwrap_or("None");
    egui::ComboBox::from_id_salt(id)
        .selected_text(selected)
        .show_ui(ui, |ui| {
            for (option, label) in options {
                ui.selectable_value(value, (*option).to_string(), *label);
            }
        })
        .response
        .changed()
}

fn snmp_version_label(version: &str) -> &'static str {
    if version.eq_ignore_ascii_case("1") {
        "SNMPv1"
    } else if version.eq_ignore_ascii_case("3") {
        "SNMPv3"
    } else if version.eq_ignore_ascii_case("auto") {
        "Auto (v3, v2c, v1)"
    } else {
        "SNMPv2c"
    }
}

fn opcua_credential_label(credential: &OpcuaCredential) -> String {
    match credential
        .username
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        Some(username) => format!("User {username}"),
        None => "Anonymous".into(),
    }
}

fn opcua_credential_detail(credential: &OpcuaCredential) -> String {
    match credential
        .username
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        Some(_) => {
            if credential
                .password
                .as_deref()
                .is_some_and(|value| !value.is_empty())
            {
                "Password set".into()
            } else {
                "Password missing".into()
            }
        }
        None => "No credentials (anonymous access)".into(),
    }
}

fn snmp_credential_detail(settings: &SnmpSettings) -> String {
    let version = otserver_otter::snmp::resolved_version(settings);
    if version.eq_ignore_ascii_case("auto") {
        return "Fallback: v3 if configured, then v2c, then v1".into();
    }
    if version.eq_ignore_ascii_case("3") {
        let user = settings
            .username
            .as_deref()
            .filter(|value| !value.is_empty())
            .unwrap_or("(username missing)");
        let security = match (
            settings
                .auth_protocol
                .as_deref()
                .filter(|value| !value.is_empty()),
            settings
                .privacy_protocol
                .as_deref()
                .filter(|value| !value.is_empty()),
        ) {
            (None, None) => "no authentication",
            (Some(_), None) => "authentication",
            (Some(_), Some(_)) => "authentication + encryption",
            (None, Some(_)) => "invalid: encryption requires authentication",
        };
        return format!("User {user}, {security}");
    }
    match settings
        .community
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        Some(community) => format!("Community {community}"),
        None => "Community \"public\" (default)".into(),
    }
}

pub struct GuiApp {
    configs: ScannerConfigs,
    selected_config: usize,
    config_name: String,
    targets: String,
    interface: String,
    source_mac: String,
    output: String,
    snmp_credentials: Vec<SnmpSettings>,
    selected_snmp: usize,
    snmp_version: String,
    snmp_community: String,
    snmp_username: String,
    snmp_context: String,
    snmp_auth_protocol: String,
    snmp_auth_password: String,
    snmp_privacy_protocol: String,
    snmp_privacy_password: String,
    opcua_credentials: Vec<OpcuaCredential>,
    selected_opcua: usize,
    opcua_username: String,
    opcua_password: String,
    arp_enabled: bool,
    profinet_enabled: bool,
    allow_dcp_source: bool,
    s7_enabled: bool,
    enip_enabled: bool,
    bacnet_enabled: bool,
    fins_enabled: bool,
    fox_enabled: bool,
    dnp3_enabled: bool,
    iec61850_enabled: bool,
    netbios_enabled: bool,
    smb_enabled: bool,
    rpc_enabled: bool,
    http_enabled: bool,
    ads_enabled: bool,
    opcua_enabled: bool,
    snmp_enabled: bool,
    lldp_enabled: bool,
    controller_url: String,
    enrollment_token: String,
    overwrite_enrollment: bool,
    controller_http: HttpOptions,
    controller_info: Option<controller::EnrollmentInfo>,
    controller_status: String,
    controller_rx: Option<Receiver<Result<ControllerMessage, String>>>,
    ack_authorized: bool,

    interfaces: Vec<CaptureInterface>,
    log_text: String,
    status: String,
    config_save_result: Option<Result<String, String>>,
    is_scanning: bool,
    cancellation: Option<Arc<AtomicBool>>,
    log_rx: Option<Receiver<ScanMessage>>,
    assets: Vec<Device>,
    asset_window_open: bool,
    selected_asset: Option<String>,
    #[cfg(windows)]
    npcap_available: bool,
    #[cfg(windows)]
    npcap_version: Option<String>,
    #[cfg(windows)]
    npcap_interface_available: bool,
}

impl GuiApp {
    pub fn new(configs: ScannerConfigs) -> Self {
        let interfaces = profinet::interfaces().unwrap_or_default();
        #[cfg(windows)]
        let npcap_available = profinet::npcap_available();
        #[cfg(windows)]
        let npcap_version = profinet::npcap_version();
        let mut app = Self {
            configs,
            selected_config: 0,
            config_name: String::new(),
            targets: String::new(),
            interface: String::new(),
            source_mac: String::new(),
            output: String::new(),
            snmp_credentials: vec![SnmpSettings::default()],
            selected_snmp: 0,
            snmp_version: "2c".into(),
            snmp_community: String::new(),
            snmp_username: String::new(),
            snmp_context: String::new(),
            snmp_auth_protocol: String::new(),
            snmp_auth_password: String::new(),
            snmp_privacy_protocol: String::new(),
            snmp_privacy_password: String::new(),
            opcua_credentials: vec![OpcuaCredential::default()],
            selected_opcua: 0,
            opcua_username: String::new(),
            opcua_password: String::new(),
            arp_enabled: true,
            profinet_enabled: true,
            allow_dcp_source: false,
            s7_enabled: true,
            enip_enabled: true,
            bacnet_enabled: true,
            fins_enabled: true,
            fox_enabled: true,
            dnp3_enabled: true,
            iec61850_enabled: true,
            netbios_enabled: true,
            smb_enabled: true,
            rpc_enabled: true,
            http_enabled: true,
            ads_enabled: true,
            opcua_enabled: true,
            snmp_enabled: true,
            lldp_enabled: true,
            controller_url: String::new(),
            enrollment_token: String::new(),
            overwrite_enrollment: false,
            controller_http: HttpOptions::default(),
            controller_info: None,
            controller_status:
                "Not enrolled. Create a scanner in OTserver and copy its enrollment token.".into(),
            controller_rx: None,
            ack_authorized: false,
            interfaces,
            log_text: format!("{}\n", format_log_line("OTserver Otter GUI ready.")),
            status: "Ready".to_string(),
            config_save_result: None,
            is_scanning: false,
            cancellation: None,
            log_rx: None,
            assets: Vec::new(),
            asset_window_open: false,
            selected_asset: None,
            #[cfg(windows)]
            npcap_available,
            #[cfg(windows)]
            npcap_version,
            #[cfg(windows)]
            npcap_interface_available: false,
        };
        app.apply_selected_config();
        app
    }

    fn apply_selected_config(&mut self) {
        let config = self.configs.configs()[self.selected_config].clone();
        self.config_name = config.name.clone().unwrap_or_default();
        self.targets = config
            .targets
            .as_ref()
            .map(|targets| targets.join(", "))
            .unwrap_or_else(|| "192.168.1.0/24".into());
        self.interface = config
            .interface
            .clone()
            .or_else(|| self.interfaces.first().map(|item| item.name.clone()))
            .unwrap_or_default();
        self.source_mac = config
            .source_mac
            .clone()
            .or_else(|| {
                self.interfaces
                    .iter()
                    .find(|item| item.name == self.interface)
                    .and_then(profinet::interface_mac)
            })
            .unwrap_or_default();
        self.output = config
            .output
            .as_ref()
            .map(|path| path.to_string_lossy().into_owned())
            .unwrap_or_else(|| "otserver-scan.json".into());

        self.snmp_credentials = config
            .snmp
            .map(|credentials| credentials.to_vec())
            .filter(|settings| !settings.is_empty())
            .unwrap_or_else(|| vec![SnmpSettings::default()]);
        self.selected_snmp = 0;
        self.load_snmp_buffers();

        let legacy_native_disabled = config.no_protocols.unwrap_or(false);
        self.arp_enabled = !config.no_arp.unwrap_or(false);
        self.profinet_enabled = !config.no_profinet.unwrap_or(false);
        self.allow_dcp_source = config.allow_dcp_source.unwrap_or(false);
        self.s7_enabled = !(legacy_native_disabled || config.no_s7.unwrap_or(false));
        self.enip_enabled = !(legacy_native_disabled || config.no_enip.unwrap_or(false));
        self.bacnet_enabled = !(legacy_native_disabled || config.no_bacnet.unwrap_or(false));
        self.fins_enabled = !(legacy_native_disabled || config.no_fins.unwrap_or(false));
        self.fox_enabled = !(legacy_native_disabled || config.no_fox.unwrap_or(false));
        self.dnp3_enabled = !(legacy_native_disabled || config.no_dnp3.unwrap_or(false));
        self.iec61850_enabled = !(legacy_native_disabled || config.no_iec61850.unwrap_or(false));
        self.netbios_enabled = !(legacy_native_disabled || config.no_netbios.unwrap_or(false));
        self.smb_enabled = !(legacy_native_disabled || config.no_smb.unwrap_or(false));
        self.rpc_enabled = !(legacy_native_disabled || config.no_rpc.unwrap_or(false));
        self.http_enabled = !(legacy_native_disabled || config.no_http.unwrap_or(false));
        self.ads_enabled = !(legacy_native_disabled || config.no_ads.unwrap_or(false));
        self.opcua_enabled = !(legacy_native_disabled || config.no_opcua.unwrap_or(false));
        self.snmp_enabled = !config.no_snmp.unwrap_or(false);
        self.lldp_enabled = !config.no_lldp.unwrap_or(false);
        let mut opcua = config
            .opcua_credentials
            .map(|credentials| credentials.to_vec())
            .unwrap_or_default();
        if opcua.is_empty() && (config.opcua_username.is_some() || config.opcua_password.is_some())
        {
            opcua.push(OpcuaCredential {
                username: config.opcua_username,
                password: config.opcua_password,
            });
        }
        if opcua.is_empty() {
            opcua.push(OpcuaCredential::default());
        }
        self.opcua_credentials = opcua;
        self.selected_opcua = 0;
        self.load_opcua_buffers();
        #[cfg(windows)]
        self.refresh_npcap();
    }

    fn load_snmp_buffers(&mut self) {
        let snmp = self.snmp_credentials[self.selected_snmp].clone();
        self.snmp_version = otserver_otter::snmp::resolved_version(&snmp).to_string();
        self.snmp_community = snmp.community.unwrap_or_default();
        self.snmp_username = snmp.username.unwrap_or_default();
        self.snmp_context = snmp.context_name.unwrap_or_default();
        self.snmp_auth_protocol = snmp.auth_protocol.unwrap_or_default();
        self.snmp_auth_password = snmp.auth_password.unwrap_or_default();
        self.snmp_privacy_protocol = snmp.privacy_protocol.unwrap_or_default();
        self.snmp_privacy_password = snmp.privacy_password.unwrap_or_default();
    }

    fn snmp_buffer_settings(&self) -> SnmpSettings {
        SnmpSettings {
            version: (self.snmp_version != "2c").then(|| self.snmp_version.clone()),
            community: nonempty_opt(&self.snmp_community),
            username: nonempty_opt(&self.snmp_username),
            context_name: nonempty_opt(&self.snmp_context),
            auth_protocol: nonempty_opt(&self.snmp_auth_protocol),
            auth_password: nonempty_opt(&self.snmp_auth_password),
            privacy_protocol: nonempty_opt(&self.snmp_privacy_protocol),
            privacy_password: nonempty_opt(&self.snmp_privacy_password),
        }
    }

    fn snmp_all_settings(&self) -> Vec<SnmpSettings> {
        let mut settings = self.snmp_credentials.clone();
        settings[self.selected_snmp] = self.snmp_buffer_settings();
        settings
    }

    fn load_opcua_buffers(&mut self) {
        let credential = self.opcua_credentials[self.selected_opcua].clone();
        self.opcua_username = credential.username.unwrap_or_default();
        self.opcua_password = credential.password.unwrap_or_default();
    }

    fn opcua_buffer_credential(&self) -> OpcuaCredential {
        OpcuaCredential {
            username: nonempty_opt(&self.opcua_username),
            password: nonempty_opt(&self.opcua_password),
        }
    }

    fn opcua_all_credentials(&self) -> Vec<OpcuaCredential> {
        let mut credentials = self.opcua_credentials.clone();
        credentials[self.selected_opcua] = self.opcua_buffer_credential();
        credentials
    }

    fn opcua_credentials_config(&self) -> Option<OpcuaCredentials> {
        let mut credentials = self.opcua_all_credentials();
        if credentials.len() == 1 && credentials[0] == OpcuaCredential::default() {
            return None;
        }
        if credentials.len() == 1 {
            Some(OpcuaCredentials::Single(credentials.remove(0)))
        } else {
            Some(OpcuaCredentials::Multiple(credentials))
        }
    }

    fn opcua_credential_row_labels(&self) -> Vec<String> {
        self.opcua_all_credentials()
            .iter()
            .enumerate()
            .map(|(index, credential)| {
                format!("{}. {}", index + 1, opcua_credential_label(credential))
            })
            .collect()
    }

    fn snmp_credentials_config(&self) -> Option<SnmpCredentials> {
        let mut settings = self.snmp_all_settings();
        if settings.len() == 1 && settings[0] == SnmpSettings::default() {
            return None;
        }
        if settings.len() == 1 {
            Some(SnmpCredentials::Single(settings.remove(0)))
        } else {
            Some(SnmpCredentials::Multiple(settings))
        }
    }

    fn to_config(&self) -> ScannerConfig {
        let targets_vec: Vec<String> = self
            .targets
            .split(&[',', '\n', ';'][..])
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let mut config = self.configs.configs()[self.selected_config].clone();
        config.name = nonempty_opt(&self.config_name);
        config.targets = (!targets_vec.is_empty()).then_some(targets_vec);
        config.interface = nonempty_opt(&self.interface);
        config.source_mac = nonempty_opt(&self.source_mac);
        config.output = nonempty_opt(&self.output).map(PathBuf::from);
        config.snmp = self.snmp_credentials_config();
        config.no_protocols = None;
        config.no_arp = (!self.arp_enabled).then_some(true);
        config.no_profinet = (!self.profinet_enabled).then_some(true);
        config.allow_dcp_source = self.allow_dcp_source.then_some(true);
        config.no_s7 = (!self.s7_enabled).then_some(true);
        config.no_enip = (!self.enip_enabled).then_some(true);
        config.no_bacnet = (!self.bacnet_enabled).then_some(true);
        config.no_fins = (!self.fins_enabled).then_some(true);
        config.no_fox = (!self.fox_enabled).then_some(true);
        config.no_dnp3 = (!self.dnp3_enabled).then_some(true);
        config.no_iec61850 = (!self.iec61850_enabled).then_some(true);
        config.no_netbios = (!self.netbios_enabled).then_some(true);
        config.no_smb = (!self.smb_enabled).then_some(true);
        config.no_rpc = (!self.rpc_enabled).then_some(true);
        config.no_http = (!self.http_enabled).then_some(true);
        config.no_ads = (!self.ads_enabled).then_some(true);
        config.no_opcua = (!self.opcua_enabled).then_some(true);
        config.no_snmp = (!self.snmp_enabled).then_some(true);
        config.no_lldp = (!self.lldp_enabled).then_some(true);
        config.opcua_credentials = self.opcua_credentials_config();
        config.opcua_username = None;
        config.opcua_password = None;
        config
    }

    fn save_config(&mut self) -> bool {
        let mut configs = self.configs.clone();
        configs.configs_mut()[self.selected_config] = self.to_config();
        self.persist_configs(configs)
    }

    fn persist_configs(&mut self, configs: ScannerConfigs) -> bool {
        match save_config_sync(&configs) {
            Ok(_) => {
                self.configs = configs;
                self.config_save_result =
                    Some(Ok(format_log_line("Configuration saved to otter.json.")));
                true
            }
            Err(err) => {
                self.config_save_result = Some(Err(format_log_line(&format!(
                    "Configuration save failed: {err}",
                ))));
                false
            }
        }
    }

    fn add_configuration(&mut self) {
        let configs =
            with_added_configuration(&self.configs, self.selected_config, self.to_config());
        let selected = configs.configs().len() - 1;
        if self.persist_configs(configs) {
            self.selected_config = selected;
            self.apply_selected_config();
            self.config_save_result =
                Some(Ok(format_log_line("Configuration added to otter.json.")));
        }
    }

    fn append_log(&mut self, message: &str) {
        self.log_text.push_str(&format_log_line(message));
        self.log_text.push('\n');
    }

    #[cfg(windows)]
    fn refresh_npcap(&mut self) {
        self.npcap_available = profinet::npcap_available();
        self.npcap_version = profinet::npcap_version();
        self.npcap_interface_available =
            self.npcap_available && profinet::npcap_interface_available(&self.interface);
    }

    fn start_scan(&mut self, run_all: bool) {
        if !self.ack_authorized {
            self.status = "Error: --ack-authorized required to start scan!".to_string();
            self.append_log("Error: You must check the authorization box before scanning.");
            return;
        }

        if !self.save_config() {
            self.status = "Configuration could not be saved.".into();
            self.append_log("Configuration could not be saved; scan not started.");
            return;
        }

        let configs = if run_all {
            self.configs.named_configs()
        } else {
            let config = self.configs.configs()[self.selected_config].clone();
            vec![(
                config
                    .name
                    .clone()
                    .unwrap_or_else(|| "Configuration".into()),
                config,
            )]
        };
        let args = ScanArgs {
            ack_authorized: true,
            ..ScanArgs::default()
        };
        let (scans, failures) = match prepare_scans(args, local_scan_configs(configs), None) {
            Ok(prepared) => prepared,
            Err(err) => {
                self.status = format!("Configuration error: {err}");
                self.append_log(&format!("Configuration error: {err}"));
                return;
            }
        };

        let scan_count = scans.len();
        let (tx, rx) = mpsc::channel::<ScanMessage>();
        let cancellation = Arc::new(AtomicBool::new(false));
        self.log_rx = Some(rx);
        self.cancellation = Some(Arc::clone(&cancellation));
        self.is_scanning = true;
        self.assets.clear();
        self.selected_asset = None;
        self.asset_window_open = true;
        self.status = format!("Running {scan_count} configuration(s)...");
        self.append_log(&format!("Starting {scan_count} configuration(s)."));

        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("Failed to build tokio runtime for scan thread");

            let logger = GuiLogger { sender: tx.clone() };
            for failure in &failures {
                logger.log(failure.clone());
            }
            let mut result = rt.block_on(run_scan_batch(&scans, &logger, &cancellation));
            let mut all_failures = failures;
            all_failures.append(&mut result.failures);
            result.failures = all_failures;
            let _ = tx.send(ScanMessage::Finished(result));
        });
    }

    fn refresh_enrollment(&mut self) {
        match controller::enrollment_info(None) {
            Ok(info) => {
                if let Some(info) = &info {
                    self.controller_url.clone_from(&info.server_url);
                    self.controller_http = info.http.clone();
                    self.controller_status = format!(
                        "Enrolled as {} at site {}. Configure managed scans in OTserver.",
                        info.name, info.site
                    );
                }
                self.controller_info = info;
            }
            Err(error) => self.controller_status = error,
        }
    }

    fn start_controller_action(&mut self, install: bool) {
        if !self.ack_authorized || self.controller_rx.is_some() {
            return;
        }
        let url = self.controller_url.clone();
        let token = std::mem::take(&mut self.enrollment_token);
        let overwrite = self.overwrite_enrollment;
        let http = self.controller_http.clone();
        let (tx, rx) = mpsc::channel();
        self.controller_rx = Some(rx);
        self.controller_status = if install {
            "Installing controller. Complete any operating-system authorization prompt..."
        } else {
            "Enrolling scanner..."
        }
        .into();
        std::thread::spawn(move || {
            let result = if install {
                controller::install_from_gui().map(ControllerMessage::Installed)
            } else {
                tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                    .map_err(|_| "Could not start enrollment worker.".to_owned())
                    .and_then(|rt| {
                        rt.block_on(controller::enroll_from_gui(url, token, overwrite, http))
                    })
                    .map(|()| ControllerMessage::Enrolled)
            };
            let _ = tx.send(result);
        });
    }

    fn controller_controls(&mut self, ui: &mut egui::Ui) {
        ui.group(|ui| {
            ui.heading("OTserver controller");
            if let Some(info) = &self.controller_info {
                ui.label(format!("Enrolled: {} ({})", info.name, info.server_url));
            }
            ui.label("Enroll with a single-use token from OTserver > Otter Scanners. Managed scan settings and protocol credentials come from OTserver.");
            let busy = self.controller_rx.is_some();
            ui.add_enabled_ui(!busy, |ui| {
                ui.label("Controller URL");
                ui.add(egui::TextEdit::singleline(&mut self.controller_url).desired_width(f32::INFINITY).hint_text("https://otserver.example"));
                ui.label("Enrollment token");
                ui.add(egui::TextEdit::singleline(&mut self.enrollment_token).password(true).desired_width(f32::INFINITY));
                ui.checkbox(&mut self.overwrite_enrollment, "Replace enrollment if this state belongs to a different controller");
                egui::CollapsingHeader::new("Connection settings").show(ui, |ui| {
                    ui.checkbox(&mut self.controller_http.ignore_self_signed, "Disable TLS certificate and hostname validation");
                    for (label, proxy) in [("HTTP proxy", &mut self.controller_http.http_proxy), ("HTTPS proxy", &mut self.controller_http.https_proxy)] {
                        let mut value = proxy.clone().unwrap_or_default();
                        ui.label(label);
                        if ui.add(egui::TextEdit::singleline(&mut value).password(true).desired_width(f32::INFINITY)).changed() { *proxy = nonempty_opt(&value); }
                    }
                });
                ui.horizontal_wrapped(|ui| {
                    if ui.add_enabled(self.ack_authorized && !self.controller_url.trim().is_empty() && !self.enrollment_token.trim().is_empty(), egui::Button::new("Enroll")).clicked() {
                        self.start_controller_action(false);
                    }
                    if self.controller_info.is_some() && ui.add_enabled(self.ack_authorized, egui::Button::new("Install controller")).clicked() {
                        self.start_controller_action(true);
                    }
                });
            });
            if !self.ack_authorized { ui.label("Confirm authorization below before enrolling or installing."); }
            if busy { ui.spinner(); }
            ui.label(&self.controller_status);
        });
    }
}

impl GuiApp {
    fn update_ui(&mut self, ctx: &egui::Context) {
        if let Some(rx) = &self.controller_rx {
            let result = match rx.try_recv() {
                Ok(result) => Some(result),
                Err(mpsc::TryRecvError::Disconnected) => Some(Err(
                    "Controller worker stopped unexpectedly. Retry the action.".into(),
                )),
                Err(mpsc::TryRecvError::Empty) => None,
            };
            if let Some(result) = result {
                self.controller_rx = None;
                match result {
                    Ok(ControllerMessage::Enrolled) => {
                        self.refresh_enrollment();
                        self.overwrite_enrollment = false;
                    }
                    Ok(ControllerMessage::Installed(message)) => self.controller_status = message,
                    Err(error) => {
                        self.controller_status = format!("Controller setup failed: {error}")
                    }
                }
            }
        }
        let scan_messages: Vec<_> = self
            .log_rx
            .as_ref()
            .map(|rx| rx.try_iter().collect())
            .unwrap_or_default();
        for message in scan_messages {
            match message {
                ScanMessage::Log(message) => {
                    self.log_text.push_str(&message);
                    self.log_text.push('\n');
                }
                ScanMessage::Devices(devices) => {
                    merge_assets(&mut self.assets, devices);
                    if let Some(selected) = &self.selected_asset
                        && !self
                            .assets
                            .iter()
                            .any(|device| device.mac_address == *selected)
                    {
                        self.selected_asset = None;
                    }
                }
                ScanMessage::Finished(result) => {
                    self.is_scanning = false;
                    self.cancellation = None;
                    self.log_rx = None;
                    let summary = format!(
                        "{} complete, {} partial, {} failed.",
                        result.completed,
                        result.partial,
                        result.failures.len()
                    );
                    if result.cancelled {
                        self.status = format!("Batch stopped: {summary}");
                        self.append_log(&format!(
                            "Batch stopped; pending configurations were skipped. {summary}"
                        ));
                    } else {
                        self.status = format!("Batch finished: {summary}");
                        self.append_log(&format!("Batch finished: {summary}"));
                    }
                }
            }
        }

        if self.is_scanning || self.controller_rx.is_some() {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }

        egui::TopBottomPanel::top("app-header").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("OTserver Otter");
                ui.weak(format!("Version {}", otserver_otter::VERSION));
            });
            ui.label("Read-only OT asset discovery tool");
        });

        egui::TopBottomPanel::bottom("app-controls").show(ctx, |ui| {
            let controls_enabled = !self.is_scanning && self.controller_rx.is_none();
            ui.horizontal_wrapped(|ui| {
                ui.add_enabled(
                    controls_enabled,
                    egui::Checkbox::new(
                        &mut self.ack_authorized,
                        "I confirm I am authorized to scan these networks (--ack-authorized)",
                    ),
                );

                if self.configs.is_multiple() {
                    if ui
                        .add_enabled(
                            controls_enabled && self.ack_authorized,
                            egui::Button::new("Run Selected"),
                        )
                        .clicked()
                    {
                        self.start_scan(false);
                    }
                    if ui
                        .add_enabled(
                            controls_enabled && self.ack_authorized,
                            egui::Button::new("Run All"),
                        )
                        .clicked()
                    {
                        self.start_scan(true);
                    }
                } else if ui
                    .add_enabled(
                        controls_enabled && self.ack_authorized,
                        egui::Button::new("Start Scan"),
                    )
                    .clicked()
                {
                    self.start_scan(false);
                }
                if ui
                    .add_enabled(self.is_scanning, egui::Button::new("Stop Scan"))
                    .clicked()
                    && let Some(cancellation) = &self.cancellation
                {
                    cancellation.store(true, Ordering::Relaxed);
                    self.status = "Stopping scan...".to_string();
                }
                if ui
                    .add_enabled(controls_enabled, egui::Button::new("Save Config"))
                    .clicked()
                {
                    self.save_config();
                }
                if ui
                    .button(format!("Show Assets ({})", self.assets.len()))
                    .clicked()
                {
                    self.asset_window_open = true;
                }
            });
            ui.horizontal_wrapped(|ui| {
                ui.label(format!("Status: {}", self.status));
                if let Some(result) = &self.config_save_result {
                    ui.separator();
                    match result {
                        Ok(message) => {
                            ui.colored_label(
                                egui::Color32::LIGHT_GREEN,
                                format!("Config: {message}"),
                            );
                        }
                        Err(message) => {
                            ui.colored_label(
                                egui::Color32::LIGHT_RED,
                                format!("Config error: {message}"),
                            );
                        }
                    }
                }
            });
        });

        egui::SidePanel::right("scan-log")
            .default_width(400.0)
            .min_width(300.0)
            .max_width(650.0)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.heading("Scan Log");
                    if ui
                        .add_enabled(!self.log_text.is_empty(), egui::Button::new("Clear Log"))
                        .clicked()
                    {
                        self.log_text.clear();
                    }
                });
                ui.separator();
                egui::ScrollArea::vertical()
                    .id_salt("scan-log-scroll")
                    .stick_to_bottom(true)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(self.log_text.as_str()).monospace(),
                            )
                            .selectable(true)
                            .wrap(),
                        );
                    });
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            if self.is_scanning {
                ui.disable();
            }
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.group(|ui| {
                    ui.set_min_width(ui.available_width());
                    ui.heading("Configurations");
                    if self.configs.is_multiple() {
                        let names: Vec<_> = self
                            .configs
                            .configs()
                            .iter()
                            .filter_map(|config| config.name.clone())
                            .collect();
                        let mut selected = self.selected_config;
                        ui.horizontal(|ui| {
                            ui.label("Selected:");
                            egui::ComboBox::from_id_salt("scanner-configuration")
                                .selected_text(&names[self.selected_config])
                                .show_ui(ui, |ui| {
                                    for (index, name) in names.iter().enumerate() {
                                        ui.selectable_value(&mut selected, index, name);
                                    }
                                });
                        });
                        if selected != self.selected_config && self.save_config() {
                            self.selected_config = selected;
                            self.apply_selected_config();
                        }
                        if text_row(
                            ui,
                            "Name:",
                            egui::TextEdit::singleline(&mut self.config_name),
                        ) {
                            self.save_config();
                        }
                    } else {
                        ui.label("This file currently contains one configuration.");
                    }
                    if ui.button("Add Configuration").clicked() {
                        self.add_configuration();
                    }
                });
                ui.add_space(8.0);
                ui.group(|ui| {
                    ui.set_min_width(ui.available_width());
                    ui.heading("Network Target Settings");
                    if text_row(
                        ui,
                        "Targets (CIDR / IP):",
                        egui::TextEdit::singleline(&mut self.targets).hint_text("192.168.1.0/24"),
                    ) {
                        self.save_config();
                    }

                    ui.horizontal(|ui| {
                        ui.label("Capture Interface:");
                        egui::ComboBox::from_label("Interface Selection")
                            .selected_text(
                                self.interfaces
                                    .iter()
                                    .find(|i| i.name == self.interface)
                                    .map(|i| format!("{} ({})", i.description, i.name))
                                    .unwrap_or_else(|| self.interface.clone()),
                            )
                            .show_ui(ui, |ui| {
                                let mut selected_changed = None;
                                for iface in &self.interfaces {
                                    let label = format!("{} ({})", iface.description, iface.name);
                                    if ui
                                        .selectable_value(
                                            &mut self.interface,
                                            iface.name.clone(),
                                            label,
                                        )
                                        .clicked()
                                    {
                                        selected_changed = Some(iface.name.clone());
                                    }
                                }
                                if let Some(selected) = selected_changed {
                                    if let Some(mac) = self
                                        .interfaces
                                        .iter()
                                        .find(|iface| iface.name == selected)
                                        .and_then(profinet::interface_mac)
                                    {
                                        self.source_mac = mac;
                                    }
                                    #[cfg(windows)]
                                    self.refresh_npcap();
                                    self.save_config();
                                }
                            });
                        if ui.button("Refresh").clicked() {
                            self.interfaces = profinet::interfaces().unwrap_or_default();
                            #[cfg(windows)]
                            self.refresh_npcap();
                        }
                    });

                    ui.horizontal(|ui| {
                        ui.label("Bound IP Address(es):");
                        let addresses = bound_ip_addresses(&self.interfaces, &self.interface);
                        if addresses.is_empty() {
                            ui.weak("No IP address assigned");
                        } else {
                            ui.monospace(addresses.join(", "));
                        }
                    });

                    if text_row(
                        ui,
                        "Custom Interface ID:",
                        egui::TextEdit::singleline(&mut self.interface),
                    ) {
                        #[cfg(windows)]
                        self.refresh_npcap();
                        self.save_config();
                    }

                    ui.horizontal(|ui| {
                        ui.label("Source MAC Address:");
                        if ui
                            .add(
                                egui::TextEdit::singleline(&mut self.source_mac)
                                    .hint_text("00:11:22:33:44:55"),
                            )
                            .changed()
                        {
                            self.save_config();
                        }
                        if ui.button("Auto-fill from Interface").clicked()
                            && let Some(iface) =
                                self.interfaces.iter().find(|i| i.name == self.interface)
                            && let Some(mac) = profinet::interface_mac(iface)
                        {
                            self.source_mac = mac;
                            self.save_config();
                        }
                    });

                    ui.label("Enabled protocols:");
                    let mut protocol_changed = false;
                    ui.add_enabled_ui(!self.is_scanning, |ui| {
                        ui.horizontal_wrapped(|ui| {
                            for (label, enabled) in [
                                ("ARP", &mut self.arp_enabled),
                                ("PROFINET DCP", &mut self.profinet_enabled),
                                ("Allow DCP source", &mut self.allow_dcp_source),
                                ("S7", &mut self.s7_enabled),
                                ("EtherNet/IP", &mut self.enip_enabled),
                                ("BACnet", &mut self.bacnet_enabled),
                                ("FINS", &mut self.fins_enabled),
                                ("Fox", &mut self.fox_enabled),
                                ("DNP3", &mut self.dnp3_enabled),
                                ("IEC 61850", &mut self.iec61850_enabled),
                                ("NetBIOS", &mut self.netbios_enabled),
                                ("SMB", &mut self.smb_enabled),
                                ("RPC", &mut self.rpc_enabled),
                                ("HTTP/HTTPS", &mut self.http_enabled),
                                ("Beckhoff ADS", &mut self.ads_enabled),
                                ("OPC UA", &mut self.opcua_enabled),
                                ("SNMP", &mut self.snmp_enabled),
                                ("LLDP", &mut self.lldp_enabled),
                            ] {
                                protocol_changed |= ui.toggle_value(enabled, label).changed();
                            }
                        });
                    });
                    ui.small("Highlighted protocols are enabled. All protocols are enabled by default.");
                    if protocol_changed {
                        self.save_config();
                    }

                    #[cfg(windows)]
                    if self.profinet_enabled && !self.npcap_available {
                        ui.separator();
                        ui.label(
                            "Npcap is not available. Windows will use passive pktmon PROFINET capture. Install Npcap explicitly to enable active DCP; driver installation never occurs during a scan.",
                        );
                        ui.hyperlink_to(
                            "Download Npcap",
                            "https://npcap.com/#download",
                        );
                    } else if self.profinet_enabled && self.npcap_interface_available {
                        ui.label(format!(
                            "Active Windows PROFINET DCP is ready through Npcap {} on the selected physical interface.",
                            self.npcap_version.as_deref().unwrap_or("(version unavailable)")
                        ));
                    } else if self.profinet_enabled {
                        ui.colored_label(
                            egui::Color32::YELLOW,
                            format!(
                                "Npcap {} is installed, but the selected interface is not usable for direct DCP. Remove any obsolete Windows Network Bridge, refresh, select the physical Ethernet adapter, and verify its Npcap binding.",
                                self.npcap_version.as_deref().unwrap_or("(version unavailable)")
                            ),
                        );
                    }
                });

                ui.add_space(8.0);

                ui.group(|ui| {
                    ui.set_min_width(ui.available_width());
                    ui.heading("Output Settings");
                    ui.horizontal(|ui| {
                        ui.label("Output File:");
                        if ui
                            .add(egui::TextEdit::singleline(&mut self.output))
                            .changed()
                        {
                            self.save_config();
                        }
                        if ui.button("Browse...").clicked() {
                            let path = Path::new(&self.output);
                            let mut dialog = rfd::FileDialog::new()
                                .add_filter("OTserver scan", &["json"]);
                            if let Some(name) = path.file_name().and_then(|name| name.to_str()) {
                                dialog = dialog.set_file_name(name);
                            }
                            if let Some(parent) = path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
                                dialog = dialog.set_directory(parent);
                            }
                            if let Some(path) = dialog.save_file() {
                                self.output = path.to_string_lossy().into_owned();
                                self.save_config();
                            }
                        }
                    });
                });

                ui.add_space(8.0);

                ui.group(|ui| {
                    ui.set_min_width(ui.available_width());
                    ui.heading("SNMP Settings");
                    ui.small(
                        "Stored in otter.json. Credentials are tried top to bottom until one succeeds. Without settings, SNMPv2c with community \"public\" is used.",
                    );
                    let entries = self.snmp_all_settings();
                    egui::Grid::new("snmp-credentials")
                        .striped(true)
                        .show(ui, |ui| {
                            for (index, entry) in entries.iter().enumerate() {
                                let selected = index == self.selected_snmp;
                                if ui
                                    .selectable_label(
                                        selected,
                                        format!(
                                            "{}. {}",
                                            index + 1,
                                            snmp_version_label(
                                                otserver_otter::snmp::resolved_version(entry)
                                            )
                                        ),
                                    )
                                    .clicked()
                                    && !selected
                                {
                                    self.snmp_credentials[self.selected_snmp] =
                                        self.snmp_buffer_settings();
                                    self.selected_snmp = index;
                                    self.load_snmp_buffers();
                                    self.save_config();
                                }
                                ui.label(snmp_credential_detail(entry));
                                if ui
                                    .add_enabled(entries.len() > 1, egui::Button::new("Remove"))
                                    .clicked()
                                {
                                    self.snmp_credentials.remove(index);
                                    self.selected_snmp =
                                        self.selected_snmp.min(self.snmp_credentials.len() - 1);
                                    self.load_snmp_buffers();
                                    self.save_config();
                                }
                                ui.end_row();
                            }
                        });
                    ui.small("Select a row to edit it below.");
                    if ui.button("Add Credential").clicked() {
                        self.snmp_credentials[self.selected_snmp] = self.snmp_buffer_settings();
                        self.snmp_credentials.push(SnmpSettings::default());
                        self.selected_snmp = self.snmp_credentials.len() - 1;
                        self.load_snmp_buffers();
                        self.save_config();
                    }
                    ui.horizontal(|ui| {
                        ui.label("Version:");
                        if protocol_combo(
                            ui,
                            "snmp-version",
                            &mut self.snmp_version,
                            &[
                                ("auto", "Auto (v3, v2c, v1)"),
                                ("1", "SNMPv1"),
                                ("2c", "SNMPv2c"),
                                ("3", "SNMPv3"),
                            ],
                        ) {
                            self.save_config();
                        }
                    });
                    if self.snmp_version == "auto" {
                        ui.small(
                            "Auto tries configured SNMPv3 credentials when present, then SNMPv2c and SNMPv1 with the configured community.",
                        );
                    }
                    if self.snmp_version == "3" || self.snmp_version == "auto" {
                        if text_row(
                            ui,
                            "Username:",
                            egui::TextEdit::singleline(&mut self.snmp_username),
                        ) {
                            self.save_config();
                        }
                        if text_row(
                            ui,
                            "Context Name:",
                            egui::TextEdit::singleline(&mut self.snmp_context),
                        ) {
                            self.save_config();
                        }
                        ui.horizontal(|ui| {
                            ui.label("Authentication Protocol:");
                            if protocol_combo(
                                ui,
                                "snmp-auth-protocol",
                                &mut self.snmp_auth_protocol,
                                &[
                                    ("", "None"),
                                    ("md5", "MD5"),
                                    ("sha1", "SHA-1"),
                                    ("sha224", "SHA-224"),
                                    ("sha256", "SHA-256"),
                                    ("sha384", "SHA-384"),
                                    ("sha512", "SHA-512"),
                                ],
                            ) {
                                self.save_config();
                            }
                        });
                        if !self.snmp_auth_protocol.is_empty()
                            && text_row(
                                ui,
                                "Authentication Password:",
                                egui::TextEdit::singleline(&mut self.snmp_auth_password)
                                    .password(true),
                            )
                        {
                            self.save_config();
                        }
                        ui.horizontal(|ui| {
                            ui.label("Privacy Protocol:");
                            if protocol_combo(
                                ui,
                                "snmp-privacy-protocol",
                                &mut self.snmp_privacy_protocol,
                                &[
                                    ("", "None"),
                                    ("des", "DES"),
                                    ("aes128", "AES-128"),
                                    ("aes192", "AES-192"),
                                    ("aes256", "AES-256"),
                                ],
                            ) {
                                self.save_config();
                            }
                        });
                        if !self.snmp_privacy_protocol.is_empty()
                            && text_row(
                                ui,
                                "Privacy Password:",
                                egui::TextEdit::singleline(&mut self.snmp_privacy_password)
                                    .password(true),
                            )
                        {
                            self.save_config();
                        }
                    }
                    if self.snmp_version != "3"
                        && text_row(
                            ui,
                            "Community:",
                            egui::TextEdit::singleline(&mut self.snmp_community)
                                .password(true)
                                .hint_text("public"),
                        )
                    {
                        self.save_config();
                    }
                });

                ui.add_space(8.0);

                ui.group(|ui| {
                    ui.set_min_width(ui.available_width());
                    ui.heading("OPC UA Credentials");
                    ui.small(
                        "Stored in otter.json. Anonymous access is tried first; credentials are tried top to bottom only if it fails. Passwords travel unencrypted because the scanner uses SecurityPolicy None.",
                    );
                    let entries = self.opcua_all_credentials();
                    let labels = self.opcua_credential_row_labels();
                    egui::Grid::new("opcua-credentials")
                        .striped(true)
                        .show(ui, |ui| {
                            for (index, entry) in entries.iter().enumerate() {
                                let selected = index == self.selected_opcua;
                                if ui
                                    .selectable_label(selected, &labels[index])
                                    .clicked()
                                    && !selected
                                {
                                    self.opcua_credentials[self.selected_opcua] =
                                        self.opcua_buffer_credential();
                                    self.selected_opcua = index;
                                    self.load_opcua_buffers();
                                    self.save_config();
                                }
                                ui.label(opcua_credential_detail(entry));
                                if ui
                                    .add_enabled(entries.len() > 1, egui::Button::new("Remove"))
                                    .clicked()
                                {
                                    self.opcua_credentials.remove(index);
                                    self.selected_opcua =
                                        self.selected_opcua.min(self.opcua_credentials.len() - 1);
                                    self.load_opcua_buffers();
                                    self.save_config();
                                }
                                ui.end_row();
                            }
                        });
                    ui.small("Select a row to edit it below.");
                    if ui.button("Add Credential").clicked() {
                        self.opcua_credentials[self.selected_opcua] =
                            self.opcua_buffer_credential();
                        self.opcua_credentials.push(OpcuaCredential::default());
                        self.selected_opcua = self.opcua_credentials.len() - 1;
                        self.load_opcua_buffers();
                        self.save_config();
                    }
                    if text_row(
                        ui,
                        "Username:",
                        egui::TextEdit::singleline(&mut self.opcua_username)
                            .hint_text("Use anonymous access when blank"),
                    ) {
                        self.save_config();
                    }
                    if text_row(
                        ui,
                        "Password:",
                        egui::TextEdit::singleline(&mut self.opcua_password).password(true),
                    ) {
                        self.save_config();
                    }
                });

                ui.add_space(8.0);
                self.controller_controls(ui);

                });
        });

        if self.asset_window_open {
            let assets = self.assets.clone();
            let selected = self.selected_asset.clone();
            let mut open = self.asset_window_open;
            egui::Window::new(format!("Discovered Assets ({})", assets.len()))
                .id(egui::Id::new("discovered-assets"))
                .open(&mut open)
                .default_size([1080.0, 600.0])
                .min_size([560.0, 360.0])
                .max_size([1140.0, 10_000.0])
                .show(ctx, |ui| {
                    if assets.is_empty() {
                        ui.label(if self.is_scanning {
                            "Scanning... no assets found yet."
                        } else {
                            "No assets discovered."
                        });
                        return;
                    }
                    let mut detail = None;
                    let table_width = (ui.available_width() * 0.55).max(420.0);
                    ui.horizontal_top(|ui| {
                        ui.vertical(|ui| {
                            ui.set_width(table_width);
                            egui::ScrollArea::both()
                                .id_salt("asset-list")
                                .auto_shrink([false, true])
                                .show(ui, |ui| {
                                    egui::Grid::new("asset-table").striped(true).show(ui, |ui| {
                                        ui.strong("MAC");
                                        ui.strong("IP");
                                        ui.strong("Manufacturer");
                                        ui.strong("Model");
                                        ui.strong("OS");
                                        ui.strong("Protocols");
                                        ui.end_row();
                                        for device in &assets {
                                            let is_selected =
                                                selected.as_deref() == Some(&device.mac_address);
                                            let mut row_clicked = false;
                                            {
                                                let mut cell = |ui: &mut egui::Ui, text| {
                                                    row_clicked |= ui
                                                        .selectable_label(is_selected, text)
                                                        .clicked();
                                                };
                                                cell(ui, device.mac_address.clone());
                                                cell(ui, device.ip_addresses.join(", "));
                                                cell(ui, asset_field(device, MANUFACTURER_KEYS));
                                                cell(ui, asset_field(device, MODEL_KEYS));
                                                cell(ui, asset_field(device, OS_KEYS));
                                                cell(ui, asset_protocols(device).join(", "));
                                            }
                                            ui.end_row();
                                            if row_clicked {
                                                self.selected_asset =
                                                    Some(device.mac_address.clone());
                                                detail = Some(device.clone());
                                            }
                                            if is_selected && detail.is_none() {
                                                detail = Some(device.clone());
                                            }
                                        }
                                    });
                                });
                        });
                        ui.separator();
                        ui.vertical(|ui| {
                            egui::ScrollArea::both()
                                .id_salt("asset-detail")
                                .auto_shrink([false, false])
                                .show(ui, |ui| match detail {
                                    Some(device) => show_asset_detail(ui, &device),
                                    None => {
                                        ui.weak(
                                            "Select an asset in the table to see its full record.",
                                        );
                                    }
                                });
                        });
                    });
                });
            self.asset_window_open = open;
        }
    }
}

impl eframe::App for GuiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.update_ui(ctx);
    }
}

fn asset_title(device: &Device) -> String {
    device
        .ip_addresses
        .first()
        .cloned()
        .unwrap_or_else(|| device.mac_address.clone())
}

fn asset_protocols(device: &Device) -> Vec<&'static str> {
    let mut labels = Vec::new();
    for observation in &device.observations {
        let label = observation.source.label();
        if !labels.contains(&label) {
            labels.push(label);
        }
    }
    labels
}

fn merge_assets(assets: &mut Vec<Device>, incoming: Vec<Device>) {
    for device in incoming {
        match assets
            .iter_mut()
            .find(|asset| asset.mac_address == device.mac_address)
        {
            Some(existing) => *existing = device,
            None => assets.push(device),
        }
    }
}

const MANUFACTURER_KEYS: &[&str] = &["vendor", "manufacturer"];
const MODEL_KEYS: &[&str] = &["model", "productName"];
const OS_KEYS: &[&str] = &["operatingSystem"];

fn asset_field(device: &Device, keys: &[&str]) -> String {
    device
        .observations
        .iter()
        .flat_map(|observation| observation.fields.iter())
        .find(|(key, _)| keys.contains(&key.as_str()))
        .map(|(_, value)| json_value_text(value))
        .unwrap_or_default()
}

fn show_asset_detail(ui: &mut egui::Ui, device: &Device) {
    let protocols = asset_protocols(device);
    ui.heading(asset_title(device));
    if !protocols.is_empty() {
        ui.weak(format!("Discovered via: {}", protocols.join(", ")));
    }
    ui.separator();
    match serde_json::to_value(device) {
        Ok(serde_json::Value::Object(fields)) => {
            for (key, value) in &fields {
                show_json(ui, &format!("device.{key}"), key, value, 1);
            }
        }
        Ok(value) => {
            ui.code(value.to_string());
        }
        Err(error) => {
            ui.colored_label(egui::Color32::LIGHT_RED, error.to_string());
        }
    }
}

fn show_json(ui: &mut egui::Ui, path: &str, key: &str, value: &serde_json::Value, depth: usize) {
    match value {
        serde_json::Value::Object(fields) => {
            egui::CollapsingHeader::new(egui::RichText::new(key).strong())
                .id_salt(path)
                .default_open(depth < 4)
                .show(ui, |ui| {
                    for (field, value) in fields {
                        show_json(ui, &format!("{path}.{field}"), field, value, depth + 1);
                    }
                });
        }
        serde_json::Value::Array(items) => {
            egui::CollapsingHeader::new(format!("{key} [{}]", items.len()))
                .id_salt(path)
                .default_open(depth < 4)
                .show(ui, |ui| {
                    for (index, value) in items.iter().enumerate() {
                        show_json(
                            ui,
                            &format!("{path}[{index}]"),
                            &index.to_string(),
                            value,
                            depth + 1,
                        );
                    }
                });
        }
        scalar => {
            ui.horizontal(|ui| {
                ui.label(key);
                ui.monospace(json_value_text(scalar));
            });
        }
    }
}

fn json_value_text(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

pub fn run_gui() -> Result<(), String> {
    let configs = load_config()?;
    #[cfg(windows)]
    unsafe {
        // SAFETY: FreeConsole has no arguments or pointer preconditions.
        windows_sys::Win32::System::Console::FreeConsole();
    }

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1200.0, 760.0])
            .with_min_inner_size([500.0, 500.0])
            .with_title(format!("OTserver Otter {}", otserver_otter::VERSION)),
        ..Default::default()
    };

    eframe::run_native(
        "OTserver Otter",
        options,
        Box::new(move |_cc| {
            let mut app = GuiApp::new(configs);
            app.refresh_enrollment();
            Ok(Box::new(app))
        }),
    )
    .map_err(|err| {
        let message = format!("GUI error: {err}");
        rfd::MessageDialog::new()
            .set_level(rfd::MessageLevel::Error)
            .set_title("OTserver Otter")
            .set_description(&message)
            .show();
        message
    })
}

#[cfg(test)]
mod tests {
    use super::{
        GuiApp, GuiLogger, MANUFACTURER_KEYS, MODEL_KEYS, OS_KEYS, OpcuaCredential,
        OpcuaCredentials, ScanMessage, SnmpCredentials, SnmpSettings, asset_field, asset_protocols,
        asset_title, bound_ip_addresses, json_value_text, merge_assets, opcua_credential_detail,
        opcua_credential_label, protocol_combo, snmp_credential_detail, snmp_version_label,
        with_added_configuration,
    };
    use crate::{ScannerConfig, ScannerConfigs};
    use otserver_otter::contract::{Device, Observation, Source};
    use otserver_otter::profinet::{CaptureInterface, interface_mac};
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    #[test]
    fn gui_scans_do_not_upload_using_hidden_legacy_api_credentials() {
        let config = ScannerConfig {
            targets: Some(vec!["192.0.2.1".into()]),
            interface: Some("eth0".into()),
            source_mac: Some("00:11:22:33:44:55".into()),
            server_url: Some("https://old.example".into()),
            site: Some("site1".into()),
            api_key: Some("legacy-secret".into()),
            ..ScannerConfig::default()
        };
        let configs = super::local_scan_configs(vec![("Local scan".into(), config.clone())]);
        let (scans, failures) =
            crate::prepare_scans(crate::ScanArgs::default(), configs, None).unwrap();
        assert!(failures.is_empty());
        assert!(scans[0].options.upload.is_none());
        let app = GuiApp::new(ScannerConfigs::Single(Box::new(config)));
        assert_eq!(app.to_config().api_key.as_deref(), Some("legacy-secret"));
    }

    #[test]
    fn controller_actions_require_local_authorization() {
        let mut app = GuiApp::new(ScannerConfigs::default());
        app.controller_url = "https://example.com".into();
        app.enrollment_token = "t".repeat(43);
        app.start_controller_action(false);
        app.start_controller_action(true);
        assert!(app.controller_rx.is_none());
        assert_eq!(app.enrollment_token, "t".repeat(43));
    }

    #[test]
    fn gui_logger_forwards_worker_logs_and_device_snapshots() {
        let (sender, receiver) = std::sync::mpsc::channel();
        let logger = GuiLogger { sender };
        let device = Device {
            mac_address: "00:11:22:33:44:55".into(),
            ..Device::default()
        };

        crate::LogOutput::write(&logger, "scan started".into());
        crate::LogOutput::devices(&logger, "Line A", std::slice::from_ref(&device));

        assert!(
            matches!(receiver.recv().unwrap(), ScanMessage::Log(message) if message == "scan started")
        );
        match receiver.recv().unwrap() {
            ScanMessage::Devices(devices) => {
                assert_eq!(devices.len(), 1);
                assert_eq!(devices[0].mac_address, device.mac_address);
            }
            _ => panic!("expected device snapshot"),
        }
    }

    #[test]
    fn controller_form_masks_tokens_and_has_real_enrollment_controls() {
        let mut app = GuiApp::new(ScannerConfigs::default());
        app.enrollment_token = "secret-enrollment-token".into();
        let context = eframe::egui::Context::default();
        let output = context.run(eframe::egui::RawInput::default(), |ctx| {
            eframe::egui::CentralPanel::default().show(ctx, |ui| app.controller_controls(ui));
        });
        let rendered = format!("{:?}", output.shapes);
        assert!(rendered.contains("Enroll"));
        assert!(!rendered.contains("secret-enrollment-token"));
        assert!(!rendered.contains("API Key") && !rendered.contains("Direct Upload"));
        assert!(app.controller_rx.is_none());
    }

    #[test]
    fn gui_update_renders_the_single_configuration_and_empty_assets_state() {
        let mut app = GuiApp::new(ScannerConfigs::default());
        app.asset_window_open = true;
        let context = eframe::egui::Context::default();
        let output = context.run(eframe::egui::RawInput::default(), |ctx| app.update_ui(ctx));
        let rendered = format!("{:?}", output.shapes);

        assert!(rendered.contains("This file currently contains one configuration."));
        assert!(rendered.contains("No assets discovered."));
        assert!(!app.is_scanning);
    }

    #[test]
    fn gui_update_shows_the_empty_assets_message_while_scanning() {
        let mut app = GuiApp::new(ScannerConfigs::default());
        app.asset_window_open = true;
        app.is_scanning = true;
        let context = eframe::egui::Context::default();
        let output = context.run(eframe::egui::RawInput::default(), |ctx| app.update_ui(ctx));

        assert!(format!("{:?}", output.shapes).contains("Scanning... no assets found yet."));
    }

    #[test]
    fn gui_update_renders_multiple_credentials_and_selected_asset_details() {
        let configuration = ScannerConfig {
            name: Some("Line A".into()),
            snmp: Some(SnmpCredentials::Multiple(vec![SnmpSettings {
                version: Some("3".into()),
                username: Some("inventory".into()),
                auth_protocol: Some("sha256".into()),
                auth_password: Some("auth-secret".into()),
                privacy_protocol: Some("aes128".into()),
                privacy_password: Some("privacy-secret".into()),
                ..SnmpSettings::default()
            }])),
            opcua_credentials: Some(OpcuaCredentials::Multiple(vec![OpcuaCredential {
                username: Some("operator".into()),
                password: Some("opcua-secret".into()),
            }])),
            ..ScannerConfig::default()
        };
        let other = ScannerConfig {
            name: Some("Line B".into()),
            ..ScannerConfig::default()
        };
        let mut app = GuiApp::new(ScannerConfigs::Multiple(vec![configuration, other]));
        app.controller_info = Some(crate::controller::EnrollmentInfo {
            server_url: "https://otserver.example".into(),
            name: "scanner-1".into(),
            site: "site-1".into(),
            http: crate::HttpOptions::default(),
        });
        app.asset_window_open = true;
        app.selected_asset = Some("00:11:22:33:44:55".into());
        app.assets.push(Device {
            mac_address: "00:11:22:33:44:55".into(),
            ip_addresses: vec!["192.0.2.10".into()],
            observations: vec![Observation {
                source: Source::Arp,
                observed_at: "2026-01-01T00:00:00Z".into(),
                ip_address: Some("192.0.2.10".into()),
                mac_address: Some("00:11:22:33:44:55".into()),
                fields: BTreeMap::from([("manufacturer".into(), serde_json::json!("Acme"))]),
                raw: serde_json::json!({"evidence": "wire", "nested": {"values": [1, 2]}}),
                warnings: Vec::new(),
            }],
            ..Device::default()
        });
        let context = eframe::egui::Context::default();
        let output = context.run(eframe::egui::RawInput::default(), |ctx| app.update_ui(ctx));
        let rendered = format!("{:?}", output.shapes);

        for text in [
            "Selected:",
            "Connection settings",
            "Authentication Password:",
            "Privacy Password:",
            "OPC UA Credentials",
            "Install controller",
            "Discovered via: arp",
            "manufacturer",
            "evidence",
        ] {
            assert!(rendered.contains(text), "missing rendered text: {text}");
        }
        assert!(!rendered.contains("auth-secret"));
        assert!(!rendered.contains("privacy-secret"));
        assert!(!rendered.contains("opcua-secret"));
    }

    #[test]
    fn asset_table_selects_rows_and_clear_log_empties_the_log() {
        use eframe::egui::{self, epaint::Shape};

        let mac = "00:11:22:33:44:55";
        let mut app = GuiApp::new(ScannerConfigs::default());
        app.asset_window_open = true;
        app.assets.push(Device {
            mac_address: mac.into(),
            ip_addresses: vec!["192.0.2.10".into()],
            ..Device::default()
        });
        let context = egui::Context::default();
        let output = context.run(egui::RawInput::default(), |ctx| app.update_ui(ctx));
        assert!(format!("{:?}", output.shapes).contains("Select an asset in the table"));

        for label in [mac, "Clear Log"] {
            let output = context.run(egui::RawInput::default(), |ctx| app.update_ui(ctx));
            let position = output
                .shapes
                .iter()
                .find_map(|clipped| match &clipped.shape {
                    Shape::Text(text) if text.galley.job.text == label => {
                        Some(text.pos + text.galley.size() * 0.5)
                    }
                    _ => None,
                })
                .unwrap_or_else(|| panic!("missing clickable label {label}"));
            for pressed in [true, false] {
                let _ = context.run(
                    egui::RawInput {
                        events: vec![
                            egui::Event::PointerMoved(position),
                            egui::Event::PointerButton {
                                pos: position,
                                button: egui::PointerButton::Primary,
                                pressed,
                                modifiers: egui::Modifiers::default(),
                            },
                        ],
                        ..egui::RawInput::default()
                    },
                    |ctx| app.update_ui(ctx),
                );
            }
            if label == mac {
                assert_eq!(app.selected_asset.as_deref(), Some(mac));
            }
        }
        assert!(app.log_text.is_empty());
    }

    #[test]
    fn credential_controls_select_add_and_remove_credentials() {
        use eframe::egui::{self, epaint::Shape};

        let _config_guard = crate::CONFIG_FILE_TEST_LOCK.lock().unwrap();
        let config_path = std::env::current_exe()
            .unwrap()
            .with_file_name("otter.json");
        if config_path.exists() {
            return;
        }
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
        let _cleanup = Cleanup(config_path);

        let config = ScannerConfig {
            snmp: Some(SnmpCredentials::Multiple(vec![
                SnmpSettings {
                    community: Some("first-community".into()),
                    ..SnmpSettings::default()
                },
                SnmpSettings {
                    community: Some("second-community".into()),
                    ..SnmpSettings::default()
                },
            ])),
            opcua_credentials: Some(OpcuaCredentials::Multiple(vec![
                OpcuaCredential {
                    username: Some("first-user".into()),
                    password: Some("first-password".into()),
                },
                OpcuaCredential {
                    username: Some("second-user".into()),
                    password: Some("second-password".into()),
                },
            ])),
            ..ScannerConfig::default()
        };
        let mut app = GuiApp::new(ScannerConfigs::Single(Box::new(config)));
        let context = egui::Context::default();
        let screen_rect = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(1600.0, 4000.0));

        fn click_text(
            app: &mut GuiApp,
            context: &egui::Context,
            screen_rect: egui::Rect,
            label: &str,
            occurrence: usize,
        ) {
            let output = context.run(
                egui::RawInput {
                    screen_rect: Some(screen_rect),
                    ..egui::RawInput::default()
                },
                |ctx| app.update_ui(ctx),
            );
            let position = output
                .shapes
                .iter()
                .filter_map(|clipped| match &clipped.shape {
                    Shape::Text(text) if text.galley.job.text == label => {
                        Some(text.pos + text.galley.size() * 0.5)
                    }
                    _ => None,
                })
                .nth(occurrence)
                .unwrap_or_else(|| panic!("missing clickable text {label} #{occurrence}"));
            for pressed in [true, false] {
                let _ = context.run(
                    egui::RawInput {
                        screen_rect: Some(screen_rect),
                        events: vec![
                            egui::Event::PointerMoved(position),
                            egui::Event::PointerButton {
                                pos: position,
                                button: egui::PointerButton::Primary,
                                pressed,
                                modifiers: egui::Modifiers::default(),
                            },
                        ],
                        ..egui::RawInput::default()
                    },
                    |ctx| app.update_ui(ctx),
                );
            }
        }

        click_text(&mut app, &context, screen_rect, "2. SNMPv2c", 0);
        assert_eq!(app.selected_snmp, 1);
        assert_eq!(app.snmp_community, "second-community");

        click_text(&mut app, &context, screen_rect, "Add Credential", 0);
        assert_eq!(app.snmp_credentials.len(), 3);
        click_text(&mut app, &context, screen_rect, "Add Credential", 1);
        assert_eq!(app.opcua_credentials.len(), 3);

        click_text(&mut app, &context, screen_rect, "Remove", 1);
        assert_eq!(app.snmp_credentials.len(), 2);
        assert_eq!(app.selected_snmp, 1);
        click_text(&mut app, &context, screen_rect, "Remove", 3);
        assert_eq!(app.opcua_credentials.len(), 2);
    }

    #[test]
    fn interface_selection_updates_the_source_mac_and_saved_configuration() {
        use eframe::egui::{self, epaint::Shape};

        let _config_guard = crate::CONFIG_FILE_TEST_LOCK.lock().unwrap();
        let config_path = std::env::current_exe()
            .unwrap()
            .with_file_name("otter.json");
        if config_path.exists() {
            return;
        }
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
        let _cleanup = Cleanup(config_path);

        let first = CaptureInterface {
            name: "interface-1".into(),
            friendly_name: "Ethernet 1".into(),
            description: "Primary Ethernet".into(),
            addresses: vec!["02:00:00:00:00:01".into(), "192.0.2.1".into()],
        };
        let second = CaptureInterface {
            name: "interface-2".into(),
            friendly_name: "Ethernet 2".into(),
            description: "Backup Ethernet".into(),
            addresses: vec!["02:00:00:00:00:02".into(), "192.0.2.2".into()],
        };
        let mut app = GuiApp::new(ScannerConfigs::default());
        app.interfaces = vec![first, second];
        app.interface = "interface-1".into();
        app.source_mac = "02:00:00:00:00:01".into();
        let context = egui::Context::default();
        let screen_rect = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(1600.0, 4000.0));

        fn click_text(
            app: &mut GuiApp,
            context: &egui::Context,
            screen_rect: egui::Rect,
            label: &str,
        ) {
            let output = context.run(
                egui::RawInput {
                    screen_rect: Some(screen_rect),
                    ..egui::RawInput::default()
                },
                |ctx| app.update_ui(ctx),
            );
            let position = output
                .shapes
                .iter()
                .find_map(|clipped| match &clipped.shape {
                    Shape::Text(text) if text.galley.job.text == label => {
                        Some(text.pos + text.galley.size() * 0.5)
                    }
                    _ => None,
                })
                .unwrap_or_else(|| panic!("missing clickable text {label}"));
            for pressed in [true, false] {
                let _ = context.run(
                    egui::RawInput {
                        screen_rect: Some(screen_rect),
                        events: vec![
                            egui::Event::PointerMoved(position),
                            egui::Event::PointerButton {
                                pos: position,
                                button: egui::PointerButton::Primary,
                                pressed,
                                modifiers: egui::Modifiers::default(),
                            },
                        ],
                        ..egui::RawInput::default()
                    },
                    |ctx| app.update_ui(ctx),
                );
            }
        }

        click_text(
            &mut app,
            &context,
            screen_rect,
            "Primary Ethernet (interface-1)",
        );
        click_text(
            &mut app,
            &context,
            screen_rect,
            "Backup Ethernet (interface-2)",
        );

        assert_eq!(app.interface, "interface-2");
        assert_eq!(app.source_mac, "02:00:00:00:00:02");
        app.source_mac = "stale-mac".into();
        click_text(&mut app, &context, screen_rect, "Auto-fill from Interface");
        assert_eq!(app.source_mac, "02:00:00:00:00:02");
        click_text(&mut app, &context, screen_rect, "ARP");
        assert!(!app.arp_enabled);
        click_text(&mut app, &context, screen_rect, "Show Assets (0)");
        assert!(app.asset_window_open);
        click_text(&mut app, &context, screen_rect, "Save Config");
        assert!(matches!(app.config_save_result, Some(Ok(_))));
        let saved: ScannerConfig =
            serde_json::from_slice(&std::fs::read(&_cleanup.0).unwrap()).unwrap();
        assert_eq!(saved.interface.as_deref(), Some("interface-2"));
        assert_eq!(saved.source_mac.as_deref(), Some("02:00:00:00:00:02"));
        assert_eq!(saved.no_arp, Some(true));
    }

    #[test]
    fn scan_buttons_cannot_start_without_authorization_or_valid_config() {
        let mut unauthorized = GuiApp::new(ScannerConfigs::default());
        unauthorized.start_scan(false);
        assert!(unauthorized.status.contains("--ack-authorized required"));
        assert!(!unauthorized.is_scanning);

        let duplicate = ScannerConfig {
            name: Some("Line".into()),
            ..ScannerConfig::default()
        };
        let mut invalid = GuiApp::new(ScannerConfigs::Multiple(vec![duplicate.clone(), duplicate]));
        invalid.ack_authorized = true;
        invalid.start_scan(false);
        assert_eq!(invalid.status, "Configuration could not be saved.");
        assert!(!invalid.is_scanning);
    }

    #[test]
    fn authorized_scan_rejects_invalid_ads_settings_before_starting_a_worker() {
        let _config_guard = crate::CONFIG_FILE_TEST_LOCK.lock().unwrap();
        let config_path = std::env::current_exe()
            .unwrap()
            .with_file_name("otter.json");
        if config_path.exists() {
            return;
        }
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
        let _cleanup = Cleanup(config_path);

        let config = ScannerConfig {
            targets: Some(vec!["192.0.2.1".into()]),
            interface: Some("test-interface".into()),
            source_mac: Some("00:11:22:33:44:55".into()),
            ads_ports: Some(vec![0]),
            ..ScannerConfig::default()
        };
        let mut app = GuiApp::new(ScannerConfigs::Single(Box::new(config)));
        app.ack_authorized = true;

        app.start_scan(false);

        assert!(!app.is_scanning);
        assert!(app.status.starts_with("Configuration error:"));
    }

    #[test]
    fn authorized_scan_persists_config_and_completes_with_probes_disabled() {
        let _config_guard = crate::CONFIG_FILE_TEST_LOCK.lock().unwrap();
        let config_path = std::env::current_exe()
            .unwrap()
            .with_file_name("otter.json");
        if config_path.exists() {
            return;
        }
        struct Cleanup {
            config: PathBuf,
            directory: PathBuf,
        }
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.config);
                let _ = std::fs::remove_dir_all(&self.directory);
            }
        }

        let directory = std::env::temp_dir().join(format!(
            "otter-gui-scan-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let _cleanup = Cleanup {
            config: config_path.clone(),
            directory: directory.clone(),
        };
        let output = directory.join("scan.json");
        let config = ScannerConfig {
            targets: Some(vec!["127.0.0.1".into()]),
            interface: Some("lo".into()),
            source_mac: Some("00:11:22:33:44:55".into()),
            output: Some(output.clone()),
            no_protocols: Some(true),
            no_arp: Some(true),
            no_profinet: Some(true),
            no_snmp: Some(true),
            no_lldp: Some(true),
            ..ScannerConfig::default()
        };
        let mut app = GuiApp::new(ScannerConfigs::Single(Box::new(config)));
        app.ack_authorized = true;
        app.start_scan(false);
        assert!(app.is_scanning);

        let context = eframe::egui::Context::default();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while app.is_scanning && std::time::Instant::now() < deadline {
            let _ = context.run(eframe::egui::RawInput::default(), |ctx| app.update_ui(ctx));
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        assert!(!app.is_scanning, "scan worker did not finish");
        assert!(app.status.starts_with("Batch finished: 1 complete"));
        assert!(config_path.exists());
        let saved: ScannerConfig =
            serde_json::from_slice(&std::fs::read(&config_path).unwrap()).unwrap();
        assert_eq!(saved.output.as_deref(), Some(output.as_path()));
        let export: serde_json::Value =
            serde_json::from_slice(&std::fs::read(output).unwrap()).unwrap();
        assert_eq!(export["format"], "otserver-scan");
        assert_eq!(export["devices"].as_array().unwrap().len(), 0);

        app.add_configuration();
        assert_eq!(app.configs.configs().len(), 2);
        assert_eq!(app.selected_config, 1);
        assert_eq!(
            app.configs.configs()[1].name.as_deref(),
            Some("Configuration 2")
        );
        assert!(matches!(app.config_save_result, Some(Ok(_))));

        app.start_scan(true);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while app.is_scanning && std::time::Instant::now() < deadline {
            let _ = context.run(eframe::egui::RawInput::default(), |ctx| app.update_ui(ctx));
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(!app.is_scanning, "run-all worker did not finish");
        assert!(app.status.starts_with("Batch finished: 2 complete"));
    }

    #[test]
    fn gui_update_applies_log_device_and_cancelled_batch_messages() {
        let mut app = GuiApp::new(ScannerConfigs::default());
        app.is_scanning = true;
        app.selected_asset = Some("00:11:22:33:44:66".into());
        app.cancellation = Some(std::sync::Arc::new(std::sync::atomic::AtomicBool::new(
            false,
        )));
        let (sender, receiver) = std::sync::mpsc::channel();
        sender
            .send(ScanMessage::Log("capture started".into()))
            .unwrap();
        sender
            .send(ScanMessage::Devices(vec![Device {
                mac_address: "00:11:22:33:44:55".into(),
                ip_addresses: vec!["192.0.2.10".into()],
                ..Device::default()
            }]))
            .unwrap();
        sender
            .send(ScanMessage::Finished(crate::BatchResult {
                completed: 1,
                cancelled: true,
                ..crate::BatchResult::default()
            }))
            .unwrap();
        app.log_rx = Some(receiver);
        let context = eframe::egui::Context::default();

        let _ = context.run(eframe::egui::RawInput::default(), |ctx| app.update_ui(ctx));

        assert_eq!(app.assets.len(), 1);
        assert!(app.selected_asset.is_none());
        assert!(app.log_text.contains("capture started"));
        assert!(!app.is_scanning);
        assert!(app.cancellation.is_none());
        assert!(app.log_rx.is_none());
        assert!(app.status.starts_with("Batch stopped:"));
    }

    #[test]
    fn gui_update_reports_a_disconnected_controller_worker() {
        let mut app = GuiApp::new(ScannerConfigs::default());
        let (sender, receiver) = std::sync::mpsc::channel();
        drop(sender);
        app.controller_rx = Some(receiver);
        let context = eframe::egui::Context::default();

        let _ = context.run(eframe::egui::RawInput::default(), |ctx| app.update_ui(ctx));

        assert!(app.controller_rx.is_none());
        assert!(app.controller_status.contains("stopped unexpectedly"));
    }

    #[test]
    fn gui_update_keeps_polling_a_pending_controller_worker() {
        let mut app = GuiApp::new(ScannerConfigs::default());
        let (_sender, receiver) = std::sync::mpsc::channel();
        app.controller_rx = Some(receiver);
        let context = eframe::egui::Context::default();

        let _ = context.run(eframe::egui::RawInput::default(), |ctx| app.update_ui(ctx));

        assert!(app.controller_rx.is_some());
        assert!(app.controller_status.starts_with("Not enrolled."));
    }

    #[test]
    fn gui_update_applies_controller_installation_and_failure_results() {
        let context = eframe::egui::Context::default();
        for (result, expected) in [
            (
                Ok(super::ControllerMessage::Installed("Installed.".into())),
                "Installed.",
            ),
            (
                Err("worker failed".into()),
                "Controller setup failed: worker failed",
            ),
        ] {
            let mut app = GuiApp::new(ScannerConfigs::default());
            let (sender, receiver) = std::sync::mpsc::channel();
            assert!(sender.send(result).is_ok());
            app.controller_rx = Some(receiver);

            let _ = context.run(eframe::egui::RawInput::default(), |ctx| app.update_ui(ctx));

            assert_eq!(app.controller_status, expected);
            assert!(app.controller_rx.is_none());
        }
    }

    #[test]
    fn gui_update_reports_a_non_cancelled_batch_summary() {
        let mut app = GuiApp::new(ScannerConfigs::default());
        app.is_scanning = true;
        let (sender, receiver) = std::sync::mpsc::channel();
        sender
            .send(ScanMessage::Finished(crate::BatchResult {
                completed: 2,
                partial: 1,
                failures: vec!["upload failed".into()],
                cancelled: false,
            }))
            .unwrap();
        app.log_rx = Some(receiver);
        let context = eframe::egui::Context::default();

        let _ = context.run(eframe::egui::RawInput::default(), |ctx| app.update_ui(ctx));

        assert_eq!(
            app.status,
            "Batch finished: 2 complete, 1 partial, 1 failed."
        );
        assert!(
            app.log_text
                .contains("Batch finished: 2 complete, 1 partial, 1 failed.")
        );
        assert!(!app.is_scanning);
        assert!(app.log_rx.is_none());
    }

    #[test]
    fn enrollment_button_dispatches_work_and_returns_url_validation_errors() {
        use eframe::egui::{self, epaint::Shape};
        let mut app = GuiApp::new(ScannerConfigs::default());
        app.ack_authorized = true;
        app.controller_url = "http://remote.example".into();
        app.enrollment_token = "t".repeat(43);
        let context = egui::Context::default();
        let output = context.run(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| app.controller_controls(ui));
        });
        let position = output
            .shapes
            .iter()
            .find_map(|clipped| match &clipped.shape {
                Shape::Text(text) if text.galley.job.text == "Enroll" => {
                    Some(text.pos + text.galley.size() * 0.5)
                }
                _ => None,
            })
            .expect("enrollment button text");
        for pressed in [true, false] {
            let _ = context.run(
                egui::RawInput {
                    events: vec![
                        egui::Event::PointerMoved(position),
                        egui::Event::PointerButton {
                            pos: position,
                            button: egui::PointerButton::Primary,
                            pressed,
                            modifiers: egui::Modifiers::default(),
                        },
                    ],
                    ..egui::RawInput::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| app.controller_controls(ui));
                },
            );
        }
        let result = app
            .controller_rx
            .take()
            .expect("enrollment worker")
            .recv_timeout(std::time::Duration::from_secs(10))
            .unwrap();
        assert!(matches!(result, Err(message) if message.contains("requires HTTPS")));
        assert!(app.enrollment_token.is_empty());
    }

    #[test]
    fn asset_title_prefers_first_ip_and_falls_back_to_mac() {
        let device = Device {
            mac_address: "00:11:22:33:44:55".into(),
            ip_addresses: vec!["192.0.2.10".into(), "192.0.2.11".into()],
            ..Device::default()
        };
        assert_eq!(asset_title(&device), "192.0.2.10");

        let device = Device {
            mac_address: "00:11:22:33:44:55".into(),
            ..Device::default()
        };
        assert_eq!(asset_title(&device), "00:11:22:33:44:55");
    }

    #[test]
    fn asset_protocols_lists_each_source_once_in_first_seen_order() {
        let observation = |source| Observation {
            source,
            observed_at: String::new(),
            ip_address: None,
            mac_address: None,
            fields: BTreeMap::new(),
            raw: serde_json::Value::Null,
            warnings: Vec::new(),
        };
        let device = Device {
            mac_address: "00:11:22:33:44:55".into(),
            observations: vec![
                observation(Source::Arp),
                observation(Source::Snmp),
                observation(Source::Arp),
                observation(Source::Lldp),
            ],
            ..Device::default()
        };
        assert_eq!(asset_protocols(&device), ["arp", "snmp", "lldp"]);
        assert!(asset_protocols(&Device::default()).is_empty());
    }

    #[test]
    fn asset_field_reads_first_matching_observation_key() {
        let observation = |source, fields| Observation {
            source,
            observed_at: String::new(),
            ip_address: None,
            mac_address: None,
            fields,
            raw: serde_json::Value::Null,
            warnings: Vec::new(),
        };
        let device = Device {
            mac_address: "00:11:22:33:44:55".into(),
            observations: vec![
                observation(
                    Source::Arp,
                    BTreeMap::from([("vendor".into(), serde_json::json!("Cisco"))]),
                ),
                observation(
                    Source::S7,
                    BTreeMap::from([
                        ("model".into(), serde_json::json!("S7-1200")),
                        ("vendor".into(), serde_json::json!("Siemens")),
                    ]),
                ),
            ],
            ..Device::default()
        };
        assert_eq!(asset_field(&device, MANUFACTURER_KEYS), "Cisco");
        assert_eq!(asset_field(&device, MODEL_KEYS), "S7-1200");
        assert_eq!(asset_field(&device, OS_KEYS), "");
    }

    #[test]
    fn merge_assets_replaces_by_mac_and_appends_new() {
        let mut assets = vec![Device {
            mac_address: "00:11:22:33:44:55".into(),
            ip_addresses: vec!["192.0.2.10".into()],
            ..Device::default()
        }];
        merge_assets(
            &mut assets,
            vec![
                Device {
                    mac_address: "00:11:22:33:44:55".into(),
                    ip_addresses: vec!["192.0.2.10".into(), "192.0.2.11".into()],
                    ..Device::default()
                },
                Device {
                    mac_address: "66:77:88:99:aa:bb".into(),
                    ip_addresses: vec!["192.0.2.20".into()],
                    ..Device::default()
                },
            ],
        );
        assert_eq!(assets.len(), 2);
        assert_eq!(assets[0].ip_addresses.len(), 2);
        assert_eq!(assets[1].mac_address, "66:77:88:99:aa:bb");
    }

    #[test]
    fn json_value_text_keeps_strings_plain() {
        assert_eq!(json_value_text(&serde_json::json!("PLC-1")), "PLC-1");
        assert_eq!(json_value_text(&serde_json::json!(7)), "7");
        assert_eq!(json_value_text(&serde_json::json!(null)), "null");
    }

    #[test]
    fn displays_only_ip_addresses_for_the_selected_interface() {
        let interfaces = vec![CaptureInterface {
            name: "interface-1".into(),
            friendly_name: "Ethernet".into(),
            description: "Physical Ethernet".into(),
            addresses: vec![
                "00:11:22:33:44:55".into(),
                "192.0.2.10".into(),
                "2001:db8::10".into(),
            ],
        }];
        assert_eq!(
            bound_ip_addresses(&interfaces, "interface-1"),
            ["192.0.2.10", "2001:db8::10"]
        );
        assert!(bound_ip_addresses(&interfaces, "missing").is_empty());
        assert_eq!(
            interface_mac(&interfaces[0]).as_deref(),
            Some("00:11:22:33:44:55")
        );
    }

    #[test]
    fn netbios_toggle_roundtrips_and_honors_legacy_disable() {
        for (no_netbios, no_protocols) in [(None, None), (Some(true), None), (None, Some(true))] {
            let config = ScannerConfig {
                no_netbios,
                no_protocols,
                ..ScannerConfig::default()
            };
            let mut app = GuiApp::new(ScannerConfigs::Single(Box::new(config)));
            let disabled = no_netbios.unwrap_or(false) || no_protocols.unwrap_or(false);
            assert_eq!(app.netbios_enabled, !disabled);
            assert_eq!(app.to_config().no_netbios, disabled.then_some(true));
            app.netbios_enabled = !app.netbios_enabled;
            assert_eq!(app.to_config().no_netbios, (!disabled).then_some(true));
            assert_eq!(app.to_config().no_protocols, None);
        }
    }

    #[test]
    fn allow_dcp_source_toggle_roundtrips() {
        for enabled in [false, true] {
            let config = ScannerConfig {
                allow_dcp_source: enabled.then_some(true),
                ..ScannerConfig::default()
            };
            let mut app = GuiApp::new(ScannerConfigs::Single(Box::new(config)));
            assert_eq!(app.allow_dcp_source, enabled);
            assert_eq!(app.to_config().allow_dcp_source, enabled.then_some(true));
            app.allow_dcp_source = !enabled;
            assert_eq!(app.to_config().allow_dcp_source, (!enabled).then_some(true));
        }
    }

    #[test]
    fn windows_toggles_roundtrip_independently_and_honor_legacy_disable() {
        for (smb, rpc, legacy) in [
            (false, false, false),
            (true, false, false),
            (false, true, false),
            (false, false, true),
        ] {
            let config = ScannerConfig {
                no_smb: Some(smb),
                no_rpc: Some(rpc),
                no_protocols: Some(legacy),
                ..ScannerConfig::default()
            };
            let mut app = GuiApp::new(ScannerConfigs::Single(Box::new(config)));
            assert_eq!(
                (app.smb_enabled, app.rpc_enabled),
                (!(smb || legacy), !(rpc || legacy))
            );
            app.smb_enabled = !app.smb_enabled;
            app.rpc_enabled = !app.rpc_enabled;
            let saved = app.to_config();
            assert_eq!(saved.no_smb, (!app.smb_enabled).then_some(true));
            assert_eq!(saved.no_rpc, (!app.rpc_enabled).then_some(true));
            assert_eq!(saved.no_protocols, None);
        }
    }

    #[test]
    fn http_toggle_roundtrips_and_honors_legacy_disable() {
        for (disabled, legacy) in [(false, false), (true, false), (false, true)] {
            let config = ScannerConfig {
                no_http: Some(disabled),
                no_protocols: Some(legacy),
                ..ScannerConfig::default()
            };
            let mut app = GuiApp::new(ScannerConfigs::Single(Box::new(config)));
            assert_eq!(app.http_enabled, !(disabled || legacy));
            assert_eq!(
                app.to_config().no_http,
                (disabled || legacy).then_some(true)
            );
            app.http_enabled = !app.http_enabled;
            assert_eq!(app.to_config().no_http, (!app.http_enabled).then_some(true));
        }
    }

    #[test]
    fn ads_toggle_roundtrips_and_honors_legacy_disable() {
        for (disabled, legacy) in [(false, false), (true, false), (false, true)] {
            let config = ScannerConfig {
                no_ads: Some(disabled),
                no_protocols: Some(legacy),
                ..ScannerConfig::default()
            };
            let mut app = GuiApp::new(ScannerConfigs::Single(Box::new(config)));
            assert_eq!(app.ads_enabled, !(disabled || legacy));
            assert_eq!(app.to_config().no_ads, (disabled || legacy).then_some(true));
            app.ads_enabled = !app.ads_enabled;
            assert_eq!(app.to_config().no_ads, (!app.ads_enabled).then_some(true));
        }
    }

    #[test]
    fn editing_selected_config_preserves_other_configs_and_hidden_fields() {
        let first = ScannerConfig {
            name: Some("Line A".into()),
            targets: Some(vec!["192.0.2.1".into()]),
            interface: Some("interface-1".into()),
            source_mac: Some("00:11:22:33:44:55".into()),
            output: Some("line-a.json".into()),
            opcua_ports: Some(vec![4841, 48400]),
            ..ScannerConfig::default()
        };
        let second = ScannerConfig {
            name: Some("Line B".into()),
            targets: Some(vec!["192.0.2.2".into()]),
            interface: Some("interface-2".into()),
            source_mac: Some("00:11:22:33:44:66".into()),
            output: Some("line-b.json".into()),
            ..ScannerConfig::default()
        };
        let mut app = GuiApp::new(ScannerConfigs::Multiple(vec![
            first.clone(),
            second.clone(),
        ]));
        app.targets = "198.51.100.1".into();

        let mut saved = app.configs.clone();
        saved.configs_mut()[app.selected_config] = app.to_config();

        assert_eq!(saved.configs()[0].opcua_ports, first.opcua_ports);
        assert_eq!(saved.configs()[1], second);
    }

    #[test]
    fn snmp_credential_list_survives_gui_roundtrip() {
        let config = ScannerConfig {
            snmp: Some(SnmpCredentials::Multiple(vec![
                SnmpSettings {
                    community: Some("first".into()),
                    ..SnmpSettings::default()
                },
                SnmpSettings {
                    version: Some("3".into()),
                    username: Some("ops".into()),
                    ..SnmpSettings::default()
                },
            ])),
            ..ScannerConfig::default()
        };
        let app = GuiApp::new(ScannerConfigs::Single(Box::new(config)));
        assert_eq!(app.snmp_credentials.len(), 2);
        assert_eq!(app.snmp_community, "first");

        let settings = app.to_config().snmp.unwrap().to_vec();
        assert_eq!(settings.len(), 2);
        assert_eq!(settings[0].community.as_deref(), Some("first"));
        assert_eq!(settings[1].username.as_deref(), Some("ops"));
    }

    #[test]
    fn lone_default_snmp_credential_is_omitted_from_config() {
        let app = GuiApp::new(ScannerConfigs::Single(Box::default()));
        assert!(app.to_config().snmp.is_none());
    }

    #[test]
    fn snmp_credential_rows_describe_entries_without_passwords() {
        assert_eq!(snmp_version_label("1"), "SNMPv1");
        assert_eq!(snmp_version_label("2c"), "SNMPv2c");
        assert_eq!(snmp_version_label("3"), "SNMPv3");
        assert_eq!(snmp_version_label("auto"), "Auto (v3, v2c, v1)");

        assert_eq!(
            snmp_credential_detail(&SnmpSettings::default()),
            "Community \"public\" (default)"
        );
        assert_eq!(
            snmp_credential_detail(&SnmpSettings {
                community: Some("lab-private".into()),
                ..SnmpSettings::default()
            }),
            "Community lab-private"
        );
        let detail = snmp_credential_detail(&SnmpSettings {
            version: Some("3".into()),
            username: Some("ops".into()),
            auth_protocol: Some("sha256".into()),
            auth_password: Some("auth-secret".into()),
            privacy_protocol: Some("aes128".into()),
            privacy_password: Some("privacy-secret".into()),
            ..SnmpSettings::default()
        });
        assert_eq!(detail, "User ops, authentication + encryption");
        assert!(!detail.contains("auth-secret"));
        assert!(!detail.contains("privacy-secret"));
        assert_eq!(
            snmp_credential_detail(&SnmpSettings {
                version: Some("3".into()),
                privacy_protocol: Some("aes128".into()),
                ..SnmpSettings::default()
            }),
            "User (username missing), invalid: encryption requires authentication"
        );
        assert_eq!(snmp_version_label("unsupported"), "SNMPv2c");
        assert_eq!(
            snmp_credential_detail(&SnmpSettings {
                version: Some("auto".into()),
                ..SnmpSettings::default()
            }),
            "Fallback: v3 if configured, then v2c, then v1"
        );
        assert_eq!(
            snmp_credential_detail(&SnmpSettings {
                version: Some("3".into()),
                username: Some("ops".into()),
                ..SnmpSettings::default()
            }),
            "User ops, no authentication"
        );
        assert_eq!(
            snmp_credential_detail(&SnmpSettings {
                version: Some("3".into()),
                username: Some("ops".into()),
                auth_protocol: Some("sha256".into()),
                ..SnmpSettings::default()
            }),
            "User ops, authentication"
        );
    }

    #[test]
    fn single_snmp_credential_is_saved_without_promoting_passwords_to_labels() {
        let config = ScannerConfig {
            snmp: Some(SnmpCredentials::Single(SnmpSettings {
                version: Some("3".into()),
                username: Some("inventory".into()),
                auth_protocol: Some("sha256".into()),
                auth_password: Some("not-for-display".into()),
                ..SnmpSettings::default()
            })),
            ..ScannerConfig::default()
        };
        let app = GuiApp::new(ScannerConfigs::Single(Box::new(config)));

        let saved = app.to_config().snmp.unwrap();
        assert!(
            matches!(saved, SnmpCredentials::Single(settings) if settings.username.as_deref() == Some("inventory") && settings.auth_password.as_deref() == Some("not-for-display"))
        );
        assert!(!snmp_credential_detail(&app.snmp_credentials[0]).contains("not-for-display"));
    }

    #[test]
    fn protocol_combo_opens_and_selects_a_supported_option() {
        use eframe::egui::{self, epaint::Shape};

        let context = egui::Context::default();
        let mut value = "2c".to_owned();
        let options = [("2c", "SNMPv2c"), ("3", "SNMPv3")];
        let output = context.run(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                protocol_combo(ui, "test-version", &mut value, &options)
            });
        });
        let combo = output
            .shapes
            .iter()
            .find_map(|clipped| match &clipped.shape {
                Shape::Text(text) if text.galley.job.text == "SNMPv2c" => {
                    Some(text.pos + text.galley.size() * 0.5)
                }
                _ => None,
            })
            .expect("selected protocol");
        for pressed in [true, false] {
            let _ = context.run(
                egui::RawInput {
                    events: vec![
                        egui::Event::PointerMoved(combo),
                        egui::Event::PointerButton {
                            pos: combo,
                            button: egui::PointerButton::Primary,
                            pressed,
                            modifiers: egui::Modifiers::default(),
                        },
                    ],
                    ..egui::RawInput::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        protocol_combo(ui, "test-version", &mut value, &options)
                    });
                },
            );
        }
        let output = context.run(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                protocol_combo(ui, "test-version", &mut value, &options)
            });
        });
        let option = output
            .shapes
            .iter()
            .find_map(|clipped| match &clipped.shape {
                Shape::Text(text) if text.galley.job.text == "SNMPv3" => {
                    Some(text.pos + text.galley.size() * 0.5)
                }
                _ => None,
            })
            .expect("SNMPv3 option in the open menu");
        for pressed in [true, false] {
            let _ = context.run(
                egui::RawInput {
                    events: vec![
                        egui::Event::PointerMoved(option),
                        egui::Event::PointerButton {
                            pos: option,
                            button: egui::PointerButton::Primary,
                            pressed,
                            modifiers: egui::Modifiers::default(),
                        },
                    ],
                    ..egui::RawInput::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        protocol_combo(ui, "test-version", &mut value, &options)
                    });
                },
            );
        }
        assert_eq!(value, "3");
    }

    #[test]
    fn opcua_credential_list_survives_gui_roundtrip() {
        let config = ScannerConfig {
            opcua_credentials: Some(OpcuaCredentials::Multiple(vec![
                OpcuaCredential {
                    username: Some("first".into()),
                    password: Some("first-password".into()),
                },
                OpcuaCredential {
                    username: Some("second".into()),
                    password: None,
                },
            ])),
            ..ScannerConfig::default()
        };
        let app = GuiApp::new(ScannerConfigs::Single(Box::new(config)));
        assert_eq!(app.opcua_credentials.len(), 2);
        assert_eq!(app.opcua_username, "first");
        assert_eq!(
            app.opcua_credential_row_labels(),
            ["1. User first", "2. User second"]
        );

        let credentials = app.to_config().opcua_credentials.unwrap().to_vec();
        assert_eq!(credentials.len(), 2);
        assert_eq!(credentials[0].password.as_deref(), Some("first-password"));
        assert_eq!(credentials[1].username.as_deref(), Some("second"));
    }

    #[test]
    fn legacy_opcua_fields_load_into_credential_list() {
        let config = ScannerConfig {
            opcua_username: Some("legacy".into()),
            opcua_password: Some("legacy-password".into()),
            ..ScannerConfig::default()
        };
        let app = GuiApp::new(ScannerConfigs::Single(Box::new(config)));
        assert_eq!(app.opcua_credentials.len(), 1);
        assert_eq!(app.opcua_username, "legacy");
        let saved = app.to_config();
        assert!(saved.opcua_username.is_none());
        assert_eq!(
            saved.opcua_credentials.unwrap().to_vec()[0]
                .username
                .as_deref(),
            Some("legacy")
        );
    }

    #[test]
    fn opcua_credential_rows_describe_entries_without_passwords() {
        assert_eq!(
            opcua_credential_label(&OpcuaCredential::default()),
            "Anonymous"
        );
        assert_eq!(
            opcua_credential_label(&OpcuaCredential {
                username: Some("ops".into()),
                password: None,
            }),
            "User ops"
        );
        assert_eq!(
            opcua_credential_detail(&OpcuaCredential::default()),
            "No credentials (anonymous access)"
        );
        let detail = opcua_credential_detail(&OpcuaCredential {
            username: Some("ops".into()),
            password: Some("secret".into()),
        });
        assert_eq!(detail, "Password set");
        assert!(!detail.contains("secret"));
        assert_eq!(
            opcua_credential_detail(&OpcuaCredential {
                username: Some("ops".into()),
                password: None,
            }),
            "Password missing"
        );
    }

    #[test]
    fn adding_to_single_config_creates_named_array_with_unique_output() {
        let original = ScannerConfig {
            output: Some("scan.json".into()),
            opcua_ports: Some(vec![4841]),
            ..ScannerConfig::default()
        };
        let configs = ScannerConfigs::Single(Box::new(original.clone()));

        let added = with_added_configuration(&configs, 0, original);

        assert!(added.is_multiple());
        assert_eq!(added.configs()[0].name.as_deref(), Some("Configuration 1"));
        assert_eq!(added.configs()[1].name.as_deref(), Some("Configuration 2"));
        assert_eq!(
            added.configs()[1].output.as_deref(),
            Some(std::path::Path::new("scan-2.json"))
        );
        assert_eq!(added.configs()[1].opcua_ports, Some(vec![4841]));
    }

    #[test]
    fn adding_to_multiple_configs_skips_existing_names_and_output_paths() {
        let configs = ScannerConfigs::Multiple(vec![
            ScannerConfig {
                name: Some("Configuration 1".into()),
                output: Some("scan".into()),
                ..ScannerConfig::default()
            },
            ScannerConfig {
                name: Some("Configuration 2".into()),
                output: Some("scan-2".into()),
                ..ScannerConfig::default()
            },
            ScannerConfig {
                name: Some("Configuration 4".into()),
                output: Some("scan-3".into()),
                ..ScannerConfig::default()
            },
        ]);

        let added = with_added_configuration(&configs, 0, configs.configs()[0].clone());

        assert_eq!(added.configs()[3].name.as_deref(), Some("Configuration 5"));
        assert_eq!(
            added.configs()[3].output.as_deref(),
            Some(std::path::Path::new("scan-4"))
        );
    }
}
