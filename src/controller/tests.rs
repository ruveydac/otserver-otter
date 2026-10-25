use super::*;
use clap::Parser;
use std::future::ready;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

struct PrivateStore {
    store: Option<store::Store>,
    path: PathBuf,
}

impl PrivateStore {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("otter-controller-{}", uuid::Uuid::new_v4()));
        Self {
            store: Some(store::Store::open(Some(path.clone())).unwrap()),
            path,
        }
    }

    fn get(&self) -> &store::Store {
        self.store.as_ref().unwrap()
    }
}

impl Drop for PrivateStore {
    fn drop(&mut self) {
        self.store.take();
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn scanner() -> Scanner {
    Scanner {
        id: "scanner1".into(),
        name: "Test".into(),
        site: "site1".into(),
    }
}

#[test]
fn interface_enumeration_failures_are_operator_actionable() {
    assert_eq!(
        Error::InterfacesUnavailable.to_string(),
        "Could not enumerate capture interfaces; retrying in 5 minutes."
    );
}

#[cfg(feature = "gui")]
#[test]
fn gui_enrollment_info_distinguishes_unenrolled_and_saved_state() {
    let store = PrivateStore::new();
    let directory = store.get().path().to_owned();

    assert!(enrollment_info(Some(directory.clone())).unwrap().is_none());
    store
        .get()
        .save(&State {
            server_url: "https://otserver.example/".into(),
            scanner: Some(scanner()),
            settings: Settings {
                http: HttpOptions {
                    http_proxy: Some("http://proxy.example:8080".into()),
                    ..HttpOptions::default()
                },
                ..Settings::default()
            },
            ..State::default()
        })
        .unwrap();

    let info = enrollment_info(Some(directory)).unwrap().unwrap();

    assert_eq!(info.server_url, "https://otserver.example/");
    assert_eq!(info.name, "Test");
    assert_eq!(info.site, "site1");
    assert_eq!(
        info.http.http_proxy.as_deref(),
        Some("http://proxy.example:8080")
    );
}

#[test]
fn scanner_report_bounds_adapter_and_address_inventory() {
    let report = scanner_report().unwrap();

    assert!(report.interfaces.len() <= 32);
    assert_eq!(report.interfaces.len(), report.network_adapters.len());
    assert!(report.network_adapters.iter().all(|adapter| {
        adapter.ip_addresses.len() <= 16
            && adapter
                .ip_addresses
                .iter()
                .all(|address| address.parse::<IpAddr>().is_ok())
    }));
    assert!(
        report
            .computer_name
            .as_ref()
            .is_none_or(|name| name.len() <= 256)
    );
}

fn credential() -> Credential {
    Credential {
        credential: "a".repeat(43),
        credential_expires_at: (OffsetDateTime::now_utc() + time::Duration::days(365))
            .format(&Rfc3339)
            .unwrap(),
    }
}

fn assignment(api: &Api) -> Assignment {
    Assignment {
        id: "run1".into(),
        configuration: json!({"name":"Test", "targets":["192.0.2.1"], "interface":"eth0", "sourceMac":"00:11:22:33:44:55", "serverUrl":api.base.as_str(), "site":"site1"}),
        credentials: json!({}),
        upload_path: "/api/asset-imports".into(),
        lease_expires_at: (OffsetDateTime::now_utc() + time::Duration::minutes(30))
            .format(&Rfc3339)
            .unwrap(),
    }
}

fn ready_upload(store: &store::Store, attempts: u8) -> State {
    std::fs::write(store.result_path("run1"), b"{\"schemaVersion\":2}").unwrap();
    let state = State {
        scanner: Some(scanner()),
        assignment: Some(RunState {
            id: "run1".into(),
            phase: Phase::Ready,
            status: "completed".into(),
            import_id: None,
            message: None,
            upload_attempts: attempts,
        }),
        ..State::default()
    };
    store.save(&state).unwrap();
    state
}

async fn server(responses: Vec<(u16, Value)>) -> (Api, tokio::task::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut api = Api::new(
        base_url(&format!("http://{}", listener.local_addr().unwrap())).unwrap(),
        &HttpOptions::default(),
    )
    .unwrap();
    api.credential = credential().credential;
    (api, serve(listener, responses))
}

async fn raw_server(response: Vec<u8>) -> (Api, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut api = Api::new(
        base_url(&format!("http://{}", listener.local_addr().unwrap())).unwrap(),
        &HttpOptions::default(),
    )
    .unwrap();
    api.credential = credential().credential;
    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = [0; 4096];
        let _ = socket.read(&mut request).await;
        let _ = socket.write_all(&response).await;
    });
    (api, task)
}

fn serve(
    listener: TcpListener,
    responses: Vec<(u16, Value)>,
) -> tokio::task::JoinHandle<Vec<String>> {
    tokio::spawn(async move {
        let mut requests = Vec::new();
        for (status, value) in responses {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut data = Vec::new();
            loop {
                let mut chunk = [0; 8192];
                let count = socket.read(&mut chunk).await.unwrap();
                assert!(count > 0);
                data.extend_from_slice(&chunk[..count]);
                if let Some(end) = data.windows(4).position(|v| v == b"\r\n\r\n") {
                    let header = String::from_utf8_lossy(&data[..end]);
                    let length = header
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    if data.len() >= end + 4 + length {
                        break;
                    }
                }
            }
            requests.push(String::from_utf8(data).unwrap());
            if status == 0 {
                // Drop the connection without a response to simulate a network interruption.
                continue;
            }
            let body = value.to_string();
            socket.write_all(format!("HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
        }
        requests
    })
}

#[test]
fn urls_require_https_and_reject_embedded_secrets() {
    for invalid in [
        "http://example.com",
        "example.com:3000",
        "192.168.1.10:3000",
        "127.0.0.1.example.com:3000",
        "localhost:3000@example.com",
        "user:password@127.0.0.1:3000",
        "127.0.0.1:3000?q=secret",
        "127.0.0.1:3000/#token",
        "https://user:password@example.com",
        "https://example.com?q=secret",
        "https://example.com/#token",
        "file:///tmp/x",
    ] {
        assert!(base_url(invalid).is_err());
    }
    assert_eq!(
        base_url("https://example.com/otserver").unwrap().path(),
        "/otserver/"
    );
    assert!(base_url("http://[::1]:3000").is_ok());
}

#[test]
fn bare_loopback_addresses_use_http_and_match_explicit_urls() {
    for address in ["127.0.0.1:3000", "localhost:3000", "[::1]:3000/otserver"] {
        assert_eq!(
            base_url(address).unwrap(),
            base_url(&format!("http://{address}/")).unwrap()
        );
    }
    assert_eq!(
        base_url("https://localhost:3000").unwrap().scheme(),
        "https"
    );
}

#[test]
fn malformed_controller_url_has_an_actionable_redacted_error() {
    let error = base_url("http://user:secret@localhost:invalid").unwrap_err();
    assert!(error.to_string().contains("Controller URL"));
    assert!(error.to_string().contains("https://"));
    assert!(!error.to_string().contains("secret"));
}

#[tokio::test]
async fn polling_retries_connection_loss_every_five_minutes_and_recovers() {
    let (mut api, task) = server(vec![
        (200, json!({"action":"idle", "retryAfterSeconds":45})),
        (0, Value::Null),
        (503, json!({"credential":"do-not-log"})),
        (429, json!({})),
        (200, json!({"action":"idle", "retryAfterSeconds":60})),
        (401, json!({})),
    ])
    .await;
    let store = PrivateStore::new();
    let mut state = State {
        scanner: Some(scanner()),
        credential_expires_at: credential().credential_expires_at,
        ..State::default()
    };
    for seconds in [45, 300, 300, 300, 60] {
        assert_eq!(
            poll_once(&mut api, store.get(), &mut state, 30, true).await,
            Ok(Duration::from_secs(seconds))
        );
    }
    assert_eq!(
        poll_once(&mut api, store.get(), &mut state, 30, true).await,
        Err(Error::Auth)
    );
    let requests = task.await.unwrap();
    assert_eq!(requests.len(), 6);
    assert!(requests.iter().all(|request| {
        request.starts_with("POST /api/otter/v1/poll ")
            && request.contains(&format!("authorization: Otter {}", "a".repeat(43)))
    }));
}

#[tokio::test]
async fn polling_retries_an_offline_controller_without_losing_retained_work() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let mut api = Api::new(
        base_url(&format!("http://{address}")).unwrap(),
        &HttpOptions::default(),
    )
    .unwrap();
    api.credential = credential().credential;
    let store = PrivateStore::new();
    let mut state = State {
        scanner: Some(scanner()),
        credential_expires_at: credential().credential_expires_at,
        assignment: Some(RunState {
            id: "run1".into(),
            phase: Phase::Finishing,
            status: "completed".into(),
            import_id: Some("import1".into()),
            message: None,
            upload_attempts: 0,
        }),
        ..State::default()
    };
    store.get().save(&state).unwrap();
    drop(listener);
    for _ in 0..2 {
        assert_eq!(
            poll_once(&mut api, store.get(), &mut state, 30, true).await,
            Ok(Duration::from_secs(300))
        );
        assert!(state.assignment.as_ref().unwrap().phase == Phase::Finishing);
        assert!(store.get().load().unwrap().assignment.unwrap().phase == Phase::Finishing);
    }
    let listener = TcpListener::bind(address).await.unwrap();
    let job = assignment(&api);
    let task = serve(
        listener,
        vec![
            (
                200,
                json!({"action":"run", "run":{
                    "id":job.id, "configuration":job.configuration, "credentials":job.credentials,
                    "uploadPath":job.upload_path, "leaseExpiresAt":job.lease_expires_at
                }}),
            ),
            (200, json!({"status":"completed"})),
        ],
    );
    assert_eq!(
        poll_once(&mut api, store.get(), &mut state, 30, true).await,
        Ok(Duration::from_secs(30))
    );
    let requests = task.await.unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests[1].starts_with("POST /api/otter/v1/runs/run1/finish "));
    assert!(requests[1].contains("\"importID\":\"import1\""));
    assert!(store.get().load().unwrap().assignment.unwrap().phase == Phase::Terminal);
}

#[test]
fn poll_requires_a_supported_action_and_assignment_shape() {
    assert!(matches!(
        serde_json::from_value::<Poll>(json!({"action":"idle","retryAfterSeconds":30})).unwrap(),
        Poll::Idle {
            retry_after_seconds: 30
        }
    ));
    assert!(matches!(
        serde_json::from_value::<Poll>(json!({"action":"cancel","runID":"run1"})).unwrap(),
        Poll::Cancel { .. }
    ));
    assert!(
        serde_json::from_value::<Poll>(json!({"action":"execute","credential":"secret"})).is_err()
    );
}

#[test]
fn enrollment_adapter_report_separates_mac_and_ip_addresses() {
    let adapter = otserver_otter::profinet::CaptureInterface {
        name: "eth0".into(),
        friendly_name: "Ethernet".into(),
        description: "Physical adapter".into(),
        addresses: vec![
            "00:11:22:33:44:55".into(),
            "192.0.2.10".into(),
            "2001:db8::10".into(),
            "not-an-address".into(),
        ],
    };
    let report = serde_json::to_value(network_adapter_report(adapter)).unwrap();
    assert_eq!(report["name"], "eth0");
    assert_eq!(report["friendlyName"], "Ethernet");
    assert_eq!(report["macAddress"], "00:11:22:33:44:55");
    assert_eq!(report["ipAddresses"], json!(["192.0.2.10", "2001:db8::10"]));
}

#[tokio::test]
async fn enrollment_decodes_credentials_without_logging_response_contents() {
    let credential = credential();
    let (mut api, task) = server(vec![(201, json!({"credential":credential.credential, "credentialExpiresAt":credential.credential_expires_at,"scanner":{"id":"scanner1","site":"site1","name":"Test"}}))]).await;
    api.credential.clear();
    let enrollment: Enrollment = api
        .post("api/otter/v1/enroll", json!({"token":"b".repeat(43)}))
        .await
        .unwrap();
    assert!(validate_credential(&enrollment.credential).is_ok());
    let requests = task.await.unwrap();
    assert!(requests[0].starts_with("POST /api/otter/v1/enroll "));
    assert!(!requests[0].to_ascii_lowercase().contains("authorization:"));
}

#[tokio::test]
async fn errors_redact_server_bodies_and_classify_auth_and_retry() {
    let (api, task) = server(vec![
        (401, json!({"password":"do-not-log"})),
        (503, json!({"credential":"do-not-log"})),
        (409, json!({"secret":"do-not-log"})),
    ])
    .await;
    let auth = api
        .post::<Value>("api/otter/v1/poll", json!({}))
        .await
        .unwrap_err();
    assert_eq!(auth, Error::Auth);
    assert!(!auth.to_string().contains("do-not-log"));
    assert!(auth.to_string().contains("OS account, and --state-dir"));
    assert_eq!(
        api.post::<Value>("api/otter/v1/poll", json!({}))
            .await
            .unwrap_err(),
        Error::Retry
    );
    assert_eq!(
        api.post::<Value>("api/otter/v1/poll", json!({}))
            .await
            .unwrap_err(),
        Error::Terminal
    );
    task.await.unwrap();
}

#[tokio::test]
async fn decode_rejects_announced_and_chunked_bodies_over_the_limit() {
    let oversized_length = crate::MAX_IMPORT_RESPONSE_BYTES + 1;
    let (api, task) = raw_server(
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {oversized_length}\r\nConnection: close\r\n\r\n"
        )
        .into_bytes(),
    )
    .await;
    let response = api
        .request(reqwest::Method::GET, "api/test")
        .unwrap()
        .send()
        .await
        .unwrap();
    assert_eq!(decode::<Value>(response).await.unwrap_err(), Error::Invalid);
    task.await.unwrap();

    let mut response =
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".to_vec();
    response.extend(format!("{oversized_length:X}\r\n").as_bytes());
    response.extend(vec![b'x'; oversized_length]);
    response.extend_from_slice(b"\r\n0\r\n\r\n");
    let (api, task) = raw_server(response).await;
    let response = api
        .request(reqwest::Method::GET, "api/test")
        .unwrap()
        .send()
        .await
        .unwrap();
    assert_eq!(decode::<Value>(response).await.unwrap_err(), Error::Invalid);
    task.await.unwrap();
}

#[test]
fn configuration_maps_profile_options_and_separate_credentials() {
    let api = Api::new(
        base_url("https://example.com").unwrap(),
        &HttpOptions::default(),
    )
    .unwrap();
    let mut job = assignment(&api);
    for option in [
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
    ] {
        job.configuration[option] = json!(true);
    }
    job.configuration["opcuaPorts"] = json!([4841]);
    job.configuration["adsSourceNetId"] = json!("192.0.2.2.1.1");
    job.configuration["adsTargetNetIds"] = json!({"192.0.2.10": "10.0.0.10.1.1"});
    job.configuration["adsPorts"] = json!([851, 801]);
    job.credentials = json!({"snmp":[{"version":"3","username":"inventory"}],"opcuaCredentials":[{"username":"reader","password":"secret"}]});
    let config = mapped_config(&job, &api, &scanner()).unwrap();
    let options = resolve_scan(ScanArgs::default(), config, None).unwrap();
    assert!(
        !options.protocols.arp
            && !options.protocols.profinet
            && !options.protocols.netbios
            && !options.protocols.smb
            && !options.protocols.rpc
            && !options.protocols.http
            && !options.protocols.ads
            && !options.protocols.snmp
    );
    assert!(options.allow_dcp_source);
    assert!(options.upload.is_none());
    assert_eq!(options.opcua.ports, vec![4841]);
    assert_eq!(options.ads.source_net_id, Some([192, 0, 2, 2, 1, 1]));
    assert_eq!(
        options.ads.target_net_ids[&"192.0.2.10".parse().unwrap()],
        [10, 0, 0, 10, 1, 1]
    );
    assert_eq!(options.ads.ams_ports, [851, 801]);
    assert_eq!(options.snmp[0].username.as_deref(), Some("inventory"));
}

#[test]
fn managed_configuration_rejects_unsafe_overrides_and_invalid_targets() {
    let api = Api::new(
        base_url("https://example.com").unwrap(),
        &HttpOptions::default(),
    )
    .unwrap();
    for (key, value) in [
        ("output", json!("/tmp/file")),
        ("apiKey", json!("secret")),
        ("snmp", json!({})),
        ("site", json!("other")),
        ("serverUrl", json!("https://attacker.example")),
        ("targets", json!(["::1"])),
        ("targets", json!(["192.0.2.0/8"])),
        ("opcuaPorts", json!([0])),
        ("adsSourceNetId", json!("192.0.2.1")),
        ("adsTargetNetIds", json!({"not-an-ip": "10.0.0.1.1.1"})),
        ("adsPorts", json!([851, 851])),
        ("noArp", json!("yes")),
    ] {
        let mut job = assignment(&api);
        job.configuration[key] = value;
        assert!(
            mapped_config(&job, &api, &scanner()).is_err(),
            "accepted {key}"
        );
    }
    let mut job = assignment(&api);
    job.upload_path = "https://attacker.example/upload".into();
    assert!(mapped_config(&job, &api, &scanner()).is_err());
}

#[test]
fn credentials_reject_unknown_or_invalid_protocol_settings() {
    let api = Api::new(
        base_url("https://example.com").unwrap(),
        &HttpOptions::default(),
    )
    .unwrap();
    for secrets in [
        json!({"apiKey":"secret"}),
        json!({"snmp":[{"version":"4"}]}),
        json!({"snmp":[{"version":"3","username":"u","authProtocol":"sha1","authPassword":"short"}]}),
        json!({"opcuaCredentials":[{"certificate":"no"}]}),
    ] {
        let mut job = assignment(&api);
        job.credentials = secrets;
        assert!(mapped_config(&job, &api, &scanner()).is_err());
    }

    let oversized_snmp = (0..33)
        .map(|_| json!({"version":"2c", "community":"public"}))
        .collect::<Vec<_>>();
    let oversized_opcua = (0..33)
        .map(|_| json!({"username":"operator", "password":"password"}))
        .collect::<Vec<_>>();
    for secrets in [
        json!({"snmp": oversized_snmp}),
        json!({"opcuaCredentials": oversized_opcua}),
        json!({"snmp":{"version":"2c", "community":"x".repeat(513)}}),
        json!({"opcuaPassword":"x".repeat(4097)}),
    ] {
        let mut job = assignment(&api);
        job.credentials = secrets;
        assert!(mapped_config(&job, &api, &scanner()).is_err());
    }
}

#[tokio::test]
async fn rejected_configuration_reports_a_specific_reason_without_discovery() {
    let (api, task) = server(vec![(200, json!({"status":"failed"}))]).await;
    let store = PrivateStore::new();
    let mut state = State {
        scanner: Some(scanner()),
        ..State::default()
    };
    let mut job = assignment(&api);
    job.configuration["serverUrl"] = json!("https://another-controller.example");
    execute(&api, store.get(), &mut state, job).await.unwrap();
    let run = store.get().load().unwrap().assignment.unwrap();
    assert!(
        run.message
            .unwrap()
            .contains("controller URL does not match --server-url")
    );
    let requests = task.await.unwrap();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].contains("controller URL does not match --server-url"));
    assert!(!store.get().result_path("run1").exists());
}

#[tokio::test]
async fn assigned_run_persists_a_protocol_disabled_scan_then_uploads_and_finishes() {
    let base = Api::new(
        base_url("https://example.com").unwrap(),
        &HttpOptions::default(),
    )
    .unwrap();
    let mut job = assignment(&base);
    let interfaces = otserver_otter::profinet::interfaces().unwrap();
    let interface = interfaces
        .iter()
        .find(|interface| otserver_otter::profinet::interface_mac(interface).is_some())
        .expect("test host has an interface with a MAC address");
    job.configuration["interface"] = json!(interface.name);
    job.configuration["sourceMac"] = json!(otserver_otter::profinet::interface_mac(interface));
    job.configuration["noProtocols"] = json!(true);
    job.configuration["noArp"] = json!(true);
    job.configuration["noProfinet"] = json!(true);
    job.configuration["noSnmp"] = json!(true);
    job.configuration["noLldp"] = json!(true);
    let lease = job.lease_expires_at.clone();
    let (api, task) = server(vec![
        (200, json!({"status":"running"})),
        (200, json!({"cancelRequested":false,"leaseExpiresAt":lease})),
        (200, json!({"cancelRequested":false,"leaseExpiresAt":lease})),
        (200, json!({"cancelRequested":false,"leaseExpiresAt":lease})),
        (201, json!({"doc":{"id":"import1","status":"completed"}})),
        (200, json!({"status":"completed"})),
    ])
    .await;
    job.configuration["serverUrl"] = json!(api.base.as_str());
    let store = PrivateStore::new();
    let mut state = State {
        scanner: Some(scanner()),
        ..State::default()
    };

    execute(&api, store.get(), &mut state, job).await.unwrap();

    let run = state.assignment.as_ref().unwrap();
    assert!(run.phase == Phase::Terminal);
    assert_eq!(run.import_id.as_deref(), Some("import1"));
    let export: crate::ScanExport =
        serde_json::from_slice(&std::fs::read(store.get().result_path("run1")).unwrap()).unwrap();
    assert!(!export.scan.partial);
    assert!(export.devices.is_empty());
    let requests = task.await.unwrap();
    assert_eq!(requests.len(), 6);
    assert!(requests[0].starts_with("POST /api/otter/v1/runs/run1/start "));
    assert!(requests[4].starts_with("POST /api/asset-imports "));
    assert!(requests[5].starts_with("POST /api/otter/v1/runs/run1/finish "));
}

#[test]
fn rejected_configuration_distinguishes_null_type_target_and_credential_errors() {
    let api = Api::new(
        base_url("http://localhost:3000").unwrap(),
        &HttpOptions::default(),
    )
    .unwrap();
    for (key, value, reason) in [
        ("sourceMac", Value::Null, "null option"),
        ("noArp", json!("do-not-log-secret"), "invalid option types"),
        ("targets", json!(["invalid-target"]), "targets are invalid"),
        ("site", json!("different-site"), "enrolled site"),
    ] {
        let mut job = assignment(&api);
        job.configuration[key] = value;
        let message = mapped_config(&job, &api, &scanner())
            .unwrap_err()
            .to_string();
        assert!(message.contains(reason), "{message}");
        assert!(!message.contains("do-not-log-secret"));
    }
}

#[test]
fn file_credentials_and_assignment_survive_atomic_state_replacement() {
    let store = PrivateStore::new();
    let mut state = State {
        server_url: "https://example.com/".into(),
        scanner: Some(scanner()),
        ..State::default()
    };
    store
        .get()
        .persist_credential(&mut state, &credential(), true)
        .unwrap();
    state.assignment = Some(RunState {
        id: "run1".into(),
        phase: Phase::Ready,
        status: "partial".into(),
        import_id: Some("import1".into()),
        message: None,
        upload_attempts: 0,
    });
    store.get().save(&state).unwrap();
    let recovered = store.get().load().unwrap();
    assert_eq!(store.get().credential(&recovered).unwrap(), "a".repeat(43));
    assert!(recovered.assignment.unwrap().phase == Phase::Ready);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(store.path.join("agent-state.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use std::ptr::{addr_of, null_mut};
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
        use windows_sys::Win32::Security::{
            ACCESS_ALLOWED_ACE, DACL_SECURITY_INFORMATION, EqualSid, GetAce,
            GetSecurityDescriptorControl, SE_DACL_PROTECTED, TOKEN_USER,
        };
        use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;

        let user = store::windows_token_user().unwrap();
        for path in [&store.path, &store.path.join("agent-state.json")] {
            let name: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
            let mut acl = null_mut();
            let mut descriptor = null_mut();
            // SAFETY: the path is NUL-terminated; output pointers remain valid for the call.
            assert_eq!(
                unsafe {
                    GetNamedSecurityInfoW(
                        name.as_ptr(),
                        SE_FILE_OBJECT,
                        DACL_SECURITY_INFORMATION,
                        null_mut(),
                        null_mut(),
                        &mut acl,
                        null_mut(),
                        &mut descriptor,
                    )
                },
                0
            );
            let mut ace = null_mut();
            let mut control = 0;
            let mut revision = 0;
            // SAFETY: GetNamedSecurityInfoW owns descriptor and its ACL/ACE until LocalFree.
            // GetAce is checked before reading the access-allowed ACE and its inline SID.
            let private = unsafe {
                let private = !acl.is_null()
                    && (*acl).AceCount == 1
                    && GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) != 0
                    && control & SE_DACL_PROTECTED != 0
                    && GetAce(acl, 0, &mut ace) != 0
                    && (*ace.cast::<ACCESS_ALLOWED_ACE>()).Header.AceType == 0
                    && (*ace.cast::<ACCESS_ALLOWED_ACE>()).Mask == FILE_ALL_ACCESS
                    && EqualSid(
                        addr_of!((*ace.cast::<ACCESS_ALLOWED_ACE>()).SidStart)
                            .cast_mut()
                            .cast(),
                        (*user.as_ptr().cast::<TOKEN_USER>()).User.Sid,
                    ) != 0;
                LocalFree(descriptor);
                private
            };
            assert!(
                private,
                "State ACL must grant only the current user full control: {path:?}"
            );
        }
    }
}

#[test]
fn state_lock_prevents_duplicate_agent_processes() {
    let store = PrivateStore::new();
    assert!(store::Store::open(Some(store.path.clone())).is_err());
}

#[cfg(unix)]
#[test]
fn state_rejects_public_directories_and_symlinks() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let store = PrivateStore::new();
    symlink("/etc/passwd", store.path.join("agent-state.json")).unwrap();
    assert!(store.get().load().is_err());
    std::fs::set_permissions(&store.path, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(store::Store::open(Some(store.path.clone())).is_err());
}

#[tokio::test]
async fn recovered_scanning_assignment_is_failed_without_rescanning_or_uploading() {
    let (api, task) = server(vec![(200, json!({"status":"failed"}))]).await;
    let store = PrivateStore::new();
    let mut state = State {
        scanner: Some(scanner()),
        assignment: Some(RunState {
            id: "run1".into(),
            phase: Phase::Scanning,
            status: "failed".into(),
            import_id: None,
            message: None,
            upload_attempts: 0,
        }),
        ..State::default()
    };
    execute(&api, store.get(), &mut state, assignment(&api))
        .await
        .unwrap();
    assert!(state.assignment.unwrap().phase == Phase::Terminal);
    let requests = task.await.unwrap();
    assert!(requests[0].starts_with("POST /api/otter/v1/runs/run1/finish "));
    assert!(requests[0].contains("Scanner restarted during discovery"));
    assert!(!store.get().result_path("run1").exists());
}

#[tokio::test]
async fn finish_rejects_a_nonterminal_status_response() {
    let (api, task) = server(vec![(200, json!({"status": "running"}))]).await;
    let store = PrivateStore::new();
    let mut state = State {
        assignment: Some(RunState {
            id: "run1".into(),
            phase: Phase::Ready,
            status: "completed".into(),
            import_id: Some("import1".into()),
            message: None,
            upload_attempts: 0,
        }),
        ..State::default()
    };
    assert_eq!(
        finish(&api, store.get(), &mut state, "completed", None).await,
        Err(Error::Invalid)
    );
    assert!(store.get().load().unwrap().assignment.unwrap().phase == Phase::Finishing);
    task.await.unwrap();
}

#[tokio::test]
async fn failure_reason_survives_a_failed_finish_request_and_restart() {
    let (api, task) = server(vec![
        (503, json!({})),
        (503, json!({})),
        (200, json!({"status":"failed"})),
    ])
    .await;
    let store = PrivateStore::new();
    let mut state = State {
        scanner: Some(scanner()),
        assignment: Some(RunState {
            id: "run1".into(),
            phase: Phase::Assigned,
            status: "failed".into(),
            import_id: None,
            message: None,
            upload_attempts: 0,
        }),
        ..State::default()
    };
    let reason = "The selected network interface is not available on this scanner.";
    assert_eq!(
        finish(&api, store.get(), &mut state, "failed", Some(reason)).await,
        Err(Error::Retry)
    );
    assert_eq!(
        finish(
            &api,
            store.get(),
            &mut state,
            "failed",
            Some("Controller response or managed scan configuration is invalid.")
        )
        .await,
        Err(Error::Retry)
    );
    let mut recovered = store.get().load().unwrap();
    assert_eq!(
        recovered.assignment.as_ref().unwrap().message.as_deref(),
        Some(reason)
    );
    execute(&api, store.get(), &mut recovered, assignment(&api))
        .await
        .unwrap();
    let requests = task.await.unwrap();
    assert!(requests.iter().all(|request| request.contains(reason)));
    assert!(recovered.assignment.unwrap().phase == Phase::Terminal);
    assert!(!store.get().result_path("run1").exists());
}

#[test]
fn failure_diagnostics_do_not_forward_arbitrary_secret_text() {
    for error in [
        "Protocol failed with password managed-secret",
        "Could not write export: managed-secret",
        "Could not determine the current MAC of interface managed-secret.",
        "Permission denied: managed-secret",
    ] {
        assert!(!scan_failure_reason(error).contains("managed-secret"));
    }
    assert!(scan_failure_reason("Could not write export: disk full").contains("disk space"));
    assert!(scan_failure_reason("Could not finalize export: disk full").contains("finalize"));
    assert!(
        scan_failure_reason("Could not determine the current MAC of interface eth0")
            .contains("current MAC")
    );
    assert!(scan_failure_reason("Operation not permitted").contains("capture privileges"));
    assert!(scan_failure_reason("invalid scan").contains("validation failed"));
    let legacy: RunState = serde_json::from_value(json!({
        "id":"run1", "phase":"scanning", "status":"failed", "importId":null
    }))
    .unwrap();
    assert!(legacy.message.is_none());
    assert_eq!(legacy.upload_attempts, 0);
}

#[tokio::test]
async fn recovered_ready_assignment_uploads_once_and_finishes_separately_from_queued_import() {
    let lease = assignment(
        &Api::new(
            base_url("https://example.com").unwrap(),
            &HttpOptions::default(),
        )
        .unwrap(),
    )
    .lease_expires_at;
    let (mut api, task) = server(vec![
        (200, json!({"cancelRequested":false,"leaseExpiresAt":lease})),
        (200, json!({"cancelRequested":false,"leaseExpiresAt":lease})),
        (201, json!({"doc":{"id":"import1","status":"pending"}})),
        (200, json!({"status":"partial"})),
        (200, json!({"status":"partial"})),
    ])
    .await;
    api.queued_imports = true;
    let store = PrivateStore::new();
    std::fs::write(store.get().result_path("run1"), b"{\"schemaVersion\":2}").unwrap();
    let mut state = State {
        scanner: Some(scanner()),
        assignment: Some(RunState {
            id: "run1".into(),
            phase: Phase::Ready,
            status: "partial".into(),
            import_id: None,
            message: None,
            upload_attempts: 0,
        }),
        ..State::default()
    };
    execute(&api, store.get(), &mut state, assignment(&api))
        .await
        .unwrap();
    execute(&api, store.get(), &mut state, assignment(&api))
        .await
        .unwrap();
    let requests = task.await.unwrap();
    let uploads: Vec<_> = requests
        .iter()
        .filter(|request| request.starts_with("POST /api/asset-imports "))
        .collect();
    assert_eq!(uploads.len(), 1);
    assert!(uploads[0].contains(&format!("authorization: Otter {}", "a".repeat(43))));
    assert!(uploads[0].contains("\"otterRun\":\"run1\""));
    assert!(uploads[0].contains("\"executionMode\":\"queued\""));
    assert!(!uploads[0].contains("\"site\"") && !uploads[0].contains("users API-Key"));
    assert_eq!(state.pending_imports[0].status, "pending");
    assert!(requests[3].contains("\"importID\":\"import1\""));
}

#[tokio::test]
async fn cancellation_stops_work_before_it_is_polled() {
    let (api, task) = server(vec![(200, json!({"cancelRequested":true}))]).await;
    let ran = AtomicBool::new(false);
    let outcome = leased(
        &api,
        "run1",
        Instant::now() + Duration::from_secs(60),
        0,
        async {
            ran.store(true, Ordering::Relaxed);
            Ok(())
        },
    )
    .await;
    assert_eq!(outcome, Err(Error::Local("cancelled")));
    assert!(!ran.load(Ordering::Relaxed));
    task.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn upload_retries_network_failures_after_two_minutes() {
    let store = PrivateStore::new();
    let mut state = ready_upload(store.get(), 0);
    let start = Instant::now();
    let mut attempts = Vec::new();
    let imported = upload_with_retries(store.get(), &mut state, || {
        attempts.push(start.elapsed());
        let saved = store.get().load().unwrap().assignment.unwrap();
        assert_eq!(usize::from(saved.upload_attempts), attempts.len());
        ready(if attempts.len() < 3 {
            Err(Error::Retry)
        } else {
            Ok(serde_json::from_value(json!({"id":"import1", "status":"completed"})).unwrap())
        })
    })
    .await
    .unwrap();
    assert_eq!(imported.id, "import1");
    assert_eq!(attempts, [0, 120, 240].map(Duration::from_secs));
}

#[tokio::test(start_paused = true)]
async fn upload_stops_after_five_retries_even_after_restart() {
    let store = PrivateStore::new();
    let mut state = ready_upload(store.get(), 0);
    let start = Instant::now();
    let mut attempts = Vec::new();
    let result = upload_with_retries(store.get(), &mut state, || {
        attempts.push(start.elapsed());
        ready(Err(Error::Retry))
    })
    .await;
    assert!(matches!(result, Err(Error::UploadRetriesExhausted)));
    assert_eq!(
        attempts,
        [0, 120, 240, 360, 480, 600].map(Duration::from_secs)
    );
    let mut recovered = store.get().load().unwrap();
    let result =
        upload_with_retries(store.get(), &mut recovered, || ready(Err(Error::Invalid))).await;
    assert!(matches!(result, Err(Error::UploadRetriesExhausted)));
    assert_eq!(recovered.assignment.unwrap().upload_attempts, 6);
}

#[tokio::test(start_paused = true)]
async fn interrupted_upload_retry_resumes_the_saved_budget_and_waits_two_minutes() {
    let store = PrivateStore::new();
    let mut state = ready_upload(store.get(), 0);
    assert!(
        tokio::time::timeout(
            Duration::from_secs(60),
            upload_with_retries(store.get(), &mut state, || ready(Err(Error::Retry)))
        )
        .await
        .is_err()
    );
    let mut recovered = store.get().load().unwrap();
    assert_eq!(recovered.assignment.as_ref().unwrap().upload_attempts, 1);
    let restart = Instant::now();
    let imported = upload_with_retries(store.get(), &mut recovered, || {
        assert_eq!(restart.elapsed(), Duration::from_secs(120));
        ready(Ok(serde_json::from_value(
            json!({"id":"import1", "status":"completed"}),
        )
        .unwrap()))
    })
    .await
    .unwrap();
    assert_eq!(imported.id, "import1");
    let saved = store.get().load().unwrap();
    assert_eq!(saved.assignment.unwrap().upload_attempts, 2);
}

#[tokio::test(start_paused = true)]
async fn upload_does_not_retry_auth_terminal_invalid_or_local_errors() {
    for error in [
        Error::Auth,
        Error::Terminal,
        Error::Invalid,
        Error::Local("Unreadable result"),
    ] {
        let store = PrivateStore::new();
        let mut state = ready_upload(store.get(), 0);
        let start = Instant::now();
        let expected = error.to_string();
        let mut error = Some(error);
        let result = upload_with_retries(store.get(), &mut state, || {
            ready(Err(error
                .take()
                .expect("non-network failures must not retry")))
        })
        .await;
        assert_eq!(result.err().unwrap().to_string(), expected);
        assert_eq!(start.elapsed(), Duration::ZERO);
        assert_eq!(state.assignment.unwrap().upload_attempts, 1);
    }
}

#[tokio::test(start_paused = true)]
async fn upload_does_not_resend_an_import_that_was_accepted_but_failed_processing() {
    let store = PrivateStore::new();
    let mut state = ready_upload(store.get(), 0);
    let start = Instant::now();
    let imported = upload_with_retries(store.get(), &mut state, || {
        ready(Ok(serde_json::from_value(
            json!({"id":"import1", "status":"failed"}),
        )
        .unwrap()))
    })
    .await
    .unwrap();
    assert_eq!(imported.status, "failed");
    assert_eq!(start.elapsed(), Duration::ZERO);
    assert_eq!(state.assignment.unwrap().upload_attempts, 1);
}

#[tokio::test]
async fn exhausted_uploads_report_failure_and_retry_only_finishing() {
    let lease = (OffsetDateTime::now_utc() + time::Duration::minutes(30))
        .format(&Rfc3339)
        .unwrap();
    let (api, task) = server(vec![
        (200, json!({"cancelRequested":false,"leaseExpiresAt":lease})),
        (200, json!({"cancelRequested":false,"leaseExpiresAt":lease})),
        (503, json!({})),
        (200, json!({"status":"failed"})),
    ])
    .await;
    let store = PrivateStore::new();
    let mut state = ready_upload(store.get(), 6);
    assert_eq!(
        execute(&api, store.get(), &mut state, assignment(&api)).await,
        Err(Error::Retry)
    );
    let mut recovered = store.get().load().unwrap();
    let run = recovered.assignment.as_ref().unwrap();
    assert!(run.phase == Phase::Finishing);
    assert_eq!(run.status, "failed");
    assert_eq!(run.message, Some(Error::UploadRetriesExhausted.to_string()));
    execute(&api, store.get(), &mut recovered, assignment(&api))
        .await
        .unwrap();
    let requests = task.await.unwrap();
    assert_eq!(requests.len(), 4);
    assert!(requests[2..].iter().all(|request| {
        request.starts_with("POST /api/otter/v1/runs/run1/finish ")
            && request.contains("initial attempt and 5 retries")
    }));
    assert!(recovered.assignment.unwrap().phase == Phase::Terminal);
    assert!(store.get().result_path("run1").exists());
}

#[tokio::test]
async fn upload_retry_wait_keeps_heartbeats_and_stops_on_cancellation() {
    let lease = (OffsetDateTime::now_utc() + time::Duration::minutes(30))
        .format(&Rfc3339)
        .unwrap();
    let (api, task) = server(vec![
        (200, json!({"cancelRequested":false,"leaseExpiresAt":lease})),
        (200, json!({"cancelRequested":true})),
    ])
    .await;
    let store = PrivateStore::new();
    let mut state = ready_upload(store.get(), 0);
    let result = leased(
        &api,
        "run1",
        Instant::now() + Duration::from_secs(30),
        90,
        upload_with_retries(store.get(), &mut state, || ready(Err(Error::Retry))),
    )
    .await;
    assert!(matches!(result, Err(Error::Local("cancelled"))));
    assert_eq!(state.assignment.unwrap().upload_attempts, 1);
    assert_eq!(task.await.unwrap().len(), 2);
}

#[tokio::test]
async fn lease_expiry_cancels_an_upload_retry_wait() {
    let (api, task) = server(vec![(503, json!({}))]).await;
    let store = PrivateStore::new();
    let mut state = ready_upload(store.get(), 0);
    let result = leased(
        &api,
        "run1",
        Instant::now() + Duration::from_secs(10),
        90,
        upload_with_retries(store.get(), &mut state, || {
            tokio::time::pause();
            ready(Err(Error::Retry))
        }),
    )
    .await;
    assert!(matches!(result, Err(Error::Terminal)));
    assert_eq!(state.assignment.unwrap().upload_attempts, 1);
    task.await.unwrap();
}

#[tokio::test]
async fn lost_lease_never_starts_upload() {
    let api = Api::new(
        base_url("https://example.com").unwrap(),
        &HttpOptions::default(),
    )
    .unwrap();
    let ran = AtomicBool::new(false);
    let result = leased(&api, "run1", Instant::now(), 90, async {
        ran.store(true, Ordering::Relaxed);
        Ok(())
    })
    .await;
    assert_eq!(result, Err(Error::Terminal));
    assert!(!ran.load(Ordering::Relaxed));
}

#[test]
fn lease_deadline_accepts_thirty_minutes_but_respects_shorter_server_deadlines() {
    for (seconds, expected) in [(120, 115), (1800, 1795), (3600, 1795)] {
        let expiry = (OffsetDateTime::now_utc() + time::Duration::seconds(seconds))
            .format(&Rfc3339)
            .unwrap();
        let remaining = lease_deadline(&expiry).unwrap() - Instant::now();
        assert!(remaining <= Duration::from_secs(expected));
        assert!(remaining >= Duration::from_secs(expected - 1));
    }
}

#[test]
fn lease_deadline_rejects_expiry_within_the_safety_margin() {
    for seconds in [-1, 0, 4] {
        let expiry = (OffsetDateTime::now_utc() + time::Duration::seconds(seconds))
            .format(&Rfc3339)
            .unwrap();
        assert_eq!(lease_deadline(&expiry), Err(Error::Terminal));
    }
}

#[test]
fn normal_file_mode_still_loads_api_key_and_local_protocol_options() {
    let local = crate::parse_config(br#"{"targets":["192.0.2.1"],"interface":"eth0","sourceMac":"00:11:22:33:44:55","serverUrl":"https://example.com","site":"site1","apiKey":"local-key","noSmb":true,"noRpc":true}"#).unwrap();
    let options = resolve_scan(ScanArgs::default(), local.configs()[0].clone(), None).unwrap();
    assert_eq!(options.upload.unwrap().api_key, "local-key");
    assert!(!options.protocols.smb && !options.protocols.rpc);
    assert!(
        crate::Cli::try_parse_from([
            "otserver-otter",
            "controller",
            "--server-url",
            "https://example.com"
        ])
        .is_err()
    );
}

#[tokio::test]
async fn failed_queued_import_retries_by_id_once_without_reuploading() {
    let (api, task) = server(vec![
        (200, json!({"id":"import1","status":"failed"})),
        (200, json!({"doc":{"id":"import1","status":"pending"}})),
        (200, json!({"id":"import1","status":"failed"})),
    ])
    .await;
    let store = PrivateStore::new();
    let mut state = State {
        pending_imports: vec![PendingImport {
            id: "import1".into(),
            status: "pending".into(),
            retries: 0,
        }],
        ..State::default()
    };
    imports(&api, store.get(), &mut state).await.unwrap();
    assert_eq!(store.get().load().unwrap().pending_imports[0].retries, 1);
    imports(&api, store.get(), &mut state).await.unwrap();
    assert!(state.pending_imports.is_empty());
    assert!(task.await.unwrap()[1].starts_with("POST /api/asset-imports/import1/retry "));
}

#[tokio::test]
async fn controller_url_mismatch_preserves_state_and_explains_the_overwrite_flag() {
    let mut store = PrivateStore::new();
    store
        .get()
        .save(&State {
            server_url: "https://previous.example/".into(),
            ..State::default()
        })
        .unwrap();
    store.store.take();
    let args = crate::Cli::try_parse_from([
        "otserver-otter",
        "controller",
        "--server-url",
        "localhost:3000",
        "--state-dir",
        store.path.to_str().unwrap(),
        "--enroll",
        "--ack-authorized",
    ])
    .unwrap();
    let Some(crate::Commands::Controller(args)) = args.command else {
        panic!("expected controller command")
    };
    let error = run_inner(args).await.unwrap_err();
    assert!(error.to_string().contains("--enroll --overwrite-state-dir"));
    let saved = store::Store::open(Some(store.path.clone()))
        .unwrap()
        .load()
        .unwrap();
    assert_eq!(saved.server_url, "https://previous.example/");
}

#[test]
fn overwrite_state_dir_requires_explicit_enrollment() {
    let args = [
        "otserver-otter",
        "controller",
        "--server-url",
        "localhost:3000",
        "--ack-authorized",
        "--overwrite-state-dir",
    ];
    assert!(crate::Cli::try_parse_from(args).is_err());
    let args = crate::Cli::try_parse_from(args.into_iter().chain(["--enroll"])).unwrap();
    let Some(crate::Commands::Controller(args)) = args.command else {
        panic!("expected controller command")
    };
    assert!(args.overwrite_state_dir && args.enroll);
}

#[test]
fn controller_accepts_http_connection_flags() {
    let cli = crate::Cli::try_parse_from([
        "otserver-otter",
        "controller",
        "--server-url",
        "https://example.com",
        "--ignore-self-signed",
        "--http-proxy",
        "http://proxy.example:8080",
        "--https-proxy",
        "http://secure-proxy.example:8080",
        "--ack-authorized",
    ])
    .unwrap();
    let Some(crate::Commands::Controller(args)) = cli.command else {
        panic!("expected controller command");
    };
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

fn controller_args(arguments: &[&str]) -> ControllerArgs {
    let cli = crate::Cli::try_parse_from(
        ["otserver-otter", "controller", "--ack-authorized"]
            .into_iter()
            .chain(arguments.iter().copied()),
    )
    .unwrap();
    let Some(crate::Commands::Controller(args)) = cli.command else {
        panic!("expected controller")
    };
    args
}

#[tokio::test]
async fn enrollment_only_saves_credentials_and_connection_settings_without_polling() {
    let issued = credential();
    let (api, requests) = server(vec![(
        201,
        json!({
            "credential": issued.credential, "credentialExpiresAt": issued.credential_expires_at,
            "scanner": {"id":"scanner1", "name":"Enrolled scanner", "site":"site1"}
        }),
    )])
    .await;
    let mut private = PrivateStore::new();
    private.store.take();
    let args = controller_args(&[
        "--server-url",
        api.base.as_str(),
        "--state-dir",
        private.path.to_str().unwrap(),
        "--enroll",
        "--enroll-only",
        "--file-credentials",
        "--queued-imports",
        "--poll-seconds",
        "75",
        "--https-proxy",
        "http://proxy.example:8080",
        "--ignore-self-signed",
    ]);
    let token = "t".repeat(43);
    let (store, state, _) = initialize(&args, Some(&token)).await.unwrap();
    let requests = requests.await.unwrap();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].starts_with("POST /api/otter/v1/enroll "));
    assert!(!requests[0].to_lowercase().contains("authorization:"));
    assert_eq!(state.settings.poll_seconds, 75);
    assert!(state.settings.queued_imports && state.settings.http.ignore_self_signed);
    assert_eq!(store.credential(&state).unwrap(), issued.credential);
    let saved = std::fs::read_to_string(private.path.join("agent-state.json")).unwrap();
    assert!(!saved.contains(&token));
    drop(store);
    // Installed services omit the URL and connection switches, reusing private saved settings.
    let restart = controller_args(&["--state-dir", private.path.to_str().unwrap()]);
    let (_, restarted, client) = initialize(&restart, None).await.unwrap();
    assert_eq!(restarted.settings.poll_seconds, 75);
    assert!(restarted.settings.file_credentials && client.queued_imports);
    assert_eq!(
        restarted.settings.http.https_proxy.as_deref(),
        Some("http://proxy.example:8080")
    );
}

#[tokio::test]
async fn failed_reenrollment_preserves_previous_machine_credential_and_settings() {
    let (api, requests) = server(vec![(400, json!({"error":"rejected"}))]).await;
    let mut private = PrivateStore::new();
    let old = credential();
    let mut state = State {
        server_url: "https://previous.example/".into(),
        scanner: Some(scanner()),
        settings: Settings {
            poll_seconds: 80,
            ..Settings::default()
        },
        ..State::default()
    };
    private
        .get()
        .persist_credential(&mut state, &old, true)
        .unwrap();
    private.store.take();
    let args = controller_args(&[
        "--server-url",
        api.base.as_str(),
        "--state-dir",
        private.path.to_str().unwrap(),
        "--enroll",
        "--enroll-only",
        "--overwrite-state-dir",
        "--poll-seconds",
        "25",
    ]);
    assert!(initialize(&args, Some(&"t".repeat(43))).await.is_err());
    requests.await.unwrap();
    let store = store::Store::open(Some(private.path.clone())).unwrap();
    let state = store.load().unwrap();
    assert_eq!(state.server_url, "https://previous.example/");
    assert_eq!(state.settings.poll_seconds, 80);
    assert_eq!(store.credential(&state).unwrap(), old.credential);
}

#[test]
fn installation_requires_enrollment_and_excludes_automatic_reenrollment_arguments() {
    let mut private = PrivateStore::new();
    private.store.take();
    assert_eq!(
        install::install(Some(private.path.clone()), false).unwrap_err(),
        "Enroll this scanner before installing the controller."
    );
    assert!(controller_args(&["--install"]).install);
    assert!(
        crate::Cli::try_parse_from([
            "otserver-otter",
            "controller",
            "--ack-authorized",
            "--enroll-only"
        ])
        .is_err()
    );
    assert!(
        crate::Cli::try_parse_from([
            "otserver-otter",
            "controller",
            "--ack-authorized",
            "--enroll",
            "--enroll-only",
            "--install"
        ])
        .is_err()
    );
}

#[test]
fn managed_scan_options_resolve_the_selected_interface_and_reject_missing_interfaces() {
    let interfaces = otserver_otter::profinet::interfaces().unwrap();
    let candidates = interfaces
        .iter()
        .find(|interface| otserver_otter::profinet::interface_mac(interface).is_some())
        .expect("test host has a capture interface with a MAC address");
    let candidate_count = interfaces
        .iter()
        .filter(|interface| otserver_otter::profinet::interface_mac(interface).is_some())
        .count();
    let selected = candidates;
    let source_mac = otserver_otter::profinet::interface_mac(selected).unwrap();
    let config = ScannerConfig {
        name: Some("Managed test".into()),
        targets: Some(vec!["192.0.2.10".into()]),
        interface: Some(selected.name.clone()),
        ..ScannerConfig::default()
    };

    let options = scan_options(config, PathBuf::from("retained.json")).unwrap();
    assert_eq!(options.interface, selected.name);
    assert_eq!(options.source_mac, source_mac);
    assert_eq!(options.output, PathBuf::from("retained.json"));

    let omitted_interface = ScannerConfig {
        name: Some("Managed test".into()),
        targets: Some(vec!["192.0.2.10".into()]),
        ..ScannerConfig::default()
    };
    let inferred = scan_options(omitted_interface, PathBuf::from("inferred.json"));
    if candidate_count == 1 {
        assert_eq!(inferred.unwrap().interface, selected.name);
    } else {
        assert!(matches!(
            inferred,
            Err(Error::Local(
                "Select an explicit interface in the managed profile."
            ))
        ));
    }

    let missing = ScannerConfig {
        name: Some("Managed test".into()),
        targets: Some(vec!["192.0.2.10".into()]),
        interface: Some("missing-test-interface".into()),
        source_mac: Some("00:11:22:33:44:55".into()),
        ..ScannerConfig::default()
    };
    assert!(matches!(
        scan_options(missing, PathBuf::from("unused.json")),
        Err(Error::Local(
            "The selected network interface is not available on this scanner."
        ))
    ));
}

#[tokio::test]
async fn initialization_fails_closed_for_missing_authorization_or_enrollment() {
    let mut private = PrivateStore::new();
    private.store.take();
    let mut args = controller_args(&[
        "--server-url",
        "https://example.com",
        "--state-dir",
        private.path.to_str().unwrap(),
    ]);
    args.ack_authorized = false;
    assert!(matches!(
        initialize(&args, None).await,
        Err(Error::Local("Managed scanning requires --ack-authorized."))
    ));

    let store = store::Store::open(Some(private.path.clone())).unwrap();
    let mut state = State {
        server_url: "https://example.com/".into(),
        ..State::default()
    };
    store
        .persist_credential(&mut state, &credential(), true)
        .unwrap();
    drop(store);
    assert!(matches!(
        initialize(
            &controller_args(&[
                "--server-url",
                "https://example.com",
                "--state-dir",
                private.path.to_str().unwrap(),
            ]),
            None
        )
        .await,
        Err(Error::Local("Enroll this scanner before polling."))
    ));
}

#[tokio::test]
async fn cancellation_poll_finishes_the_matching_run_without_starting_it() {
    let (mut api, task) = server(vec![
        (200, json!({"action":"cancel", "runID":"run-cancel"})),
        (200, json!({"status":"cancelled"})),
    ])
    .await;
    api.credential = credential().credential;
    let store = PrivateStore::new();
    let mut state = State {
        scanner: Some(scanner()),
        credential_expires_at: credential().credential_expires_at,
        ..State::default()
    };

    assert_eq!(
        poll_once(&mut api, store.get(), &mut state, 45, true).await,
        Ok(Duration::from_secs(45))
    );
    let run = state.assignment.as_ref().unwrap();
    assert_eq!(run.id, "run-cancel");
    assert!(run.phase == Phase::Terminal);
    assert_eq!(run.status, "cancelled");
    let requests = task.await.unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests[1].starts_with("POST /api/otter/v1/runs/run-cancel/finish "));
    assert!(!requests.iter().any(|request| request.contains("/start ")));
}

#[tokio::test]
async fn polling_rotates_a_near_expiry_credential_before_reporting_and_clamps_idle_delay() {
    let rotated = Credential {
        credential: "c".repeat(43),
        credential_expires_at: (OffsetDateTime::now_utc() + time::Duration::days(365))
            .format(&Rfc3339)
            .unwrap(),
    };
    let (mut api, task) = server(vec![
        (
            200,
            json!({
                "credential": rotated.credential,
                "credentialExpiresAt": rotated.credential_expires_at
            }),
        ),
        (200, json!({"action":"idle", "retryAfterSeconds":999})),
    ])
    .await;
    let old = Credential {
        credential: "b".repeat(43),
        credential_expires_at: (OffsetDateTime::now_utc() + time::Duration::days(10))
            .format(&Rfc3339)
            .unwrap(),
    };
    api.credential.clone_from(&old.credential);
    let store = PrivateStore::new();
    let mut state = State {
        scanner: Some(scanner()),
        ..State::default()
    };
    store
        .get()
        .persist_credential(&mut state, &old, true)
        .unwrap();

    assert_eq!(
        poll_once(&mut api, store.get(), &mut state, 30, true).await,
        Ok(Duration::from_secs(300))
    );
    assert_eq!(api.credential, rotated.credential);
    assert_eq!(store.get().credential(&state).unwrap(), rotated.credential);
    let requests = task.await.unwrap();
    assert!(requests[0].starts_with("POST /api/otter/v1/credentials/rotate "));
    assert!(requests[1].starts_with("POST /api/otter/v1/poll "));
    assert!(requests[1].contains(&format!("authorization: Otter {}", rotated.credential)));
}

#[tokio::test]
async fn queued_import_status_updates_retain_only_active_imports() {
    let (api, task) = server(vec![
        (200, json!({"id":"import-running", "status":"running"})),
        (200, json!({"id":"import-done", "status":"completed"})),
    ])
    .await;
    let store = PrivateStore::new();
    let mut state = State {
        pending_imports: vec![
            PendingImport {
                id: "import-running".into(),
                status: "pending".into(),
                retries: 0,
            },
            PendingImport {
                id: "import-done".into(),
                status: "running".into(),
                retries: 1,
            },
        ],
        ..State::default()
    };

    imports(&api, store.get(), &mut state).await.unwrap();

    assert_eq!(state.pending_imports.len(), 1);
    assert_eq!(state.pending_imports[0].status, "running");
    assert_eq!(store.get().load().unwrap().pending_imports.len(), 1);
    let requests = task.await.unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].starts_with("GET /api/asset-imports/import-running "));
    assert!(requests[1].starts_with("GET /api/asset-imports/import-done "));
}

#[test]
fn managed_profile_limits_reject_oversized_and_malformed_values() {
    let api = Api::new(
        base_url("https://example.com").unwrap(),
        &HttpOptions::default(),
    )
    .unwrap();
    for (key, value) in [
        ("name", json!(" ")),
        ("interface", json!("eth0\ninvalid")),
        ("targets", json!([])),
        ("targets", json!(["x".repeat(65)])),
        ("opcuaPorts", json!(vec![4840; 65])),
        ("opcuaPorts", json!([0])),
        ("sourceMac", json!("invalid")),
    ] {
        let mut job = assignment(&api);
        job.configuration[key] = value;
        assert!(
            mapped_config(&job, &api, &scanner()).is_err(),
            "accepted {key}"
        );
    }

    let mut too_many_targets = assignment(&api);
    too_many_targets.configuration["targets"] = json!(vec!["192.0.2.1"; 1025]);
    assert!(mapped_config(&too_many_targets, &api, &scanner()).is_err());

    let mut too_many_netids = assignment(&api);
    too_many_netids.configuration["adsTargetNetIds"] = json!(
        (0..1025)
            .map(|index| (
                format!("192.0.{}.{}", index / 256, index % 256),
                "1.2.3.4.5.6"
            ))
            .collect::<std::collections::BTreeMap<_, _>>()
    );
    assert!(mapped_config(&too_many_netids, &api, &scanner()).is_err());

    for credentials in [
        json!({"snmp": vec![json!({"version":"2c"}); 33]}),
        json!({"opcuaCredentials": vec![json!({"username":"reader"}); 33]}),
        json!({"opcuaPassword": "x".repeat(4097)}),
        json!({"snmp": [{"unexpected": "field"}]}),
    ] {
        let mut job = assignment(&api);
        job.credentials = credentials;
        assert!(mapped_config(&job, &api, &scanner()).is_err());
    }
}
