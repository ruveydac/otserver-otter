use super::*;
use clap::Parser;
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
        lease_expires_at: (OffsetDateTime::now_utc() + time::Duration::seconds(120))
            .format(&Rfc3339)
            .unwrap(),
    }
}

async fn server(responses: Vec<(u16, Value)>) -> (Api, tokio::task::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut api =
        Api::new(base_url(&format!("http://{}", listener.local_addr().unwrap())).unwrap()).unwrap();
    api.credential = credential().credential;
    let task = tokio::spawn(async move {
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
            let body = value.to_string();
            socket.write_all(format!("HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
        }
        requests
    });
    (api, task)
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

#[test]
fn backoff_is_bounded_and_jittered() {
    assert_eq!(backoff(0, 0), Duration::from_millis(500));
    assert_ne!(backoff(4, 0), backoff(4, 900));
    assert!(backoff(100, u64::MAX) <= Duration::from_secs(300));
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

#[test]
fn configuration_maps_profile_options_and_separate_credentials() {
    let api = Api::new(base_url("https://example.com").unwrap()).unwrap();
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
        "noOpcua",
        "noSnmp",
        "noLldp",
    ] {
        job.configuration[option] = json!(true);
    }
    job.configuration["opcuaPorts"] = json!([4841]);
    job.credentials = json!({"snmp":[{"version":"3","username":"inventory"}],"opcuaCredentials":[{"username":"reader","password":"secret"}]});
    let config = mapped_config(&job, &api, &scanner()).unwrap();
    let options = resolve_scan(ScanArgs::default(), config, None).unwrap();
    assert!(
        !options.protocols.arp
            && !options.protocols.profinet
            && !options.protocols.netbios
            && !options.protocols.smb
            && !options.protocols.rpc
            && !options.protocols.snmp
    );
    assert!(options.allow_dcp_source);
    assert!(options.upload.is_none());
    assert_eq!(options.opcua.ports, vec![4841]);
    assert_eq!(options.snmp[0].username.as_deref(), Some("inventory"));
}

#[test]
fn managed_configuration_rejects_unsafe_overrides_and_invalid_targets() {
    let api = Api::new(base_url("https://example.com").unwrap()).unwrap();
    for (key, value) in [
        ("output", json!("/tmp/file")),
        ("apiKey", json!("secret")),
        ("snmp", json!({})),
        ("site", json!("other")),
        ("serverUrl", json!("https://attacker.example")),
        ("targets", json!(["::1"])),
        ("targets", json!(["192.0.2.0/8"])),
        ("opcuaPorts", json!([0])),
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
    let api = Api::new(base_url("https://example.com").unwrap()).unwrap();
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

#[test]
fn rejected_configuration_distinguishes_null_type_target_and_credential_errors() {
    let api = Api::new(base_url("http://localhost:3000").unwrap()).unwrap();
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
    let legacy: RunState = serde_json::from_value(json!({
        "id":"run1", "phase":"scanning", "status":"failed", "importId":null
    }))
    .unwrap();
    assert!(legacy.message.is_none());
}

#[tokio::test]
async fn recovered_ready_assignment_uploads_once_and_finishes_separately_from_queued_import() {
    let lease =
        assignment(&Api::new(base_url("https://example.com").unwrap()).unwrap()).lease_expires_at;
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

#[tokio::test]
async fn lost_lease_never_starts_upload() {
    let api = Api::new(base_url("https://example.com").unwrap()).unwrap();
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
