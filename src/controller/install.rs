use super::{Credential, store::Store};
use std::path::{Path, PathBuf};
use std::process::Command;

pub(super) fn install(directory: Option<PathBuf>, graphical: bool) -> Result<String, String> {
    let store = Store::open(directory).map_err(|e| e.to_string())?;
    let mut state = store.load().map_err(|e| e.to_string())?;
    if state.scanner.is_none() {
        return Err("Enroll this scanner before installing the controller.".into());
    }
    #[cfg(target_os = "linux")]
    {
        // SAFETY: geteuid has no arguments or memory preconditions.
        if unsafe { libc::geteuid() } == 0 {
            return Err("Run controller --install as your normal user, without sudo. It requests elevation only when needed.".into());
        }
        if Command::new(system_tool("systemctl")?)
            .args([
                "--user",
                "is-active",
                "--quiet",
                "otserver-otter-controller.service",
            ])
            .status()
            .is_ok_and(|status| status.success())
        {
            return Err("The installed controller service is already running. Stop it with systemctl --user stop otserver-otter-controller.service before changing its installation.".into());
        }
    }
    super::base_url(&state.server_url).map_err(|e| e.to_string())?;
    let credential = Credential {
        credential: store.credential(&state).map_err(|e| e.to_string())?,
        credential_expires_at: state.credential_expires_at.clone(),
    };
    super::validate_credential(&credential).map_err(|e| e.to_string())?;
    let directory = store.path().to_owned();
    let executable = installed_executable()?;
    let source = std::env::current_exe().map_err(|_| "Could not locate the running executable.")?;
    copy_executable(&source, &executable)?;
    #[cfg(target_os = "linux")]
    prepare_linux(&executable, graphical)?;
    #[cfg(not(target_os = "linux"))]
    let _ = graphical;
    // Desktop keyrings need an interactive login. Only the machine credential is persisted;
    // managed protocol credentials still arrive from the server and remain memory-only.
    state.settings.file_credentials = true;
    store
        .persist_credential(&mut state, &credential, true)
        .map_err(|e| e.to_string())?;
    drop(store);
    start_installation(&executable, &directory)
}

fn installed_executable() -> Result<PathBuf, String> {
    #[cfg(windows)]
    let path = std::env::var_os("LOCALAPPDATA")
        .map(|base| PathBuf::from(base).join("Programs/OTserver Otter/otserver-otter.exe"));
    #[cfg(not(windows))]
    let path =
        std::env::var_os("HOME").map(|base| PathBuf::from(base).join(".local/bin/otserver-otter"));
    path.filter(|path| path.is_absolute())
        .ok_or_else(|| "Could not locate this user's installation directory.".into())
}

fn copy_executable(source: &Path, destination: &Path) -> Result<(), String> {
    if std::fs::symlink_metadata(destination).is_ok_and(|metadata| metadata.is_file())
        && std::fs::canonicalize(destination).is_ok_and(|path| path == source)
    {
        return Ok(());
    }
    let parent = destination
        .parent()
        .ok_or("Invalid executable installation path.")?;
    std::fs::create_dir_all(parent)
        .map_err(|_| "Could not create the user installation directory.")?;
    let temporary = parent.join(format!("otter-{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o700);
        }
        let mut target = options
            .open(&temporary)
            .map_err(|_| "Could not stage the controller executable.")?;
        let mut source =
            std::fs::File::open(source).map_err(|_| "Could not read the controller executable.")?;
        std::io::copy(&mut source, &mut target)
            .and_then(|_| target.sync_all())
            .map_err(|_| "Could not copy the controller executable.")?;
        drop(target);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o700))
                .map_err(|_| "Could not make the installed controller executable.")?;
        }
        #[cfg(windows)]
        let backup = destination.with_extension(format!("{}.old", uuid::Uuid::new_v4()));
        #[cfg(windows)]
        let backed_up = destination.exists();
        #[cfg(windows)]
        if backed_up {
            // Windows cannot overwrite a running image. The state lock excludes an active
            // controller; a GUI using the installed executable must be closed before updating.
            std::fs::rename(destination, &backup).map_err(|_| "Close the installed Otter GUI and stop its controller before updating the executable.")?;
        }
        if std::fs::rename(&temporary, destination).is_err() {
            #[cfg(windows)]
            if backed_up {
                let _ = std::fs::rename(&backup, destination);
            }
            return Err("Could not publish the installed controller executable.".into());
        }
        #[cfg(windows)]
        if backed_up {
            let _ = std::fs::remove_file(backup);
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temporary);
    }
    result
}

#[cfg(target_os = "linux")]
fn system_tool(name: &str) -> Result<PathBuf, String> {
    system_tool_in(
        name,
        &[
            Path::new("/usr/sbin"),
            Path::new("/usr/bin"),
            Path::new("/sbin"),
            Path::new("/bin"),
        ],
    )
}

#[cfg(target_os = "linux")]
fn system_tool_in(name: &str, directories: &[&Path]) -> Result<PathBuf, String> {
    directories
        .iter()
        .map(|base| base.join(name))
        .find(|path| path.is_file())
        .ok_or_else(|| {
            format!("Required tool {name} is missing. Install it and retry controller --install.")
        })
}

#[cfg(target_os = "linux")]
fn privileged(
    program: &Path,
    arguments: &[&std::ffi::OsStr],
    graphical: bool,
) -> Result<(), String> {
    privileged_with(program, arguments, graphical, system_tool)
}

#[cfg(target_os = "linux")]
fn privileged_with(
    program: &Path,
    arguments: &[&std::ffi::OsStr],
    graphical: bool,
    find_tool: impl Fn(&str) -> Result<PathBuf, String>,
) -> Result<(), String> {
    if Command::new(program)
        .args(arguments)
        .output()
        .is_ok_and(|output| output.status.success())
    {
        return Ok(());
    }
    use std::io::IsTerminal;
    let elevator = if graphical || !std::io::stdin().is_terminal() {
        "pkexec"
    } else {
        "sudo"
    };
    eprintln!(
        "Administrator authorization is required for {}.",
        program.display()
    );
    let status = Command::new(find_tool(elevator)?)
        .arg(program)
        .args(arguments)
        .status()
        .map_err(|_| {
            format!("Could not request administrator authorization through {elevator}.")
        })?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "Administrator authorization for {} failed or was cancelled. Enrollment is retained; retry installation.",
            program.display()
        ))
    }
}

#[cfg(target_os = "linux")]
fn prepare_linux(executable: &Path, graphical: bool) -> Result<(), String> {
    prepare_linux_with(executable, graphical, system_tool, privileged)
}

#[cfg(target_os = "linux")]
fn prepare_linux_with(
    executable: &Path,
    graphical: bool,
    find_tool: impl Fn(&str) -> Result<PathBuf, String>,
    authorize: impl Fn(&Path, &[&std::ffi::OsStr], bool) -> Result<(), String>,
) -> Result<(), String> {
    let setcap = find_tool("setcap")?;
    if !Command::new(&setcap)
        .args([
            std::ffi::OsStr::new("-v"),
            std::ffi::OsStr::new("cap_net_raw=ep"),
            executable.as_os_str(),
        ])
        .output()
        .is_ok_and(|output| output.status.success())
    {
        authorize(
            &setcap,
            &[
                std::ffi::OsStr::new("cap_net_raw=ep"),
                executable.as_os_str(),
            ],
            graphical,
        )?;
    }
    if !Command::new(&setcap)
        .args([
            std::ffi::OsStr::new("-v"),
            std::ffi::OsStr::new("cap_net_raw=ep"),
            executable.as_os_str(),
        ])
        .output()
        .is_ok_and(|output| output.status.success())
    {
        return Err("CAP_NET_RAW verification failed on the installed executable.".into());
    }
    // SAFETY: getuid has no arguments or memory preconditions.
    let uid = unsafe { libc::getuid() }.to_string();
    let loginctl = find_tool("loginctl")?;
    let lingering = Command::new(&loginctl)
        .args(["show-user", &uid, "--property=Linger", "--value"])
        .output()
        .map_err(|_| "Could not inspect systemd user lingering.")?;
    if !lingering.status.success() || String::from_utf8_lossy(&lingering.stdout).trim() != "yes" {
        authorize(
            &loginctl,
            &[
                std::ffi::OsStr::new("enable-linger"),
                std::ffi::OsStr::new(&uid),
            ],
            graphical,
        )?;
    }
    if !Command::new(&loginctl)
        .args(["show-user", &uid, "--property=Linger", "--value"])
        .output()
        .is_ok_and(|output| {
            output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "yes"
        })
    {
        return Err("Could not verify boot/after-logout startup. Check loginctl show-user --property=Linger before retrying installation.".into());
    }
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
fn systemd_argument(input: &str) -> Result<String, String> {
    if input.chars().any(char::is_control) {
        return Err("Controller paths must not contain control characters.".into());
    }
    Ok(format!(
        "\"{}\"",
        input
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
    ))
}

#[cfg(any(target_os = "linux", test))]
fn systemd_unit(executable: &Path, directory: &Path) -> Result<String, String> {
    let executable = systemd_argument(
        executable
            .to_str()
            .ok_or("Executable path must be UTF-8.")?,
    )?;
    let directory = systemd_argument(directory.to_str().ok_or("State path must be UTF-8.")?)?;
    // ':' disables environment expansion for every argument; quoted paths still need %% escaping.
    Ok(format!(
        "[Unit]\nDescription=OTserver Otter controller\n\n[Service]\nType=exec\nExecStart=:{executable} controller --state-dir {directory} --ack-authorized\nRestart=on-failure\nRestartSec=30\nUMask=0077\n\n[Install]\nWantedBy=default.target\n"
    ))
}

#[cfg(target_os = "linux")]
fn start_installation(executable: &Path, directory: &Path) -> Result<String, String> {
    let config = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .filter(|path| path.is_absolute())
        .ok_or("Could not locate the user systemd configuration directory.")?;
    start_installation_with(executable, directory, &config, || system_tool("systemctl"))
}

#[cfg(target_os = "linux")]
fn start_installation_with(
    executable: &Path,
    directory: &Path,
    config: &Path,
    find_systemctl: impl FnOnce() -> Result<PathBuf, String>,
) -> Result<String, String> {
    let units = config.join("systemd/user");
    std::fs::create_dir_all(&units)
        .map_err(|_| "Could not create the user systemd unit directory.")?;
    let unit = units.join("otserver-otter-controller.service");
    let temporary = units.join(format!("otter-{}.tmp", uuid::Uuid::new_v4()));
    std::fs::write(&temporary, systemd_unit(executable, directory)?)
        .and_then(|()| std::fs::rename(&temporary, &unit))
        .map_err(|_| "Could not write the user systemd service unit.")?;
    let systemctl = find_systemctl()?;
    for arguments in [
        vec!["--user", "daemon-reload"],
        vec![
            "--user",
            "enable",
            "--now",
            "otserver-otter-controller.service",
        ],
    ] {
        if !Command::new(&systemctl)
            .args(arguments)
            .status()
            .map_err(|_| "Could not run systemctl --user.")?
            .success()
        {
            return Err("Could not enable/start the user controller service. Check systemctl --user status otserver-otter-controller.service and journalctl --user -u otserver-otter-controller.service, then retry installation.".into());
        }
    }
    Ok(format!(
        "Controller installed at {}. User service enabled at boot and after logout. Machine credential stored in the private state file. Logs: journalctl --user -u otserver-otter-controller.service",
        executable.display()
    ))
}

#[cfg(any(windows, test))]
fn windows_argument(input: &str) -> Result<String, String> {
    if input.chars().any(char::is_control) {
        return Err("Controller paths must not contain control characters.".into());
    }
    let mut output = String::from("\"");
    let mut slashes = 0;
    for ch in input.chars() {
        if ch == '\\' {
            slashes += 1;
            continue;
        }
        if ch == '"' {
            output.push_str(&"\\".repeat(slashes * 2 + 1));
        } else {
            output.push_str(&"\\".repeat(slashes));
        }
        output.push(ch);
        slashes = 0;
    }
    output.push_str(&"\\".repeat(slashes * 2));
    output.push('"');
    Ok(output)
}

#[cfg(any(windows, test))]
const WINDOWS_INSTALL: &str = r#"
$ErrorActionPreference = 'Stop'
$scheduler = New-Object -ComObject 'Schedule.Service'
$scheduler.Connect()
$folder = $scheduler.GetFolder('\')
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$name = 'OTserver Otter controller-' + $sid
$existing = $folder.GetTasks(1) | Where-Object { $_.Name -eq $name }
if ($existing -and $existing.State -eq 4) { throw 'Stop the existing controller task before changing its installation.' }
$task = $scheduler.NewTask(0)
$task.RegistrationInfo.Description = 'Managed OTserver Otter controller; runs as this user, including after logout.'
$task.Principal.UserId = $sid
$task.Principal.LogonType = 2
$task.Principal.RunLevel = 0
$trigger = $task.Triggers.Create(9)
$trigger.UserId = $sid
$task.Settings.MultipleInstances = 2
$task.Settings.ExecutionTimeLimit = 'PT0S'
$task.Settings.DisallowStartIfOnBatteries = $false
$task.Settings.StopIfGoingOnBatteries = $false
$task.Settings.StartWhenAvailable = $true
$task.Settings.RestartInterval = 'PT1M'
$task.Settings.RestartCount = 3
$action = $task.Actions.Create(0)
$action.Path = $env:OTTER_INSTALL_EXE
$action.Arguments = $env:OTTER_INSTALL_ARGS
$action.WorkingDirectory = $env:OTTER_INSTALL_STATE
$registered = $folder.RegisterTaskDefinition($name, $task, 6, $sid, $null, 2)
if ($registered.State -ne 4) { $null = $registered.Run($null) }
"#;

#[cfg(windows)]
fn start_installation(executable: &Path, directory: &Path) -> Result<String, String> {
    use std::os::windows::process::CommandExt;
    let powershell = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .ok_or("Could not locate Windows PowerShell.")?
        .join("System32/WindowsPowerShell/v1.0/powershell.exe");
    let arguments = format!(
        "controller --state-dir {} --ack-authorized",
        windows_argument(directory.to_str().ok_or("State path must be Unicode.")?)?
    );
    let output = Command::new(powershell)
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            WINDOWS_INSTALL,
        ])
        .env("OTTER_INSTALL_EXE", executable)
        .env("OTTER_INSTALL_ARGS", arguments)
        .env("OTTER_INSTALL_STATE", directory)
        .creation_flags(windows_sys::Win32::System::Threading::CREATE_NO_WINDOW)
        .output()
        .map_err(|_| "Could not start Windows Task Scheduler installation.")?;
    if !output.status.success() {
        return Err("Could not register/start the per-user background task. Stop any existing Otter controller task before updating. This account needs 'Log on as a batch job' and permission to create its own S4U scheduled tasks; ask an administrator to grant missing rights, then retry Install controller. Enrollment is retained.".into());
    }
    Ok(format!(
        "Controller installed at {}. Its per-user login task runs in the background and continues after logout. Task Scheduler: OTserver Otter controller-<your SID>. Machine credential stored in the private state file.",
        executable.display()
    ))
}

#[cfg(not(any(windows, target_os = "linux")))]
fn start_installation(_: &Path, _: &Path) -> Result<String, String> {
    Err("Controller installation supports Linux and Windows.".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executable_installation_replaces_bytes_without_touching_local_configuration() {
        let directory =
            std::env::temp_dir().join(format!("otter-install-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let source = directory.join("download");
        let destination = directory.join("bin/otter");
        std::fs::write(&source, b"first executable").unwrap();
        copy_executable(&source, &destination).unwrap();
        std::fs::write(
            destination.with_file_name("otter.json"),
            b"local configuration",
        )
        .unwrap();
        std::fs::write(&source, b"replacement executable").unwrap();
        copy_executable(&source, &destination).unwrap();
        assert_eq!(
            std::fs::read(&destination).unwrap(),
            b"replacement executable"
        );
        assert_eq!(
            std::fs::read(destination.with_file_name("otter.json")).unwrap(),
            b"local configuration"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&destination)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
        copy_executable(&std::fs::canonicalize(&destination).unwrap(), &destination).unwrap();
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn executable_copy_failures_keep_the_existing_destination_and_clean_staging_files() {
        let directory =
            std::env::temp_dir().join(format!("otter-install-failure-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&directory).unwrap();
        let destination = directory.join("bin/otter");

        let missing = copy_executable(&directory.join("missing"), &destination).unwrap_err();
        assert_eq!(missing, "Could not read the controller executable.");
        assert!(
            std::fs::read_dir(destination.parent().unwrap())
                .unwrap()
                .next()
                .is_none()
        );

        let source = directory.join("source");
        let blocked_parent = directory.join("not-a-directory");
        let blocked_destination = directory.join("bin/directory");
        std::fs::write(&source, b"new executable").unwrap();
        std::fs::write(&blocked_parent, b"keep this file").unwrap();
        assert_eq!(
            copy_executable(&source, &blocked_parent.join("otter")).unwrap_err(),
            "Could not create the user installation directory."
        );
        std::fs::create_dir(&blocked_destination).unwrap();
        assert_eq!(
            copy_executable(&source, &blocked_destination).unwrap_err(),
            "Could not publish the installed controller executable."
        );
        assert!(blocked_destination.is_dir());
        assert_eq!(
            std::fs::read_dir(blocked_destination.parent().unwrap())
                .unwrap()
                .count(),
            1
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn installation_requires_enrollment_before_touching_the_executable() {
        let directory =
            std::env::temp_dir().join(format!("otter-unenrolled-{}", uuid::Uuid::new_v4()));

        let error = install(Some(directory.clone()), false).unwrap_err();

        assert_eq!(
            error,
            "Enroll this scanner before installing the controller."
        );
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 1);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn enrolled_installation_refuses_to_run_as_root_before_system_changes() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let directory =
            std::env::temp_dir().join(format!("otter-root-install-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let state = super::super::State {
            server_url: "https://controller.example".into(),
            scanner: Some(super::super::Scanner {
                id: "scanner1".into(),
                name: "Test".into(),
                site: "site1".into(),
            }),
            ..super::super::State::default()
        };
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        use std::io::Write;
        options
            .open(directory.join("agent-state.json"))
            .unwrap()
            .write_all(&serde_json::to_vec(&state).unwrap())
            .unwrap();

        let error = install(Some(directory.clone()), false).unwrap_err();

        assert_eq!(
            error,
            "Run controller --install as your normal user, without sudo. It requests elevation only when needed."
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(not(windows))]
    #[test]
    fn installed_executable_is_scoped_to_the_users_local_bin() {
        let home = std::env::var_os("HOME").expect("test process has a home directory");

        assert_eq!(
            installed_executable().unwrap(),
            PathBuf::from(home).join(".local/bin/otserver-otter")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn enrolled_installation_rejects_remote_http_before_copying_or_enabling_services() {
        if unsafe { libc::geteuid() } == 0 || system_tool("systemctl").is_err() {
            return;
        }
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let directory =
            std::env::temp_dir().join(format!("otter-invalid-install-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let state = super::super::State {
            server_url: "http://controller.example".into(),
            scanner: Some(super::super::Scanner {
                id: "scanner1".into(),
                name: "Test".into(),
                site: "site1".into(),
            }),
            ..super::super::State::default()
        };
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        use std::io::Write;
        options
            .open(directory.join("agent-state.json"))
            .unwrap()
            .write_all(&serde_json::to_vec(&state).unwrap())
            .unwrap();

        let error = install(Some(directory.clone()), false).unwrap_err();

        assert!(error.contains("requires HTTPS"), "{error}");
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 2);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_tool_lookup_and_nonprivileged_commands_are_bounded() {
        let true_command = system_tool("true").unwrap();
        assert!(true_command.is_absolute());
        assert!(system_tool("otter-test-tool-that-does-not-exist").is_err());
        privileged(&true_command, &[], false).unwrap();
    }

    #[cfg(target_os = "linux")]
    fn executable_script(path: &Path, body: &str, mode: u32) {
        use std::os::unix::fs::PermissionsExt;

        std::fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn system_tool_lookup_uses_only_the_supplied_directories() {
        let directory = std::env::temp_dir().join(format!("otter-tools-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let tool = directory.join("mock-tool");
        std::fs::write(&tool, "").unwrap();

        assert_eq!(system_tool_in("mock-tool", &[&directory]).unwrap(), tool);
        assert!(system_tool_in("missing-tool", &[&directory]).is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn privilege_fallback_uses_the_injected_authorizer_and_reports_failures() {
        let directory =
            std::env::temp_dir().join(format!("otter-elevation-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let elevator = directory.join("pkexec");
        executable_script(&elevator, "exit 0", 0o700);
        let find_tool = |name: &str| system_tool_in(name, &[&directory]);

        privileged_with(Path::new("/bin/false"), &[], true, find_tool).unwrap();

        executable_script(&elevator, "exit 1", 0o700);
        assert!(
            privileged_with(Path::new("/bin/false"), &[], true, find_tool)
                .unwrap_err()
                .contains("Enrollment is retained")
        );

        executable_script(&elevator, "exit 0", 0o600);
        assert!(
            privileged_with(Path::new("/bin/false"), &[], true, find_tool)
                .unwrap_err()
                .contains("Could not request administrator authorization through pkexec")
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_preparation_verifies_capability_and_lingering_without_system_changes() {
        let directory =
            std::env::temp_dir().join(format!("otter-prepare-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let capability = directory.join("capability");
        let lingering = directory.join("lingering");
        let setcap = directory.join("setcap");
        let loginctl = directory.join("loginctl");
        executable_script(
            &setcap,
            &format!(
                "if [ \"$1\" = \"-v\" ]; then [ -f '{}' ]; else exit 0; fi",
                capability.display()
            ),
            0o700,
        );
        executable_script(
            &loginctl,
            &format!(
                "if [ -f '{}' ]; then echo yes; else echo no; fi",
                lingering.display()
            ),
            0o700,
        );
        let find_tool = |name: &str| match name {
            "setcap" => Ok(setcap.clone()),
            "loginctl" => Ok(loginctl.clone()),
            _ => Err(format!("unexpected tool {name}")),
        };
        let authorizations = std::sync::atomic::AtomicUsize::new(0);
        let authorize = |program: &Path, _: &[&std::ffi::OsStr], _: bool| {
            authorizations.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            match program.file_name().and_then(|name| name.to_str()) {
                Some("setcap") => {
                    std::fs::write(&capability, "verified").map_err(|e| e.to_string())
                }
                Some("loginctl") => {
                    std::fs::write(&lingering, "enabled").map_err(|e| e.to_string())
                }
                _ => Err("unexpected privileged program".into()),
            }
        };

        prepare_linux_with(&directory.join("otter"), true, find_tool, authorize).unwrap();

        assert_eq!(authorizations.load(std::sync::atomic::Ordering::Relaxed), 2);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_preparation_fails_when_capability_cannot_be_verified() {
        let directory =
            std::env::temp_dir().join(format!("otter-prepare-fail-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let setcap = directory.join("setcap");
        executable_script(&setcap, "exit 1", 0o700);
        let find_tool = |name: &str| {
            if name == "setcap" {
                Ok(setcap.clone())
            } else {
                Err("unexpected tool lookup".into())
            }
        };

        let error =
            prepare_linux_with(&directory.join("otter"), false, find_tool, |_, _, _| Ok(()))
                .unwrap_err();

        assert_eq!(
            error,
            "CAP_NET_RAW verification failed on the installed executable."
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn systemd_installation_writes_unit_and_only_invokes_the_supplied_systemctl() {
        let directory =
            std::env::temp_dir().join(format!("otter-systemd-{}", uuid::Uuid::new_v4()));
        let config = directory.join("config");
        let tools = directory.join("tools");
        std::fs::create_dir_all(&tools).unwrap();
        let log = directory.join("calls");
        let systemctl = tools.join("systemctl");
        executable_script(
            &systemctl,
            &format!("printf '%s\\n' \"$*\" >> '{}'", log.display()),
            0o700,
        );
        let executable = directory.join("otter executable");
        let state = directory.join("private state");

        let message =
            start_installation_with(&executable, &state, &config, || Ok(systemctl.clone()))
                .unwrap();

        let unit =
            std::fs::read_to_string(config.join("systemd/user/otserver-otter-controller.service"))
                .unwrap();
        assert!(unit.contains(&format!("ExecStart=:\"{}\"", executable.display())));
        assert!(unit.contains(&format!("--state-dir \"{}\"", state.display())));
        assert!(message.contains("enabled at boot and after logout"));
        assert_eq!(
            std::fs::read_to_string(log)
                .unwrap()
                .lines()
                .collect::<Vec<_>>(),
            [
                "--user daemon-reload",
                "--user enable --now otserver-otter-controller.service"
            ]
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn systemd_installation_reports_command_and_directory_failures() {
        let directory =
            std::env::temp_dir().join(format!("otter-systemd-fail-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&directory).unwrap();
        let blocked_config = directory.join("not-a-directory");
        std::fs::write(&blocked_config, b"file").unwrap();
        assert_eq!(
            start_installation_with(
                Path::new("/bin/true"),
                Path::new("/tmp/state"),
                &blocked_config,
                || { Ok(PathBuf::from("/bin/true")) }
            )
            .unwrap_err(),
            "Could not create the user systemd unit directory."
        );

        let config = directory.join("config");
        let systemctl = directory.join("systemctl");
        executable_script(&systemctl, "exit 1", 0o700);
        let error = start_installation_with(
            Path::new("/bin/true"),
            Path::new("/tmp/state"),
            &config,
            || Ok(systemctl.clone()),
        )
        .unwrap_err();
        assert!(error.contains("Could not enable/start the user controller service"));

        let config = directory.join("missing-tool-config");
        let error = start_installation_with(
            Path::new("/bin/true"),
            Path::new("/tmp/state"),
            &config,
            || Err("missing systemctl".into()),
        )
        .unwrap_err();
        assert_eq!(error, "missing systemctl");
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn user_service_escapes_paths_without_expansion_or_enrollment_secrets() {
        let unit = systemd_unit(
            Path::new("/home/a b/$bin%/otter"),
            Path::new("/home/a b/state\\\"%"),
        )
        .unwrap();
        assert!(unit.contains("ExecStart=:\"/home/a b/$bin%%/otter\" controller --state-dir \"/home/a b/state\\\\\\\"%%\" --ack-authorized"));
        assert!(unit.contains("WantedBy=default.target"));
        assert!(
            !unit.contains("--enroll")
                && !unit.contains("--install")
                && !unit.contains("NoNewPrivileges")
        );
        assert!(systemd_argument("/home/a\nExecStart=bad").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn user_service_rejects_non_utf8_executable_and_state_paths() {
        use std::os::unix::ffi::OsStringExt;

        let invalid = PathBuf::from(std::ffi::OsString::from_vec(b"/tmp/\xff".to_vec()));
        assert_eq!(
            systemd_unit(&invalid, Path::new("/tmp/state")).unwrap_err(),
            "Executable path must be UTF-8."
        );
        assert_eq!(
            systemd_unit(Path::new("/tmp/otter"), &invalid).unwrap_err(),
            "State path must be UTF-8."
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn generated_unit_passes_the_native_systemd_parser() {
        let Ok(analyzer) = system_tool("systemd-analyze") else {
            return;
        };
        let directory = std::env::temp_dir().join(format!("otter-unit-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let executable = directory.join("otter $ % executable");
        std::fs::copy("/bin/true", &executable).unwrap();
        let unit = directory.join("otserver-otter-controller.service");
        std::fs::write(
            &unit,
            systemd_unit(&executable, &directory.join("state $ %")).unwrap(),
        )
        .unwrap();
        let output = Command::new(analyzer)
            .args(["--user", "verify"])
            .arg(&unit)
            .output()
            .unwrap();
        std::fs::remove_dir_all(directory).unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn windows_task_survives_logout_and_does_not_expire_or_duplicate() {
        assert!(WINDOWS_INSTALL.contains("$task.Principal.LogonType = 2"));
        assert!(WINDOWS_INSTALL.contains("$task.Settings.MultipleInstances = 2"));
        assert!(WINDOWS_INSTALL.contains("$task.Settings.ExecutionTimeLimit = 'PT0S'"));
        assert!(WINDOWS_INSTALL.contains(
            "$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value"
        ));
        assert!(WINDOWS_INSTALL.contains("if ($registered.State -ne 4)"));
        assert_eq!(
            windows_argument("C:\\User space\\state\\").unwrap(),
            "\"C:\\User space\\state\\\\\""
        );
        assert_eq!(windows_argument("a\"b").unwrap(), "\"a\\\"b\"");
        assert!(windows_argument("bad\rpath").is_err());
    }
}
