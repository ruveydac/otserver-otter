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
    ["/usr/sbin", "/usr/bin", "/sbin", "/bin"]
        .iter()
        .map(|base| Path::new(base).join(name))
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
    let status = Command::new(system_tool(elevator)?)
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
    let setcap = system_tool("setcap")?;
    if !Command::new(&setcap)
        .args([
            std::ffi::OsStr::new("-v"),
            std::ffi::OsStr::new("cap_net_raw=ep"),
            executable.as_os_str(),
        ])
        .output()
        .is_ok_and(|output| output.status.success())
    {
        privileged(
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
    let loginctl = system_tool("loginctl")?;
    let lingering = Command::new(&loginctl)
        .args(["show-user", &uid, "--property=Linger", "--value"])
        .output()
        .map_err(|_| "Could not inspect systemd user lingering.")?;
    if !lingering.status.success() || String::from_utf8_lossy(&lingering.stdout).trim() != "yes" {
        privileged(
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
    let units = config.join("systemd/user");
    std::fs::create_dir_all(&units)
        .map_err(|_| "Could not create the user systemd unit directory.")?;
    let unit = units.join("otserver-otter-controller.service");
    let temporary = units.join(format!("otter-{}.tmp", uuid::Uuid::new_v4()));
    std::fs::write(&temporary, systemd_unit(executable, directory)?)
        .and_then(|()| std::fs::rename(&temporary, &unit))
        .map_err(|_| "Could not write the user systemd service unit.")?;
    let systemctl = system_tool("systemctl")?;
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
