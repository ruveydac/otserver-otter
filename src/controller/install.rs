use super::{Credential, store::Store};
use sha2::{Digest, Sha256};
use std::fs::File;
#[cfg(target_os = "linux")]
use std::fs::OpenOptions;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

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
    let signed =
        otserver_otter::update::verify_binary(&source, otserver_otter::update::BUILD_TARGET)?;
    copy_executable(&source, &executable)?;
    #[cfg(target_os = "linux")]
    {
        prepare_linux(&executable, graphical)?;
        install_update_helper(&source, graphical)?;
    }
    #[cfg(not(target_os = "linux"))]
    let _ = graphical;
    // Desktop keyrings need an interactive login. Only the machine credential is persisted;
    // managed protocol credentials still arrive from the server and remain memory-only.
    state.settings.file_credentials = true;
    store
        .persist_credential(&mut state, &credential, true)
        .map_err(|e| e.to_string())?;
    drop(store);
    start_installation(&executable, &directory).map(|message| {
        format!(
            "{message} Signed Otter version {} installed.",
            signed.version()
        )
    })
}

#[cfg(target_os = "linux")]
const UPDATE_HELPER: &str = "/usr/local/libexec/otserver-otter-update-helper";

#[cfg(target_os = "linux")]
const UPDATE_HELPER_STAGING: &str = "/usr/local/libexec/.otserver-otter-update-helper.installing";

#[cfg(target_os = "linux")]
fn install_update_helper(source: &Path, graphical: bool) -> Result<(), String> {
    let install = system_tool("install")?;
    privileged(
        &install,
        &[
            std::ffi::OsStr::new("-D"),
            std::ffi::OsStr::new("-o"),
            std::ffi::OsStr::new("root"),
            std::ffi::OsStr::new("-g"),
            std::ffi::OsStr::new("root"),
            std::ffi::OsStr::new("-m"),
            std::ffi::OsStr::new("0755"),
            source.as_os_str(),
            std::ffi::OsStr::new(UPDATE_HELPER_STAGING),
        ],
        graphical,
    )?;
    let verified = Command::new(UPDATE_HELPER_STAGING)
        .args(["verify-binary", UPDATE_HELPER_STAGING])
        .status()
        .is_ok_and(|status| status.success());
    if !verified {
        return Err(
            "The staged privileged update helper did not pass Otter's pinned signature check."
                .into(),
        );
    }
    let chmod = system_tool("chmod")?;
    privileged(
        &chmod,
        &[
            std::ffi::OsStr::new("4755"),
            std::ffi::OsStr::new(UPDATE_HELPER_STAGING),
        ],
        graphical,
    )?;
    let mv = system_tool("mv")?;
    privileged(
        &mv,
        &[
            std::ffi::OsStr::new("-f"),
            std::ffi::OsStr::new(UPDATE_HELPER_STAGING),
            std::ffi::OsStr::new(UPDATE_HELPER),
        ],
        graphical,
    )?;
    let metadata = std::fs::symlink_metadata(UPDATE_HELPER)
        .map_err(|_| "Could not verify the installed privileged update helper.")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if !metadata.file_type().is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o4000 == 0
            || metadata.mode() & 0o022 != 0
        {
            return Err("The privileged update helper must be root-owned and executable only by its trusted installation.".into());
        }
    }
    Ok(())
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
        // Windows would otherwise move a directory aside as if it were the old executable.
        if destination.is_dir() {
            return Err("Could not publish the installed controller executable.".into());
        }
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
pub(super) fn is_update_helper_executable() -> bool {
    std::fs::canonicalize(UPDATE_HELPER).ok()
        == std::env::current_exe()
            .ok()
            .and_then(|path| std::fs::canonicalize(path).ok())
}

#[cfg(target_os = "linux")]
pub(super) fn check_update_helper() -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let current = std::env::current_exe().map_err(|_| "Could not locate the update helper.")?;
    let metadata =
        std::fs::symlink_metadata(&current).map_err(|_| "Could not inspect the update helper.")?;
    if unsafe { libc::getuid() } == 0
        || unsafe { libc::geteuid() } != 0
        || !metadata.file_type().is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o4000 == 0
        || metadata.mode() & 0o022 != 0
        || otserver_otter::update::verify_binary(&current, otserver_otter::update::BUILD_TARGET)
            .is_err()
    {
        return Err("The privileged Otter update helper failed its ownership, privilege, or signature check.".into());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub(super) fn check_update_helper() -> Result<(), String> {
    Err("The privileged update helper check is available only on Linux.".into())
}

#[cfg(not(target_os = "linux"))]
pub(super) fn is_update_helper_executable() -> bool {
    false
}

#[cfg(target_os = "linux")]
pub(super) fn launch_update(directory: &Path, id: &str, parent_pid: u32) -> Result<(), String> {
    if !super::valid_id(id) {
        return Err("Invalid update identifier.".into());
    }
    let current =
        std::env::current_exe().map_err(|_| "Could not locate the installed Otter executable.")?;
    if std::fs::canonicalize(&current).ok() != std::fs::canonicalize(installed_executable()?).ok() {
        return Err("Managed updates require the installed Otter controller; run controller --install first.".into());
    }
    let helper = Path::new(UPDATE_HELPER);
    let metadata = std::fs::symlink_metadata(helper)
        .map_err(|_| "Install the signed privileged updater with controller --install first.")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != 0 || metadata.mode() & 0o4000 == 0 || metadata.mode() & 0o022 != 0 {
            return Err("The privileged Otter update helper is not safely installed.".into());
        }
    }
    otserver_otter::update::verify_binary(helper, otserver_otter::update::BUILD_TARGET)?;
    let check = Command::new(helper)
        .args(["controller", "--check-update-helper", "--ack-authorized"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    if !check {
        return Err(
            "The installed privileged update helper cannot acquire its required Linux privileges."
                .into(),
        );
    }
    let status = Command::new(helper)
        .args([
            "controller",
            "--apply-update",
            "--ack-authorized",
            "--update-id",
        ])
        .arg(id)
        .args(["--parent-pid", &parent_pid.to_string(), "--state-dir"])
        .arg(directory)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|_| "Could not start the installed privileged update helper.")?;
    drop(status);
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub(super) fn launch_update(directory: &Path, id: &str, parent_pid: u32) -> Result<(), String> {
    launch_windows_update(directory, id, parent_pid)
}

#[cfg(not(target_os = "linux"))]
fn launch_windows_update(directory: &Path, id: &str, parent_pid: u32) -> Result<(), String> {
    if !super::valid_id(id) {
        return Err("Invalid update identifier.".into());
    }
    let source = std::env::current_exe().map_err(|_| "Could not locate the running executable.")?;
    if std::fs::canonicalize(&source).ok() != std::fs::canonicalize(installed_executable()?).ok() {
        return Err("Managed updates require the installed Otter controller; run controller --install first.".into());
    }
    otserver_otter::update::verify_binary(&source, otserver_otter::update::BUILD_TARGET)?;
    let helper = directory.join(format!("update-{id}.updater.exe"));
    copy_executable(&source, &helper)?;
    Command::new(helper)
        .args([
            "controller",
            "--apply-update",
            "--ack-authorized",
            "--update-id",
        ])
        .arg(id)
        .args(["--parent-pid", &parent_pid.to_string(), "--state-dir"])
        .arg(directory)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map(|_| ())
        .map_err(|_| "Could not start the verified Windows update helper.".to_owned())
}

#[cfg(target_os = "linux")]
pub(super) fn apply_update(
    directory: Option<PathBuf>,
    id: &str,
    parent_pid: u32,
) -> Result<(), String> {
    let directory = Store::directory(directory).map_err(|error| error.to_string())?;
    let recover_on_error = unsafe { libc::getuid() } != 0
        && unsafe { libc::geteuid() } == 0
        && parent_pid != 0
        && unsafe { libc::getppid() } == parent_pid as libc::pid_t
        && super::valid_id(id)
        && is_update_helper_executable()
        && otserver_otter::update::verify_binary(
            Path::new(UPDATE_HELPER),
            otserver_otter::update::BUILD_TARGET,
        )
        .is_ok();
    let result = apply_linux_update(Some(directory.clone()), id, parent_pid);
    if result.is_err() && recover_on_error {
        let _ = recover_linux_update(&directory, id);
    }
    result
}

#[cfg(target_os = "linux")]
fn apply_linux_update(directory: Option<PathBuf>, id: &str, parent_pid: u32) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let uid = unsafe { libc::getuid() };
    if !is_update_helper_executable()
        || uid == 0
        || unsafe { libc::geteuid() } != 0
        || parent_pid == 0
        || unsafe { libc::getppid() } != parent_pid as libc::pid_t
        || !super::valid_id(id)
    {
        return Err("The privileged update helper rejected this invocation.".into());
    }
    let helper_metadata = std::fs::symlink_metadata(UPDATE_HELPER)
        .map_err(|_| "Could not inspect the privileged update helper.")?;
    if !helper_metadata.file_type().is_file()
        || helper_metadata.uid() != 0
        || helper_metadata.mode() & 0o4000 == 0
        || helper_metadata.mode() & 0o022 != 0
        || otserver_otter::update::verify_binary(
            Path::new(UPDATE_HELPER),
            otserver_otter::update::BUILD_TARGET,
        )
        .is_err()
    {
        return Err("The privileged update helper failed its ownership or signature check.".into());
    }
    let deadline = Instant::now() + Duration::from_secs(60);
    while unsafe { libc::getppid() } == parent_pid as libc::pid_t {
        if Instant::now() >= deadline {
            return Err("The controller did not stop before its update timeout.".into());
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    let directory = Store::directory(directory).map_err(|error| error.to_string())?;
    let mut update_state =
        Store::read_update_state_for(&directory, uid).map_err(|error| error.to_string())?;
    let pending = update_state
        .pending
        .clone()
        .filter(|pending| pending.id == id)
        .ok_or("The private pending update record does not match this request.")?;
    let home = user_home(uid)?;
    let executable = home.join(".local/bin/otserver-otter");
    reject_symlink_components(&executable)?;
    let parent = executable.parent().ok_or("Invalid installation path.")?;
    let parent_metadata =
        std::fs::metadata(parent).map_err(|_| "The installed Otter directory is unavailable.")?;
    if !parent_metadata.is_dir() || parent_metadata.uid() != uid {
        return Err("The installed Otter directory must belong to the scanner user.".into());
    }
    let original_metadata = std::fs::symlink_metadata(&executable)
        .map_err(|_| "The installed Otter executable is unavailable.")?;
    if !original_metadata.file_type().is_file()
        || (original_metadata.uid() != uid && original_metadata.uid() != 0)
        || original_metadata.mode() & 0o022 != 0
    {
        return Err(
            "The installed Otter executable is not a regular file owned by the scanner user."
                .into(),
        );
    }
    let original =
        otserver_otter::update::verify_binary(&executable, otserver_otter::update::BUILD_TARGET)?;
    if original.version() != pending.previous_version
        || digest_file(&executable)? != pending.previous_digest
    {
        return Err("The installed executable changed after the update was queued.".into());
    }

    let candidate = directory.join(format!("update-{}.bin", id));
    let candidate_metadata = std::fs::symlink_metadata(&candidate)
        .map_err(|_| "The verified Otter update staging file is missing.")?;
    if !candidate_metadata.file_type().is_file()
        || candidate_metadata.uid() != uid
        || candidate_metadata.mode() & 0o077 != 0
        || candidate_metadata.len() != pending.binary_size
        || digest_file(&candidate)? != pending.binary_digest
    {
        return Err(
            "The private Otter update staging file failed its ownership or digest check.".into(),
        );
    }
    let verified =
        otserver_otter::update::verify_binary(&candidate, otserver_otter::update::BUILD_TARGET)?;
    if verified.version() != pending.version
        || verified.target() != pending.target
        || verified
            .require_newer_than(
                update_state
                    .version_floor
                    .as_deref()
                    .unwrap_or(&pending.previous_version),
            )
            .is_err()
    {
        return Err(
            "The staged Otter executable is not a newer release signed for this platform.".into(),
        );
    }

    let backup = parent.join(format!(".otserver-otter-update-{id}.previous"));
    let backup_valid = if std::fs::symlink_metadata(&backup).is_ok() {
        let metadata = std::fs::symlink_metadata(&backup)
            .map_err(|_| "Could not inspect the retained rollback executable.")?;
        metadata.file_type().is_file()
            && metadata.uid() == 0
            && otserver_otter::update::verify_binary(&backup, otserver_otter::update::BUILD_TARGET)
                .is_ok_and(|binary| binary.version() == pending.previous_version)
            && digest_file(&backup).is_ok_and(|digest| digest == pending.previous_digest)
    } else {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o755);
        let mut file = options
            .open(&backup)
            .map_err(|_| "Could not retain the previous signed Otter executable for rollback.")?;
        let mut source = File::open(&executable)
            .map_err(|_| "Could not read the previous signed Otter executable.")?;
        std::io::copy(&mut source, &mut file)
            .and_then(|_| file.sync_all())
            .map_err(|_| "Could not retain the previous signed Otter executable.")?;
        set_raw_capability(&file)?;
        true
    };
    if !backup_valid {
        return Err(
            "The retained rollback executable did not match the expected signed version.".into(),
        );
    }

    let staged = parent.join(format!(
        ".otserver-otter-update-{id}-{}.new",
        uuid::Uuid::new_v4()
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o755);
    let mut file = options
        .open(&staged)
        .map_err(|_| "Could not create the installed Otter staging file.")?;
    let mut source = File::open(&candidate)
        .map_err(|_| "Could not read the verified Otter update staging file.")?;
    std::io::copy(&mut source, &mut file)
        .and_then(|_| file.sync_all())
        .map_err(
            |_| "Could not copy the verified Otter executable into its installation directory.",
        )?;
    verify_open_file(&file)?;
    if digest_open_file(&file)? != pending.binary_digest {
        let _ = std::fs::remove_file(&staged);
        return Err("The installed Otter staging file failed its digest check.".into());
    }
    set_executable_permissions(&file)?;
    set_raw_capability(&file)?;
    drop(file);
    std::fs::rename(&staged, &executable)
        .map_err(|_| "Could not atomically install the signed Otter executable.")?;
    if otserver_otter::update::verify_binary(&executable, otserver_otter::update::BUILD_TARGET)
        .is_err()
        || digest_file(&executable)? != pending.binary_digest
    {
        rollback_linux(
            &directory,
            uid,
            &executable,
            &backup,
            &pending,
            &mut update_state,
            None,
        )?;
        return Err("The installed Otter executable failed post-install verification.".into());
    }

    let service = home.join(".config/systemd/user/otserver-otter-controller.service");
    let mut child = None;
    if service.is_file() {
        let systemctl = system_tool("systemctl")?;
        let restart = with_user_euid(uid, || {
            let active = Command::new(&systemctl)
                .args([
                    "--user",
                    "is-active",
                    "--quiet",
                    "otserver-otter-controller.service",
                ])
                .status()
                .is_ok_and(|status| status.success());
            Command::new(&systemctl)
                .args([
                    "--user",
                    if active { "restart" } else { "start" },
                    "otserver-otter-controller.service",
                ])
                .status()
                .is_ok_and(|status| status.success())
        })?;
        if !restart {
            rollback_linux(
                &directory,
                uid,
                &executable,
                &backup,
                &pending,
                &mut update_state,
                None,
            )?;
            return Err("Could not restart the installed Otter controller; the previous signed executable was restored.".into());
        }
    } else {
        child = with_user_euid(uid, || {
            Command::new(&executable)
                .args(["controller", "--state-dir"])
                .arg(&directory)
                .arg("--ack-authorized")
                .spawn()
                .ok()
        })?;
        if child.is_none() {
            rollback_linux(
                &directory,
                uid,
                &executable,
                &backup,
                &pending,
                &mut update_state,
                None,
            )?;
            return Err("Could not start the updated Otter controller; the previous signed executable was restored.".into());
        }
    }

    let deadline = Instant::now() + Duration::from_secs(90);
    while Instant::now() < deadline {
        if child
            .as_mut()
            .is_some_and(|process| process.try_wait().ok().flatten().is_some())
        {
            rollback_linux(
                &directory,
                uid,
                &executable,
                &backup,
                &pending,
                &mut update_state,
                child.as_mut(),
            )?;
            return Err("The updated Otter controller exited during startup; the previous signed executable was restored.".into());
        }
        if Store::read_update_state_for(&directory, uid).is_ok_and(|state| {
            state.pending.is_none() && state.version_floor.as_deref() == Some(&pending.version)
        }) {
            let _ = std::fs::remove_file(&backup);
            let _ = std::fs::remove_file(&candidate);
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    rollback_linux(
        &directory,
        uid,
        &executable,
        &backup,
        &pending,
        &mut update_state,
        child.as_mut(),
    )?;
    Err("The updated Otter controller did not confirm startup; the previous signed executable was restored.".into())
}

#[cfg(target_os = "windows")]
pub(super) fn apply_update(
    directory: Option<PathBuf>,
    id: &str,
    parent_pid: u32,
) -> Result<(), String> {
    let directory = Store::directory(directory).map_err(|error| error.to_string())?;
    let result = apply_windows_update(Some(directory.clone()), id, parent_pid);
    if result.is_err() {
        let _ = recover_windows_update(&directory, id);
    }
    result
}

#[cfg(target_os = "windows")]
fn apply_windows_update(
    directory: Option<PathBuf>,
    id: &str,
    parent_pid: u32,
) -> Result<(), String> {
    use std::os::windows::process::CommandExt;

    if !super::valid_id(id) || parent_pid == 0 {
        return Err("Invalid Windows update request.".into());
    }
    let directory = Store::directory(directory).map_err(|error| error.to_string())?;
    let wait_until = Instant::now() + Duration::from_secs(60);
    let store = loop {
        match Store::open(Some(directory.clone())) {
            Ok(store) => break store,
            Err(_) if Instant::now() < wait_until => std::thread::sleep(Duration::from_millis(100)),
            Err(_) => {
                return Err(
                    "The controller did not release its state before the update timeout.".into(),
                );
            }
        }
    };
    let state = store
        .load_update_state()
        .map_err(|error| error.to_string())?;
    let pending = state
        .pending
        .clone()
        .filter(|pending| pending.id == id)
        .ok_or("The private pending update record does not match this request.")?;
    let candidate = store
        .update_path(id, "bin")
        .map_err(|error| error.to_string())?;
    let executable = installed_executable()?;
    let original =
        otserver_otter::update::verify_binary(&executable, otserver_otter::update::BUILD_TARGET)?;
    if original.version() != pending.previous_version
        || digest_file(&executable)? != pending.previous_digest
    {
        return Err("The installed executable changed after the update was queued.".into());
    }
    let staged =
        otserver_otter::update::verify_binary(&candidate, otserver_otter::update::BUILD_TARGET)?;
    if staged.version() != pending.version
        || staged.target() != pending.target
        || digest_file(&candidate)? != pending.binary_digest
        || staged
            .require_newer_than(
                state
                    .version_floor
                    .as_deref()
                    .unwrap_or(&pending.previous_version),
            )
            .is_err()
    {
        return Err(
            "The staged Otter executable failed signature, version, or digest verification.".into(),
        );
    }

    let parent = executable.parent().ok_or("Invalid installation path.")?;
    let backup = parent.join(format!("otserver-otter-update-{id}.previous.exe"));
    let staged_path = parent.join(format!("otserver-otter-update-{id}.new.exe"));
    if backup.exists() || staged_path.exists() {
        return Err(
            "A previous Otter update recovery file already exists; resolve it before retrying."
                .into(),
        );
    }
    copy_executable(&candidate, &staged_path)?;
    if digest_file(&staged_path)? != pending.binary_digest
        || otserver_otter::update::verify_binary(&staged_path, otserver_otter::update::BUILD_TARGET)
            .is_err()
    {
        let _ = std::fs::remove_file(&backup);
        let _ = std::fs::remove_file(&staged_path);
        return Err("The staged Windows Otter executable failed its final verification.".into());
    }
    if let Err(_) = std::fs::rename(&executable, &backup) {
        let _ = std::fs::remove_file(&staged_path);
        return Err("Could not move the old Otter executable aside for replacement.".into());
    }
    if std::fs::rename(&staged_path, &executable).is_err() {
        let _ = std::fs::rename(&backup, &executable);
        return Err("Could not publish the signed Windows Otter update.".into());
    }
    drop(store);

    let mut child = Command::new(&executable)
        .args(["controller", "--state-dir"])
        .arg(&directory)
        .arg("--ack-authorized")
        .creation_flags(windows_sys::Win32::System::Threading::CREATE_NO_WINDOW)
        .spawn()
        .map_err(|_| "Could not start the updated Windows Otter controller.")?;
    let deadline = Instant::now() + Duration::from_secs(90);
    while Instant::now() < deadline {
        if Store::read_update_state(&directory).is_ok_and(|state| {
            state.pending.is_none() && state.version_floor.as_deref() == Some(&pending.version)
        }) {
            let _ = std::fs::remove_file(&backup);
            let _ = std::fs::remove_file(&candidate);
            return Ok(());
        }
        if child.try_wait().ok().flatten().is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    let _ = child.kill();
    let _ = child.wait();
    Err("The updated Otter controller did not confirm startup; the previous signed executable was restored.".into())
}

#[cfg(target_os = "windows")]
fn recover_windows_update(directory: &Path, id: &str) -> Result<(), String> {
    use std::os::windows::process::CommandExt;

    if !super::valid_id(id) {
        return Ok(());
    }
    let store = Store::open(Some(directory.to_owned())).map_err(|error| error.to_string())?;
    let mut state = store
        .load_update_state()
        .map_err(|error| error.to_string())?;
    let Some(pending) = state.pending.clone().filter(|pending| pending.id == id) else {
        return Ok(());
    };
    let executable = installed_executable()?;
    let parent = executable.parent().ok_or("Invalid installation path.")?;
    let backup = parent.join(format!("otserver-otter-update-{id}.previous.exe"));
    let current_is_previous =
        otserver_otter::update::verify_binary(&executable, otserver_otter::update::BUILD_TARGET)
            .is_ok_and(|binary| binary.version() == pending.previous_version)
            && digest_file(&executable).is_ok_and(|digest| digest == pending.previous_digest);
    let rolled_back = if current_is_previous {
        false
    } else {
        if otserver_otter::update::verify_binary(&backup, otserver_otter::update::BUILD_TARGET)
            .is_err()
            || digest_file(&backup)? != pending.previous_digest
        {
            return Err("The signed rollback executable failed verification.".into());
        }
        if executable.exists() {
            std::fs::remove_file(&executable).map_err(
                |_| "Could not remove the failed Windows Otter executable for rollback.",
            )?;
        }
        std::fs::rename(&backup, &executable)
            .map_err(|_| "Could not restore the previous signed Windows Otter executable.")?;
        true
    };
    state.pending = None;
    state.version_floor = Some(pending.previous_version);
    if rolled_back {
        state.rolled_back = Some(id.to_owned());
    } else {
        state.failed = Some(id.to_owned());
        state.failed_reason = Some(super::UpdateFailureReason::InstallationFailed);
    }
    store
        .save_update_state(&state)
        .map_err(|error| error.to_string())?;
    drop(store);
    for suffix in ["bin", "updater.exe"] {
        let _ = std::fs::remove_file(directory.join(format!("update-{id}.{suffix}")));
    }
    Command::new(&executable)
        .args(["controller", "--state-dir"])
        .arg(directory)
        .arg("--ack-authorized")
        .creation_flags(windows_sys::Win32::System::Threading::CREATE_NO_WINDOW)
        .spawn()
        .map(|_| ())
        .map_err(|_| "Could not restart the restored Windows Otter controller.".to_owned())
}

#[cfg(target_os = "linux")]
fn digest_file(path: &Path) -> Result<String, String> {
    let mut file = File::open(path).map_err(|_| "Could not read the signed Otter executable.")?;
    let mut digest = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let length = file
            .read(&mut buffer)
            .map_err(|_| "Could not hash the signed Otter executable.")?;
        if length == 0 {
            break;
        }
        digest.update(&buffer[..length]);
    }
    Ok(digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

#[cfg(target_os = "windows")]
fn digest_file(path: &Path) -> Result<String, String> {
    let mut file = File::open(path).map_err(|_| "Could not read the signed Otter executable.")?;
    let mut digest = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let length = file
            .read(&mut buffer)
            .map_err(|_| "Could not hash the signed Otter executable.")?;
        if length == 0 {
            break;
        }
        digest.update(&buffer[..length]);
    }
    Ok(digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

#[cfg(target_os = "linux")]
fn set_raw_capability(file: &File) -> Result<(), String> {
    use std::os::fd::AsRawFd;
    let attribute = b"security.capability\0";
    let data = [
        0x01, 0x00, 0x00, 0x02, // revision 2, effective
        0x00, 0x20, 0x00, 0x00, // CAP_NET_RAW (13)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    // SAFETY: file is a live descriptor for the staged regular executable; data is the Linux
    // revision-2 capability xattr granting only CAP_NET_RAW in its effective/permitted sets.
    let result = unsafe {
        libc::fsetxattr(
            file.as_raw_fd(),
            attribute.as_ptr().cast(),
            data.as_ptr().cast(),
            data.len(),
            0,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err("Could not grant CAP_NET_RAW to the verified Otter executable.".into())
    }
}

#[cfg(target_os = "linux")]
fn verify_open_file(file: &File) -> Result<otserver_otter::update::VerifiedBinary, String> {
    use std::os::fd::AsRawFd;
    otserver_otter::update::verify_binary(
        &PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd())),
        otserver_otter::update::BUILD_TARGET,
    )
}

#[cfg(target_os = "linux")]
fn digest_open_file(file: &File) -> Result<String, String> {
    use std::io::Seek;
    let mut file = file
        .try_clone()
        .map_err(|_| "Could not read the signed Otter executable.")?;
    file.seek(std::io::SeekFrom::Start(0))
        .map_err(|_| "Could not read the signed Otter executable.")?;
    let mut digest = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let length = file
            .read(&mut buffer)
            .map_err(|_| "Could not hash the signed Otter executable.")?;
        if length == 0 {
            break;
        }
        digest.update(&buffer[..length]);
    }
    Ok(digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

#[cfg(target_os = "linux")]
fn set_executable_permissions(file: &File) -> Result<(), String> {
    use std::os::fd::AsRawFd;
    // SAFETY: this changes only the mode of the already-open staged executable, not a pathname.
    if unsafe { libc::fchmod(file.as_raw_fd(), 0o755) } == 0 {
        Ok(())
    } else {
        Err("Could not set executable permissions on the signed Otter update.".into())
    }
}

#[cfg(target_os = "linux")]
fn user_home(uid: u32) -> Result<PathBuf, String> {
    use std::ffi::CStr;
    let mut entry = unsafe { std::mem::zeroed::<libc::passwd>() };
    let mut result = std::ptr::null_mut();
    let mut buffer = vec![0_u8; 16 * 1024];
    // SAFETY: getpwuid_r writes only into the initialized passwd record and supplied byte buffer.
    let status = unsafe {
        libc::getpwuid_r(
            uid,
            &mut entry,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if status != 0 || result.is_null() || entry.pw_dir.is_null() {
        return Err("Could not locate the scanner user's home directory.".into());
    }
    let home = unsafe { CStr::from_ptr(entry.pw_dir) }
        .to_str()
        .map_err(|_| "The scanner user's home directory is not valid UTF-8.")?;
    let path = PathBuf::from(home);
    if !path.is_absolute() {
        return Err("The scanner user's home directory is not absolute.".into());
    }
    Ok(path)
}

#[cfg(target_os = "linux")]
fn reject_symlink_components(path: &Path) -> Result<(), String> {
    let mut component = PathBuf::new();
    for part in path.components() {
        component.push(part.as_os_str());
        if std::fs::symlink_metadata(&component)
            .is_ok_and(|metadata| metadata.file_type().is_symlink())
        {
            return Err("The Otter installation path must not contain symbolic links.".into());
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn with_user_euid<T>(uid: u32, action: impl FnOnce() -> T) -> Result<T, String> {
    if unsafe { libc::seteuid(uid) } != 0 {
        return Err("Could not temporarily drop privileges to the scanner user.".into());
    }
    let result = action();
    if unsafe { libc::seteuid(0) } != 0 {
        return Err("Could not restore the verified updater's privileged identity.".into());
    }
    Ok(result)
}

#[cfg(target_os = "linux")]
fn rollback_linux(
    directory: &Path,
    uid: u32,
    executable: &Path,
    backup: &Path,
    pending: &super::PendingUpdate,
    update_state: &mut super::UpdateState,
    mut child: Option<&mut std::process::Child>,
) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    if let Some(child) = child.as_mut() {
        let _ = child.kill();
        let _ = child.wait();
    }
    let home = user_home(uid)?;
    let service = home.join(".config/systemd/user/otserver-otter-controller.service");
    if service.is_file() {
        let systemctl = system_tool("systemctl")?;
        let _ = with_user_euid(uid, || {
            Command::new(systemctl)
                .args(["--user", "stop", "otserver-otter-controller.service"])
                .status()
        })?;
    }
    let metadata = std::fs::symlink_metadata(backup)
        .map_err(|_| "The signed rollback executable is unavailable.")?;
    if !metadata.file_type().is_file()
        || metadata.uid() != 0
        || digest_file(backup)? != pending.previous_digest
        || otserver_otter::update::verify_binary(backup, otserver_otter::update::BUILD_TARGET)
            .is_err()
    {
        return Err("The signed rollback executable failed verification.".into());
    }
    std::fs::rename(backup, executable)
        .map_err(|_| "Could not atomically restore the previous signed Otter executable.")?;
    update_state.version_floor = Some(pending.previous_version.clone());
    update_state.pending = None;
    update_state.rolled_back = Some(pending.id.clone());
    Store::save_update_state_for(directory, uid, update_state)
        .map_err(|error| error.to_string())?;
    start_linux_controller(uid, &home, executable, directory)
}

#[cfg(target_os = "linux")]
fn recover_linux_update(directory: &Path, id: &str) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;

    let uid = unsafe { libc::getuid() };
    if uid == 0
        || unsafe { libc::geteuid() } != 0
        || !is_update_helper_executable()
        || !super::valid_id(id)
    {
        return Ok(());
    }
    let mut state =
        Store::read_update_state_for(directory, uid).map_err(|error| error.to_string())?;
    let Some(pending) = state.pending.clone().filter(|pending| pending.id == id) else {
        return Ok(());
    };
    let home = user_home(uid)?;
    let executable = home.join(".local/bin/otserver-otter");
    reject_symlink_components(&executable)?;
    let parent = executable.parent().ok_or("Invalid installation path.")?;
    let backup = parent.join(format!(".otserver-otter-update-{id}.previous"));
    let current_is_previous =
        otserver_otter::update::verify_binary(&executable, otserver_otter::update::BUILD_TARGET)
            .is_ok_and(|binary| binary.version() == pending.previous_version)
            && digest_file(&executable).is_ok_and(|digest| digest == pending.previous_digest);
    let rolled_back = if current_is_previous {
        false
    } else {
        let backup_metadata = std::fs::symlink_metadata(&backup)
            .map_err(|_| "The signed rollback executable is unavailable.")?;
        if !backup_metadata.file_type().is_file()
            || backup_metadata.uid() != 0
            || otserver_otter::update::verify_binary(&backup, otserver_otter::update::BUILD_TARGET)
                .is_err()
            || digest_file(&backup)? != pending.previous_digest
        {
            return Err("The signed rollback executable failed verification.".into());
        }
        std::fs::rename(&backup, &executable)
            .map_err(|_| "Could not atomically restore the previous signed Otter executable.")?;
        true
    };
    state.version_floor = Some(pending.previous_version.clone());
    state.pending = None;
    if rolled_back {
        state.rolled_back = Some(id.to_owned());
    } else {
        state.failed = Some(id.to_owned());
        state.failed_reason = Some(super::UpdateFailureReason::InstallationFailed);
    }
    Store::save_update_state_for(directory, uid, &state).map_err(|error| error.to_string())?;
    for suffix in ["bin", "updater.exe"] {
        let _ = std::fs::remove_file(directory.join(format!("update-{id}.{suffix}")));
    }
    if !rolled_back && std::fs::symlink_metadata(&backup).is_ok_and(|metadata| metadata.uid() == 0)
    {
        let _ = std::fs::remove_file(backup);
    }
    start_linux_controller(uid, &home, &executable, directory)
}

#[cfg(target_os = "linux")]
fn start_linux_controller(
    uid: u32,
    home: &Path,
    executable: &Path,
    directory: &Path,
) -> Result<(), String> {
    let service = home.join(".config/systemd/user/otserver-otter-controller.service");
    if service.is_file() {
        let systemctl = system_tool("systemctl")?;
        let restarted = with_user_euid(uid, || {
            Command::new(&systemctl)
                .args(["--user", "restart", "otserver-otter-controller.service"])
                .status()
                .is_ok_and(|status| status.success())
                || Command::new(&systemctl)
                    .args(["--user", "start", "otserver-otter-controller.service"])
                    .status()
                    .is_ok_and(|status| status.success())
        })?;
        if restarted {
            return Ok(());
        }
        return Err("Could not restart the restored Otter controller.".into());
    }
    with_user_euid(uid, || {
        Command::new(executable)
            .args(["controller", "--state-dir"])
            .arg(directory)
            .arg("--ack-authorized")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .is_ok()
    })
    .and_then(|started| {
        started
            .then_some(())
            .ok_or("Could not start the restored Otter controller.".into())
    })
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub(super) fn apply_update(_: Option<PathBuf>, _: &str, _: u32) -> Result<(), String> {
    Err("Managed Otter updates support Linux and Windows.".into())
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
        "[Unit]\nDescription=OTserver Otter controller\n\n[Service]\nType=exec\nExecStart=:{executable} controller --state-dir {directory} --ack-authorized\nRestart=on-failure\nRestartSec=30\nKillMode=process\nUMask=0077\n\n[Install]\nWantedBy=default.target\n"
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

    #[cfg(target_os = "linux")]
    #[test]
    fn privileged_staging_permissions_follow_the_open_file_not_a_replaced_path() {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};

        let directory =
            std::env::temp_dir().join(format!("otter-update-fd-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let staged = directory.join("staged");
        let victim = directory.join("victim");
        std::fs::write(&victim, b"do not chmod this file").unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o644)).unwrap();
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true).mode(0o600);
        let file = options.open(&staged).unwrap();
        std::fs::remove_file(&staged).unwrap();
        symlink(&victim, &staged).unwrap();

        set_executable_permissions(&file).unwrap();

        assert_eq!(
            std::fs::metadata(&victim).unwrap().permissions().mode() & 0o777,
            0o644
        );
        assert!(
            std::fs::symlink_metadata(&staged)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

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
        std::fs::write(&destination, b"existing executable").unwrap();
        assert_eq!(
            copy_executable(&directory.join("missing"), &destination).unwrap_err(),
            "Could not read the controller executable."
        );
        assert_eq!(std::fs::read(&destination).unwrap(), b"existing executable");

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
        for contents in [None, Some(b"keep directory contents".as_slice())] {
            let retained_file = blocked_destination.join("keep");
            if let Some(contents) = contents {
                std::fs::write(&retained_file, contents).unwrap();
            }
            assert_eq!(
                copy_executable(&source, &blocked_destination).unwrap_err(),
                "Could not publish the installed controller executable."
            );
            assert!(blocked_destination.is_dir());
            if let Some(contents) = contents {
                assert_eq!(std::fs::read(&retained_file).unwrap(), contents);
            }
            assert_eq!(
                std::fs::read_dir(blocked_destination.parent().unwrap())
                    .unwrap()
                    .count(),
                2
            );
        }
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
        assert!(directory.join("controller.log").is_file());
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 2);
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
        assert!(directory.join("controller.log").is_file());
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 3);
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
