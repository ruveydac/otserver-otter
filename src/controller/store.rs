use super::{Credential, Error, State};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub(super) struct Store {
    directory: PathBuf,
    _lock: File,
}

impl Store {
    pub(super) fn open(directory: Option<PathBuf>) -> Result<Self, Error> {
        let directory = directory
            .or_else(|| {
                #[cfg(windows)]
                let base = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
                #[cfg(not(windows))]
                let base = std::env::var_os("XDG_STATE_HOME")
                    .map(PathBuf::from)
                    .or_else(|| {
                        std::env::var_os("HOME")
                            .map(|home| PathBuf::from(home).join(".local/state"))
                    });
                base.map(|base| base.join("otserver-otter"))
            })
            .ok_or(Error::Local(
                "Choose --state-dir for managed scanner state.",
            ))?;
        if !directory.exists() {
            std::fs::create_dir_all(directory.parent().ok_or(Error::Invalid)?)
                .map_err(|_| Error::Local("Could not create managed state parent directory."))?;
            let mut builder = std::fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder
                .create(&directory)
                .map_err(|_| Error::Local("Could not create managed state directory."))?;
            #[cfg(windows)]
            restrict_windows(&directory)?;
        }
        check_private(&directory, true)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let lock = options
            .open(directory.join("agent.lock"))
            .map_err(|_| Error::Local("Could not open managed scanner lock."))?;
        lock.try_lock()
            .map_err(|_| Error::Local("Another managed scanner is using this state directory."))?;
        Ok(Self {
            directory,
            _lock: lock,
        })
    }

    pub(super) fn load(&self) -> Result<State, Error> {
        let path = self.directory.join("agent-state.json");
        if !path.exists() {
            return Ok(State::default());
        }
        check_private(&path, false)?;
        let mut data = Vec::new();
        File::open(path)
            .and_then(|file| file.take(1024 * 1024 + 1).read_to_end(&mut data))
            .map_err(|_| Error::Local("Could not read managed scanner state."))?;
        if data.len() > 1024 * 1024 {
            return Err(Error::Invalid);
        }
        let state: State = serde_json::from_slice(&data).map_err(|_| {
            Error::Local("Managed scanner state is invalid; recover by re-enrollment.")
        })?;
        if state
            .assignment
            .as_ref()
            .is_some_and(|run| !super::valid_id(&run.id))
            || state
                .pending_imports
                .iter()
                .any(|i| !super::valid_id(&i.id))
        {
            return Err(Error::Invalid);
        }
        Ok(state)
    }

    pub(super) fn save(&self, state: &State) -> Result<(), Error> {
        let data = serde_json::to_vec(state)
            .map_err(|_| Error::Local("Could not encode managed scanner state."))?;
        let temporary = self.directory.join(format!("{}.tmp", uuid::Uuid::new_v4()));
        let result = (|| {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options
                .open(&temporary)
                .map_err(|_| Error::Local("Could not create private scanner state."))?;
            file.write_all(&data)
                .and_then(|()| file.sync_all())
                .map_err(|_| Error::Local("Could not durably save scanner state."))?;
            replace(&temporary, &self.directory.join("agent-state.json"))?;
            #[cfg(unix)]
            File::open(&self.directory)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| Error::Local("Could not synchronize scanner state directory."))?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(temporary);
        }
        result
    }

    pub(super) fn result_path(&self, id: &str) -> PathBuf {
        self.directory.join(format!("{id}.otserver.json"))
    }

    pub(super) fn sync_result(&self, id: &str) -> Result<(), Error> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(self.result_path(id), std::fs::Permissions::from_mode(0o600))
                .map_err(|_| {
                    Error::Local("Could not restrict retained scan result permissions.")
                })?;
        }
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.result_path(id))
            .and_then(|file| file.sync_all())
            .map_err(|_| Error::Local("Could not durably retain scan result."))?;
        #[cfg(unix)]
        File::open(&self.directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| Error::Local("Could not synchronize result directory."))?;
        Ok(())
    }

    pub(super) fn credential(&self, state: &State) -> Result<String, Error> {
        if let Some(credential) = &state.file_credential {
            super::validate_credential(credential)?;
            return Ok(credential.credential.clone());
        }
        let key = state
            .credential_key
            .as_deref()
            .ok_or(Error::Local("No saved credential; enroll with --enroll."))?;
        keyring::Entry::new("org.otserver.otter.controller", key)
            .and_then(|entry| entry.get_password())
            .map_err(|_| {
                Error::Local("OS credential store unavailable; restore access or re-enroll.")
            })
    }

    pub(super) fn persist_credential(
        &self,
        state: &mut State,
        credential: &Credential,
        force_file: bool,
    ) -> Result<(), Error> {
        super::validate_credential(credential)?;
        let key = uuid::Uuid::new_v4().to_string();
        let entry = keyring::Entry::new("org.otserver.otter.controller", &key);
        let stored = !force_file
            && entry.as_ref().is_ok_and(|entry| {
                entry.set_password(&credential.credential).is_ok()
                    && entry
                        .get_password()
                        .is_ok_and(|saved| saved == credential.credential)
            });
        let old_key = state.credential_key.take();
        state
            .credential_expires_at
            .clone_from(&credential.credential_expires_at);
        if stored {
            state.credential_key = Some(key);
            state.file_credential = None;
        } else {
            state.file_credential = Some(Credential {
                credential: credential.credential.clone(),
                credential_expires_at: credential.credential_expires_at.clone(),
            });
        }
        self.save(state)?;
        // Only remove the previous secret after the new credential and reference are durable.
        if let Some(key) = old_key {
            let _ = keyring::Entry::new("org.otserver.otter.controller", &key)
                .and_then(|entry| entry.delete_credential());
        }
        Ok(())
    }
}

fn check_private(path: &Path, directory: bool) -> Result<(), Error> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| Error::Local("Could not inspect private scanner state."))?;
    if metadata.file_type().is_symlink() || metadata.is_dir() != directory {
        return Err(Error::Local(
            "Scanner state must be a private regular file/directory, not a symlink.",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid has no arguments or memory preconditions.
        if metadata.mode() & 0o077 != 0 || metadata.uid() != unsafe { libc::geteuid() } {
            return Err(Error::Local(
                "Scanner state must belong to this user with directory mode 0700 and file mode 0600.",
            ));
        }
    }
    #[cfg(windows)]
    restrict_windows(path)?;
    Ok(())
}

#[cfg(windows)]
fn restrict_windows(path: &Path) -> Result<(), Error> {
    // Use a fixed script and a positional path; no credentials or untrusted code in the command.
    let script = "$ErrorActionPreference='Stop'; $p=$env:OTTER_STATE_ACL_PATH; $sid=[System.Security.Principal.WindowsIdentity]::GetCurrent().User; $acl=Get-Acl -LiteralPath $p; $acl.SetAccessRuleProtection($true,$false); foreach($r in @($acl.Access)){$acl.RemoveAccessRuleAll($r)}; if((Get-Item -LiteralPath $p).PSIsContainer){$rule=New-Object System.Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')}else{$rule=New-Object System.Security.AccessControl.FileSystemAccessRule($sid,'FullControl','Allow')}; $acl.SetOwner($sid); $acl.AddAccessRule($rule); Set-Acl -LiteralPath $p -AclObject $acl";
    let output = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .env("OTTER_STATE_ACL_PATH", path)
        .output()
        .map_err(|_| Error::Local("Could not restrict scanner state ACL."))?;
    if !output.status.success() {
        return Err(Error::Local("Could not restrict scanner state ACL."));
    }
    Ok(())
}

#[cfg(not(windows))]
fn replace(source: &Path, destination: &Path) -> Result<(), Error> {
    std::fs::rename(source, destination)
        .map_err(|_| Error::Local("Could not atomically replace scanner state."))
}

#[cfg(windows)]
fn replace(source: &Path, destination: &Path) -> Result<(), Error> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };
    let source: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    // SAFETY: both paths are valid NUL-terminated UTF-16 buffers for the duration of the call.
    if unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        return Err(Error::Local("Could not atomically replace scanner state."));
    }
    Ok(())
}
