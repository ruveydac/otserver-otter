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
        let directory = Self::directory(directory)?;
        if !directory.exists() {
            std::fs::create_dir_all(directory.parent().ok_or(Error::Invalid)?)
                .map_err(|_| Error::Local("Could not create managed state parent directory."))?;
            let builder = std::fs::DirBuilder::new();
            #[cfg(unix)]
            let mut builder = builder;
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
            .map_err(|_| Error::Local("Another managed scanner is using this state directory. Stop that controller before enrolling or changing its installation."))?;
        Ok(Self {
            directory,
            _lock: lock,
        })
    }

    pub(super) fn directory(directory: Option<PathBuf>) -> Result<PathBuf, Error> {
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
        if directory.is_absolute() {
            Ok(directory)
        } else {
            std::env::current_dir()
                .map(|base| base.join(directory))
                .map_err(|_| Error::Local("Could not resolve managed state directory."))
        }
    }

    pub(super) fn load(&self) -> Result<State, Error> {
        Self::read_state(&self.directory)
    }

    pub(super) fn path(&self) -> &Path {
        &self.directory
    }

    pub(super) fn read_state(directory: &Path) -> Result<State, Error> {
        let path = directory.join("agent-state.json");
        if !path.exists() {
            return Ok(State::default());
        }
        check_private(directory, true)?;
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
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        EXPLICIT_ACCESS_W, NO_MULTIPLE_TRUSTEE, SE_FILE_OBJECT, SET_ACCESS, SetEntriesInAclW,
        SetNamedSecurityInfoW, TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_W,
    };
    use windows_sys::Win32::Security::{
        CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, OBJECT_INHERIT_ACE,
        PROTECTED_DACL_SECURITY_INFORMATION, TOKEN_USER,
    };
    use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;

    let user = windows_token_user()?;
    let directory = std::fs::metadata(path)
        .map_err(|_| Error::Local("Could not inspect private scanner state."))?
        .is_dir();
    let mut name: Vec<u16> = path.as_os_str().encode_wide().collect();
    if name.contains(&0) {
        return Err(Error::Invalid);
    }
    name.push(0);
    // SAFETY: windows_token_user returns a successful TOKEN_USER in a pointer-aligned buffer.
    // Its SID storage remains alive until SetEntriesInAclW has copied it into the new ACL.
    let sid = unsafe { (*user.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    let access = EXPLICIT_ACCESS_W {
        grfAccessPermissions: FILE_ALL_ACCESS,
        grfAccessMode: SET_ACCESS,
        grfInheritance: if directory {
            CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE
        } else {
            0
        },
        Trustee: TRUSTEE_W {
            pMultipleTrustee: null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_USER,
            ptstrName: sid.cast(),
        },
    };
    let mut acl = null_mut();
    // SAFETY: access contains a valid SID; a null old ACL builds a user-only ACL.
    if unsafe { SetEntriesInAclW(1, &access, null(), &mut acl) } != 0 {
        return Err(Error::Local(
            "Could not construct private scanner state ACL.",
        ));
    }
    // SAFETY: name is NUL-terminated and acl is owned by this call. Only the DACL is changed;
    // owner, group and SACL are untouched. Protection removes inherited access from parents.
    let status = unsafe {
        let status = SetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            acl,
            null(),
        );
        LocalFree(acl.cast());
        status
    };
    if status != 0 {
        return Err(Error::Local("Could not restrict scanner state ACL."));
    }
    Ok(())
}

#[cfg(windows)]
pub(super) fn windows_token_user() -> Result<Box<[usize; 32]>, Error> {
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TokenUser};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = null_mut();
    // SAFETY: the process pseudo-handle is valid and token points to writable handle storage.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(Error::Local("Could not query scanner state owner token."));
    }
    // TOKEN_USER plus SECURITY_MAX_SID_SIZE (68 bytes) fits even on 32-bit Windows.
    // usize storage supplies the alignment required by TOKEN_USER's pointer fields.
    // Keep the allocation stable: TOKEN_USER contains a pointer into this buffer.
    let mut user = Box::new([0usize; 32]);
    let mut length = 0;
    // SAFETY: the token is valid and the aligned buffer's full size is supplied. CloseHandle
    // releases the token on both paths; the returned SID is copied into user, not token-owned.
    let success = unsafe {
        let success = GetTokenInformation(
            token,
            TokenUser,
            user.as_mut_ptr().cast(),
            std::mem::size_of_val(user.as_ref()) as u32,
            &mut length,
        );
        CloseHandle(token);
        success
    };
    if success == 0 {
        return Err(Error::Local("Could not read scanner state owner SID."));
    }
    Ok(user)
}

#[cfg(not(windows))]
fn replace(source: &Path, destination: &Path) -> Result<(), Error> {
    std::fs::rename(source, destination)
        .map_err(|_| Error::Local("Could not atomically replace scanner state."))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state_dir() -> PathBuf {
        std::env::temp_dir().join(format!("otter-store-{}", uuid::Uuid::new_v4()))
    }

    #[test]
    fn state_defaults_and_result_sync_require_a_durable_private_file() {
        let directory = state_dir();
        let store = Store::open(Some(directory.clone())).unwrap();
        let loaded = store.load().unwrap();
        assert!(loaded.scanner.is_none());
        assert!(loaded.pending_imports.is_empty());

        std::fs::write(store.result_path("run-1"), b"scan export").unwrap();
        store.sync_result("run-1").unwrap();
        assert!(matches!(store.sync_result("missing"), Err(Error::Local(_))));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(store.result_path("run-1"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        drop(store);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn relative_state_directories_resolve_from_the_current_directory() {
        let current = std::env::current_dir().unwrap();

        assert_eq!(
            Store::directory(Some("relative-state".into())).unwrap(),
            current.join("relative-state")
        );
    }

    #[test]
    fn default_state_directory_uses_the_platform_user_state_location() {
        let directory = Store::directory(None).unwrap();

        assert!(directory.is_absolute());
        assert!(directory.ends_with("otserver-otter"));
        #[cfg(target_os = "linux")]
        {
            let base = std::env::var_os("XDG_STATE_HOME")
                .map(PathBuf::from)
                .or_else(|| {
                    std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/state"))
                })
                .unwrap();
            assert_eq!(directory, base.join("otserver-otter"));
        }
    }

    #[test]
    fn file_credentials_are_validated_and_a_missing_reference_is_an_error() {
        let directory = state_dir();
        let store = Store::open(Some(directory.clone())).unwrap();
        let mut state = State::default();
        assert!(matches!(store.credential(&state), Err(Error::Local(_))));

        let credential = Credential {
            credential: "a234567890123456789012345678901234567890".into(),
            credential_expires_at: "2027-01-01T00:00:00Z".into(),
        };
        store
            .persist_credential(&mut state, &credential, true)
            .unwrap();
        assert_eq!(
            store.credential(&state).unwrap(),
            "a234567890123456789012345678901234567890"
        );

        state.file_credential.as_mut().unwrap().credential.clear();
        assert!(store.credential(&state).is_err());
        drop(store);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn malformed_state_is_rejected_instead_of_reset() {
        let directory = state_dir();
        let store = Store::open(Some(directory.clone())).unwrap();
        let path = directory.join("agent-state.json");
        std::fs::write(&path, b"{not-json").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        assert!(matches!(store.load(), Err(Error::Local(_))));
        drop(store);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn oversized_state_is_rejected_before_deserialization() {
        let directory = state_dir();
        let store = Store::open(Some(directory.clone())).unwrap();
        let path = directory.join("agent-state.json");
        std::fs::write(&path, vec![b' '; 1024 * 1024 + 1]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        assert!(matches!(store.load(), Err(Error::Invalid)));
        drop(store);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn saved_run_and_import_ids_are_validated_on_load() {
        let directory = state_dir();
        let store = Store::open(Some(directory.clone())).unwrap();
        let invalid_run = State {
            assignment: Some(super::super::RunState {
                id: "../run".into(),
                phase: super::super::Phase::Ready,
                status: "completed".into(),
                import_id: None,
                message: None,
                upload_attempts: 0,
            }),
            ..State::default()
        };
        store.save(&invalid_run).unwrap();
        assert!(matches!(store.load(), Err(Error::Invalid)));

        let invalid_import = State {
            pending_imports: vec![super::super::PendingImport {
                id: "bad/id".into(),
                status: "pending".into(),
                retries: 0,
            }],
            ..State::default()
        };
        store.save(&invalid_import).unwrap();
        assert!(matches!(store.load(), Err(Error::Invalid)));
        drop(store);
        std::fs::remove_dir_all(directory).unwrap();
    }
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
