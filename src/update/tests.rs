use super::*;
use std::path::PathBuf;

struct Fixture {
    directory: PathBuf,
    path: PathBuf,
    key: SigningKey,
}

impl Fixture {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!("otter-binary-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("candidate");
        std::fs::write(&path, vec![0x42; 130_000]).unwrap();
        Self {
            directory,
            path,
            key: SigningKey::from_bytes(&[1; 32]),
        }
    }

    fn sign(&self, target: &str) {
        embed_with_key(
            &self.path,
            "v0.14",
            target,
            &self.key,
            &self.key.verifying_key(),
        )
        .unwrap();
    }

    fn verify(&self, target: &str) -> Result<VerifiedBinary, String> {
        verify_with_key(
            &mut File::open(&self.path).unwrap(),
            target,
            &self.key.verifying_key(),
        )
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.directory).unwrap();
    }
}

#[test]
fn embedded_signature_matches_an_independent_openssl_vector() {
    let fixture = Fixture::new();
    std::fs::write(&fixture.path, b"Otter fixture\n").unwrap();
    fixture.sign("x86_64-unknown-linux-gnu");
    let bytes = std::fs::read(&fixture.path).unwrap();
    let trailer = &bytes[14..];
    // OpenSSL pkeyutl -sign -rawin, PKCS#8 seed [1; 32], using the documented v1 record.
    let expected = "4392d34ac43391363f5c03be337b5e68a9782798781ce98ce9af29ee8f9cf6d9dd853434adf5d60a152903b7b4d2ee7755d19fd300c5bb5ffbe0383fbbfd1804";
    let signature: String = trailer[248..]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(signature, expected);
    fixture.verify("x86_64-unknown-linux-gnu").unwrap();
}

#[test]
fn embedded_signatures_authenticate_each_target_without_sidecars_or_fixed_filenames() {
    for target in RELEASE_TARGETS {
        let fixture = Fixture::new();
        fixture.sign(target);
        let verified = fixture.verify(target).unwrap();
        assert_eq!(verified.version(), "v0.14");
        assert_eq!(verified.target(), target);
        verified.require_newer_than("v0.13.2").unwrap();
        for version in ["v0.14", "v0.14.0+build", "v0.15", "invalid"] {
            assert!(verified.require_newer_than(version).is_err());
        }
        assert_eq!(std::fs::read_dir(&fixture.directory).unwrap().count(), 1);
        let renamed = fixture.directory.join("renamed.exe");
        std::fs::rename(&fixture.path, &renamed).unwrap();
        verify_with_key(
            &mut File::open(renamed).unwrap(),
            target,
            &fixture.key.verifying_key(),
        )
        .unwrap();
    }
}

#[test]
fn embedded_signatures_reject_wrong_keys_targets_and_unsigned_files() {
    let fixture = Fixture::new();
    let target = RELEASE_TARGETS[0];
    assert!(
        fixture
            .verify(target)
            .unwrap_err()
            .contains("no supported embedded")
    );
    let original = std::fs::read(&fixture.path).unwrap();
    assert!(embed_binary_signature(&fixture.path, "v0.14", target, &fixture.key).is_err());
    assert_eq!(std::fs::read(&fixture.path).unwrap(), original);
    fixture.sign(target);
    assert!(
        verify_binary(&fixture.path, target)
            .unwrap_err()
            .contains("signature is invalid")
    );
    assert!(fixture.verify(RELEASE_TARGETS[2]).is_err());
    assert!(fixture.verify("unknown").is_err());
    let signed = std::fs::read(&fixture.path).unwrap();
    assert!(
        embed_with_key(
            &fixture.path,
            "v0.15",
            target,
            &fixture.key,
            &fixture.key.verifying_key()
        )
        .unwrap_err()
        .contains("already has")
    );
    assert_eq!(std::fs::read(&fixture.path).unwrap(), signed);
}

#[test]
fn embedded_signature_covers_payload_metadata_and_signature_bytes() {
    let fixture = Fixture::new();
    let target = RELEASE_TARGETS[0];
    fixture.sign(target);
    let signed = std::fs::read(&fixture.path).unwrap();
    let start = signed.len() - TRAILER_LEN;
    for index in [
        0,
        65_536,
        start - 1,
        start,
        start + 16,
        start + 24,
        start + 152,
        start + 216,
        start + MESSAGE_LEN,
        signed.len() - 1,
    ] {
        let mut tampered = signed.clone();
        tampered[index] ^= 1;
        std::fs::write(&fixture.path, tampered).unwrap();
        assert!(
            fixture.verify(target).is_err(),
            "accepted tampering at {index}"
        );
    }
}

#[test]
fn embedded_signature_rejects_truncation_appends_copied_trailers_and_wrapping() {
    let fixture = Fixture::new();
    let target = RELEASE_TARGETS[0];
    fixture.sign(target);
    let signed = std::fs::read(&fixture.path).unwrap();
    let start = signed.len() - TRAILER_LEN;
    for length in [0, 1, TRAILER_LEN, start, signed.len() - 1] {
        std::fs::write(&fixture.path, &signed[..length]).unwrap();
        assert!(fixture.verify(target).is_err());
    }
    let mut appended = signed.clone();
    appended.push(0);
    std::fs::write(&fixture.path, appended).unwrap();
    assert!(fixture.verify(target).is_err());
    let mut wrapped = signed.clone();
    wrapped.extend_from_slice(&signed[start..]);
    std::fs::write(&fixture.path, wrapped).unwrap();
    assert!(fixture.verify(target).unwrap_err().contains("length"));
    let mut copied = signed;
    copied[..start].fill(0x43);
    std::fs::write(&fixture.path, copied).unwrap();
    assert!(fixture.verify(target).unwrap_err().contains("SHA-256"));
}

#[test]
fn rejects_authenticated_but_malformed_metadata_and_incorrect_payload_length() {
    let fixture = Fixture::new();
    let target = RELEASE_TARGETS[0];
    fixture.sign(target);
    let signed = std::fs::read(&fixture.path).unwrap();
    let start = signed.len() - TRAILER_LEN;
    for (range, value) in [
        (16..24, vec![0xff; 8]),
        (24..152, vec![0; 128]),
        (24..25, vec![0xff]),
        (30..31, vec![b'x']),
        (152..216, vec![b'x'; 64]),
        (152..153, vec![0xff]),
        (216..248, vec![0; 32]),
    ] {
        let mut malformed = signed.clone();
        malformed[start + range.start..start + range.end].copy_from_slice(&value);
        let signature = fixture.key.sign(&malformed[start..start + MESSAGE_LEN]);
        malformed[start + MESSAGE_LEN..].copy_from_slice(&signature.to_bytes());
        std::fs::write(&fixture.path, malformed).unwrap();
        assert!(
            fixture.verify(target).is_err(),
            "accepted malformed field {range:?}"
        );
    }
}

#[test]
fn signing_and_verification_bound_files_and_validate_inputs_before_modification() {
    let fixture = Fixture::new();
    let target = RELEASE_TARGETS[0];
    let original = std::fs::read(&fixture.path).unwrap();
    for version in ["latest", "", &format!("1.0.0+{}", "x".repeat(128))] {
        assert!(
            embed_with_key(
                &fixture.path,
                version,
                target,
                &fixture.key,
                &fixture.key.verifying_key()
            )
            .is_err()
        );
    }
    assert!(
        embed_with_key(
            &fixture.path,
            "v0.14",
            "unknown",
            &fixture.key,
            &fixture.key.verifying_key()
        )
        .is_err()
    );
    assert_eq!(std::fs::read(&fixture.path).unwrap(), original);
    assert!(verify_binary(&fixture.directory, target).is_err());
    assert!(
        embed_with_key(
            &fixture.directory,
            "v0.14",
            target,
            &fixture.key,
            &fixture.key.verifying_key()
        )
        .is_err()
    );
    let missing = fixture.directory.join("missing");
    assert!(verify_binary(&missing, target).is_err());
    assert!(
        embed_with_key(
            &missing,
            "v0.14",
            target,
            &fixture.key,
            &fixture.key.verifying_key()
        )
        .is_err()
    );
    let file = File::create(&fixture.path).unwrap();
    for size in [
        0,
        MAX_PAYLOAD_BYTES + 1,
        MAX_PAYLOAD_BYTES - TRAILER_LEN as u64 + 1,
    ] {
        file.set_len(size).unwrap();
        assert!(
            embed_with_key(
                &fixture.path,
                "v0.14",
                target,
                &fixture.key,
                &fixture.key.verifying_key()
            )
            .is_err()
        );
        assert!(fixture.verify(target).is_err());
    }
    drop(file);
    std::fs::write(&fixture.path, [1]).unwrap();
    let version = format!("1.0.0+{}", "x".repeat(122));
    assert_eq!(version.len(), 128);
    embed_with_key(
        &fixture.path,
        &version,
        target,
        &fixture.key,
        &fixture.key.verifying_key(),
    )
    .unwrap();
    assert_eq!(fixture.verify(target).unwrap().version(), version);
}

#[test]
fn signed_native_executable_still_runs_after_appending_the_trailer() {
    let fixture = Fixture::new();
    // Exercise the native loader without hashing a debug test harness of several hundred MiB.
    let executable = if cfg!(windows) {
        PathBuf::from(std::env::var_os("SystemRoot").unwrap()).join("System32/cmd.exe")
    } else {
        PathBuf::from("/bin/true")
    };
    // GNU Windows test builds exercise the PE loader with the release's Windows target label.
    let target = if cfg!(windows) {
        RELEASE_TARGETS[2]
    } else {
        BUILD_TARGET
    };
    let path = fixture.directory.join(if cfg!(windows) {
        "signed.exe"
    } else {
        "signed"
    });
    std::fs::copy(executable, &path).unwrap();
    embed_with_key(
        &path,
        "v0.14",
        target,
        &fixture.key,
        &fixture.key.verifying_key(),
    )
    .unwrap();
    let mut command = std::process::Command::new(path);
    if cfg!(windows) {
        command.args(["/d", "/c", "exit", "0"]);
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn version_checks_preserve_semver_rules_short_tags_and_prerelease_ordering() {
    assert_eq!(release_version("v0.14").unwrap(), Version::new(0, 14, 0));
    assert_eq!(
        release_version("0.14.2-rc.1+build").unwrap(),
        Version::parse("0.14.2-rc.1+build").unwrap()
    );
    for version in [
        "", "1", "v.10.2", "vv1.2.3", "01.2", "v1.02.3", "1.2.3.4", " 1.2.3", "1.2.3\n", "1.2.3-01",
    ] {
        assert!(release_version(version).is_err(), "{version}");
    }
    let fixture = Fixture::new();
    let target = RELEASE_TARGETS[0];
    embed_with_key(
        &fixture.path,
        "v0.14.0-rc.2+new",
        target,
        &fixture.key,
        &fixture.key.verifying_key(),
    )
    .unwrap();
    let verified = fixture.verify(target).unwrap();
    verified.require_newer_than("v0.14-rc.1").unwrap();
    assert!(verified.require_newer_than("v0.14").is_err());
    assert!(verified.require_newer_than("v0.14-rc.2+old").is_err());
    assert!(!public_key(PUBLIC_KEY_PEM).unwrap().is_weak());
}

#[test]
fn unreadable_executable_fails_verification_instead_of_accepting_its_metadata() {
    let fixture = Fixture::new();
    let target = RELEASE_TARGETS[0];
    fixture.sign(target);
    let mut file = File::options().write(true).open(&fixture.path).unwrap();
    let error = verify_with_key(&mut file, target, &fixture.key.verifying_key()).unwrap_err();
    let mut byte = [0];
    assert_eq!(error, file.read(&mut byte).unwrap_err().to_string());
}

struct VerificationReader<'a> {
    file: &'a File,
    fail_read: usize,
    fail_seek: usize,
    resize_on_rewind: Option<u64>,
    reads: usize,
    seeks: usize,
}

impl Read for VerificationReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.reads += 1;
        if self.reads == self.fail_read {
            return Err(std::io::Error::other("injected read failure"));
        }
        self.file.read(buffer)
    }
}

impl Seek for VerificationReader<'_> {
    fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
        self.seeks += 1;
        if self.seeks == self.fail_seek {
            return Err(std::io::Error::other("injected seek failure"));
        }
        if position == SeekFrom::Start(0)
            && let Some(size) = self.resize_on_rewind.take()
        {
            self.file.set_len(size)?;
        }
        self.file.seek(position)
    }
}

#[test]
fn verification_propagates_io_failures_before_and_after_authenticating_the_trailer() {
    let fixture = Fixture::new();
    let target = RELEASE_TARGETS[0];
    fixture.sign(target);
    let file = File::open(&fixture.path).unwrap();
    for (fail_read, fail_seek, expected) in [
        (0, 1, "injected seek failure"),
        (1, 0, "injected read failure"),
        (0, 2, "injected seek failure"),
        (2, 0, "injected read failure"),
        (3, 0, "injected read failure"),
    ] {
        let reader = VerificationReader {
            file: &file,
            fail_read,
            fail_seek,
            resize_on_rewind: None,
            reads: 0,
            seeks: 0,
        };
        assert_eq!(
            verify_reader(reader, &file, target, &fixture.key.verifying_key()).unwrap_err(),
            expected
        );
    }
}

#[test]
fn verification_rejects_size_changes_after_reading_a_valid_trailer() {
    let fixture = Fixture::new();
    let target = RELEASE_TARGETS[0];
    fixture.sign(target);
    let signed = std::fs::read(&fixture.path).unwrap();
    let file = File::options()
        .read(true)
        .write(true)
        .open(&fixture.path)
        .unwrap();
    let size = signed.len() as u64;
    for (new_size, expected) in [
        (size + 1, "Executable changed size while being verified."),
        (size - 1, "Executable changed size while being verified."),
        (
            1,
            "Executable SHA-256 does not match its embedded signature.",
        ),
    ] {
        std::fs::write(&fixture.path, &signed).unwrap();
        let reader = VerificationReader {
            file: &file,
            fail_read: 0,
            fail_seek: 0,
            resize_on_rewind: Some(new_size),
            reads: 0,
            seeks: 0,
        };
        assert_eq!(
            verify_reader(reader, &file, target, &fixture.key.verifying_key()).unwrap_err(),
            expected
        );
    }
}

#[test]
fn digest_read_failure_never_returns_a_partial_digest() {
    struct FailingReader;
    impl Read for FailingReader {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("injected read failure"))
        }
    }
    let reader = std::io::Cursor::new(b"partial payload").chain(FailingReader);
    assert_eq!(digest_reader(reader).unwrap_err(), "injected read failure");
}

#[test]
fn public_key_errors_are_fixed_and_do_not_echo_invalid_key_material() {
    for pem in [
        "",
        "not a key",
        "-----BEGIN PRIVATE KEY-----\nprivate material\n-----END PRIVATE KEY-----",
    ] {
        assert_eq!(
            public_key(pem).unwrap_err(),
            "The embedded update public key is invalid."
        );
    }
    assert!(!public_key(PUBLIC_KEY_PEM).unwrap().is_weak());
}
