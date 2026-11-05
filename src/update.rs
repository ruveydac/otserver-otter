//! Embedded release signatures. Installation and persistent rollback state belong to the updater.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey, pkcs8::DecodePublicKey};
use semver::Version;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

pub const PUBLIC_KEY_PEM: &str = include_str!("../otter-update-public.pem");
pub const BUILD_TARGET: &str = env!("OTTER_BUILD_TARGET");
const RELEASE_TARGETS: [&str; 3] = [
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-pc-windows-msvc",
];
const MAX_PAYLOAD_BYTES: u64 = 512 * 1024 * 1024;

// A fixed EOF record avoids trusting offsets or lengths supplied by an unsigned file.
const MAGIC: &[u8; 16] = b"OTTER-SIGNED-v1\0";
const MESSAGE_LEN: usize = 248;
const TRAILER_LEN: usize = MESSAGE_LEN + 64;

/// Executable content and release metadata authenticated with the embedded release key.
#[derive(Debug)]
pub struct VerifiedBinary {
    version: String,
    target: String,
}

impl VerifiedBinary {
    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn target(&self) -> &str {
        &self.target
    }

    /// Supply a locally trusted version, never a floor received from the update server.
    pub fn require_newer_than(&self, version: &str) -> Result<(), String> {
        if !release_version(self.version())?
            .cmp_precedence(&release_version(version)?)
            .is_gt()
        {
            return Err("Update version is not newer than the trusted local version.".into());
        }
        Ok(())
    }
}

/// Authenticates an executable without sidecar files or executing it. Use BUILD_TARGET for updates.
/// The caller must keep the verified staging file private and unchanged until installation.
pub fn verify_binary(path: &Path, target: &str) -> Result<VerifiedBinary, String> {
    let mut file = File::open(path).map_err(|error| error.to_string())?;
    verify_with_key(&mut file, target, &public_key(PUBLIC_KEY_PEM)?)
}

fn verify_with_key(
    file: &mut File,
    target: &str,
    key: &VerifyingKey,
) -> Result<VerifiedBinary, String> {
    verify_reader(&*file, file, target, key)
}

fn verify_reader(
    mut reader: impl Read + Seek,
    file: &File,
    target: &str,
    key: &VerifyingKey,
) -> Result<VerifiedBinary, String> {
    let file_size = binary_size(file)?;
    if file_size <= TRAILER_LEN as u64 {
        return Err("Executable has no embedded Otter signature.".into());
    }
    let payload_size = file_size - TRAILER_LEN as u64;
    reader
        .seek(SeekFrom::Start(payload_size))
        .map_err(|error| error.to_string())?;
    let mut trailer = [0; TRAILER_LEN];
    reader
        .read_exact(&mut trailer)
        .map_err(|error| error.to_string())?;
    if &trailer[..16] != MAGIC {
        return Err("Executable has no supported embedded Otter signature.".into());
    }
    let mut signature = [0; 64];
    signature.copy_from_slice(&trailer[MESSAGE_LEN..]);
    let signature = Signature::from_bytes(&signature);
    key.verify_strict(&trailer[..MESSAGE_LEN], &signature)
        .map_err(|_| "Embedded executable signature is invalid.")?;
    if trailer[16..24] != payload_size.to_le_bytes() {
        return Err("Executable length does not match its embedded signature.".into());
    }
    let version = padded_text(&trailer[24..152])?;
    release_version(version)?;
    let signed_target = padded_text(&trailer[152..216])?;
    if signed_target != target || !supported_target(target) {
        return Err("Executable signature does not match the required target.".into());
    }
    reader.rewind().map_err(|error| error.to_string())?;
    let (size, digest) = digest_reader(reader.take(payload_size))?;
    if size != payload_size || digest[..] != trailer[216..MESSAGE_LEN] {
        return Err("Executable SHA-256 does not match its embedded signature.".into());
    }
    if binary_size(file)? != file_size {
        return Err("Executable changed size while being verified.".into());
    }
    Ok(VerifiedBinary {
        version: version.into(),
        target: signed_target.into(),
    })
}

/// Appends and verifies the release signature in disposable CI staging, before packaging.
/// Refuses keys other than the compiled-in release key and already-signed executables.
pub fn embed_binary_signature(
    path: &Path,
    version: &str,
    target: &str,
    key: &SigningKey,
) -> Result<(), String> {
    embed_with_key(path, version, target, key, &public_key(PUBLIC_KEY_PEM)?)
}

fn embed_with_key(
    path: &Path,
    version: &str,
    target: &str,
    key: &SigningKey,
    expected_key: &VerifyingKey,
) -> Result<(), String> {
    if key.verifying_key() != *expected_key {
        return Err("The signing secret does not match otter-update-public.pem.".into());
    }
    release_version(version)?;
    if !supported_target(target) {
        return Err("Unsupported executable signing target.".into());
    }
    let mut file = File::options()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|error| error.to_string())?;
    let payload_size = binary_size(&file)?;
    if payload_size > MAX_PAYLOAD_BYTES - TRAILER_LEN as u64 {
        return Err("Executable leaves no room for its embedded signature within 512 MiB.".into());
    }
    if payload_size >= TRAILER_LEN as u64 {
        file.seek(SeekFrom::Start(payload_size - TRAILER_LEN as u64))
            .map_err(|error| error.to_string())?;
        let mut magic = [0; 16];
        file.read_exact(&mut magic)
            .map_err(|error| error.to_string())?;
        if &magic == MAGIC {
            return Err("Executable already has an embedded Otter signature.".into());
        }
    }
    file.rewind().map_err(|error| error.to_string())?;
    let (size, digest) = digest_reader((&mut file).take(payload_size + 1))?;
    if size != payload_size || binary_size(&file)? != payload_size {
        return Err("Executable changed size while being signed.".into());
    }
    let mut trailer = [0; TRAILER_LEN];
    trailer[..16].copy_from_slice(MAGIC);
    trailer[16..24].copy_from_slice(&payload_size.to_le_bytes());
    trailer[24..24 + version.len()].copy_from_slice(version.as_bytes());
    trailer[152..152 + target.len()].copy_from_slice(target.as_bytes());
    trailer[216..MESSAGE_LEN].copy_from_slice(&digest);
    let signature = key.sign(&trailer[..MESSAGE_LEN]);
    trailer[MESSAGE_LEN..].copy_from_slice(&signature.to_bytes());
    file.write_all(&trailer)
        .and_then(|()| file.sync_all())
        .map_err(|error| error.to_string())?;
    verify_with_key(&mut file, target, &key.verifying_key())?;
    Ok(())
}

fn binary_size(file: &File) -> Result<u64, String> {
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_PAYLOAD_BYTES {
        return Err("Executable must be a regular file between 1 byte and 512 MiB.".into());
    }
    Ok(metadata.len())
}

fn supported_target(target: &str) -> bool {
    RELEASE_TARGETS.contains(&target)
}

fn padded_text(bytes: &[u8]) -> Result<&str, String> {
    std::str::from_utf8(bytes)
        .map(|text| text.trim_end_matches('\0'))
        .map_err(|_| "Invalid text in executable signature.".into())
}

fn public_key(pem: &str) -> Result<VerifyingKey, String> {
    VerifyingKey::from_public_key_pem(pem)
        .map_err(|_| "The embedded update public key is invalid.".into())
}

fn digest_reader(mut reader: impl Read) -> Result<(u64, sha2::digest::Output<Sha256>), String> {
    let mut digest = Sha256::new();
    let mut size = 0;
    let mut buffer = [0; 64 * 1024];
    loop {
        let length = reader
            .read(&mut buffer)
            .map_err(|error| error.to_string())?;
        if length == 0 {
            break;
        }
        size += length as u64;
        digest.update(&buffer[..length]);
    }
    Ok((size, digest.finalize()))
}

fn release_version(version: &str) -> Result<Version, String> {
    if version.len() > 128 {
        return Err("Update version exceeds 128 bytes.".into());
    }
    let version = version.strip_prefix('v').unwrap_or(version);
    let core_end = version.find(['-', '+']).unwrap_or(version.len());
    let core = &version[..core_end];
    // Existing release tags include v0.13; compare them as 0.13.0.
    let normalized = if core.split('.').count() == 2 {
        format!("{core}.0{}", &version[core_end..])
    } else {
        version.to_string()
    };
    Version::parse(&normalized).map_err(|_| "Invalid update version; expected [v]MAJOR.MINOR[.PATCH] with optional SemVer prerelease/build metadata.".into())
}

#[cfg(test)]
mod tests;
