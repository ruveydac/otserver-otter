use std::path::Path;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=OTTER_BUILD_VERSION");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/packed-refs");
    println!("cargo:rerun-if-changed=.git/refs/tags");

    let package_version = std::env::var("CARGO_PKG_VERSION").expect("Cargo package version");
    let build_version = std::env::var("OTTER_BUILD_VERSION")
        .ok()
        .filter(|version| !version.trim().is_empty())
        .or_else(git_tag)
        .unwrap_or_else(|| package_version.clone());
    println!("cargo:rustc-env=OTTER_BUILD_VERSION={build_version}");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let numeric_version = numeric_version(&build_version)
            .or_else(|| numeric_version(&package_version))
            .expect("Cargo package version must contain numeric components");
        let mut resource = winresource::WindowsResource::new();
        resource
            .set("CompanyName", "OTserver")
            .set("FileDescription", "Read-only OT discovery for OTserver")
            .set("FileVersion", &build_version)
            .set("InternalName", "otserver-otter")
            .set("OriginalFilename", "otserver-otter.exe")
            .set("ProductName", "OTserver Otter")
            .set("ProductVersion", &build_version)
            .set_version_info(winresource::VersionInfo::FILEVERSION, numeric_version)
            .set_version_info(winresource::VersionInfo::PRODUCTVERSION, numeric_version)
            .compile()
            .expect("failed to compile Windows executable metadata");
    }
}

fn git_tag() -> Option<String> {
    let repository = std::env::var_os("CARGO_MANIFEST_DIR")?;
    if !Path::new(&repository).join(".git").exists() {
        return None;
    }
    let output = Command::new("git")
        .args(["describe", "--tags", "--abbrev=0"])
        .current_dir(repository)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let tag = String::from_utf8(output.stdout).ok()?;
    let tag = tag.trim();
    (!tag.is_empty()).then(|| tag.to_string())
}

fn numeric_version(version: &str) -> Option<u64> {
    let core = version
        .trim()
        .trim_start_matches(['v', 'V'])
        .split(['-', '+'])
        .next()?;
    let mut components = [0_u16; 4];
    let mut found = false;
    for (index, component) in core.split('.').take(4).enumerate() {
        components[index] = component.parse().ok()?;
        found = true;
    }
    found.then(|| {
        (u64::from(components[0]) << 48)
            | (u64::from(components[1]) << 32)
            | (u64::from(components[2]) << 16)
            | u64::from(components[3])
    })
}
