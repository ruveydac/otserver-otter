use ed25519_dalek::{SigningKey, pkcs8::DecodePrivateKey};
use otserver_otter::update;
use std::path::Path;

fn main() {
    if let Err(error) = run() {
        eprintln!("Release signing failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    let [version, target, file] = arguments.as_slice() else {
        return Err("Usage: sign-update VERSION TARGET EXECUTABLE".into());
    };
    let secret = std::env::var("OTTER_UPDATE_SIGNING_PRIVATE_KEY")
        .map_err(|_| "OTTER_UPDATE_SIGNING_PRIVATE_KEY is required.")?;
    let signing_key = SigningKey::from_pkcs8_pem(&secret)
        .map_err(|_| "The signing secret must be an unencrypted Ed25519 PKCS#8 PEM key.")?;
    update::embed_binary_signature(Path::new(file), version, target, &signing_key)?;
    println!("Embedded and verified executable signature for {version} ({target}).");
    Ok(())
}
