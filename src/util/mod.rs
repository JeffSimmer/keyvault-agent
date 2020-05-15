use anyhow::{anyhow, bail, Result};
use keyvault_agent_azure_key_vault_keys::models::Key;
use ssh_agent::proto::{EcDsaPublicKey, KeyType, PublicKey, RsaPublicKey};
use std::fs::create_dir_all;
use std::io::{stdout, Write};
use std::path::PathBuf;

pub fn key_vault_curve_to_ssh_curve(crv: &str) -> Result<String> {
    Ok(match crv {
        "P-256" => "nistp256",
        "P-384" => "nistp384",
        "P-521" => "nistp521",
        _ => bail!("Unknown curve"),
    }
    .to_string())
}

pub fn key_vault_key_to_public_key(key: Key) -> Result<PublicKey> {
    Ok(match key {
        Key::RsaJsonWebKey(key) => PublicKey::Rsa(RsaPublicKey {
            e: key.e,
            n: [&[0u8], &key.n[..]].concat(),
        }),
        Key::EcJsonWebKey(key) => PublicKey::EcDsa(EcDsaPublicKey {
            identifier: key_vault_curve_to_ssh_curve(key.crv.as_str())?,
            q: key.q(),
        }),
        _ => bail!("Unknown key type"),
    })
}

pub fn get_public_key_type(key: &PublicKey) -> Result<String> {
    match key.clone() {
        PublicKey::Rsa(key) => Ok(key.key_type()),
        PublicKey::EcDsa(key) => Ok(key.key_type()),
        _ => Err(anyhow!("Unknown key type")),
    }
}

pub fn get_socket_path() -> PathBuf {
    // Get socket path and cleanup
    let mut socket_path = dirs::runtime_dir().unwrap_or_else(|| dirs::config_dir().unwrap());
    socket_path.push(crate::AGENT_NAME);
    let _ = create_dir_all(&socket_path);

    socket_path.push(format!("{}.sock", crate::AGENT_NAME));
    socket_path
}

pub fn get_config_path() -> PathBuf {
    // Get config file path and cleanup
    let mut config_path = dirs::config_dir().unwrap();
    config_path.push(crate::AGENT_NAME);
    let _ = create_dir_all(&config_path);

    config_path.push(format!("{}.config", crate::AGENT_NAME));
    config_path
}

pub fn get_pid_path() -> PathBuf {
    // Get config file path and cleanup
    let mut config_path = dirs::runtime_dir().unwrap_or_else(|| dirs::config_dir().unwrap());
    config_path.push(crate::AGENT_NAME);
    let _ = create_dir_all(&config_path);

    config_path.push(format!("{}.pid", crate::AGENT_NAME));
    config_path
}

pub fn prompt_password(prompt: &str) -> Result<String> {
    print!("{}", prompt);
    stdout().flush()?;
    let password = rpassword::read_password()?;
    println!();

    Ok(password)
}
