use anyhow::Result;
use keyvault_agent_azure_key_vault_keys::models::KeyVaultKey;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::ErrorKind as IoErrorKind;
use std::path::PathBuf;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Credential {
    AzureSdk,
    ManagedService,
    Application(ApplicationCredential),
    UserPassword(UserPasswordCredential),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ApplicationCredential {
    pub client_id: String,
    pub client_secret: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct UserPasswordCredential {
    pub username: String,
    pub password: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct KeyConfig {
    pub key_uri: String,
    pub comment: Option<String>,
    pub key_vault_key: KeyVaultKey,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct KeyVaultSshAgentConfig {
    #[serde(default = "default_credentials")]
    pub credentials: Credential,
    pub keys: Vec<KeyConfig>,
}

fn default_credentials() -> Credential {
    Credential::AzureSdk
}

impl KeyVaultSshAgentConfig {
    pub fn new() -> KeyVaultSshAgentConfig {
        KeyVaultSshAgentConfig {
            credentials: Credential::AzureSdk,
            keys: Vec::new(),
        }
    }

    pub fn load(config_path: PathBuf) -> Result<KeyVaultSshAgentConfig> {
        match OpenOptions::new().read(true).open(&config_path) {
            Ok(file) => Ok(serde_yaml::from_reader(file)?),
            Err(err) => match err.kind() {
                IoErrorKind::NotFound => Ok(KeyVaultSshAgentConfig::new()),
                _ => Err(err.into()),
            },
        }
    }

    pub fn save(&self, config_path: PathBuf) -> Result<()> {
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&config_path)?;
        serde_yaml::to_writer(file, &self).map_err(|e| e.into())
    }
}
