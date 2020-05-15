use crate::config::Credential;
use anyhow::{anyhow, Result};
use keyvault_agent_azure_auth::{
    ApplicationCredential, Credential as KvCredential, UserPasswordCredential,
};
use keyvault_agent_azure_key_vault_keys::models::KeyVaultKey;
use keyvault_agent_azure_key_vault_keys::KeyClient;
use std::sync::Mutex;
use tokio::runtime::Runtime;

pub struct AgentKeyClient {
    runtime: Mutex<Runtime>,
    client: KeyClient,
}

impl AgentKeyClient {
    pub fn new(credential: Credential) -> Result<AgentKeyClient> {
        let runtime = Mutex::new(Runtime::new()?);

        let credential = match credential {
            Credential::Application(credential) => {
                KvCredential::Application(ApplicationCredential {
                    client_id: credential.client_id,
                    client_secret: credential.client_secret,
                })
            }
            Credential::UserPassword(credential) => {
                KvCredential::UserPassword(UserPasswordCredential {
                    // Using the Azure PowerShell client ID to avoid the need to register an application in the tenant.
                    client_id: "1950a258-227b-4e31-a9cf-717495945fc2".to_string(),
                    username: credential.username,
                    password: credential.password,
                })
            }
            Credential::AzureSdk => KvCredential::AzureSdk,
            Credential::ManagedService => KvCredential::ManagedService,
        };

        let client = KeyClient::new(credential);

        Ok(AgentKeyClient { runtime, client })
    }

    pub fn get_key(&self, key_uri: &str) -> Result<KeyVaultKey> {
        match self.runtime.lock() {
            Ok(mut runtime) => runtime.block_on(async { Ok(self.client.get_key(&key_uri).await?) }),
            Err(_) => Err(anyhow!("Failed to obtain runtime lock")),
        }
    }

    pub fn sign_digest(&self, key_name: &str, alg: &str, value: &[u8]) -> Result<Vec<u8>> {
        match self.runtime.lock() {
            Ok(mut runtime) => runtime.block_on(async move {
                Ok(self.client.sign_digest(key_name, alg, value).await?.value)
            }),
            Err(_) => Err(anyhow!("Failed to obtain runtime lock")),
        }
    }
}
