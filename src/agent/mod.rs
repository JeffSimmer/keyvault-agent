use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use ssh_agent::agent::Agent;
use ssh_agent::proto::message::{Message, SignRequest};
use ssh_agent::proto::public_key::PublicKey;
use ssh_agent::proto::signature::{self, Signature};
use ssh_agent::proto::{
    from_bytes, to_bytes, EcDsaPublicKey, EcDsaSignature, EcDsaSignatureData, Identity,
};

use openssl::hash::{hash, MessageDigest};

use crate::config::*;
use crate::key_client::AgentKeyClient;
use crate::util::*;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct KeyVaultIdentity {
    pub public_key: PublicKey,
    pub key_uri: String,
    pub comment: String,
}

pub struct KeyVaultSshAgent {
    client: AgentKeyClient,
    identities: Vec<KeyVaultIdentity>,
    //config: KeyVaultSshAgentConfig,
}

impl KeyVaultSshAgent {
    pub fn new(config: KeyVaultSshAgentConfig) -> Result<KeyVaultSshAgent> {
        let client = AgentKeyClient::new(config.credentials)?;

        let mut identities: Vec<KeyVaultIdentity> = Vec::new();
        for key_config in &config.keys {
            let key = client.get_key(&key_config.key_uri)?.key.key;

            identities.push(KeyVaultIdentity {
                key_uri: key_config.key_uri.clone(),
                comment: key_config
                    .comment
                    .clone()
                    .unwrap_or_else(|| key_config.key_uri.clone()),
                public_key: key_vault_key_to_public_key(key)?,
            });
        }
        Ok(KeyVaultSshAgent {
            client,
            identities,
            //config,
        })
    }

    fn identity_from_public_key(&self, public_key: &PublicKey) -> Option<&KeyVaultIdentity> {
        self.identities.iter().find(|i| public_key == &i.public_key)
    }

    fn sign(&self, request: SignRequest) -> Result<Signature> {
        let public_key: PublicKey = from_bytes(&request.pubkey_blob)?;
        let identity = self
            .identity_from_public_key(&public_key)
            .ok_or_else(|| anyhow!("Key not found"))?;

        match public_key {
            PublicKey::Rsa(_) => self.sign_rsa(request, &identity),
            PublicKey::EcDsa(public_key) => self.sign_ecdsa(request, &identity, public_key),
            _ => bail!("Unsupported key type"),
        }
    }

    fn sign_ecdsa(
        &self,
        request: SignRequest,
        identity: &KeyVaultIdentity,
        public_key: EcDsaPublicKey,
    ) -> Result<Signature> {
        let data = request.data;

        let (digest, kv_alg) = match public_key.identifier.as_str() {
            "nistp256" => (hash(MessageDigest::sha256(), &data)?, "ES256"),
            "nistp384" => (hash(MessageDigest::sha384(), &data)?, "ES384"),
            "nistp521" => (hash(MessageDigest::sha512(), &data)?, "ES512"),
            _ => bail!("Unsupported key type"),
        };

        let sig: Vec<u8> = self
            .client
            .sign_digest(&identity.key_uri, kv_alg, &digest)?;

        let (r, s) = KeyVaultSshAgent::split_ec_sig(&sig)?;

        Ok(Signature::from(EcDsaSignature {
            identifier: public_key.identifier,
            data: EcDsaSignatureData { r, s },
        }))
    }

    fn split_ec_sig(sig: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        if sig.is_empty() {
            bail!("Unexpected signature length");
        }

        let half_len = sig.len() / 2;
        let pad_r = if sig[0] & 80u8 != 0 { 1 } else { 0 };
        let pad_s = if sig[half_len] & 80u8 != 0 { 1 } else { 0 };
        Ok((
            [&[0u8, pad_r], &sig[..half_len]].concat(),
            [&[0u8, pad_s], &sig[half_len..]].concat(),
        ))
    }

    fn sign_rsa(&self, request: SignRequest, identity: &KeyVaultIdentity) -> Result<Signature> {
        let data = request.data;
        let (digest, kv_alg, ssh_alg) = if (request.flags & signature::RSA_SHA2_512) != 0 {
            (
                hash(MessageDigest::sha512(), &data).unwrap().to_vec(),
                "RS512",
                "rsa-sha2-512",
            )
        } else if (request.flags & signature::RSA_SHA2_256) != 0 {
            (
                hash(MessageDigest::sha256(), &data).unwrap().to_vec(),
                "RS256",
                "rsa-sha2-256",
            )
        } else {
            (
                KeyVaultSshAgent::get_sha1_digest_info(&data),
                "RSNULL",
                "ssh-rsa",
            )
        };

        let result: Vec<u8> = self
            .client
            .sign_digest(&identity.key_uri, kv_alg, &digest)?;

        Ok(Signature {
            algorithm: ssh_alg.to_string(),
            blob: result,
        })
    }

    fn get_sha1_digest_info(data: &[u8]) -> Vec<u8> {
        [
            &[
                0x30u8,
                0x21u8, // SEQUENCE DigestInfo (33 bytes) (13 of header + 20 of SHA1 digest)
                0x30u8, 0x09u8, // SEQUENCE AlgorithmIdentifier (9 bytes)
                0x06u8, 0x05u8, // OBJECT IDENTIFIER algorithm (5 bytes)
                0x2bu8, 0x0eu8, 0x03u8, 0x02u8, 0x1au8, // OID of SHA1 (1.3.14.3.2.26)
                0x05u8,
                0x00u8, // NUL algorithm parameters (05 00 is the DER encoding for NUL)
                0x04u8, 0x14u8, // OCTET STRING digest (20 bytes)
            ],
            &hash(MessageDigest::sha1(), &data).unwrap()[..],
        ]
        .concat()
    }

    fn handle_inner(&self, message: Message) -> Result<Message> {
        match message {
            Message::RequestIdentities => {
                let identity_list = self
                    .identities
                    .iter()
                    .map(|id| Identity {
                        comment: id.comment.clone(),
                        pubkey_blob: to_bytes(&id.public_key).unwrap(),
                    })
                    .collect();

                Ok(Message::IdentitiesAnswer(identity_list))
            }
            Message::SignRequest(request) => {
                let response = self.sign(request).unwrap();
                Ok(Message::SignResponse(to_bytes(&response).unwrap()))
            }
            message => bail!("Unsupported message: {:?}", message),
        }
    }
}

impl Agent for KeyVaultSshAgent {
    type Error = anyhow::Error;

    fn handle(&self, message: Message) -> Result<Message> {
        self.handle_inner(message).or_else(|error| {
            println!("Error handling message - {:?}", error);
            Ok(Message::Failure)
        })
    }
}
