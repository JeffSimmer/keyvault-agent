# keyvault-agent
An SSH Agent backed by Azure Key Vault keys

* Authenticate to Key Vault using Active Directory credentials, including VM managed identities
* SSH private keys are safeguarded in a vault
* Access to keys can be controlled by AD group membership, enabling just-in-time access via group membership

## Installation
### Linux or Mac OS
```
cargo install keyvault-agent
# Authenticate using a logged in Azure SDK (requires the Azure SDK).
# Other authentication methods are available.
keyvault-agent authenticate azure-sdk
keyvault-agent add-key {key vault key URI}

# Run this line for every new console.
eval $(keyvault-agent daemon)
```

