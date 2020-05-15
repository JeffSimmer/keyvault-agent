use anyhow::{anyhow, Result};
use base64::encode;
use clap::{AppSettings, Clap};
use colored::*;
use daemonize::{Daemonize, DaemonizeError};
use nix::{
    errno::Errno,
    sys::signal::{kill, SIGTERM},
    unistd::Pid,
};
use ssh_agent::proto::to_bytes;
use ssh_agent::Agent;
use std::error::Error;
use std::fs::{read_to_string, remove_file};

use crate::agent::KeyVaultSshAgent;
use crate::config::*;
use crate::key_client::AgentKeyClient;
use crate::util::{get_public_key_type, key_vault_key_to_public_key};

mod agent;
mod config;
mod key_client;
mod util;

const AGENT_NAME: &str = "keyvault-agent";

#[derive(Clap, Debug, PartialEq)]
#[clap(about, version)]
#[clap(setting = AppSettings::InferSubcommands)]
struct Opts {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Clap, Debug, PartialEq)]
enum Command {
    Daemon(DaemonArgs),
    Server,
    Authenticate(AuthArgs),
    AddKey(AddKeyArgs),
    RemoveKey(RemoveKeyArgs),
    ListKeys(ListKeysArgs),
    GetVariable(VariableArg),
}

#[derive(Clap, Debug, PartialEq)]
enum VariableArg {
    AgentConfigPath,
    AgentPidPath,
    SshAuthSock,
}

#[derive(Clap, Debug, PartialEq)]
struct DaemonArgs {
    #[clap(short, long)]
    restart: bool,
}

#[derive(Clap, Debug, PartialEq)]
struct AddKeyArgs {
    uri: String,
    comment: Option<String>,
}

#[derive(Clap, Debug, PartialEq)]
struct RemoveKeyArgs {
    uri: String,
}

#[derive(Clap, Debug, PartialEq)]
struct ListKeysArgs {}

#[derive(Clap, Debug, PartialEq)]
enum AuthArgs {
    AzureSdk,
    ManagedService,
    Application(ApplicationAuthArgs),
    UserPassword(UserPasswordAuthArgs),
}

#[derive(Clap, Debug, PartialEq)]
struct ApplicationAuthArgs {
    client_id: String,
    client_secret: Option<String>,
}

#[derive(Clap, Debug, PartialEq)]
struct UserPasswordAuthArgs {
    username: String,
    password: Option<String>,
}

fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let config_path = util::get_config_path();
    let mut config = KeyVaultSshAgentConfig::load(config_path.clone())?;

    let opts = Opts::parse();

    match opts.command {
        Command::Daemon(args) => {
            print_variables();
            if args.restart {
                let pid_path = util::get_pid_path();
                let pid: i32 = read_to_string(&pid_path)?.parse()?;
                match kill(Pid::from_raw(pid), SIGTERM) {
                    Ok(()) => Ok(()),
                    Err(nix::Error::Sys(Errno::ESRCH)) => Ok(()),
                    Err(e) => Err(e),
                }?;
                remove_file(pid_path)?;
            }

            match Daemonize::new()
                .pid_file(util::get_pid_path())
                .chown_pid_file(true)
                .start()
            {
                Ok(()) => run_agent(config)?,
                Err(e) => match e {
                    DaemonizeError::LockPidfile(_) => {
                        eprintln!("keyvault-agent already running");
                        return Ok(());
                    }
                    _ => return Err(e.into()),
                },
            }
        }
        Command::Server => {
            print_variables();
            run_agent(config)?;
        }
        Command::AddKey(args) => {
            let client = AgentKeyClient::new(config.credentials.clone())?;

            if config.keys.iter().find(|k| k.key_uri == args.uri) != None {
                return Err(anyhow!("Key already added").into());
            }

            let key = client.get_key(&args.uri)?;
            config.keys.push(KeyConfig {
                key_uri: args.uri,
                comment: args.comment,
                key_vault_key: key,
            });
            config.save(config_path)?;
        }
        Command::RemoveKey(args) => {
            config.keys = config
                .keys
                .into_iter()
                .filter(|key| key.key_uri != args.uri)
                .collect();
            config.save(config_path)?;
        }
        Command::ListKeys(_) => {
            for identity in config.keys {
                println!("{}", &identity.key_uri.bold());
                let public_key =
                    key_vault_key_to_public_key(identity.key_vault_key.key.key.clone())?;
                let key_type = get_public_key_type(&public_key)?;
                println!(
                    "{} {} {}",
                    key_type.dimmed(),
                    encode(to_bytes(&public_key)?).dimmed(),
                    identity.comment.unwrap_or_default().dimmed()
                );
                println!();
            }
        }
        Command::Authenticate(args) => {
            config.credentials = match args {
                AuthArgs::AzureSdk => Credential::AzureSdk,
                AuthArgs::ManagedService => Credential::ManagedService,
                AuthArgs::Application(args) => {
                    match args
                        .client_secret
                        .map_or_else(|| util::prompt_password("Enter application secret: "), Ok)
                    {
                        Ok(client_secret) => Credential::Application(ApplicationCredential {
                            client_id: args.client_id,
                            client_secret,
                        }),
                        Err(e) => return Err(e.into()),
                    }
                }
                AuthArgs::UserPassword(args) => {
                    match args
                        .password
                        .map_or_else(|| util::prompt_password("Enter password: "), Ok)
                    {
                        Ok(password) => Credential::UserPassword(UserPasswordCredential {
                            username: args.username,
                            password,
                        }),
                        Err(e) => return Err(e.into()),
                    }
                }
            };

            config.save(config_path)?;
        }
        Command::GetVariable(arg) => match arg {
            VariableArg::AgentConfigPath => {
                print!("{}", &util::get_config_path().to_string_lossy())
            }
            VariableArg::AgentPidPath => print!("{}", &util::get_pid_path().to_string_lossy()),
            VariableArg::SshAuthSock => print!(
                "{}",
                &util::get_socket_path().into_os_string().to_string_lossy()
            ),
        },
    }

    Ok(())
}

fn print_variables() {
    println!(
        "export KV_AGENT_CONFIG_PATH={}",
        &util::get_config_path().to_string_lossy()
    );
    println!(
        "export KV_AGENT_PID_PATH={}",
        &util::get_pid_path().to_string_lossy()
    );
    println!(
        "export SSH_AUTH_SOCK={}",
        &util::get_socket_path().to_string_lossy()
    );
}

fn run_agent(config: KeyVaultSshAgentConfig) -> Result<(), Box<dyn Error + Send + Sync>> {
    let socket_path = util::get_socket_path();
    let _ = remove_file(&socket_path);

    let agent = KeyVaultSshAgent::new(config)?;
    agent.run_unix(&socket_path)?;

    Ok(())
}
