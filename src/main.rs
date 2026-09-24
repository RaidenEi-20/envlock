mod cli;
mod crypto;
mod vault;

use anyhow::{anyhow, Result};
use clap::Parser;
use cli::{Cli, Commands};
use crypto::{decrypt, derive_key, encrypt, generate_random_bytes, NONCE_LEN, SALT_LEN};
use std::collections::HashMap;
use std::env;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use vault::{EncryptedVault, VaultData};

fn get_vault_path() -> Result<PathBuf> {
    let proj_dirs = directories::ProjectDirs::from("", "", "envlock")
        .ok_or_else(|| anyhow!("Failed to determine config directory"))?;
    let config_dir = proj_dirs.config_dir();
    fs::create_dir_all(config_dir)?;
    Ok(config_dir.join("vault.envlock"))
}

fn get_socket_path() -> Result<PathBuf> {
    let proj_dirs = directories::ProjectDirs::from("", "", "envlock")
        .ok_or_else(|| anyhow!("Failed to determine config directory"))?;
    Ok(proj_dirs.config_dir().join("envlockd.sock"))
}

fn try_get_cached_password() -> Option<String> {
    let socket_path = get_socket_path().ok()?;
    if !socket_path.exists() {
        return None;
    }

    let mut stream = UnixStream::connect(socket_path).ok()?;
    stream.write_all(b"GET_PASS").ok()?;

    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;

    if response.is_empty() {
        None
    } else {
        Some(response)
    }
}

fn stop_daemon() -> Result<()> {
    let socket_path = get_socket_path()?;
    if socket_path.exists() {
        fs::remove_file(&socket_path)?;
        println!("Session locked! Cached password cleared from RAM.");
    } else {
        println!("No active session found.");
    }
    Ok(())
}

fn start_daemon(password: String) -> Result<()> {
    let socket_path = get_socket_path()?;
    if socket_path.exists() {
        let _ = fs::remove_file(&socket_path);
    }

    let listener = UnixListener::bind(&socket_path)?;
    println!("Session unlocked! Password cached in RAM until system reboot or manual lock.");

    // Timeout (zaman aşımı) kaldırıldı; sadece kapanana/reboot veya lock edilene kadar kalır
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let mut buf = [0u8; 8];
                if let Ok(n) = stream.read(&mut buf) {
                    if &buf[..n] == b"GET_PASS" {
                        let _ = stream.write_all(password.as_bytes());
                    }
                }
            }
            Err(_) => break,
        }
    }

    Ok(())
}

fn get_password() -> Result<String> {
    if let Some(cached_pass) = try_get_cached_password() {
        return Ok(cached_pass);
    }
    rpassword::prompt_password("Enter Master Password: ").map_err(|e| anyhow!(e))
}

fn read_vault(password: &str) -> Result<(VaultData, Vec<u8>)> {
    let vault_path = get_vault_path()?;
    if !vault_path.exists() {
        return Err(anyhow!("Vault not initialized. Run 'envlock init' first."));
    }

    let mut file = File::open(vault_path)?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;

    let encrypted: EncryptedVault = bincode::deserialize(&contents)
        .map_err(|_| anyhow!("Failed to parse vault file. Corrupted data?"))?;

    let key = derive_key(password, &encrypted.salt)?;
    let decrypted_bytes = decrypt(&encrypted.ciphertext, &key, &encrypted.nonce)?;
    let vault_data: VaultData = bincode::deserialize(&decrypted_bytes)
        .map_err(|_| anyhow!("Decryption failed. Wrong password or corrupted vault."))?;

    Ok((vault_data, encrypted.salt))
}

fn write_vault(vault_data: &VaultData, password: &str, salt: Option<Vec<u8>>) -> Result<()> {
    let salt = salt.unwrap_or_else(|| generate_random_bytes(SALT_LEN));
    let nonce = generate_random_bytes(NONCE_LEN);
    let key = derive_key(password, &salt)?;

    let serialized_data = bincode::serialize(vault_data)?;
    let ciphertext = encrypt(&serialized_data, &key, &nonce)?;

    let encrypted_vault = EncryptedVault {
        salt,
        nonce,
        ciphertext,
    };

    let serialized_vault = bincode::serialize(&encrypted_vault)?;
    let vault_path = get_vault_path()?;
    let mut file = File::create(vault_path)?;
    file.write_all(&serialized_vault)?;

    Ok(())
}

fn get_current_dir_string() -> Result<String> {
    let p = env::current_dir()?;
    Ok(p.to_string_lossy().to_string())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Init) => {
            let vault_path = get_vault_path()?;
            if vault_path.exists() {
                println!("Vault already exists at {:?}", vault_path);
                return Ok(());
            }

            let p1 = rpassword::prompt_password("Create Master Password: ")?;
            let p2 = rpassword::prompt_password("Confirm Master Password: ")?;

            if p1 != p2 {
                return Err(anyhow!("Passwords do not match!"));
            }

            let empty_vault = VaultData {
                store: HashMap::new(),
            };
            write_vault(&empty_vault, &p1, None)?;
            println!("Vault successfully initialized at {:?}", vault_path);
        }

        Some(Commands::Unlock) => {
            let password = rpassword::prompt_password("Enter Master Password to unlock session: ")?;
            let _ = read_vault(&password)?;

            if unsafe { libc::fork() } == 0 {
                let _ = start_daemon(password);
                std::process::exit(0);
            }
        }

        Some(Commands::Lock) => {
            stop_daemon()?;
        }

        Some(Commands::Set { pair }) => {
            let parts: Vec<&str> = pair.splitn(2, '=').collect();
            if parts.len() != 2 {
                return Err(anyhow!("Invalid format. Expected KEY=VALUE"));
            }
            let key = parts[0].trim();
            let val = parts[1].trim();

            let password = get_password()?;
            let (mut vault_data, salt) = read_vault(&password)?;
            let current_dir = get_current_dir_string()?;

            vault_data
                .store
                .entry(current_dir.clone())
                .or_insert_with(HashMap::new)
                .insert(key.to_string(), val.to_string());

            write_vault(&vault_data, &password, Some(salt))?;
            println!("Saved '{}' for path [{}]", key, current_dir);
        }

        Some(Commands::Delete { key }) => {
            let password = get_password()?;
            let (mut vault_data, salt) = read_vault(&password)?;
            let current_dir = get_current_dir_string()?;

            let mut removed = false;
            if let Some(env_map) = vault_data.store.get_mut(&current_dir) {
                if env_map.remove(&key).is_some() {
                    removed = true;
                }
            }

            if removed {
                write_vault(&vault_data, &password, Some(salt))?;
                println!("Deleted '{}' from path [{}]", key, current_dir);
            } else {
                println!("Key '{}' not found in path [{}]", key, current_dir);
            }
        }

        Some(Commands::List) => {
            let password = get_password()?;
            let (vault_data, _) = read_vault(&password)?;
            let current_dir = get_current_dir_string()?;

            if let Some(env_map) = vault_data.store.get(&current_dir) {
                println!("Stored variables for [{}]:", current_dir);
                for (k, v) in env_map {
                    println!("  {} = {}", k, v);
                }
            } else {
                println!("No variables stored for path [{}]", current_dir);
            }
        }

        Some(Commands::Export { format }) => {
            let password = get_password()?;
            let (vault_data, _) = read_vault(&password)?;
            let current_dir = get_current_dir_string()?;

            if let Some(env_map) = vault_data.store.get(&current_dir) {
                for (k, v) in env_map {
                    if format == "shell" {
                        println!("export {}=\"{}\"", k, v);
                    } else {
                        println!("{}={}", k, v);
                    }
                }
            } else {
                eprintln!("No variables stored for path [{}]", current_dir);
            }
        }

        Some(Commands::Run { args }) => {
            if args.is_empty() {
                return Err(anyhow!("No command specified to run."));
            }

            let password = get_password()?;
            let (vault_data, _) = read_vault(&password)?;
            let current_dir = get_current_dir_string()?;

            let mut command = Command::new(&args[0]);
            if args.len() > 1 {
                command.args(&args[1..]);
            }

            if let Some(env_map) = vault_data.store.get(&current_dir) {
                for (k, v) in env_map {
                    command.env(k, v);
                }
            }

            let err = command.exec();
            return Err(anyhow!("Failed to execute command: {}", err));
        }

        None => {}
    }

    Ok(())
}

