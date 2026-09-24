🔒 envlock

envlock is a zero-file, high-security environment variable manager built for Arch Linux and Unix-like systems. It keeps your sensitive secrets (API keys, database credentials) encrypted on disk using Argon2id + AES-256-GCM and injects them directly into application memory without ever creating plain-text .env files.
🌟 Features

    Zero-File Footprint: Eliminates .env files completely. Secrets are injected directly into child processes via RAM.

    Strong Encryption: Uses Argon2id for key derivation and AES-256-GCM for payload encryption.

    Reboot-Persistent Session Daemon: Enter your Master Password once with envlock unlock. The session stays cached in RAM via a background Unix socket daemon until system reboot or manual lock (envlock lock).

    Path-Aware Secrets: Stores secrets scoped to your project paths (/home/user/projects/api vs /home/user/projects/web).

    Modern CLI (clap-v4): Fully modular CLI interface with helpful usage menus and flag handling.

🚀 Installation
Option 1: From AUR (Arch User Repository)

If you are using Arch Linux, install envlock using your favorite AUR helper:

yay -S envlock
Option 2: Build from Source

Ensure you have Rust and Cargo installed:

git clone https://github.com/RaidenEi-20/envlock
cd envlock
cargo install --path .
🛠️ Quick Start & Workflow
1. Initialize Your Vault

Create your secure vault once:
envlock init
2. Unlock Session

Unlock your vault once per boot session:
envlock unlock

Your key is cached securely in RAM. Subsequent set, list, run, and export commands won't prompt for a password until you reboot or run envlock lock.
3. Add Environment Variables

Add secrets specifically for your current directory:
cd ~/projects/my-app
envlock set DB_PASS=super_secret_123
envlock set API_KEY=sk_live_xyz987
4. Run Applications Safely

Inject variables directly into your running application process:
envlock run -- npm start
or
envlock run -- python main.py
5. Export for Current Shell Session

Export stored variables formatted for your shell:
eval "$(envlock export --format shell)"
6. Lock Session

Clear cached credentials from RAM manually whenever needed:
envlock lock
🔒 Security Architecture

    Vault File (~/.config/envlock/vault.envlock): Serialized with bincode and encrypted using AES-256-GCM.

    Key Derivation: Master Password + Random Salt -> Argon2id Key Generation.

    Daemon Socket (~/.config/envlock/envlockd.sock): Listens on local Unix Domain Socket for ephemeral password sharing between envlock commands in memory.
