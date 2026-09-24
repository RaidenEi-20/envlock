use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "envlock",
    author = "Efe Tan",
    version = "0.1.0",
    about = "Secure environment variable manager with RAM caching daemon",
    // Hiçbir komut girilmediğinde varsayılan olarak yardım menüsünü basar:
    arg_required_else_help = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize a new envlock vault
    Init,

    /// Unlock session and cache master password in RAM
    Unlock,

    /// Lock session and clear cached master password
    Lock,

    /// Set an environment variable (e.g. KEY=VALUE)
    Set {
        /// Key-value pair in KEY=VALUE format
        pair: String,
    },

    /// List stored environment variables for the current path
    List,

    /// Delete a variable by key
    Delete {
        /// Key name to delete
        key: String,
    },

    /// Run a command with injected environment variables
    Run {
        /// Command and arguments to run after '--'
        #[arg(raw = true)]
        args: Vec<String>,
    },

    /// Export environment variables in various formats (env, shell, json)
    Export {
        /// Output format (env, shell, json)
        #[arg(long, default_value = "env")]
        format: String,
    },
}

