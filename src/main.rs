mod commands;
mod config;
mod credentials;
mod crypto;
mod discovery;
mod error;
mod github;
mod manifest;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "latch",
    version,
    about = "Encrypted .env secrets manager backed by a private GitHub repository"
)]
struct Cli {
    /// Increase logging verbosity (use -v for info, -vv for debug).
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialise Latch for the current project (interactive).
    Init,

    /// Encrypt and push all .env files to the remote secrets repo.
    Save {
        /// Target environment name (e.g. dev, staging, prod).
        #[arg(long, short, default_value = "dev")]
        env: String,
    },

    /// Pull and decrypt .env files from the remote secrets repo.
    Export {
        /// Source environment name.
        #[arg(long, short, default_value = "dev")]
        env: String,

        /// Preview what would be written without touching the filesystem.
        #[arg(long)]
        dry_run: bool,
    },

    /// Show sync status (local vs remote) for each tracked .env file.
    Status {
        #[arg(long, short, default_value = "dev")]
        env: String,
    },

    /// Rotate the encryption key: re-encrypt every secret with a new key.
    Rotate,

    /// Run a subprocess with decrypted secrets injected into its environment.
    /// Secrets never touch the filesystem.
    ///
    /// Example: latch run --env prod -- node server.js
    Run {
        /// Environment whose secrets to inject.
        #[arg(long, short, default_value = "dev")]
        env: String,

        /// The program to execute.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },

    /// Set or rotate the encryption key for a specific environment (multi-key).
    Key {
        /// If set, the key applies only to this environment.
        /// Omit to update the default project-wide key.
        #[arg(long, short)]
        env: Option<String>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Initialise tracing
    let level = match cli.verbose {
        0 => tracing::Level::WARN,
        1 => tracing::Level::INFO,
        _ => tracing::Level::DEBUG,
    };
    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_target(false)
        .init();

    match cli.command {
        Commands::Init => commands::init::run().await,
        Commands::Save { env } => commands::save::run(&env).await,
        Commands::Export { env, dry_run } => commands::export::run(&env, dry_run).await,
        Commands::Status { env } => commands::status::run(&env).await,
        Commands::Rotate => commands::rotate::run().await,
        Commands::Run { env, command } => {
            if command.is_empty() {
                anyhow::bail!(
                    "No command specified. Usage: latch run --env <env> -- <program> [args…]"
                );
            }
            commands::run::run(&env, &command[0], &command[1..].to_vec()).await
        }
        Commands::Key { env } => commands::key::run(env.as_deref()).await,
    }
}
