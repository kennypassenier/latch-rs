mod commands;
mod config;
mod credentials;
mod crypto;
mod discovery;
mod error;
mod github;
mod manifest;

use clap::{Parser, Subcommand};

const BUILD_VERSION: &str = match option_env!("LATCH_BUILD_VERSION") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};

#[derive(Parser)]
#[command(
    name = "latch",
    version = BUILD_VERSION,
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
    /// Securely clone Latch credentials to another machine.
    Clone {
        #[command(subcommand)]
        action: CloneCommands,
    },

    /// Store global GitHub credentials (PAT + default secrets repo) in keyring.
    Login,

    /// Initialise Latch for the current project (interactive).
    Init,

    /// Encrypt and push all .env files to the remote secrets repo.
    Save {
        /// Target environment name (e.g. dev, staging, prod).
        #[arg(long, short, default_value = "dev")]
        env: String,
    },

    /// Pull and decrypt .env files from the remote secrets repo.
    #[command(alias = "export")]
    Load {
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

    /// Manage shell PATH integration for the current Latch binary.
    Path {
        #[command(subcommand)]
        action: PathCommands,
    },

    /// Interactively bind this folder to a remote project.
    Project {
        /// Secrets repo in owner/repo format. If omitted, uses login defaults.
        #[arg(long)]
        repo: Option<String>,
        /// Environment to use; if omitted you can pick interactively.
        #[arg(long, short)]
        env: Option<String>,
        /// List projects in the repo and exit.
        #[arg(long)]
        list: bool,
    },
}

#[derive(Subcommand)]
enum PathCommands {
    /// Install the current Latch binary into a user PATH location.
    Add,
    /// Remove the user-level PATH installation added by Latch.
    #[command(alias = "delete")]
    Remove,
    /// Show PATH installation status for the current machine.
    Status,
}

#[derive(Subcommand)]
enum CloneCommands {
    /// Generate a target-side offer containing an ephemeral public key.
    Offer {
        /// Offer expiry in minutes.
        #[arg(long, default_value_t = 10)]
        ttl_minutes: u64,
    },
    /// Create an encrypted payload from local credentials and an offer.
    Create {
        /// Offer JSON string.
        #[arg(long)]
        offer: Option<String>,
        /// Path to a file containing offer JSON.
        #[arg(long)]
        offer_file: Option<String>,
        /// Write payload JSON to this file (in addition to stdout).
        #[arg(long)]
        stdout_file: Option<String>,
        /// Include only these projects (repeat flag to select multiple).
        #[arg(long = "project")]
        projects: Vec<String>,
        /// Include only these env-specific keys (repeat flag to select multiple).
        #[arg(long = "env")]
        envs: Vec<String>,
        /// Optional one-time verification code to derive an integrity tag.
        #[arg(long)]
        verify_code: Option<String>,
    },
    /// Apply an encrypted payload on the target and restore keyring state.
    Apply {
        /// Payload JSON string.
        #[arg(long)]
        payload: Option<String>,
        /// Path to a file containing payload JSON.
        #[arg(long)]
        payload_file: Option<String>,
        /// Read payload JSON from stdin.
        #[arg(long)]
        stdin: bool,
        /// Optional one-time verification code used to verify payload integrity.
        #[arg(long)]
        verify_code: Option<String>,
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
        Commands::Clone { action } => match action {
            CloneCommands::Offer { ttl_minutes } => commands::clone::offer(ttl_minutes).await,
            CloneCommands::Create {
                offer,
                offer_file,
                stdout_file,
                projects,
                envs,
                verify_code,
            } => {
                commands::clone::create(
                    offer.as_deref(),
                    offer_file.as_deref(),
                    stdout_file.as_deref(),
                    &projects,
                    &envs,
                    verify_code.as_deref(),
                )
                .await
            }
            CloneCommands::Apply {
                payload,
                payload_file,
                stdin,
                verify_code,
            } => {
                commands::clone::apply(
                    payload.as_deref(),
                    payload_file.as_deref(),
                    stdin,
                    verify_code.as_deref(),
                )
                .await
            }
        },
        Commands::Login => commands::login::run().await,
        Commands::Init => commands::init::run().await,
        Commands::Save { env } => commands::save::run(&env).await,
        Commands::Load { env, dry_run } => commands::export::run(&env, dry_run).await,
        Commands::Status { env } => commands::status::run(&env).await,
        Commands::Rotate => commands::rotate::run().await,
        Commands::Run { env, command } => {
            if command.is_empty() {
                anyhow::bail!(
                    "No command specified. Usage: latch run --env <env> -- <program> [args…]"
                );
            }
            commands::run::run(&env, &command[0], &command[1..]).await
        }
        Commands::Key { env } => commands::key::run(env.as_deref()).await,
        Commands::Path { action } => match action {
            PathCommands::Add => commands::path::add().await,
            PathCommands::Remove => commands::path::remove().await,
            PathCommands::Status => commands::path::status().await,
        },
        Commands::Project { repo, env, list } => {
            if list {
                commands::project::list(repo.as_deref()).await
            } else {
                commands::project::run(repo.as_deref(), env.as_deref()).await
            }
        }
    }
}
