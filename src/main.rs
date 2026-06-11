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

    /// Store global credentials (PAT + KEY + default secrets repo).
    Login {
        /// GitHub PAT. Supports --PAT and --pat.
        #[arg(long = "PAT", alias = "pat")]
        pat: Option<String>,
        /// Global encryption key. Supports --KEY and --key.
        #[arg(long = "KEY", alias = "key")]
        key: Option<String>,
        /// Default secrets repo. Supports --REPO and --repo.
        #[arg(long = "REPO", alias = "repo")]
        repo: Option<String>,
    },

    /// Initialise Latch for the current project (interactive).
    Init,

    /// Encrypt and stage .env files locally in `.latch/` (no network needed).
    ///
    /// After committing, run `latch push` to upload to GitHub.
    #[command(alias = "lock")]
    Commit {
        /// Target environment name (e.g. dev, staging, prod).
        #[arg(long, short, default_value = "dev")]
        env: String,
    },

    /// Upload staged encrypted files from `.latch/` to the remote secrets repo.
    ///
    /// Requires `latch commit` to have been run first. No encryption key needed.
    #[command(alias = "save")]
    Push {
        /// Target environment name (e.g. dev, staging, prod).
        #[arg(long, short, default_value = "dev")]
        env: String,
    },

    /// Pull and decrypt .env files from the remote secrets repo.
    ///
    /// Also caches encrypted blobs to `.latch/` for offline `commit` support.
    #[command(alias = "load", alias = "unlock", alias = "export")]
    Pull {
        /// Source environment name.
        #[arg(long, short, default_value = "dev")]
        env: String,

        /// Preview what would be written without touching the filesystem.
        #[arg(long)]
        dry_run: bool,

        /// Only write files whose parent directory already exists.
        #[arg(long)]
        sparse: bool,

        /// Optional pull mode alias, e.g. `latch pull sparse`.
        #[arg(value_enum)]
        mode: Option<PullMode>,
    },

    /// Show sync status (local vs remote) for each tracked .env file.
    Status {
        #[arg(long, short, default_value = "dev")]
        env: String,
    },

    /// Rotate the encryption key: re-encrypt every secret with a new key.
    Rotate,

    /// Show resolved credential state across env, keyring, and config sources.
    State {
        /// Environment label used when checking env-specific keyring slots.
        #[arg(long, short, default_value = "dev")]
        env: String,
    },

    /// Reset Latch credentials/caches while keeping project .latch/config.toml metadata.
    Reset,

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

    /// List or inspect clone groups for an environment.
    Group {
        #[command(subcommand)]
        action: GroupCommands,
    },

    /// Show save history for the current project.
    History {
        /// Environment name (informational only; history is per-project).
        #[arg(long, short, default_value = "dev")]
        env: String,

        /// Number of commits to show.
        #[arg(long, default_value_t = 10)]
        limit: usize,
    },

    /// Roll back an environment to a previous save state.
    ///
    /// Creates a new forward commit; history is never rewritten.
    Rollback {
        /// Environment to roll back.
        #[arg(long, short, default_value = "dev")]
        env: String,

        /// Roll back this many commits (default: 1 = one step back).
        #[arg(long, default_value_t = 1, conflicts_with = "to")]
        steps: usize,

        /// Roll back to this exact commit SHA.
        #[arg(long, conflicts_with = "steps")]
        to: Option<String>,
    },

    /// Download and install the latest Latch release binary.
    Update,
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
enum GroupCommands {
    /// List all clone groups for an environment.
    List {
        /// Environment name.
        #[arg(long, short, default_value = "dev")]
        env: String,
    },
    /// Show details (member paths) of a specific clone group.
    Show {
        /// Group name.
        name: String,
        /// Environment name.
        #[arg(long, short, default_value = "dev")]
        env: String,
    },
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
        /// Read offer JSON from stdin.
        #[arg(long)]
        offer_stdin: bool,
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

#[derive(clap::ValueEnum, Clone)]
enum PullMode {
    /// Only write files whose parent directory already exists.
    Sparse,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Compatibility: treat legacy single-dash long flags as proper clap longs.
    let normalized_args: Vec<String> = std::env::args()
        .map(|arg| match arg.as_str() {
            "-PAT" => "--PAT".to_string(),
            "-KEY" => "--KEY".to_string(),
            "-REPO" => "--REPO".to_string(),
            _ => arg,
        })
        .collect();
    let cli = Cli::parse_from(normalized_args);

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
                offer_stdin,
                stdout_file,
                projects,
                envs,
                verify_code,
            } => {
                commands::clone::create(
                    offer.as_deref(),
                    offer_file.as_deref(),
                    offer_stdin,
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
        Commands::Login { pat, key, repo } => {
            commands::login::run(commands::login::LoginArgs { pat, key, repo }).await
        }
        Commands::Init => commands::init::run().await,
        Commands::Commit { env } => commands::commit::run(&env).await,
        Commands::Push { env } => commands::push::run(&env).await,
        Commands::Pull {
            env,
            dry_run,
            sparse,
            mode,
        } => {
            let sparse_mode = sparse || matches!(mode, Some(PullMode::Sparse));
            commands::pull::run(&env, dry_run, sparse_mode).await
        }
        Commands::Status { env } => commands::status::run(&env).await,
        Commands::Rotate => commands::rotate::run().await,
        Commands::State { env } => commands::state::run(&env).await,
        Commands::Reset => commands::reset::run().await,
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
        Commands::Group { action } => match action {
            GroupCommands::List { env } => commands::group::run_list(&env).await,
            GroupCommands::Show { name, env } => commands::group::run_show(&env, &name).await,
        },
        Commands::History { env, limit } => commands::history::run(&env, limit).await,
        Commands::Rollback { env, steps, to } => {
            commands::rollback::run(&env, to.as_deref(), steps).await
        }
        Commands::Update => commands::update::run().await,
    }
}
