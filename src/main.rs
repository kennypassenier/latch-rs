use anyhow::{Context, Result};
use clap::{ArgGroup, Parser, Subcommand};
use std::path::PathBuf;

mod commands;
mod config;
mod crypto;
mod error;
mod github;
mod manifest;

use crate::commands::*;
use crate::error::{LatchError, Result as LatchResult};

/// A CLI tool for managing secrets across multiple environments.
#[derive(Parser)]
#[command(name = "latch")]
#[command(author = "Kenny Wu <kenny@kennywu.dev>")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "Latch - Manage secrets across multiple environments", long_about = None)]
struct Cli {
    /// Enable verbose output
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Disable output (useful for scripting)
    #[arg(short, long, global = true)]
    quiet: bool,

    /// Project name
    #[arg(short = 'P', long)]
    project: Option<String>,

    /// Path to secrets repository
    #[arg(short = 'R', long)]
    repo_path: Option<PathBuf>,

    /// Command to execute
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Manage secrets lifecycle (add, get, list, delete)
    Secrets {
        #[command(subcommand)]
        secret_command: SecretCommand,
    },
    /// Initialize a new project with its secrets repository configuration
    Init {
        /// Project name to initialize
        project: String,
    },
    /// Set up or update a project's configuration with GitHub PAT
    SetProject,
    /// Delete a project and optionally its secrets from configuration
    DeleteProject {
        /// Project name to delete (or 'all' to delete all)
        #[arg(default_value = "all")]
        project: String,
    },
    /// Decrypt secrets from encrypted storage
    Decrypt,
}

#[derive(Subcommand)]
enum SecretCommand {
    /// Add a new secret to a project's environment
    Add {
        /// Project name
        project: String,
        /// Environment name
        #[arg(short = 'E', long)]
        env: String,
        /// Secret key name
        #[arg(short = 'k', long)]
        key: String,
        /// Secret value (will be encrypted)
        value: String,
    },
    /// Get a secret's encrypted value
    Get {
        /// Project name
        project: String,
        /// Environment name
        #[arg(short = 'E', long)]
        env: String,
        /// Secret key name
        #[arg(short = 'k', long)]
        key: String,
    },
    /// List all secrets in a project's environment
    List {
        /// Project name
        project: String,
        /// Environment name
        #[arg(short = 'E', long)]
        env: String,
    },
    /// Delete a secret from a project's environment
    Delete {
        /// Project name
        project: String,
        /// Environment name
        #[arg(short = 'E', long)]
        env: String,
        /// Secret key name
        #[arg(short = 'k', long)]
        key: String,
    },
}

#[tokio::main]
async fn main() -> LatchResult<()> {
    let cli = Cli::parse();

    // Apply verbosity flags
    match cli.verbose {
        0 => {}
        1 => println!("[DEBUG] Verbose output enabled"),
        _ => eprintln!("[DEBUG] Debug output enabled"),
    }

    // Handle help for subcommands with proper clap group handling
    if matches!(
        cli.command,
        Some(Commands::Secrets {
            secret_command: SecretCommand::Add { .. }
        })
    ) && cli.project.is_none()
    {
        eprintln!("Error: Project name is required for 'latch secrets add'");
        eprintln!("Usage: latch secrets add <project> -E env -k key -- value");
        std::process::exit(1);
    }

    // Default command: help
    if cli.command.is_none() {
        show_help();
        return Ok(());
    }

    let project = get_project_name(&cli)?;
    let repo_path = match &cli.repo_path {
        Some(path) => path.clone(),
        None => PathBuf::from("/home/kenny/.latch-secrets"),
    };

    // Handle subcommands
    match cli.command.unwrap() {
        Commands::Secrets { secret_command } => match secret_command {
            SecretCommand::Add {
                project,
                env,
                key,
                value,
            } => {
                add_secret(&project, &repo_path, &env, &key, value).await?;
            }
            SecretCommand::Get { project, env, key } => {
                get_secret(&project, &repo_path, &env, &key).await?;
            }
            SecretCommand::List { project, env } => {
                list_secrets(&project, &repo_path, &env).await?;
            }
            SecretCommand::Delete { project, env, key } => {
                delete_secret(&project, &repo_path, &env, &key).await?;
            }
        },
        Commands::Init { project } => {
            init_project(&project).await?;
        }
        Commands::SetProject => {
            set_project(&project).await?;
        }
        Commands::DeleteProject { project } => {
            delete_project(&project).await?;
        }
        Commands::Decrypt => {
            decrypt_all_secrets().await?;
        }
    }

    Ok(())
}

/// Get project name from CLI arguments or environment variable
fn get_project_name(cli: &Cli) -> Result<String> {
    // Try -p / --project flag first
    if let Some(name) = &cli.project {
        return Ok(name.clone());
    }

    // Fallback to environment variable
    if let Ok(project) = std::env::var("LATCH_PROJECT") {
        return Ok(project);
    }

    Err(anyhow::anyhow!(
        "Project name not specified. Use -p/--project or set LATCH_PROJECT env var"
    ))
}

/// Show help and version info for commands that don't have their own help
fn show_help() {
    println!("Latch - Manage secrets across multiple environments");
    println!();
    println!("Usage: latch [OPTIONS] <COMMAND>");
    println!();
    println!("Commands:");
    println!("  secrets    Manage secrets lifecycle (add, get, list, delete)");
    println!("  init       Initialize a new project with its secrets repository");
    println!("  set-project   Set up or update a project's configuration");
    println!("  delete-project   Delete a project and optionally its secrets");
    println!("  decrypt    Decrypt secrets from encrypted storage");
    println!();
    println!("Options:");
    println!("  -p, --project <NAME>        Project name (can use LATCH_PROJECT env var)");
    println!("  -q, --quiet                  Disable output");
    println!("  -v, --verbose                Enable verbose output (-vv for debug)");
    println!("  -h, --help                   Print help");
    println!("  -V, --version                Print version");
    println!();
    println!("Examples:");
    println!("  latch init myproject              # Initialize a new project");
    println!("  latch secrets add myproject -E dev -k DB_HOST -- my-db-host.example.com");
    println!("  latch secrets get myproject -E dev -k DB_HOST");
    println!("  latch secrets list myproject -E dev");
    println!("  latch secrets delete myproject -E dev -k OLD_KEY");
    println!();
}
