//! latch v2 CLI — thin shell over latch-core (AR1). Assembles the real
//! platform, parses arguments, prints results; every decision lives in
//! core.

use clap::{Parser, Subcommand};
use latch_core::platform::real::{
    latch_home, runtime_dir, RealClock, RealEnv, RealFiles, RealKeyring, RealProc, RealPrompt,
};
use latch_core::platform::Platform;

#[derive(Parser)]
#[command(
    name = "latch",
    version,
    about = "Encrypted .env secrets, done right (v2)"
)]
struct Cli {
    /// Never prompt: anything that would need interactive input becomes a
    /// hard error (M7). Auto-detected when there is no terminal.
    #[arg(long, global = true)]
    non_interactive: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// First-time setup on this machine: PAT + secrets repo, validated
    /// live, stored in the keyring or the encrypted credential file (M1).
    Login {
        /// GitHub personal access token (or set LATCH_PAT).
        #[arg(long)]
        pat: Option<String>,
        /// Secrets repository as owner/name.
        #[arg(long)]
        repo: Option<String>,
    },
    /// Link this directory to a project (W1); creates its key on first use.
    Init {
        /// Project name (default: directory name).
        #[arg(long)]
        name: Option<String>,
    },
    /// Encrypt this project's env files into the local clone — offline (W2).
    Commit {
        #[arg(long, default_value = "dev")]
        env: String,
    },
    /// Upload committed secrets (W3); refuses if the remote moved (S4).
    Push {
        #[arg(long, default_value = "dev")]
        env: String,
        /// Make YOUR content the newest version (history is kept).
        #[arg(long)]
        force: bool,
    },
    /// Download and decrypt this project's env files (W4), all-or-nothing.
    Pull {
        #[arg(long, default_value = "dev")]
        env: String,
        /// Use the cached clone without contacting the remote (S5).
        #[arg(long)]
        offline: bool,
        /// Overwrite local files that differ from the incoming content.
        #[arg(long)]
        overwrite: bool,
    },
    /// Local vs. committed state per file (W5).
    Status {
        #[arg(long, default_value = "dev")]
        env: String,
    },
}

fn main() {
    let cli = Cli::parse();

    let env = RealEnv;
    let files = RealFiles;
    let keyring = RealKeyring;
    let prompt = RealPrompt::detect(cli.non_interactive);
    let clock = RealClock;
    let proc = RealProc;
    let platform = Platform {
        env: &env,
        files: &files,
        keyring: &keyring,
        prompt: &prompt,
        clock: &clock,
        proc: &proc,
        latch_home: latch_home(&env),
        runtime_dir: runtime_dir(&env),
    };

    let cwd = std::env::current_dir()
        .map(|d| d.display().to_string())
        .unwrap_or_else(|_| ".".into());

    let result = match cli.command {
        Command::Login { pat, repo } => login(&platform, pat, repo),
        Command::Init { name } => latch_core::ops::init::run(&platform, &cwd, name).map(|out| {
            if out.already_linked {
                println!("already linked to project '{}'", out.project);
            } else {
                println!(
                    "✓ linked to project '{}'{}",
                    out.project,
                    if out.created_key {
                        " (new key created)"
                    } else {
                        ""
                    }
                );
            }
        }),
        Command::Commit { env } => {
            latch_core::ops::sync::commit(&platform, &cwd, &env).map(|out| {
                for (rel, changed) in &out.files {
                    println!("  {} {}", if *changed { "✚" } else { "=" }, rel);
                }
                for rel in &out.removed {
                    println!("  ✖ {} (removed)", rel);
                }
                let changed = out.files.iter().filter(|(_, c)| *c).count();
                println!(
                    "✓ committed — {} file(s), {} changed, {} removed :: push when ready",
                    out.files.len(),
                    changed,
                    out.removed.len()
                );
            })
        }
        Command::Push { env, force } => latch_core::ops::sync::push(&platform, &cwd, &env, force)
            .map(|out| match out {
                latch_core::repo::PushOutcome::Pushed => println!("✓ pushed"),
                latch_core::repo::PushOutcome::NothingToPush => {
                    println!("nothing to push (commit first?)")
                }
            }),
        Command::Pull {
            env,
            offline,
            overwrite,
        } => latch_core::ops::sync::pull(&platform, &cwd, &env, offline, overwrite).map(|out| {
            for rel in &out.written {
                println!("  ↓ {}", rel);
            }
            println!(
                "✓ pulled — {} written, {} unchanged{}",
                out.written.len(),
                out.unchanged.len(),
                if out.offline {
                    " (cached clone — offline)"
                } else {
                    ""
                }
            );
        }),
        Command::Status { env } => {
            latch_core::ops::sync::status(&platform, &cwd, &env).map(|out| {
                use latch_core::ops::sync::FileState as S;
                for (rel, state) in &out.entries {
                    let tag = match state {
                        S::Clean => "clean    ",
                        S::Modified => "modified ",
                        S::LocalOnly => "local    ",
                        S::RemoteOnly => "remote   ",
                    };
                    println!("  {} {}", tag, rel);
                }
                if out.entries.is_empty() {
                    println!("no env files found");
                }
            })
        }
    };

    if let Err(e) = result {
        eprintln!("\x1b[31merror:\x1b[0m {e}");
        std::process::exit(1);
    }
}

fn login(
    p: &Platform,
    pat: Option<String>,
    repo: Option<String>,
) -> Result<(), latch_core::error::LatchError> {
    let out = latch_core::ops::login::run(p, pat, repo)?;
    let where_ = match out.stored_in {
        latch_core::credentials::Source::Keyring => "OS keyring",
        latch_core::credentials::Source::File => "encrypted credential file",
        latch_core::credentials::Source::EnvVar => "environment",
    };
    println!(
        "✓ logged in — repo {} verified, token stored in the {}",
        out.repo, where_
    );
    Ok(())
}
