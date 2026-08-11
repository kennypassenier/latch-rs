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

    let result = match cli.command {
        Command::Login { pat, repo } => login(&platform, pat, repo),
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
