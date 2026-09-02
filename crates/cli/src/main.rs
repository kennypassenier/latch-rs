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
        /// Publish even though no key backup is recorded for this key
        /// (D13). The choice is recorded and stays visible in
        /// `latch state` until an escrow covers this generation.
        #[arg(long)]
        no_escrow: bool,
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
        /// Also list the env files the exclusion rules are hiding (D8).
        /// Shows only; a commit still respects the rules.
        #[arg(long)]
        no_ignore: bool,
    },
    /// Run a command with secrets injected into its environment — nothing
    /// ever touches disk (W6). Works offline on the cached clone (S5).
    Run {
        #[arg(long, default_value = "dev")]
        env: String,
        /// When a variable has different values in two files, keep the
        /// alphabetically last file's value instead of erroring (D11).
        #[arg(long)]
        last_wins: bool,
        /// The command and its arguments (after --).
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },
    /// Print one env file decrypted to stdout — nothing touches disk
    /// (D10). Raw by default: byte-identical to what was committed.
    Cat {
        /// Path of the file inside the project (as `latch status` shows it).
        file: String,
        #[arg(long, default_value = "dev")]
        env: String,
        /// Resolve ${VAR} references against the whole project/env,
        /// strictly — an unresolved reference is a hard error (W7).
        #[arg(long)]
        expand: bool,
        /// With --expand: on a name clash with different values, keep the
        /// alphabetically last file's value instead of erroring (D11).
        #[arg(long)]
        last_wins: bool,
    },
    /// List the versions of this project's secrets (S3).
    History,
    /// Restore this project's secrets to an older version in the clone;
    /// push to publish, pull to apply locally (S3).
    Rollback {
        reference: String,
        #[arg(long, default_value = "dev")]
        env: String,
    },
    /// Authenticate every ciphertext in the repository without writing
    /// anything (S6).
    Verify {
        #[arg(long)]
        project: Option<String>,
    },
    /// Where does every credential come from, and what is missing? (W8)
    State,
    /// Wipe the local clone + session cache; credentials and config stay (W9).
    Reset {
        /// Skip the confirmation prompt.
        #[arg(long)]
        yes: bool,
    },
    /// What would push change? Key names only; --reveal shows values (W10).
    Diff {
        #[arg(long, default_value = "dev")]
        env: String,
        #[arg(long)]
        reveal: bool,
    },
    /// Edit a secret file in $EDITOR via tmpfs — zero plaintext on disk (W11).
    Edit {
        /// File to edit (default .env).
        file: Option<String>,
        #[arg(long, default_value = "dev")]
        env: String,
    },
    /// Write keys-only .env.example files (D3 — explicit, never automatic).
    Example,
    /// W12 file groups: shared content across projects via a pragma line.
    Group {
        #[command(subcommand)]
        action: GroupAction,
    },
    /// Key management: show, rotate, backup, restore (K2/K3/K5/K6).
    Key {
        #[command(subcommand)]
        action: KeyAction,
    },
    /// Open the management TUI (G1).
    Ui,
    /// Manage project↔directory links on this machine (D5).
    Project {
        #[command(subcommand)]
        action: ProjectAction,
    },
    /// Where latch is installed and whether it is on PATH (M4).
    Path,
    /// Self-update from GitHub Releases — checksum-verified, previous
    /// binary kept, new binary proven to run before replacing (M5).
    Update,
    /// Print shell completions (D7): bash, zsh or fish.
    Completions { shell: clap_complete::Shell },
    /// M2 machine clone: move credentials to another machine, E2E-encrypted.
    Clone {
        /// ssh target (user@host) — runs the whole dance in one command.
        #[arg(long)]
        to: Option<String>,
        /// Limit to one project.
        #[arg(long)]
        project: Option<String>,
        /// Limit to one environment of that project.
        #[arg(long)]
        env: Option<String>,
        #[command(subcommand)]
        action: Option<CloneAction>,
    },
}

#[derive(clap::Subcommand)]
enum ProjectAction {
    /// Every project in the secrets repo, marking which are linked here (D9).
    List,
    /// Link an EXISTING project to a directory (default: here).
    Bind {
        name: String,
        #[arg(long)]
        dir: Option<String>,
    },
    /// Forget the link on this machine (keys and repo content stay).
    Unbind { name: String },
    /// Remove a project from the secrets repo: all envs' ciphertexts,
    /// the local link and marker. Keys stay unless --purge-keys (D9).
    Remove {
        name: String,
        /// Confirm non-interactively (required without a terminal).
        #[arg(long)]
        yes: bool,
        /// Also delete the project's keys — the git history becomes
        /// unreadable FOREVER. Take a key backup first (latch key backup).
        #[arg(long)]
        purge_keys: bool,
    },
}

#[derive(clap::Subcommand)]
enum KeyAction {
    /// Show the key's identity; --reveal prints the hex value (K5).
    Show {
        #[arg(long)]
        env: Option<String>,
        /// Print the key material itself (never shown without this).
        #[arg(long)]
        reveal: bool,
    },
    /// Mint the next key generation and re-encrypt (K3); --env creates or
    /// rotates a per-environment key (K2); --group rotates a group key.
    Rotate {
        #[arg(long)]
        env: Option<String>,
        /// Rotate the key of this W12 group instead of a project key.
        #[arg(long)]
        group: Option<String>,
    },
    /// Export ALL credentials as one passphrase-encrypted file (K6).
    Backup { file: String },
    /// Restore a backup file into this machine's credential store (K6).
    Restore { file: String },
}

#[derive(clap::Subcommand)]
enum CloneAction {
    /// (target) Generate an offer for this machine to receive credentials.
    Offer {
        /// Print machine-readable OFFER= output (for the --to wrapper).
        #[arg(long)]
        machine: bool,
    },
    /// (source) Create a sealed payload for an offer.
    Create {
        offer: String,
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        env: Option<String>,
    },
    /// (target) Apply a payload against this machine's pending offer.
    Apply {
        payload: String,
        /// The 6-digit verify code shown by the machine that created the
        /// payload. Required without a TTY (M7).
        #[arg(long)]
        code: Option<String>,
        #[arg(long)]
        machine: bool,
    },
}

#[derive(clap::Subcommand)]
enum GroupAction {
    /// Show every group for the environment, with members and key status.
    List {
        #[arg(long, default_value = "dev")]
        env: String,
    },
    /// Pick the winner after a divergence error (W12b): SOURCE's content
    /// becomes the group content; all other members are overwritten.
    Resolve {
        name: String,
        #[arg(long)]
        source: String,
        #[arg(long, default_value = "dev")]
        env: String,
    },
    /// Make a new member's differing content THE group content (W12c).
    Adopt {
        name: String,
        #[arg(long)]
        from: String,
        #[arg(long, default_value = "dev")]
        env: String,
    },
}

/// K1: refuse to dump core. latch holds decrypted secrets and derived
/// keys in memory; a core file would spill them to disk. PR_SET_DUMPABLE
/// also blocks ptrace by another process at the same uid. Linux-only;
/// Windows has no equivalent core-file default to disable here (WER is
/// off for console apps unless configured), so it is a no-op there.
#[cfg(target_os = "linux")]
fn harden_process() {
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        let zero = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &zero);
    }
}
#[cfg(not(target_os = "linux"))]
fn harden_process() {}

/// K1: ~/.latch holds the credential file and clone — restrict it to the
/// current user. On Unix that is mode 0700; on Windows the profile
/// directory (C:\Users\<you>) is already user-private by default NTFS
/// ACLs, so creating the directory there is enough.
#[cfg(unix)]
fn secure_latch_home(home: &str) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::create_dir_all(home);
    let _ = std::fs::set_permissions(home, std::fs::Permissions::from_mode(0o700));
}
#[cfg(not(unix))]
fn secure_latch_home(home: &str) {
    let _ = std::fs::create_dir_all(home);
}

fn main() {
    harden_process();
    let cli = Cli::parse();

    let env = RealEnv;
    let files = RealFiles;
    let keyring = RealKeyring;
    let prompt = RealPrompt::detect(cli.non_interactive);
    let clock = RealClock;
    let proc = RealProc;
    let home = latch_home(&env);
    secure_latch_home(&home);
    let platform = Platform {
        env: &env,
        files: &files,
        keyring: &keyring,
        prompt: &prompt,
        clock: &clock,
        proc: &proc,
        latch_home: home,
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
            if out.created_ignore {
                println!(
                    "  wrote {} — commit it; it says what latch may not pick up",
                    latch_core::discovery::IGNORE_FILE
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
                // D8: "0 file(s)" reported as success is how a project
                // whose secrets were never stored still looks fine.
                if out.files.is_empty() && out.removed.is_empty() {
                    eprintln!(
                        "\x1b[33mwarning:\x1b[0m {}",
                        latch_core::discovery::no_files_hint(&cwd)
                    );
                }
            })
        }
        Command::Push {
            env,
            force,
            no_escrow,
        } => latch_core::ops::sync::push(&platform, &cwd, &env, force, no_escrow)
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
            if out.diverged {
                println!(
                    "  ⚠ you have unpushed local work — this pull did NOT take in the remote; push or reset first"
                );
            }
        }),
        Command::Run {
            env,
            last_wins,
            command,
        } => {
            let (prog, rest) = command.split_first().expect("clap requires at least one");
            let arg_refs: Vec<&str> = rest.iter().map(|s| s.as_str()).collect();
            match latch_core::ops::consume::run(&platform, &cwd, &env, prog, &arg_refs, last_wins) {
                Ok(out) => {
                    if out.stale {
                        eprintln!("(offline — using the cached clone)");
                    }
                    std::process::exit(out.exit_code);
                }
                Err(e) => Err(e),
            }
        }
        Command::Cat {
            file,
            env,
            expand,
            last_wins,
        } => {
            latch_core::ops::consume::cat(&platform, &cwd, &env, &file, expand, last_wins).map(
                |out| {
                    if out.stale {
                        eprintln!("(offline — using the cached clone)");
                    }
                    use std::io::Write;
                    std::io::stdout()
                        .write_all(&out.content)
                        .expect("write to stdout");
                },
            )
        }
        Command::History => latch_core::ops::consume::history(&platform, &cwd).map(|entries| {
            for e in &entries {
                println!("  {}  {}  {}", e.reference, e.time_unix, e.message);
            }
            if entries.is_empty() {
                println!("no history yet — push something first");
            }
        }),
        Command::Rollback { reference, env } => {
            latch_core::ops::consume::rollback(&platform, &cwd, &env, &reference).map(|()| {
                println!(
                    "✓ restored {} in the local clone :: 'latch push' publishes it, 'latch pull --overwrite' applies it here",
                    reference
                );
            })
        }
        Command::Verify { project } => {
            latch_core::ops::consume::verify(&platform, project.as_deref()).map(|out| {
                use latch_core::ops::consume::VerifyState as V;
                let mut bad = 0;
                for (rel, state) in &out.entries {
                    match state {
                        V::Ok => println!("  ok       {}", rel),
                        V::Corrupt => {
                            bad += 1;
                            println!("  CORRUPT  {} — restore via latch history/rollback", rel)
                        }
                        V::NoKey { needed, generation } => println!(
                            "  no-key   {} (needs '{}' gen {})",
                            rel, needed, generation
                        ),
                        V::BadFormat(d) => {
                            bad += 1;
                            println!("  format   {} ({})", rel, d)
                        }
                    }
                }
                // D14: the per-file lines say what is wrong with a file but
                // never that files are GONE. Two sessions read the same
                // output on 2026-09-02 and drew opposite conclusions — one
                // counted 25 where there had been 38 and inferred a format
                // change instead of a removal. One summary line settles it.
                let (mut ok, mut nokey) = (0usize, 0usize);
                for (_, st) in &out.entries {
                    match st {
                        V::Ok => ok += 1,
                        V::NoKey { .. } => nokey += 1,
                        _ => {}
                    }
                }
                println!(
                    "  — {} file(s) in the repository: {} ok, {} unreadable here ({} without a key)",
                    out.entries.len(),
                    ok,
                    out.entries.len() - ok,
                    nokey
                );
                if out.stale {
                    eprintln!("(offline — verified the cached clone)");
                }
                if bad > 0 {
                    std::process::exit(1);
                }
            })
        }
        Command::State => {
            // K1: opportunistically sweep an abandoned clone offer.
            let _ = latch_core::ops::clone::cleanup_expired_offer(&platform);
            latch_core::ops::consume::state(&platform).map(|st| {
            println!("latch home   : {}", st.latch_home);
            println!("repository   : {}", st.repo.as_deref().unwrap_or("(not set — latch login)"));
            println!(
                "PAT          : {}",
                match st.pat {
                    Some(s) => format!("present ({:?})", s),
                    None => "MISSING — latch login".into(),
                }
            );
            println!("keyring      : {}", if st.keyring_available { "available" } else { "unavailable (file backend)" });
            println!("cred file    : {}", if st.cred_file { "present" } else { "none" });
            println!("local clone  : {}", if st.clone_exists { "present" } else { "none (first sync creates it)" });
            for pr in &st.projects {
                println!(
                    "project {:12} {} — key {}",
                    pr.name,
                    if pr.dir_exists { &pr.dir } else { "(dir missing!)" },
                    match (&pr.key, pr.key_unreadable_bytes) {
                        (Some((src, generation)), _) => format!("gen {} ({:?})", generation, src),
                        // D14: something IS stored, it just is not a key.
                        (None, Some(n)) => format!(
                            "UNREADABLE — {} bytes stored where 34 are expected (hex written into a raw slot?) :: latch key restore <backup>, or latch clone from a machine that has it",
                            n
                        ),
                        (None, None) => "MISSING — nothing stored here :: on Linux try 'keyctl get_persistent @s' first, the kernel keyring may still hold it".into(),
                    }
                );
                // D13: a key with no second copy is one wipe away from
                // taking the secrets with it — so state says so, in the
                // same breath as the key itself.
                use latch_core::escrow::{EscrowStatus, FileState};
                match &pr.escrow {
                    Some(EscrowStatus::Recorded {
                        generation,
                        path_hint,
                        file,
                        ..
                    }) => println!(
                        "  escrow     : recorded for gen {} — {} ({})",
                        generation,
                        path_hint,
                        match file {
                            FileState::Matches => "file still there and unchanged",
                            FileState::Differs =>
                                "a DIFFERENT file is at that path now — check your escrow",
                            FileState::Absent =>
                                "not at that path on this machine, which is fine if you moved it off",
                        }
                    ),
                    Some(EscrowStatus::SkippedOnPurpose { generation, .. }) => println!(
                        "  escrow     : NONE for gen {} — deliberately skipped with --no-escrow :: 'latch key backup <file>' still fixes it",
                        generation
                    ),
                    Some(EscrowStatus::None) => println!(
                        "  escrow     : NONE — this key exists in one place only :: run 'latch key backup <file>'"
                    ),
                    None => {}
                }
            }
        })
        }
        Command::Reset { yes } => latch_core::ops::consume::reset(&platform, yes)
            .map(|()| println!("✓ local clone wiped — the next command re-clones")),
        Command::Diff { env, reveal } => {
            latch_core::ops::edit_diff::diff(&platform, &cwd, &env, reveal).map(|diffs| {
                use latch_core::ops::edit_diff::Change;
                for d in &diffs {
                    println!("{}:", d.file);
                    for (k, change, old, new) in &d.entries {
                        let sym = match change {
                            Change::Added => "+",
                            Change::Removed => "-",
                            Change::Changed => "~",
                        };
                        match (old, new) {
                            (Some(o), Some(n)) => println!("  {} {} {} -> {}", sym, k, o, n),
                            (None, Some(n)) => println!("  {} {} = {}", sym, k, n),
                            (Some(o), None) => println!("  {} {} (was {})", sym, k, o),
                            (None, None) => println!("  {} {}", sym, k),
                        }
                    }
                }
                if diffs.is_empty() {
                    println!("no differences with the committed state");
                }
            })
        }
        Command::Edit { file, env } => {
            latch_core::ops::edit_diff::edit(&platform, &cwd, &env, file.as_deref()).map(|out| {
                if out.changed {
                    println!("✓ {} edited and committed :: 'latch push' publishes it", out.file);
                } else {
                    println!("no changes made to {}", out.file);
                }
            })
        }
        Command::Example => {
            latch_core::ops::edit_diff::write_examples(&platform, &cwd).map(|written| {
                for w in &written {
                    println!("  ✚ {}", w);
                }
                println!("✓ {} example file(s) written (keys only)", written.len());
            })
        }
        Command::Group { action } => match action {
            GroupAction::List { env } => latch_core::groups::list(&platform, &env).map(|infos| {
                if infos.is_empty() {
                    println!("no groups in env '{}'", env);
                }
                for g in infos {
                    let key = if g.key_held { "key held" } else { "NO KEY on this machine" };
                    let content = if g.has_content { "content stored" } else { "no content yet" };
                    println!("{} — {} member(s), {}, {}", g.name, g.members.len(), content, key);
                    for m in &g.members {
                        println!("    {}", m);
                    }
                }
            }),
            GroupAction::Resolve { name, source, env } | GroupAction::Adopt { name, from: source, env } => {
                latch_core::groups::resolve(&platform, &cwd, &env, &name, &source).map(|r| {
                    println!(
                        "✓ group '{}' now follows {} :: {} member(s) updated — 'latch push' publishes it",
                        r.name,
                        source,
                        r.fanned_out.len()
                    );
                })
            }
        },
        Command::Ui => latch_ui::run(),
        Command::Project { action } => match action {
            ProjectAction::List => match latch_core::ops::project::list_all(&platform) {
                Ok(projects) => {
                    if projects.is_empty() {
                        println!("no projects in the secrets repo yet :: latch init + commit + push creates one");
                    }
                    for pr in &projects {
                        let envs = if pr.envs.is_empty() {
                            "(nothing pushed yet)".to_string()
                        } else {
                            pr.envs
                                .iter()
                                .map(|(e, n)| format!("{}({})", e, n))
                                .collect::<Vec<_>>()
                                .join(" ")
                        };
                        match &pr.linked_dir {
                            Some(dir) => println!("{:16} {:24} linked: {}", pr.name, envs, dir),
                            None => println!("{:16} {:24} (not linked here)", pr.name, envs),
                        }
                    }
                    Ok(())
                }
                // No repo configured / unreachable clone: fall back to the
                // local links so the verb stays useful pre-login.
                Err(_) => latch_core::ops::project::list(&platform).map(|projects| {
                    for pr in projects {
                        println!("{}  {}", pr.name, pr.dir);
                    }
                    println!("(repo not reachable — showing local links only)");
                }),
            },
            ProjectAction::Remove {
                name,
                yes,
                purge_keys,
            } => {
                if purge_keys {
                    println!("⚠ --purge-keys also deletes the project's keys: the git history becomes unreadable forever. Take 'latch key backup' first if in doubt.");
                }
                latch_core::ops::project::remove(&platform, &name, yes, purge_keys).map(|out| {
                    println!(
                        "✓ project '{}' removed — {} file(s) across {} env(s) deleted from the repo and pushed",
                        out.name,
                        out.removed_files,
                        out.envs.len()
                    );
                    if out.was_linked {
                        println!("  local link removed");
                    }
                    if out.purged_keys.is_empty() {
                        println!("  keys kept (history stays readable) :: --purge-keys deletes them");
                    } else {
                        for k in &out.purged_keys {
                            println!("  ✗ key slot {} deleted", k);
                        }
                    }
                    println!("  ⚠ {}", out.rotation_tip);
                })
            }
            ProjectAction::Bind { name, dir } => {
                let dir = dir.unwrap_or_else(|| cwd.clone());
                latch_core::ops::project::bind(&platform, &name, &dir)
                    .map(|_| println!("✓ {} -> {}", name, dir))
            }
            ProjectAction::Unbind { name } => latch_core::ops::project::unbind(&platform, &name)
                .map(|_| println!("✓ {} unlinked (keys and repo content stay)", name)),
        },
        Command::Path => {
            let exe = std::env::current_exe()
                .map(|e| e.display().to_string())
                .unwrap_or_else(|_| "latch".into());
            latch_core::ops::project::path_report(&platform, &exe).map(|r| {
                println!("install path  {}", r.install_path);
                if r.on_path {
                    println!("on $PATH      yes");
                } else {
                    println!("on $PATH      NO :: {}", r.remedy);
                }
            })
        }
        Command::Update => {
            let exe = std::env::current_exe()
                .map(|e| e.display().to_string())
                .unwrap_or_else(|_| "latch".into());
            let exe = latch_core::ops::project::install_path(&platform, &exe)
                .unwrap_or_else(|_| exe.clone());
            latch_core::ops::update::run(&platform, env!("CARGO_PKG_VERSION"), &exe).map(|out| {
                match out {
                    latch_core::ops::update::UpdateOutcome::UpToDate { version } => {
                        println!("✓ already current ({})", version);
                    }
                    latch_core::ops::update::UpdateOutcome::Updated { from, to, previous } => {
                        println!("✓ updated {} -> {}", from, to);
                        println!("  previous binary kept at {}", previous);
                    }
                }
            })
        }
        Command::Completions { shell } => {
            use clap::CommandFactory;
            clap_complete::generate(shell, &mut Cli::command(), "latch", &mut std::io::stdout());
            Ok(())
        }
        Command::Key { action } => match action {
            KeyAction::Show { env, reveal } => {
                latch_core::ops::keyops::show(&platform, &cwd, env.as_deref(), reveal).map(|k| {
                    println!("key       {} (generation {})", k.label, k.generation);
                    println!("source    {:?}", k.source);
                    println!("env var   {}", k.env_var);
                    match k.hex {
                        Some(h) => println!("value     {}", h),
                        None => println!("value     hidden :: --reveal prints it"),
                    }
                })
            }
            KeyAction::Rotate { env, group } => {
                let result = match group {
                    Some(name) => latch_core::ops::keyops::rotate_group(
                        &platform,
                        env.as_deref().unwrap_or("dev"),
                        &name,
                    ),
                    None => latch_core::ops::keyops::rotate(&platform, &cwd, env.as_deref()),
                };
                result.map(|r| {
                    match r.old_generation {
                        Some(old) => println!(
                            "✓ {} rotated: generation {} -> {}",
                            r.label, old, r.new_generation
                        ),
                        None => println!(
                            "✓ {} created (generation {})",
                            r.label, r.new_generation
                        ),
                    }
                    println!("  {} file(s) re-encrypted — 'latch push' publishes them", r.reencrypted.len());
                    println!("  ⚠ {}", r.caveat);
                })
            }
            KeyAction::Backup { file } => {
                latch_core::ops::keyops::backup(&platform, &file).map(|b| {
                    println!("✓ {} credential(s) backed up to {}", b.slots.len(), b.path);
                    for s in &b.slots {
                        println!("    {}", s);
                    }
                    if !b.recorded.is_empty() {
                        println!(
                            "  escrow recorded for {} key(s) — 'latch push' is unblocked; the record itself reaches the repo with your next push",
                            b.recorded.len()
                        );
                    }
                    if !b.skipped.is_empty() {
                        println!(
                            "  ⚠ {} key(s) the repo expects are NOT on this machine, so this backup does NOT cover them:",
                            b.skipped.len()
                        );
                        for s in &b.skipped {
                            println!("    (not here) {}", s);
                        }
                        println!("    if another machine holds them, back up there too (latch clone brings them here);");
                        println!("    if no machine holds them any more, they are gone — the repo files sealed with them");
                        println!("    cannot be opened again, and the fix is to re-create those secrets, not to keep looking");
                    }
                })
            }
            KeyAction::Restore { file } => {
                latch_core::ops::keyops::restore(&platform, &file).map(|r| {
                    println!("✓ {} credential(s) restored", r.restored.len());
                    if r.repo_configured {
                        println!("  repo configured from the backup");
                    }
                })
            }
        },
        Command::Clone { to, project, env, action } => match (to, action) {
            (Some(target), None) => {
                latch_core::ops::clone::clone_to(&platform, &target, project.as_deref(), env.as_deref())
                    .map(|r| {
                        println!(
                            "✓ {} credential(s) cloned to {} (verify code was {})",
                            r.applied, target, r.code
                        );
                    })
            }
            (None, Some(CloneAction::Offer { machine })) => {
                latch_core::ops::clone::offer(&platform).map(|o| {
                    if machine {
                        println!("OFFER={}", o.offer);
                    } else {
                        println!("offer (valid 15 min, single use):");
                        println!("  {}", o.offer);
                        println!("on the SOURCE machine: latch clone create '{}'", o.offer);
                    }
                })
            }
            (None, Some(CloneAction::Create { offer, project, env })) => {
                latch_core::ops::clone::create(&platform, &offer, project.as_deref(), env.as_deref())
                    .map(|c| {
                        println!("payload ({} credential(s)):", c.slots.len());
                        println!("  {}", c.payload);
                        println!("verify code: {} — the target must confirm THIS code", c.code);
                    })
            }
            (None, Some(CloneAction::Apply { payload, code, machine })) => {
                latch_core::ops::clone::apply(&platform, &payload, code.as_deref()).map(|a| {
                    if machine {
                        println!("APPLIED={}", a.applied.len());
                    } else {
                        println!("✓ {} credential(s) applied", a.applied.len());
                        if a.repo_configured {
                            println!("  repo configured from the payload");
                        }
                    }
                })
            }
            (Some(_), Some(_)) => Err(latch_core::error::LatchError::other(
                "--to and a subcommand are mutually exclusive",
                "use 'latch clone --to <ssh>' OR the manual offer/create/apply verbs",
            )),
            (None, None) => Err(latch_core::error::LatchError::other(
                "clone needs --to <ssh> or a subcommand",
                "one-shot: latch clone --to user@host; manual: offer (there), create (here), apply (there)",
            )),
        },
        Command::Status { env, no_ignore } => {
            latch_core::ops::sync::status(&platform, &cwd, &env).and_then(|out| {
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
                if no_ignore {
                    // D8 diagnostic: everything discovery would have
                    // found with no rules at all, minus what it did find.
                    let seen: std::collections::BTreeSet<&str> =
                        out.entries.iter().map(|(rel, _)| rel.as_str()).collect();
                    let all = latch_core::discovery::discover_all(platform.files, &cwd)?;
                    for rel in all.iter().filter(|r| !seen.contains(r.as_str())) {
                        println!("  ignored   {}", rel);
                    }
                }
                if out.entries.is_empty() {
                    eprintln!(
                        "\x1b[33mwarning:\x1b[0m {}",
                        latch_core::discovery::no_files_hint(&cwd)
                    );
                }
                Ok(())
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
