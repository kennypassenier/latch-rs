//! latch v2 CLI — thin shell over latch-core (AR1). Commands grow per the
//! realization plan; L0 ships only the skeleton and --version.

use clap::Parser;

#[derive(Parser)]
#[command(
    name = "latch",
    version,
    about = "Encrypted .env secrets, done right (v2)"
)]
struct Cli {}

fn main() {
    let _cli = Cli::parse();
    // No subcommand yet (L0): clap handles --version/--help; anything else
    // lands here.
    println!(
        "latch v2 is under construction — this build carries only the core (L0). \
         The v1 binary lives on as latch-legacy."
    );
}
