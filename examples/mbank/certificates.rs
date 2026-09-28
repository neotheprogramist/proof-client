#[path = "support/identity.rs"]
mod identity;
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = ".data/identity")]
    directory: PathBuf,
}
fn main() -> Result<(), identity::Error> {
    let args = Args::parse();
    identity::get_or_create(&args.directory, "verifier")?;
    Ok(())
}
