use clap::Parser;
use std::{fs::OpenOptions, io::Write, path::PathBuf};

#[derive(Parser)]
struct Args {
    /// New directory beneath an existing parent; no trust-store installation.
    #[arg(long)]
    directory: PathBuf,
}
#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("cannot create local verifier identity: {0}")]
    Certificate(#[from] rcgen::Error),
    #[error("cannot write local verifier identity: {0}")]
    Io(#[from] std::io::Error),
}
fn main() -> Result<(), Error> {
    let args = Args::parse();
    let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    std::fs::create_dir(&args.directory)?;
    for (name, contents) in [
        ("verifier.pem", identity.cert.pem()),
        ("verifier.key", identity.signing_key.serialize_pem()),
    ] {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options
            .open(args.directory.join(name))?
            .write_all(contents.as_bytes())?;
    }
    Ok(())
}
