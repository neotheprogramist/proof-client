#[path = "support/fixture.rs"]
mod fixture;
use clap::Parser;
use std::{net::SocketAddr, path::PathBuf};

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = ".data/fixture")]
    directory: PathBuf,
    #[arg(long, default_value = "127.0.0.1:7443")]
    listen: SocketAddr,
}
#[derive(Debug, thiserror::Error)]
enum Error {
    #[error(transparent)]
    Fixture(#[from] fixture::Error),
    #[error("cannot initialize logging: {0}")]
    Logging(#[from] tracing_subscriber::util::TryInitError),
}
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Error> {
    proof_client::logging::init()?;
    let args = Args::parse();
    let fixture = fixture::Fixture::bind(&args.directory, args.listen).await?;
    tracing::info!(target: "proof_client::fixture", event = "ready", address = %fixture.address()?);
    fixture.serve(&fixture::response()).await?;
    Ok(())
}
