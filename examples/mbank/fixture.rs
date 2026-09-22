#[path = "support/fixture.rs"]
mod fixture;
use clap::Parser;
use std::{net::SocketAddr, path::PathBuf};

#[derive(Parser)]
struct Args {
    #[arg(long)]
    directory: PathBuf,
    #[arg(long, default_value = "127.0.0.1:7443")]
    listen: SocketAddr,
}
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), fixture::Error> {
    let args = Args::parse();
    let fixture = fixture::Fixture::bind(&args.directory, args.listen).await?;
    eprintln!("fixture listening on {}", fixture.address()?);
    tokio::time::timeout(
        proof_client_core::tls::attest::SESSION_TIMEOUT,
        fixture.serve(&fixture::response()),
    )
    .await??;
    Ok(())
}
