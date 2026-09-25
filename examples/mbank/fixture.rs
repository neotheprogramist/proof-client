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
    let path = |name: &str| -> Result<String, fixture::Error> {
        let path = args.directory.join(name);
        let value = path
            .to_str()
            .ok_or(fixture::Error::Request("fixture path must be UTF-8"))?;
        Ok(format!("'{}'", value.replace('\'', "'\\''")))
    };
    println!(
        "cargo run --release --locked --quiet --bin proof-client -- attest --verifier 127.0.0.1:7047 --verifier-name localhost --verifier-ca {} --target-ca {} --disclosure {} --metadata-output {} --url https://localhost:{}/balance -H 'content-type: application/json' -H 'Connection: keep-alive' -b '{}' --data-raw '{{}}'",
        path("verifier.pem")?,
        path("target.pem")?,
        path("disclosure.json")?,
        path("private-metadata.json")?,
        fixture.address()?.port(),
        fixture::sample_data().request_cookie
    );
    tokio::time::timeout(
        proof_client_core::tls::attest::SESSION_TIMEOUT,
        fixture.serve(&fixture::response()),
    )
    .await??;
    Ok(())
}
