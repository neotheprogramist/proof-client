use crate::files::{FileError, Output, read};
use crate::{identity::IdentityError, stdio};
use base64::{Engine, engine::general_purpose::STANDARD};
use clap::{Args, Parser, Subcommand};
use proof_client_core::{
    proof::{self as prover, Artifact, Job, PublicInput},
    tls::{attest, disclosure::Disclosure, quic},
};
use serde_json::{Value, json};
// Policy: bound local certificate and disclosure documents independently of network framing.
const MAX_LOCAL_INPUT_BYTES: usize = 1024 * 1024;
use std::{
    io,
    net::SocketAddr,
    num::NonZeroUsize,
    path::{Path, PathBuf},
};

#[derive(Parser)]
#[command(
    name = "proof-client",
    args_conflicts_with_subcommands = true,
    subcommand_negates_reqs = true,
    version,
    about = "Native declarative proofs and live TLSNotary disclosure"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
    #[arg(hide = true)]
    pub origin: Option<String>,
    #[arg(long, hide = true, requires = "origin")]
    parent_window: Option<u64>,
}
#[derive(Parser)]
#[command(name = "proof-client", version)]
struct Invocation {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
pub enum Command {
    /// Prepare circuit and verifier-set IDs.
    Prepare {
        #[arg(long)]
        circuit: PathBuf,
        #[arg(long)]
        threads: Option<NonZeroUsize>,
        #[arg(long)]
        output: PathBuf,
    },
    /// Prove the supplied statement.
    Prove {
        #[arg(long)]
        circuit: PathBuf,
        #[arg(long)]
        public: PathBuf,
        #[arg(long)]
        witness: PathBuf,
        #[arg(long)]
        threads: Option<NonZeroUsize>,
        #[arg(long)]
        output: PathBuf,
    },
    /// Verify the supplied statement.
    Verify {
        #[arg(long)]
        circuit: PathBuf,
        #[arg(long)]
        public: PathBuf,
        #[arg(long)]
        proof: PathBuf,
        #[arg(long)]
        threads: Option<NonZeroUsize>,
    },
    /// Attest selected HTTPS transcript bytes.
    Attest(Attest),
    /// Verify and log one TLSN disclosure.
    Serve {
        #[arg(long)]
        listen: SocketAddr,
        #[arg(long)]
        cert: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        server_name: String,
        /// Explicit target CA bundle; otherwise use the pinned Mozilla roots.
        #[arg(long)]
        target_ca: Option<PathBuf>,
        #[arg(long)]
        metadata_output: PathBuf,
    },
}
impl Command {
    fn admit_native(self) -> Result<Self, CliError> {
        let paths = match &self {
            Self::Prepare {
                circuit, output, ..
            } => vec![circuit, output],
            Self::Prove {
                circuit,
                public,
                witness,
                output,
                ..
            } => vec![circuit, public, witness, output],
            Self::Verify {
                circuit,
                public,
                proof,
                ..
            } => vec![circuit, public, proof],
            Self::Serve {
                cert,
                key,
                target_ca,
                metadata_output,
                ..
            } => vec![cert, key, metadata_output]
                .into_iter()
                .chain(target_ca)
                .collect(),
            Self::Attest(args) => vec![&args.disclosure, &args.metadata_output]
                .into_iter()
                .chain(&args.verifier_ca)
                .chain(&args.target_ca)
                .collect(),
        };
        if paths.into_iter().any(|path| !path.is_absolute()) {
            return Err(CliError::AbsolutePath);
        }
        Ok(self)
    }
}

#[derive(Args)]
pub struct Attest {
    #[command(flatten)]
    request: crate::request::RequestArgs,
    #[arg(long)]
    disclosure: PathBuf,
    #[arg(long)]
    verifier: SocketAddr,
    #[arg(long)]
    verifier_name: String,
    #[arg(long)]
    verifier_ca: Option<PathBuf>,
    #[arg(long)]
    target_ca: Option<PathBuf>,
    #[arg(long)]
    metadata_output: PathBuf,
}

pub enum Execution {
    Json(Value),
    Http {
        bytes: Vec<u8>,
        metadata_output: String,
    },
}
impl Execution {
    pub fn native(self) -> Value {
        match self {
            Self::Json(value) => value,
            Self::Http {
                bytes,
                metadata_output,
            } => json!({
                "stdout_base64": STANDARD.encode(bytes), "metadata_output": metadata_output,
            }),
        }
    }
}
#[derive(thiserror::Error)]
pub enum CliError {
    #[error("invalid command line ({0}); use --help for supported arguments")]
    Arguments(clap::error::ErrorKind),
    #[error(transparent)]
    Identity(#[from] IdentityError),
    #[error(transparent)]
    Frame(#[from] stdio::FrameError),
    #[error(transparent)]
    Proof(#[from] proof_client_core::proof::Error),
    #[error(transparent)]
    Attest(#[from] attest::AttestError),
    #[error(transparent)]
    Quic(#[from] quic::QuicError),
    #[error(transparent)]
    Disclosure(#[from] proof_client_core::tls::disclosure::DisclosureError),
    #[error("invalid JSON or result encoding")]
    Json(#[from] serde_json::Error),
    #[error("local I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error(transparent)]
    Files(#[from] FileError),
    #[error("native file arguments must use absolute paths")]
    AbsolutePath,
    #[error("incompatible launch or command arguments")]
    Invocation,
}
impl std::fmt::Debug for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

fn workers(requested: Option<NonZeroUsize>) -> Result<NonZeroUsize, CliError> {
    match requested {
        Some(count) => Ok(count),
        None => Ok(std::thread::available_parallelism()?),
    }
}

fn runtime() -> Result<tokio::runtime::Runtime, CliError> {
    Ok(tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?)
}
fn pem(path: Option<&Path>) -> Result<Option<Vec<u8>>, FileError> {
    path.map(|path| read(path, MAX_LOCAL_INPUT_BYTES))
        .transpose()
}

pub fn invoke(
    args: Vec<String>,
    ready: impl FnMut(SocketAddr) -> Result<(), CliError>,
) -> Result<Value, CliError> {
    let parsed = Invocation::try_parse_from(std::iter::once("proof-client".to_owned()).chain(args));
    match parsed {
        Ok(invocation) => Ok(execute(invocation.command.admit_native()?, ready)?.native()),
        Err(error) => Err(CliError::Arguments(error.kind())),
    }
}

pub fn execute(
    command: Command,
    mut ready: impl FnMut(SocketAddr) -> Result<(), CliError>,
) -> Result<Execution, CliError> {
    match command {
        Command::Prepare {
            circuit,
            threads,
            output,
        } => {
            let out = Output::prepare(&output)?;
            let metadata = prover::prepare(crate::files::circuit(&circuit)?, workers(threads)?)?;
            let result = json!({"output": out.path(), "metadata": metadata});
            out.publish(&metadata)?;
            Ok(Execution::Json(result))
        }
        Command::Prove {
            circuit,
            public,
            witness,
            threads,
            output,
        } => {
            let out = Output::prepare(&output)?;
            let circuit = crate::files::circuit(&circuit)?;
            let public = PublicInput::parse(&read(&public, prover::MAX_INPUT_BYTES)?)?;
            let job = Job::parse(circuit, public, &read(&witness, prover::MAX_WITNESS_BYTES)?)?;
            let proof = prover::prove(job, workers(threads)?)?;
            let result = json!({"output": out.path(), "circuit_id": proof.circuit_id(), "public": proof.public()});
            out.publish(&proof)?;
            Ok(Execution::Json(result))
        }
        Command::Verify {
            circuit,
            public,
            proof,
            threads,
        } => {
            let circuit = crate::files::circuit(&circuit)?;
            let public = PublicInput::parse(&read(&public, prover::MAX_INPUT_BYTES)?)?;
            let proof = Artifact::parse(&read(&proof, prover::MAX_PROOF_BYTES)?)?;
            let id = proof.circuit_id();
            let public = prover::verify(circuit, public, proof, workers(threads)?)?;
            Ok(Execution::Json(json!({"circuit_id": id, "public": public})))
        }
        Command::Serve {
            listen,
            cert,
            key,
            server_name,
            target_ca,
            metadata_output,
        } => {
            let metadata = Output::prepare(&metadata_output)?;
            let metadata_output = metadata.path().to_owned();
            let config = quic::server_config(
                &read(&cert, MAX_LOCAL_INPUT_BYTES)?,
                &read(&key, MAX_LOCAL_INPUT_BYTES)?,
            )?;
            let roots = quic::roots(pem(target_ca.as_deref())?.as_deref())?;
            let receipt = runtime()?.block_on(async {
                let verifier = quic::Verifier::bind(listen, config, &server_name, roots)?;
                ready(verifier.local_addr()?)?;
                Ok::<_, CliError>(verifier.verify().await?)
            })?;
            let transcript = receipt.report().redacted()?;
            metadata.publish(&receipt.metadata())?;
            let mut bytes = b"--- Sent ---\n".to_vec();
            bytes.extend_from_slice(transcript.sent());
            bytes.extend_from_slice(b"\n--- Received ---\n");
            bytes.extend_from_slice(transcript.received());
            Ok(Execution::Http {
                bytes,
                metadata_output,
            })
        }
        Command::Attest(args) => {
            let metadata = Output::prepare(&args.metadata_output)?;
            let metadata_output = metadata.path().to_owned();
            let request = args.request.parse()?;
            let disclosure = Disclosure::parse(&read(&args.disclosure, MAX_LOCAL_INPUT_BYTES)?)?;
            let peer = quic::Peer::new(
                args.verifier,
                &args.verifier_name,
                quic::roots(pem(args.verifier_ca.as_deref())?.as_deref())?,
            )?;
            let roots = quic::roots(pem(args.target_ca.as_deref())?.as_deref())?;
            let artifact = runtime()?.block_on(quic::attest(request, disclosure, peer, roots))?;
            metadata.publish(&artifact.metadata())?;
            Ok(Execution::Http {
                bytes: artifact.into_response(),
                metadata_output,
            })
        }
    }
}
