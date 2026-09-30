use crate::files::{FileError, Output, read};
use crate::{identity::IdentityError, stdio};
use base64::{Engine, engine::general_purpose::STANDARD};
use clap::builder::{PossibleValuesParser, TypedValueParser};
use clap::{Args, Parser, Subcommand, ValueEnum};
use proof_client_core::{
    proof::{self as prover, Artifact, PublicInput},
    tls::{
        attest,
        commitment::{CommitmentHash, CommitmentPolicy},
        disclosure::Disclosure,
        quic,
    },
};
use serde_json::{Value, json};
// Policy: bound local certificate and disclosure documents independently of network framing.
const MAX_LOCAL_INPUT_BYTES: usize = 1024 * 1024;
// Policy: the local verifier endpoint shared by both commands.
const VERIFIER_ADDRESS: &str = "127.0.0.1:7047";
const VERIFIER_CERTIFICATE: &str = "identity/verifier.pem";
use std::{
    io,
    net::SocketAddr,
    num::NonZeroUsize,
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Format {
    Human,
    Json,
    Raw,
}

#[derive(Parser)]
#[command(
    name = "proof-client",
    version,
    about = "Native declarative proofs and live TLSNotary disclosure"
)]
pub struct Cli {
    #[command(flatten)]
    pub storage: Storage,
    /// Output representation; raw is available only for attest.
    #[arg(long, global = true, value_enum, default_value = "human")]
    pub format: Format,
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
    #[command(flatten)]
    storage: Storage,
    #[command(subcommand)]
    command: Command,
}
#[derive(Args)]
pub struct Storage {
    /// Runtime artifacts and the local verifier identity.
    #[arg(long, global = true, default_value = ".data")]
    data_dir: PathBuf,
}
#[derive(Subcommand)]
pub enum Command {
    /// Inspect the circuit contract and save derived IDs; no proof is created.
    Prepare {
        /// Trusted circuit source; references resolve relative to this file.
        #[arg(long)]
        circuit: PathBuf,
        /// Worker count; defaults to available parallelism.
        #[arg(long)]
        threads: Option<NonZeroUsize>,
        /// New artifact path; existing files are never overwritten.
        #[arg(long)]
        output: PathBuf,
    },
    /// Prove the supplied statement, self-verify and save the proof.
    Prove {
        /// Trusted circuit source; references resolve relative to this file.
        #[arg(long)]
        circuit: PathBuf,
        /// Independently expected public field words (JSON array).
        #[arg(long)]
        public: PathBuf,
        /// Private witness JSON; never printed in reports.
        #[arg(long)]
        witness: PathBuf,
        /// Worker count; defaults to available parallelism.
        #[arg(long)]
        threads: Option<NonZeroUsize>,
        /// New artifact path; existing files are never overwritten.
        #[arg(long)]
        output: PathBuf,
    },
    /// Verify against trusted circuit definitions and independently expected public input.
    Verify {
        /// Trusted circuit source; references resolve relative to this file.
        #[arg(long)]
        circuit: PathBuf,
        /// Independently expected public field words (JSON array).
        #[arg(long)]
        public: PathBuf,
        /// Proof artifact to verify.
        #[arg(long)]
        proof: PathBuf,
        /// Worker count; defaults to available parallelism.
        #[arg(long)]
        threads: Option<NonZeroUsize>,
    },
    /// Send a new HTTPS request and attest the selected transcript bytes.
    Attest(Attest),
    /// Inspect a saved TLS record; this does not repeat live verification.
    Inspect {
        /// Saved metadata file, including custom --metadata-output paths.
        path: PathBuf,
    },
    /// Accept one live TLSN disclosure for the expected HTTPS target.
    Serve {
        /// Admit only this commitment hash; peers must select the same suite.
        #[arg(long, default_value_t = CommitmentHash::default(), value_parser = commitment_hash_parser())]
        commitment_hash: CommitmentHash,
        /// Required for the default KoalaBear suite; total permutation budget per session.
        #[arg(long)]
        max_commitment_permutations: Option<NonZeroUsize>,
        /// Local QUIC listener; accepts one attestation.
        #[arg(long, default_value = VERIFIER_ADDRESS)]
        listen: SocketAddr,
        /// Local verifier certificate; defaults to the data directory identity.
        #[arg(long)]
        cert: Option<PathBuf>,
        /// Local verifier private key; defaults to the data directory identity.
        #[arg(long)]
        key: Option<PathBuf>,
        /// Independently expected HTTPS target hostname, not the local verifier name.
        #[arg(long)]
        server_name: String,
        /// Explicit target CA bundle; otherwise use the pinned Mozilla roots.
        #[arg(long)]
        target_ca: Option<PathBuf>,
        /// New record path; otherwise create a unique run directory.
        #[arg(long)]
        metadata_output: Option<PathBuf>,
    },
}
impl Command {
    fn admit_native(self, storage: &Storage) -> Result<Self, CliError> {
        let paths = match &self {
            Self::Inspect { path } => vec![path],
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
            } => std::iter::once(&storage.data_dir)
                .chain(cert)
                .chain(key)
                .chain(metadata_output)
                .chain(target_ca)
                .collect(),
            Self::Attest(args) => std::iter::once(&storage.data_dir)
                .chain(&args.disclosure)
                .chain(&args.metadata_output)
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
    /// Hash each committed selection using this suite.
    #[arg(long, default_value_t = CommitmentHash::default(), value_parser = commitment_hash_parser())]
    commitment_hash: CommitmentHash,
    #[command(flatten)]
    request: crate::request::RequestArgs,
    /// Reveal/commit policy; omitted means reveal nothing and commit nothing.
    #[arg(long)]
    disclosure: Option<PathBuf>,
    /// Local QUIC verifier endpoint.
    #[arg(long, default_value = VERIFIER_ADDRESS)]
    verifier: SocketAddr,
    /// Expected TLS name of the local verifier, not the HTTPS target.
    #[arg(long, default_value = "localhost")]
    verifier_name: String,
    /// Verifier trust bundle; defaults to the local verifier certificate.
    #[arg(long)]
    verifier_ca: Option<PathBuf>,
    /// Target trust bundle; otherwise use the pinned Mozilla roots.
    #[arg(long)]
    target_ca: Option<PathBuf>,
    /// New record path; otherwise create a unique run directory.
    #[arg(long)]
    metadata_output: Option<PathBuf>,
}

pub enum Execution {
    Prepared {
        output: String,
        metadata: prover::Metadata,
    },
    Proved {
        output: String,
        circuit_id: prover::CircuitId,
        public: Vec<u32>,
    },
    Verified {
        circuit_id: prover::CircuitId,
        public: Vec<u32>,
    },
    Served {
        receipt: attest::VerifiedReport,
        metadata_output: String,
    },
    Attested {
        artifact: Box<quic::Attestation>,
        metadata_output: String,
    },
    Inspected {
        record: proof_client_core::tls::evidence::Record,
        path: PathBuf,
    },
}
impl Execution {
    pub fn json(&self) -> Value {
        match self {
            Self::Prepared { output, metadata } => json!({"output":output,"metadata":metadata}),
            Self::Proved {
                output,
                circuit_id,
                public,
            } => json!({"output":output,"circuit_id":circuit_id,"public":public}),
            Self::Verified { circuit_id, public } => {
                json!({"circuit_id":circuit_id,"public":public})
            }
            Self::Served {
                receipt,
                metadata_output,
            } => {
                json!({"evidence":receipt.evidence(),"metadata_output":metadata_output,"verification":"live-tls-disclosure"})
            }
            Self::Attested {
                artifact,
                metadata_output,
            } => {
                json!({"evidence":artifact.receipt().evidence(),"selections":artifact.selections(),"metadata_output":metadata_output,"verification":"live-tls-disclosure"})
            }
            Self::Inspected { record, path } => {
                json!({"record":record,"path":path,"verification":"not-performed"})
            }
        }
    }
    fn native(self) -> Result<Value, CliError> {
        let (bytes, metadata_output) = match self {
            Self::Served {
                receipt,
                metadata_output,
            } => {
                let transcript = receipt.evidence().redacted()?;
                let mut bytes = b"--- Sent ---\n".to_vec();
                bytes.extend_from_slice(transcript.sent());
                bytes.extend_from_slice(b"\n--- Received ---\n");
                bytes.extend_from_slice(transcript.received());
                (bytes, metadata_output)
            }
            Self::Attested {
                artifact,
                metadata_output,
            } => (artifact.into_response(), metadata_output),
            other @ (Self::Prepared { .. }
            | Self::Proved { .. }
            | Self::Verified { .. }
            | Self::Inspected { .. }) => return Ok(other.json()),
        };
        Ok(json!({"stdout_base64":STANDARD.encode(bytes),"metadata_output":metadata_output}))
    }
}
#[derive(thiserror::Error)]
pub enum CliError {
    #[error("{}", argument_error(.0))]
    Arguments(#[from] clap::Error),
    #[error("--format raw requires the attest command")]
    RawFormat,
    #[error(transparent)]
    Record(#[from] proof_client_core::tls::evidence::RecordError),
    #[error("cannot initialize logging: {0}")]
    Logging(#[from] tracing_subscriber::util::TryInitError),
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
fn argument_error(error: &clap::Error) -> String {
    use clap::error::{ContextKind, ErrorKind};
    if error.kind() == ErrorKind::MissingRequiredArgument {
        return error.to_string();
    }
    let mut message = format!("invalid command line ({})", error.kind());
    // Only schema-owned names and choices are safe; values may contain credentials.
    if matches!(
        error.kind(),
        ErrorKind::InvalidValue
            | ErrorKind::ValueValidation
            | ErrorKind::TooFewValues
            | ErrorKind::WrongNumberOfValues
    ) {
        if let Some(argument) = error.get(ContextKind::InvalidArg) {
            message.push_str(&format!(" for {argument}"));
        }
        if let Some(choices) = error.get(ContextKind::ValidValue) {
            message.push_str(&format!("; expected {choices}"));
        }
    }
    message.push_str("; use --help for supported arguments");
    message
}
impl std::fmt::Debug for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

fn commitment_hash_parser() -> impl TypedValueParser<Value = CommitmentHash> {
    PossibleValuesParser::new(CommitmentHash::ALL.map(CommitmentHash::as_str))
        .try_map(|value| value.parse::<CommitmentHash>())
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
    let invocation =
        Invocation::try_parse_from(std::iter::once("proof-client".to_owned()).chain(args))?;
    execute(
        invocation.command.admit_native(&invocation.storage)?,
        &invocation.storage,
        ready,
    )?
    .native()
}

pub fn execute(
    command: Command,
    storage: &Storage,
    mut ready: impl FnMut(SocketAddr) -> Result<(), CliError>,
) -> Result<Execution, CliError> {
    match command {
        Command::Inspect { path } => {
            let record = proof_client_core::tls::evidence::Record::parse(&read(
                &path,
                prover::MAX_INPUT_BYTES,
            )?)?;
            Ok(Execution::Inspected { record, path })
        }
        Command::Prepare {
            circuit,
            threads,
            output,
        } => {
            tracing::info!(phase = "reading_inputs", operation = "prepare", ?circuit);
            let out = Output::prepare(&output)?;
            let metadata = prover::prepare(crate::files::circuit(&circuit)?, workers(threads)?)?;
            let output = out.path().to_owned();
            out.publish(&metadata)?;
            Ok(Execution::Prepared { output, metadata })
        }
        Command::Prove {
            circuit,
            public,
            witness,
            threads,
            output,
        } => {
            tracing::info!(
                phase = "reading_inputs",
                operation = "prove",
                ?circuit,
                ?public,
                ?witness
            );
            let out = Output::prepare(&output)?;
            let circuit = crate::files::circuit(&circuit)?;
            let public = PublicInput::parse(&read(&public, prover::MAX_INPUT_BYTES)?)?;
            let proof = prover::prove(
                circuit,
                public,
                &read(&witness, prover::MAX_WITNESS_BYTES)?,
                workers(threads)?,
            )?;
            let output = out.path().to_owned();
            out.publish(&proof)?;
            Ok(Execution::Proved {
                output,
                circuit_id: proof.circuit_id(),
                public: proof.public().to_vec(),
            })
        }
        Command::Verify {
            circuit,
            public,
            proof,
            threads,
        } => {
            tracing::info!(
                phase = "reading_inputs",
                operation = "verify",
                ?circuit,
                ?public,
                ?proof
            );
            let circuit = crate::files::circuit(&circuit)?;
            let public = PublicInput::parse(&read(&public, prover::MAX_INPUT_BYTES)?)?;
            let proof = Artifact::parse(&read(&proof, prover::MAX_PROOF_BYTES)?)?;
            let id = proof.circuit_id();
            let public = prover::verify(circuit, public, proof, workers(threads)?)?;
            Ok(Execution::Verified {
                circuit_id: id,
                public,
            })
        }
        Command::Serve {
            listen,
            cert,
            key,
            server_name,
            target_ca,
            metadata_output,
            commitment_hash,
            max_commitment_permutations,
        } => {
            let policy = match CommitmentPolicy::new(commitment_hash, max_commitment_permutations) {
                Ok(policy) => policy,
                Err(error) => return Err(attest::AttestError::from(error).into()),
            };
            let cert = cert.unwrap_or_else(|| storage.data_dir.join(VERIFIER_CERTIFICATE));
            let key = key.unwrap_or_else(|| storage.data_dir.join("identity/verifier.key"));
            let metadata =
                Output::metadata(metadata_output.as_deref(), &storage.data_dir, "serve")?;
            let metadata_output = metadata.path().to_owned();
            let config = quic::server_config(
                &read(&cert, MAX_LOCAL_INPUT_BYTES)?,
                &read(&key, MAX_LOCAL_INPUT_BYTES)?,
            )?;
            let roots = quic::roots(pem(target_ca.as_deref())?.as_deref())?;
            tracing::info!(phase = "inputs_parsed", operation = "serve", expected_target = ?server_name, ?cert, ?target_ca, commitment_hash = %commitment_hash, ?max_commitment_permutations);
            let receipt = runtime()?.block_on(async {
                let verifier = quic::Verifier::bind(listen, config, &server_name, roots, policy)?;
                ready(verifier.local_addr()?)?;
                Ok::<_, CliError>(verifier.verify().await?)
            })?;
            metadata.publish(&receipt.evidence())?;
            Ok(Execution::Served {
                receipt,
                metadata_output,
            })
        }
        Command::Attest(args) => {
            let (artifact, metadata_output) = attest(args, storage)?;
            Ok(Execution::Attested {
                artifact: Box::new(artifact),
                metadata_output,
            })
        }
    }
}

fn attest(args: Attest, storage: &Storage) -> Result<(quic::Attestation, String), CliError> {
    let metadata = Output::metadata(args.metadata_output.as_deref(), &storage.data_dir, "attest")?;
    let metadata_output = metadata.path().to_owned();
    let request = args.request.parse()?;
    let disclosure = match &args.disclosure {
        Some(path) => Disclosure::parse(&read(path, MAX_LOCAL_INPUT_BYTES)?)?,
        None => Disclosure::default(),
    };
    let verifier_ca = args
        .verifier_ca
        .unwrap_or_else(|| storage.data_dir.join(VERIFIER_CERTIFICATE));
    let peer = quic::Peer::new(
        args.verifier,
        &args.verifier_name,
        quic::roots(Some(&read(&verifier_ca, MAX_LOCAL_INPUT_BYTES)?))?,
    )?;
    let roots = quic::roots(pem(args.target_ca.as_deref())?.as_deref())?;
    tracing::info!(phase = "inputs_parsed", operation = "attest", verifier = %args.verifier, verifier_name = ?args.verifier_name, ?verifier_ca, target_ca = ?args.target_ca, disclosure = ?args.disclosure, target = ?request.server_name(), method = %request.method(), commitment_hash = %args.commitment_hash, action = "send new HTTPS request");
    let artifact = runtime()?.block_on(quic::attest(
        request,
        disclosure,
        peer,
        roots,
        args.commitment_hash,
    ))?;
    tracing::info!(phase = "publishing_private_record", output = ?metadata_output);
    metadata.publish(&artifact.metadata())?;
    Ok((artifact, metadata_output))
}
