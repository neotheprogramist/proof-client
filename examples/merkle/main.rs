mod support {
    #[allow(dead_code)]
    pub mod merkle;
}
use clap::{Parser, Subcommand, ValueEnum};
use proof_client_core::proof::{Artifact, MAX_INPUT_BYTES, MAX_PROOF_BYTES, Metadata};
use serde_json::{Value, json};
use std::{
    fs::File,
    io::{self, Read, Write},
    path::{Path, PathBuf},
};
use support::merkle;
#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("example file I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("invalid example JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Proof(#[from] proof_client_core::proof::Error),
    #[error("invalid example input: {0}")]
    Input(&'static str),
}
#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: Command,
}
#[derive(Clone, Copy, ValueEnum)]
enum Output {
    Public,
    Witness,
}
#[derive(Subcommand)]
enum Command {
    /// Base input.
    Leaf {
        #[arg(long,value_parser=clap::value_parser!(u32).range(0..8))]
        index: u32,
        #[arg(value_enum)]
        output: Output,
    },
    /// Merge input.
    Parent {
        #[arg(long)]
        left: PathBuf,
        #[arg(long)]
        right: PathBuf,
        #[arg(long)]
        metadata: PathBuf,
        #[arg(value_enum)]
        output: Output,
    },
    /// Expected sample statement.
    Public {
        #[arg(long,value_parser=clap::value_parser!(u32).range(0..=3))]
        height: u32,
        #[arg(long)]
        metadata: PathBuf,
    },
}
fn read(path: &Path, limit: usize) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(Error::Input("example input exceeds admission limit"));
    }
    Ok(bytes)
}
fn metadata(path: &Path) -> Result<Metadata, Error> {
    Ok(serde_json::from_slice(&read(path, MAX_INPUT_BYTES)?)?)
}
fn set_id(metadata: &Metadata) -> Result<proof_client_core::proof::VerifierSetId, Error> {
    metadata
        .verifier_sets()
        .get(Path::new("merge-verifier.json"))
        .copied()
        .ok_or(Error::Input("missing verifier-set ID"))
}
fn parent(left: &Path, right: &Path, metadata_path: &Path, output: Output) -> Result<Value, Error> {
    let left = Artifact::parse(&read(left, MAX_PROOF_BYTES)?)?;
    let right = Artifact::parse(&read(right, MAX_PROOF_BYTES)?)?;
    if left.circuit_id() != right.circuit_id() {
        return Err(Error::Input("child circuit IDs differ"));
    }
    match output {
        Output::Witness => Ok(json!({"private":[],"proofs":[left,right]})),
        Output::Public => {
            let level = *left
                .public()
                .first()
                .ok_or(Error::Input("missing child height"))?;
            if right.public().first() != Some(&level) {
                return Err(Error::Input("child heights differ"));
            }
            let height = level
                .checked_add(1)
                .ok_or(Error::Input("height overflow"))?;
            let words = left
                .public()
                .get(1..9)
                .ok_or(Error::Input("missing left root"))?
                .iter()
                .chain(
                    right
                        .public()
                        .get(1..9)
                        .ok_or(Error::Input("missing right root"))?,
                )
                .copied()
                .collect::<Vec<_>>();
            Ok(json!(
                std::iter::once(height)
                    .chain(merkle::hash(merkle::NODE, &words))
                    .chain(*left.circuit_id().words())
                    .chain(*set_id(&metadata(metadata_path)?)?.words())
                    .collect::<Vec<_>>()
            ))
        }
    }
}
fn main() -> Result<(), Error> {
    let result = match Args::parse().command {
        Command::Leaf { index, output } => {
            let (public, private) = merkle::leaf(index);
            match output {
                Output::Public => json!(public),
                Output::Witness => json!({"private":private,"proofs":[]}),
            }
        }
        Command::Parent {
            left,
            right,
            metadata,
            output,
        } => parent(&left, &right, &metadata, output)?,
        Command::Public {
            height,
            metadata: path,
        } => {
            let expected = merkle::expected(height);
            if height == 0 {
                json!(expected)
            } else {
                let metadata = metadata(&path)?;
                let child = match height {
                    1 => "base.json",
                    2 => "merge-bases.json",
                    _ => "merge-recursive.json",
                };
                let child = metadata
                    .circuits()
                    .get(Path::new(child))
                    .ok_or(Error::Input("missing circuit ID"))?;
                json!(
                    expected
                        .into_iter()
                        .chain(*child.words())
                        .chain(*set_id(&metadata)?.words())
                        .collect::<Vec<_>>()
                )
            }
        }
    };
    let mut output = io::stdout().lock();
    serde_json::to_writer_pretty(&mut output, &result)?;
    output.write_all(b"\n")?;
    Ok(())
}
