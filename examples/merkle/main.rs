mod support {
    #[allow(dead_code)]
    pub mod merkle;
}
use clap::{Parser, Subcommand};
use proof_client_core::proof::{Artifact, MAX_INPUT_BYTES, MAX_PROOF_BYTES};
use serde_json::{Value, json};
use std::{
    fs::File,
    io::{self, Read},
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
#[derive(Subcommand)]
enum Command {
    /// Direct eight-leaf assignment or expected root.
    Direct {
        #[arg(value_enum)]
        output: DirectOutput,
    },
    /// Prepare the fixed family once for parent witness construction.
    Prepare {
        #[arg(long)]
        threads: std::num::NonZeroUsize,
    },
    Circuit {
        #[arg(long,value_parser=clap::value_parser!(u32).range(0..=3))]
        height: u32,
    },
    Public {
        #[arg(long,value_parser=clap::value_parser!(u32).range(0..=3))]
        height: u32,
        #[arg(long)]
        family: PathBuf,
    },
    Leaf {
        #[arg(long,value_parser=clap::value_parser!(u32).range(0..8))]
        index: u32,
    },
    Parent {
        #[arg(long)]
        left: PathBuf,
        #[arg(long)]
        right: PathBuf,
        #[arg(long)]
        family: PathBuf,
    },
}
#[derive(Clone, clap::ValueEnum)]
enum DirectOutput {
    Witness,
    Public,
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
fn source(height: u32) -> Result<Value, Error> {
    let mut source: Value = serde_json::from_str(include_str!("family.json"))?;
    source
        .as_object_mut()
        .ok_or(Error::Input("expected circuit object"))?
        .insert(
            "entry".into(),
            json!(match height {
                0 => "base",
                1 => "join",
                _ => "fold",
            }),
        );
    Ok(source)
}
fn family(path: &Path) -> Result<[u32; 8], Error> {
    #[derive(serde::Deserialize)]
    struct Metadata {
        family: [u32; 8],
    }
    Ok(serde_json::from_slice::<Metadata>(&read(path, MAX_INPUT_BYTES)?)?.family)
}
fn parent(left: &Path, right: &Path, manifest: &Path) -> Result<Value, Error> {
    let left = Artifact::parse(&read(left, MAX_PROOF_BYTES)?)?;
    let right = Artifact::parse(&read(right, MAX_PROOF_BYTES)?)?;
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
    let public = std::iter::once(height)
        .chain(merkle::hash(merkle::NODE, &words))
        .chain(family(manifest)?)
        .collect::<Vec<_>>();
    Ok(json!({"public":public,"private":[],"proofs":[left,right]}))
}
fn main() -> Result<(), Error> {
    let output = match Args::parse().command {
        Command::Direct { output } => {
            let public = merkle::expected(3).into_iter().skip(1).collect::<Vec<_>>();
            match output {
                DirectOutput::Public => json!(public),
                DirectOutput::Witness => {
                    let witness: Value = serde_json::from_str(include_str!("leaves.json"))?;
                    json!({"public":public,"private":witness.get("private").ok_or(Error::Input("missing private inputs"))?,"proofs":[]})
                }
            }
        }
        Command::Prepare { threads } => {
            use proof_client_core::proof::family;
            family::prepare(
                family::Circuit::parse(include_bytes!("family.json"))?,
                threads,
            )?
        }
        Command::Circuit { height } => source(height)?,
        Command::Public {
            height,
            family: path,
        } => {
            let public = merkle::expected(height);
            if height == 0 {
                json!(public)
            } else {
                json!(public.into_iter().chain(family(&path)?).collect::<Vec<_>>())
            }
        }
        Command::Leaf { index } => merkle::leaf(index),
        Command::Parent {
            left,
            right,
            family,
        } => parent(&left, &right, &family)?,
    };
    serde_json::to_writer(io::stdout().lock(), &output)?;
    Ok(())
}
