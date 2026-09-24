use proof_client_core::proof::{Circuit, Error, Source};
use serde_json::Value;
use std::{collections::BTreeMap, path::PathBuf};

pub fn documents() -> BTreeMap<PathBuf, Value> {
    [
        (
            "base.json",
            include_bytes!("../../../../examples/merkle/base.json").as_slice(),
        ),
        (
            "merge-bases.json",
            include_bytes!("../../../../examples/merkle/merge-bases.json").as_slice(),
        ),
        (
            "merge-recursive.json",
            include_bytes!("../../../../examples/merkle/merge-recursive.json").as_slice(),
        ),
        (
            "merge-verifier.json",
            include_bytes!("../../../../examples/merkle/merge-verifier.json").as_slice(),
        ),
    ]
    .into_iter()
    .map(|(name, bytes)| (PathBuf::from(name), serde_json::from_slice(bytes).unwrap()))
    .collect()
}
pub fn link(entry: &str, documents: &BTreeMap<PathBuf, Value>) -> Result<Circuit, Error> {
    Circuit::link(
        entry.into(),
        documents
            .iter()
            .map(|(name, document)| {
                Ok((name.clone(), Source::parse(&serde_json::to_vec(document)?)?))
            })
            .collect::<Result<_, Error>>()?,
    )
}
