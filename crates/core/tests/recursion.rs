#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "direct cryptographic observations"
)]
use proof_client_core::proof::{self as prover, Artifact, PublicInput};
use serde_json::json;
use std::path::Path;
#[path = "support/circuits.rs"]
mod circuits;
#[path = "../../../examples/merkle/support/merkle.rs"]
#[allow(dead_code)]
mod merkle;
mod support;
fn public(words: &[u32]) -> PublicInput {
    PublicInput::parse(&serde_json::to_vec(words).unwrap()).unwrap()
}
#[test]
#[ignore = "worker for the bounded recursion gate"]
fn recursion_worker() -> Result<(), prover::Error> {
    let documents = circuits::documents();
    let (proof, expected) = prover::with_session(
        circuits::link("merge-recursive.json", &documents)?,
        4.try_into().unwrap(),
        |session| {
            let metadata = session.metadata()?;
            let set_id = metadata.verifier_sets()[Path::new("merge-verifier.json")];
            let mut level = Vec::new();
            for index in 0..8 {
                let (words, private) = merkle::leaf(index);
                let proof = session.prove(
                    Path::new("base.json"),
                    public(&words),
                    &serde_json::to_vec(&json!({"private":private,"proofs":[]}))?,
                )?;
                assert_eq!(
                    proof.circuit_id(),
                    metadata.circuits()[Path::new("base.json")]
                );
                level.push(proof);
            }
            for height in 1..=3 {
                let circuit = if height == 1 {
                    "merge-bases.json"
                } else {
                    "merge-recursive.json"
                };
                let mut parents = Vec::new();
                for pair in level.as_chunks::<2>().0 {
                    let root = merkle::hash(
                        merkle::NODE,
                        &pair
                            .iter()
                            .flat_map(|proof| proof.public()[1..9].iter().copied())
                            .collect::<Vec<_>>(),
                    );
                    assert_eq!(pair[0].circuit_id(), pair[1].circuit_id());
                    let words = std::iter::once(height)
                        .chain(root)
                        .chain(*pair[0].circuit_id().words())
                        .chain(*set_id.words())
                        .collect::<Vec<_>>();
                    let proof = session.prove(
                        Path::new(circuit),
                        public(&words),
                        &serde_json::to_vec(&json!({"private":[],"proofs":pair}))?,
                    )?;
                    assert_eq!(proof.public(), words);
                    assert_eq!(proof.circuit_id(), metadata.circuits()[Path::new(circuit)]);
                    parents.push(proof);
                }
                level = parents;
            }
            let proof = level.pop().unwrap();
            let expected = merkle::expected(merkle::MAX_HEIGHT)
                .into_iter()
                .chain(*metadata.circuits()[Path::new("merge-recursive.json")].words())
                .chain(*set_id.words())
                .collect::<Vec<_>>();
            assert_eq!(proof.public(), expected);
            let encoded = serde_json::to_value(&proof)?;
            let exported = encoded["proof"]["non_primitives"]
                .as_array()
                .unwrap()
                .iter()
                .flat_map(|table| table["public_values"].as_array().unwrap().iter().cloned())
                .collect::<Vec<_>>();
            let exported: Vec<p3_koala_bear::KoalaBear> = serde_json::from_value(json!(exported))?;
            use p3_field::PrimeField32;
            assert_eq!(
                exported
                    .iter()
                    .map(PrimeField32::as_canonical_u32)
                    .collect::<Vec<_>>(),
                expected
            );
            let bytes = serde_json::to_vec(&proof)?;
            for index in 0..expected.len() {
                let mut changed = expected.clone();
                changed[index] ^= 1;
                let mut altered = encoded.clone();
                altered["public"] = json!(changed);
                let result = session.verify(
                    Path::new("merge-recursive.json"),
                    public(&changed),
                    Artifact::parse(&serde_json::to_vec(&altered)?)?,
                );
                if index < expected.len() - set_id.words().len() {
                    assert!(matches!(result, Err(prover::Error::Proof(_))), "{result:?}");
                } else {
                    assert!(
                        matches!(result, Err(prover::Error::Statement)),
                        "{result:?}"
                    );
                }
            }
            assert_eq!(
                session.verify(
                    Path::new("merge-recursive.json"),
                    public(&expected),
                    Artifact::parse(&bytes)?
                )?,
                expected
            );
            Ok((proof, expected))
        },
    )?;
    let renamed = documents
        .iter()
        .map(|(path, source)| {
            let source = prover::Source::parse(&serde_json::to_vec(source)?)?.resolve(|path| {
                Ok::<_, prover::Error>(format!("renamed-{}", path.display()).into())
            })?;
            Ok((format!("renamed-{}", path.display()).into(), source))
        })
        .collect::<Result<_, prover::Error>>()?;
    assert_eq!(
        prover::verify(
            prover::Circuit::link("renamed-merge-recursive.json".into(), renamed)?,
            public(&expected),
            proof,
            1.try_into().unwrap()
        )?,
        expected
    );
    Ok(())
}
#[test]
#[ignore = "bounded eight-leaf recursive proof gate"]
fn eight_leaf_recursion() {
    // Policy: match the CLI process budget.
    support::worker("recursion_worker", std::time::Duration::from_secs(600));
}
