#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "negative controls intentionally bypass honest host admission"
)]
use super::*;
use serde_json::{Value, json};
#[path = "../../../../examples/merkle/support/merkle.rs"]
#[allow(dead_code)]
mod merkle;
fn source() -> Value {
    serde_json::from_slice(include_bytes!("../../../../examples/merkle/family.json")).unwrap()
}
fn child(session: &Session, source: &Value, family: [u32; 8]) -> Artifact {
    let leaves = (0..2)
        .map(|index| {
            let mut job = merkle::leaf(index);
            let mut circuit = source.clone();
            circuit["entry"] = json!("base");
            // Derive roots from the source's leaf domain, including the foreign domain control.
            let tag = source["base"]["operations"][0]["tag"].as_u64().unwrap() as u32;
            let words = (index * 8..index * 8 + 8).collect::<Vec<_>>();
            job["public"] = json!(
                std::iter::once(0)
                    .chain(merkle::hash(tag, &words))
                    .collect::<Vec<_>>()
            );
            session
                .prove(
                    Job::parse(
                        Circuit::parse(&serde_json::to_vec(&circuit).unwrap()).unwrap(),
                        &serde_json::to_vec(&job).unwrap(),
                    )
                    .unwrap(),
                )
                .unwrap()
        })
        .collect::<Vec<_>>();
    let root = merkle::hash(
        merkle::NODE,
        &leaves
            .iter()
            .flat_map(|proof| proof.public[1..9].iter().copied())
            .collect::<Vec<_>>(),
    );
    // Bypass the host family check: a join's source permits any family words, and the fold must bind them.
    prove_prepared(
        &session.join,
        Assignment {
            public: std::iter::once(1).chain(root).chain(family).collect(),
            private: vec![],
            proofs: leaves,
        },
        |_, _| Ok((&session.base, vec![])),
    )
    .unwrap()
}
#[test]
#[ignore = "real fixed-family foreign-key and membership controls"]
fn family_membership_is_enforced_without_host_admission() {
    rayon::ThreadPoolBuilder::new()
        .num_threads(4)
        .build()
        .unwrap()
        .install(|| {
            let source = source();
            let trusted =
                Session::new(&Circuit::parse(&serde_json::to_vec(&source).unwrap()).unwrap())
                    .unwrap();
            let proof = child(&trusted, &source, trusted.root);
            let mut changed = source.clone();
            changed["base"]["operations"][0]["tag"] = json!(0x504d_0103);
            let foreign =
                Session::new(&Circuit::parse(&serde_json::to_vec(&changed).unwrap()).unwrap())
                    .unwrap();
            assert_eq!(
                descriptor(&trusted.join.prover.verifier()).unwrap(),
                descriptor(&foreign.join.prover.verifier()).unwrap()
            );
            let foreign_proof = child(&foreign, &changed, trusted.root);
            let mismatched = child(&trusted, &source, foreign.root);
            for (candidate, child, bit, sibling, accepted) in [
                (&proof, &trusted.join, 0, trusted.keys[1], true),
                (&foreign_proof, &foreign.join, 0, trusted.keys[1], false),
                (&mismatched, &trusted.join, 0, trusted.keys[1], false),
                (&proof, &trusted.join, 1, trusted.keys[1], false),
                (&proof, &trusted.join, 2, trusted.keys[1], false),
                (&proof, &trusted.join, 0, trusted.keys[0], false),
            ] {
                let root = merkle::hash(
                    merkle::NODE,
                    &candidate.public[1..9]
                        .iter()
                        .cycle()
                        .take(16)
                        .copied()
                        .collect::<Vec<_>>(),
                );
                let public = std::iter::once(2)
                    .chain(root)
                    .chain(trusted.root)
                    .collect::<Vec<_>>();
                let bytes = serde_json::to_vec(candidate).unwrap();
                let assignment = Assignment {
                    public,
                    private: vec![],
                    proofs: vec![
                        Artifact::parse(&bytes).unwrap(),
                        Artifact::parse(&bytes).unwrap(),
                    ],
                };
                let result = prove_prepared(&trusted.fold, assignment, |_, _| {
                    Ok((
                        child,
                        std::iter::once(E::from_u32(bit))
                            .chain(sibling.map(E::from))
                            .collect(),
                    ))
                });
                if accepted {
                    result.unwrap();
                } else {
                    rejected(result);
                }
            }
            let parent = |left: &Artifact, right: &Artifact, height, change_root| {
                let mut root = merkle::hash(
                    merkle::NODE,
                    &left.public[1..9]
                        .iter()
                        .chain(&right.public[1..9])
                        .copied()
                        .collect::<Vec<_>>(),
                );
                if change_root {
                    root[0] ^= 1;
                }
                let public = std::iter::once(height)
                    .chain(root)
                    .chain(trusted.root)
                    .collect();
                let proofs = [left, right]
                    .into_iter()
                    .map(|proof| Artifact::parse(&serde_json::to_vec(proof).unwrap()).unwrap())
                    .collect();
                prove_prepared(
                    &trusted.fold,
                    Assignment {
                        public,
                        private: vec![],
                        proofs,
                    },
                    |_, child| {
                        let (prepared, bit, sibling) = if child.circuit == trusted.join.id {
                            (&trusted.join, 0, trusted.keys[1])
                        } else {
                            assert_eq!(child.circuit, trusted.fold.id);
                            (&trusted.fold, 1, trusted.keys[0])
                        };
                        Ok((
                            prepared,
                            std::iter::once(E::from_u32(bit))
                                .chain(sibling.map(E::from))
                                .collect(),
                        ))
                    },
                )
            };
            let folded = parent(&proof, &proof, 2, false).unwrap();
            parent(&folded, &folded, 3, false).unwrap();
            rejected(parent(&proof, &proof, 2, true));
            rejected(parent(&proof, &proof, 3, false));
            rejected(parent(&proof, &folded, 2, false));
        });
}

fn rejected(result: Result<Artifact, Error>) {
    assert!(
        matches!(
            &result,
            Err(Error::Circuit(
                p3_circuit::CircuitError::WitnessConflict { .. }
            ))
        ),
        "unexpected rejection phase: {:?}",
        result.err()
    );
}
