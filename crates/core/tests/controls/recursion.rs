#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "negative controls intentionally bypass honest host admission"
)]
use super::*;
use crate::proof::{compiler::tests::assert_recursive_constraints, identity::descriptor};
use serde_json::{Value, json};
use std::path::Path;
#[path = "../support/circuits.rs"]
mod circuits;
#[path = "../../../../examples/merkle/support/merkle.rs"]
#[allow(dead_code)]
mod merkle;
fn child(session: &mut Session, source: &BTreeMap<PathBuf, Value>, set_id: [u32; 8]) -> Artifact {
    let leaves = (0..2)
        .map(|index| {
            let (_, private) = merkle::leaf(index);
            // Preserve the foreign-domain control.
            let tag = source[Path::new("base.json")]["operations"][0]["tag"]
                .as_u64()
                .unwrap() as u32;
            let public = json!(
                std::iter::once(0)
                    .chain(merkle::hash(tag, &private))
                    .collect::<Vec<_>>()
            );
            session
                .prove(
                    Path::new("base.json"),
                    PublicInput::parse(&serde_json::to_vec(&public).unwrap()).unwrap(),
                    &serde_json::to_vec(&json!({"private":private,"proofs":[]})).unwrap(),
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
    let base = &session.prepared[Path::new("base.json")];
    let base_id = base.id;
    let public = std::iter::once(1)
        .chain(root)
        .chain(*base_id.words())
        .chain(set_id)
        .collect();
    // Remove host policy only; the prepared relation remains unchanged.
    let bindings = std::mem::take(
        &mut session
            .prepared
            .get_mut(Path::new("merge-bases.json"))
            .unwrap()
            .bindings,
    );
    let proof = prove_prepared(
        &session.prepared[Path::new("merge-bases.json")],
        Assignment {
            public,
            private: vec![],
            proofs: leaves,
        },
        |_, _| Ok((&session.prepared[Path::new("base.json")], vec![])),
    )
    .unwrap();
    session
        .prepared
        .get_mut(Path::new("merge-bases.json"))
        .unwrap()
        .bindings = bindings;
    proof
}
#[test]
#[ignore = "real verifier-set foreign-key and membership controls"]
fn verifier_set_membership_is_enforced_without_host_admission() {
    rayon::ThreadPoolBuilder::new()
        .num_threads(4)
        .build()
        .unwrap()
        .install(|| {
            let source = circuits::documents();
            let mut trusted =
                Session::new(circuits::link("merge-recursive.json", &source).unwrap()).unwrap();
            let trusted_root = *trusted.sets[Path::new("merge-verifier.json")].words();
            let proof = child(&mut trusted, &source, trusted_root);
            let mut changed = source.clone();
            changed.get_mut(Path::new("base.json")).unwrap()["operations"][0]["tag"] =
                json!(0x504d_0103);
            let mut foreign =
                Session::new(circuits::link("merge-recursive.json", &changed).unwrap()).unwrap();
            assert_eq!(
                descriptor(
                    &trusted.prepared[Path::new("merge-bases.json")]
                        .prover
                        .verifier()
                )
                .unwrap(),
                descriptor(
                    &foreign.prepared[Path::new("merge-bases.json")]
                        .prover
                        .verifier()
                )
                .unwrap()
            );
            let foreign_root = *foreign.sets[Path::new("merge-verifier.json")].words();
            let foreign_proof = child(&mut foreign, &changed, trusted_root);
            let mismatched = child(&mut trusted, &source, foreign_root);
            let wrapper = Source::parse(
                &serde_json::to_vec(&json!({
                    "format": crate::proof::FORMAT,
                    "inputs": {"public": 8, "private": 0},
                    "operations": [{"op": "verify", "verifier": "merge-bases.json", "proof": 0,
                        "circuit_id_wires": [0,1,2,3,4,5,6,7]}],
                    "constraints": []
                }))
                .unwrap(),
            )
            .unwrap();
            let Source::Circuit(wrapper) = wrapper else {
                unreachable!()
            };
            let wrapper = compiler::compile(&wrapper, &trusted.prepared, engine::prepare).unwrap();
            let member = &trusted.prepared[Path::new("merge-bases.json")];
            for (candidate, accepted) in [(&proof, true), (&mismatched, false)] {
                assert_eq!(checked_values(candidate, member).is_ok(), accepted);
                assert_recursive_constraints(
                    &wrapper,
                    member.id.words(),
                    &[(member, candidate, vec![])],
                    accepted,
                );
            }
            for (candidate, child, bit, sibling, id, accepted) in [
                (
                    &proof,
                    &trusted.prepared[Path::new("merge-bases.json")],
                    0,
                    trusted.prepared[Path::new("merge-recursive.json")]
                        .id
                        .words()
                        .map(F::new),
                    trusted.prepared[Path::new("merge-bases.json")].id,
                    true,
                ),
                (
                    &foreign_proof,
                    &foreign.prepared[Path::new("merge-bases.json")],
                    0,
                    trusted.prepared[Path::new("merge-recursive.json")]
                        .id
                        .words()
                        .map(F::new),
                    foreign.prepared[Path::new("merge-bases.json")].id,
                    false,
                ),
                (
                    &mismatched,
                    &trusted.prepared[Path::new("merge-bases.json")],
                    0,
                    trusted.prepared[Path::new("merge-recursive.json")]
                        .id
                        .words()
                        .map(F::new),
                    trusted.prepared[Path::new("merge-bases.json")].id,
                    false,
                ),
                (
                    &proof,
                    &trusted.prepared[Path::new("merge-bases.json")],
                    1,
                    trusted.prepared[Path::new("merge-recursive.json")]
                        .id
                        .words()
                        .map(F::new),
                    trusted.prepared[Path::new("merge-bases.json")].id,
                    false,
                ),
                (
                    &proof,
                    &trusted.prepared[Path::new("merge-bases.json")],
                    2,
                    trusted.prepared[Path::new("merge-recursive.json")]
                        .id
                        .words()
                        .map(F::new),
                    trusted.prepared[Path::new("merge-bases.json")].id,
                    false,
                ),
                (
                    &proof,
                    &trusted.prepared[Path::new("merge-bases.json")],
                    0,
                    trusted.prepared[Path::new("merge-bases.json")]
                        .id
                        .words()
                        .map(F::new),
                    trusted.prepared[Path::new("merge-bases.json")].id,
                    false,
                ),
                (
                    &proof,
                    &trusted.prepared[Path::new("merge-bases.json")],
                    0,
                    trusted.prepared[Path::new("merge-recursive.json")]
                        .id
                        .words()
                        .map(F::new),
                    trusted.prepared[Path::new("merge-recursive.json")].id,
                    false,
                ),
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
                    .chain(*id.words())
                    .chain(*trusted.sets[Path::new("merge-verifier.json")].words())
                    .collect::<Vec<_>>();
                let extra = std::iter::once(E::from_u32(bit))
                    .chain(sibling.map(E::from))
                    .collect::<Vec<_>>();
                assert_recursive_constraints(
                    &trusted.prepared[Path::new("merge-recursive.json")],
                    &public,
                    &[(child, candidate, extra.clone()), (child, candidate, extra)],
                    accepted,
                );
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
                    .chain(*left.circuit_id.words())
                    .chain(*trusted.sets[Path::new("merge-verifier.json")].words())
                    .collect();
                let proofs = [left, right]
                    .into_iter()
                    .map(|proof| Artifact::parse(&serde_json::to_vec(proof).unwrap()).unwrap())
                    .collect();
                prove_prepared(
                    &trusted.prepared[Path::new("merge-recursive.json")],
                    Assignment {
                        public,
                        private: vec![],
                        proofs,
                    },
                    |_, child| {
                        let (prepared, bit, sibling) = if child.circuit_id
                            == trusted.prepared[Path::new("merge-bases.json")].id
                        {
                            (
                                &trusted.prepared[Path::new("merge-bases.json")],
                                0,
                                trusted.prepared[Path::new("merge-recursive.json")]
                                    .id
                                    .words()
                                    .map(F::new),
                            )
                        } else {
                            assert_eq!(
                                child.circuit_id,
                                trusted.prepared[Path::new("merge-recursive.json")].id
                            );
                            (
                                &trusted.prepared[Path::new("merge-recursive.json")],
                                1,
                                trusted.prepared[Path::new("merge-bases.json")]
                                    .id
                                    .words()
                                    .map(F::new),
                            )
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
