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
            let foreign_root = *foreign.sets[Path::new("merge-verifier.json")].words();
            let foreign_proof = child(&mut foreign, &changed, trusted_root);
            let mismatched = child(&mut trusted, &source, foreign_root);
            let member = &trusted.prepared[Path::new("merge-bases.json")];
            let foreign_member = &foreign.prepared[Path::new("merge-bases.json")];
            let recursive = &trusted.prepared[Path::new("merge-recursive.json")];
            let sibling = recursive.id.words().map(F::new);
            assert_eq!(
                descriptor(&member.prover.verifier()).unwrap(),
                descriptor(&foreign_member.prover.verifier()).unwrap()
            );
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
                (&proof, member, 0, sibling, member.id, true),
                (
                    &foreign_proof,
                    foreign_member,
                    0,
                    sibling,
                    foreign_member.id,
                    false,
                ),
                (&mismatched, member, 0, sibling, member.id, false),
                (&proof, member, 1, sibling, member.id, false),
                (&proof, member, 2, sibling, member.id, false),
                (
                    &proof,
                    member,
                    0,
                    member.id.words().map(F::new),
                    member.id,
                    false,
                ),
                (&proof, member, 0, sibling, recursive.id, false),
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
                    .chain(trusted_root)
                    .collect::<Vec<_>>();
                let extra = std::iter::once(E::from_u32(bit))
                    .chain(sibling.map(E::from))
                    .collect::<Vec<_>>();
                assert_recursive_constraints(
                    recursive,
                    &public,
                    &[(child, candidate, extra.clone()), (child, candidate, extra)],
                    accepted,
                );
            }
        });
}
