#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "direct boundary observations"
)]
use p3_field::PrimeField32;
use proof_client_core::proof::{self as prover, Artifact, Circuit, Job, PublicInput, Source};
use serde_json::{Value, json};
use std::{collections::BTreeMap, num::NonZeroUsize, path::Path};
#[path = "support/circuits.rs"]
mod circuits;
fn public(words: &[u32]) -> PublicInput {
    PublicInput::parse(&serde_json::to_vec(words).unwrap()).unwrap()
}
fn circuit(source: &Value) -> Circuit {
    Circuit::parse(&serde_json::to_vec(source).unwrap()).unwrap()
}
fn square() -> Value {
    json!({"format":prover::FORMAT,"inputs":{"public":1,"private":1},"operations":[{"op":"mul","left":1,"right":1}],"constraints":[{"op":"equal","left":0,"right":2}]})
}
fn parent(slots: [usize; 2]) -> Value {
    json!({"format":prover::FORMAT,"inputs":{"public":10,"private":0},"operations":[
        {"op":"verify","verifier":"square.json","proof":slots[0],"circuit_id_wires":[2,3,4,5,6,7,8,9]},
        {"op":"verify","verifier":"square.json","proof":slots[1],"circuit_id_wires":[2,3,4,5,6,7,8,9]}
    ],"constraints":[{"op":"equal","left":0,"right":10},{"op":"equal","left":1,"right":11}]})
}
fn linked(parent: &Value) -> Result<Circuit, prover::Error> {
    circuits::link(
        "parent.json",
        &BTreeMap::from([
            ("parent.json".into(), parent.clone()),
            ("square.json".into(), square()),
        ]),
    )
}
#[test]
fn nonzero_witness_binds_the_independent_circuit_and_public_values() {
    let threads = NonZeroUsize::new(4).unwrap();
    let proof = prover::prove(
        Job::parse(
            circuit(&square()),
            public(&[49]),
            br#"{"private":[7],"proofs":[]}"#,
        )
        .unwrap(),
        threads,
    )
    .unwrap();
    let bytes = serde_json::to_vec(&proof).unwrap();
    for expected in [49, 50] {
        for attached in [49, 50] {
            let mut artifact: Value = serde_json::from_slice(&bytes).unwrap();
            artifact["public"][0] = json!(attached);
            let result = prover::verify(
                circuit(&square()),
                public(&[expected]),
                Artifact::parse(&serde_json::to_vec(&artifact).unwrap()).unwrap(),
                threads,
            );
            assert_eq!(result.is_ok(), expected == 49 && attached == 49);
        }
    }
    let mut foreign = square();
    foreign["operations"][0]["op"] = json!("add");
    let foreign_proof = prover::prove(
        Job::parse(
            circuit(&foreign),
            public(&[14]),
            br#"{"private":[7],"proofs":[]}"#,
        )
        .unwrap(),
        threads,
    )
    .unwrap();
    let mut forged: Value = serde_json::from_slice(&bytes).unwrap();
    forged["circuit_id"] = json!(foreign_proof.circuit_id());
    assert_eq!(
        prover::verify(circuit(&foreign), public(&[14]), foreign_proof, threads).unwrap(),
        [14]
    );
    assert!(
        prover::verify(
            circuit(&foreign),
            public(&[49]),
            Artifact::parse(&serde_json::to_vec(&forged).unwrap()).unwrap(),
            threads
        )
        .is_err()
    );
}
#[test]
fn assignment_and_circuit_boundaries() {
    for word in [0, p3_koala_bear::KoalaBear::ORDER_U32 - 1] {
        let witness = serde_json::to_vec(&json!({"private":[word],"proofs":[]})).unwrap();
        assert!(Job::parse(circuit(&square()), public(&[word]), &witness).is_ok());
    }
    for words in [json!([-1]), json!([p3_koala_bear::KoalaBear::ORDER_U32])] {
        assert!(PublicInput::parse(&serde_json::to_vec(&words).unwrap()).is_err());
    }
    for witness in [
        json!({"private":[],"proofs":[]}),
        json!({"private":[-1],"proofs":[]}),
        json!({"private":[p3_koala_bear::KoalaBear::ORDER_U32],"proofs":[]}),
    ] {
        assert!(
            Job::parse(
                circuit(&square()),
                public(&[49]),
                &serde_json::to_vec(&witness).unwrap()
            )
            .is_err()
        );
    }
    assert!(
        Job::parse(
            circuit(&square()),
            public(&[49, 50]),
            br#"{"private":[7],"proofs":[]}"#
        )
        .is_err()
    );
    assert!(
        Job::parse(
            circuit(&square()),
            public(&[49]),
            br#"{"private":[8],"private":[7],"proofs":[]}"#
        )
        .is_err()
    );
    for (pointer, bad) in [
        ("/operations/0/left", json!(2)),
        ("/format", json!("unsupported")),
    ] {
        let mut source = square();
        *source.pointer_mut(pointer).unwrap() = bad;
        assert!(Circuit::parse(&serde_json::to_vec(&source).unwrap()).is_err());
    }
    for slots in [[0, 1], [1, 0]] {
        for (pointer, replacement) in [
            ("/operations/0/proof", json!(slots[1])),
            ("/operations/0/proof", json!(2)),
            ("/operations/0/verifier", json!("missing")),
            ("/operations/0/circuit_id_wires", json!([2, 3, 4])),
            ("/operations/0/circuit_id_wires/0", json!(10)),
        ] {
            let mut invalid = parent(slots);
            *invalid.pointer_mut(pointer).unwrap() = replacement;
            assert!(linked(&invalid).is_err());
        }
    }
    let mut excessive = parent([0, 1]);
    let mut third = excessive["operations"][0].clone();
    third["proof"] = json!(2);
    excessive["operations"].as_array_mut().unwrap().push(third);
    assert!(linked(&excessive).is_err());
    assert!(
        Job::parse(
            linked(&parent([0, 1])).unwrap(),
            public(&[0; 10]),
            br#"{"private":[],"proofs":[]}"#
        )
        .is_err()
    );
}
#[test]
fn equality_lowering_handles_constants_and_reflexive_wires() {
    for (left, right, value) in [
        (0, 1, 0),
        (1, 0, 0),
        (0, 0, 7),
        (1, 1, 7),
        (0, 1, 7),
        (1, 0, 7),
    ] {
        let source = json!({"format":prover::FORMAT,"inputs":{"public":1,"private":0},"operations":[{"op":"constant","value":0}],"constraints":[{"op":"equal","left":left,"right":right}]});
        let proof = prover::prove(
            Job::parse(
                circuit(&source),
                public(&[value]),
                br#"{"private":[],"proofs":[]}"#,
            )
            .unwrap(),
            1.try_into().unwrap(),
        );
        assert_eq!(
            proof.is_ok(),
            left == right || value == 0,
            "equality({left},{right}): {:?}",
            proof.err()
        );
    }
}
#[test]
fn witness_errors_do_not_disclose_private_values() {
    let source = p3_circuit::CircuitError::WitnessConflict {
        witness_id: p3_circuit::WitnessId(0),
        existing: "PRIVATE_OLD_VALUE".into(),
        new: "PRIVATE_NEW_VALUE".into(),
        expr_ids: Vec::new(),
    };
    let error = prover::Error::Circuit(source);
    assert_eq!(error.to_string(), "circuit execution failed");
    assert_eq!(format!("{error:?}"), error.to_string());
}
#[test]
fn bit_range_constraints_reject_wraparound_at_the_proof_boundary() {
    for bits in 1..=30 {
        let source = json!({"format":prover::FORMAT,"inputs":{"public":1,"private":0},"operations":[],"constraints":[{"op":"bits","wire":0,"bits":bits}]});
        for (value, accepted) in [
            (0, true),
            ((1u32 << bits) - 1, true),
            (1u32 << bits, false),
            (p3_koala_bear::KoalaBear::ORDER_U32 - 1, false),
        ] {
            let result = prover::prove(
                Job::parse(
                    circuit(&source),
                    public(&[value]),
                    br#"{"private":[],"proofs":[]}"#,
                )
                .unwrap(),
                1.try_into().unwrap(),
            );
            assert_eq!(result.is_ok(), accepted, "range {bits}, value {value}");
        }
    }
}
proptest::proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(3))]
    #[test]
    fn explicit_proof_slots_bind_order_keys_and_child_statements(value in 1u32..(p3_koala_bear::KoalaBear::ORDER_U32 / 2)) {
        let threads = NonZeroUsize::new(4).unwrap();
        let proofs = [value, value + 1].map(|v| {
            let squared =
                ((u64::from(v) * u64::from(v)) % u64::from(p3_koala_bear::KoalaBear::ORDER_U32)) as u32;
            prover::prove(
                Job::parse(
                    circuit(&square()),
                    public(&[squared]),
                    &serde_json::to_vec(&json!({"private":[v],"proofs":[]})).unwrap(),
                )
                .unwrap(),
                threads,
            )
            .unwrap()
        });
        for slots in [[0, 1], [1, 0]] {
            let source = parent(slots);
            let statement = [proofs[slots[0]].public()[0], proofs[slots[1]].public()[0]]
                .into_iter()
                .chain(*proofs[0].circuit_id().words())
                .collect::<Vec<_>>();
            let witness = serde_json::to_vec(&json!({"private":[],"proofs":proofs})).unwrap();
            prover::with_session(linked(&source).unwrap(), threads, |session| {
                let path = Path::new("parent.json");
                let proof = session.prove(path, public(&statement), &witness)?;
                assert_eq!(session.verify(path, public(&statement), proof)?, statement);
                let mut wrong_id = statement.clone();
                wrong_id[2] ^= 1;
                assert!(session.prove(path, public(&wrong_id), &witness).is_err());
                let swapped =
                    serde_json::to_vec(&json!({"private":[],"proofs":[proofs[1],proofs[0]]}))?;
                assert!(session.prove(path, public(&statement), &swapped).is_err());
                Ok(())
            })
            .unwrap();
        }
    }
}
#[test]
fn source_links_reject_missing_cycles_and_incompatible_contracts() {
    let documents = circuits::documents();
    circuits::link("base.json", &documents).unwrap();
    for entry in ["merge-bases.json", "merge-recursive.json"] {
        circuits::link(entry, &documents).unwrap();
        for (file, pointer, value) in [
            (
                "merge-verifier.json",
                "/circuits/1",
                json!("merge-bases.json"),
            ),
            (
                "merge-verifier.json",
                "/circuits",
                json!(["merge-recursive.json", "merge-bases.json"]),
            ),
            (
                "merge-verifier.json",
                "/verifier_set_id_positions/0",
                json!(25),
            ),
            (
                "merge-verifier.json",
                "/verifier_set_id_positions/0",
                json!(18),
            ),
            ("merge-verifier.json", "/layout/alu", json!(19)),
            (
                "merge-bases.json",
                "/operations/0/verifier",
                json!("merge-verifier.json"),
            ),
            ("merge-recursive.json", "/inputs/public", json!(24)),
            ("merge-bases.json", "/verifier_set", json!(null)),
            ("merge-recursive.json", "/verifier_set", json!(null)),
            (
                "merge-bases.json",
                "/operations/0/verifier",
                json!("missing.json"),
            ),
            (
                "merge-bases.json",
                "/operations/0/verifier",
                json!("merge-recursive.json"),
            ),
            ("merge-bases.json", "/verifier_set", json!("base.json")),
        ] {
            let mut invalid = documents.clone();
            *invalid
                .get_mut(Path::new(file))
                .unwrap()
                .pointer_mut(pointer)
                .unwrap() = value;
            assert!(
                circuits::link(entry, &invalid).is_err(),
                "{entry}: {file}{pointer}"
            );
        }
    }
    let mut recursive = parent([0, 1]);
    recursive["operations"][0]["verifier"] = json!("parent.json");
    assert!(linked(&recursive).is_err());
    let mut missing = documents;
    missing.remove(Path::new("base.json"));
    assert!(circuits::link("merge-recursive.json", &missing).is_err());
}
#[test]
fn preparation_is_independent_of_filenames_formatting_and_threads() {
    let source = parent([0, 1]);
    let first = prover::prepare(linked(&source).unwrap(), 1.try_into().unwrap()).unwrap();
    let mut renamed = source;
    for operation in renamed["operations"].as_array_mut().unwrap() {
        operation["verifier"] = json!("renamed.json");
    }
    let graph = Circuit::link(
        "root.json".into(),
        BTreeMap::from([
            (
                "root.json".into(),
                Source::parse(&serde_json::to_vec_pretty(&renamed).unwrap()).unwrap(),
            ),
            (
                "renamed.json".into(),
                Source::parse(&serde_json::to_vec_pretty(&square()).unwrap()).unwrap(),
            ),
        ]),
    )
    .unwrap();
    let second = prover::prepare(graph, 4.try_into().unwrap()).unwrap();
    assert_eq!(first.circuit_id(), second.circuit_id());
    assert_eq!(
        first.circuits()[Path::new("square.json")],
        second.circuits()[Path::new("renamed.json")]
    );
}
#[test]
fn source_admission_bounds_bytes_and_document_count() {
    let leaf = square();
    let mut source = serde_json::to_vec(&leaf).unwrap();
    source.resize(prover::MAX_INPUT_BYTES, b' ');
    Circuit::parse(&source).unwrap();
    source.push(b' ');
    assert!(Circuit::parse(&source).is_err());
    assert!(Source::parse(&source).is_err());
    for count in [prover::MAX_SOURCES, prover::MAX_SOURCES + 1] {
        let sources = (0..count)
            .map(|i| {
                Ok((
                    format!("{i}.json").into(),
                    Source::parse(&serde_json::to_vec(&leaf).unwrap())?,
                ))
            })
            .collect::<Result<_, prover::Error>>()
            .unwrap();
        assert_eq!(
            Circuit::link("0.json".into(), sources).is_ok(),
            count == prover::MAX_SOURCES
        );
    }
}

#[test]
fn dependency_depth_includes_previously_visited_subgraphs() {
    for depth in 0..=4 {
        let mut documents = BTreeMap::from([("leaf.json".into(), square())]);
        for index in (0..depth).rev() {
            let next = if index + 1 == depth {
                "leaf.json".to_owned()
            } else {
                format!("{}.json", index + 1)
            };
            let source = json!({"format":prover::FORMAT,"inputs":{"public":8,"private":0},"operations":[
                {"op":"verify","verifier":"leaf.json","proof":0,"circuit_id_wires":[0,1,2,3,4,5,6,7]},
                {"op":"verify","verifier":next,"proof":1,"circuit_id_wires":[0,1,2,3,4,5,6,7]}
            ],"constraints":[]});
            documents.insert(format!("{index}.json").into(), source);
        }
        let entry = if depth == 0 { "leaf.json" } else { "0.json" };
        assert_eq!(circuits::link(entry, &documents).is_ok(), depth <= 3);
    }
}
