#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test observations are direct"
)]
use proof_client_core::proof::{self as prover, Artifact};
use proof_client_core::proof::{Circuit, Job};
use serde_json::json;
use std::num::NonZeroUsize;
#[test]
fn nonzero_witness_binds_the_independent_circuit_and_public_values() {
    let circuit = json!({"format":prover::FORMAT,"inputs":{"public":1,"private":1},"operations":[{"op":"mul","left":1,"right":1}],"constraints":[{"op":"equal","left":0,"right":2}]});
    let job = json!({"public":[49],"private":[7],"proofs":[]});
    let threads = NonZeroUsize::new(4).unwrap();
    let proof = prover::prove(
        Job::parse(
            Circuit::parse(&serde_json::to_vec(&circuit).unwrap()).unwrap(),
            &serde_json::to_vec(&job).unwrap(),
        )
        .unwrap(),
        threads,
    )
    .unwrap();
    let bytes = serde_json::to_vec(&proof).unwrap();
    let source = serde_json::to_vec(&circuit).unwrap();
    assert_eq!(
        prover::verify(
            Circuit::parse(&source).unwrap(),
            Artifact::parse(&bytes).unwrap(),
            threads
        )
        .unwrap(),
        vec![49]
    );
    let mut tampered: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    tampered["public"][0] = json!(50);
    assert!(
        prover::verify(
            Circuit::parse(&source).unwrap(),
            Artifact::parse(&serde_json::to_vec(&tampered).unwrap()).unwrap(),
            threads
        )
        .is_err()
    );
    let mut foreign = circuit.clone();
    foreign["operations"][0]["op"] = json!("add");
    let mut forged: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let foreign = serde_json::to_vec(&foreign).unwrap();
    let foreign_job = Job::parse(
        Circuit::parse(&foreign).unwrap(),
        br#"{"public":[14],"private":[7],"proofs":[]}"#,
    )
    .unwrap();
    let foreign_proof = prover::prove(foreign_job, threads).unwrap();
    forged["circuit"] = json!(foreign_proof.circuit());
    let different =
        prover::verify(Circuit::parse(&foreign).unwrap(), foreign_proof, threads).unwrap();
    assert_ne!(different, vec![49]);
    assert!(
        prover::verify(
            Circuit::parse(&foreign).unwrap(),
            Artifact::parse(&serde_json::to_vec(&forged).unwrap()).unwrap(),
            threads
        )
        .is_err()
    );
}

proptest::proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(16))]
    #[test]
    fn canonical_inputs_and_wires_are_checked_at_admission(word in 0u32..2_130_706_433) {
        let circuit=json!({"format":prover::FORMAT,"inputs":{"public":1,"private":1},"operations":[{"op":"add","left":1,"right":1}],"constraints":[{"op":"equal","left":0,"right":2}]});
        let valid=json!({"public":[word],"private":[word],"proofs":[]});
        proptest::prop_assert!(Job::parse(Circuit::parse(&serde_json::to_vec(&circuit).unwrap()).unwrap(), &serde_json::to_vec(&valid).unwrap()).is_ok());
    }
}

#[test]
fn malformed_assignments_and_circuit_shapes_are_rejected() {
    let circuit = json!({"format":prover::FORMAT,"inputs":{"public":1,"private":1},"operations":[{"op":"add","left":1,"right":1}],"constraints":[{"op":"equal","left":0,"right":2}]});
    let valid = json!({"public":[0],"private":[0],"proofs":[]});
    for (pointer, bad) in [
        ("/public/0", json!(2_130_706_433u32)),
        ("/private/0", json!(-1)),
        ("/private", json!([])),
    ] {
        let mut invalid = valid.clone();
        *invalid.pointer_mut(pointer).unwrap() = bad;
        assert!(
            Job::parse(
                Circuit::parse(&serde_json::to_vec(&circuit).unwrap()).unwrap(),
                &serde_json::to_vec(&invalid).unwrap()
            )
            .is_err()
        );
    }
    for (pointer, bad) in [
        ("/operations/0/left", json!(2)),
        ("/format", json!("unsupported")),
    ] {
        let mut invalid = circuit.clone();
        *invalid.pointer_mut(pointer).unwrap() = bad;
        assert!(Circuit::parse(&serde_json::to_vec(&invalid).unwrap()).is_err());
    }
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
        let circuit = json!({"format":prover::FORMAT,"inputs":{"public":1,"private":0},"operations":[{"op":"constant","value":0}],"constraints":[{"op":"equal","left":left,"right":right}]});
        let job = json!({"public":[value],"private":[],"proofs":[]});
        let proof = prover::prove(
            Job::parse(
                Circuit::parse(&serde_json::to_vec(&circuit).unwrap()).unwrap(),
                &serde_json::to_vec(&job).unwrap(),
            )
            .unwrap(),
            NonZeroUsize::new(1).unwrap(),
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
    let error = proof_client_core::proof::Error::Circuit(source);
    assert_eq!(error.to_string(), "circuit execution failed");
    assert_eq!(format!("{error:?}"), error.to_string());
}

#[test]
fn bit_range_constraints_reject_wraparound_at_the_proof_boundary() {
    let threads = NonZeroUsize::new(1).unwrap();
    for bits in 1..=30 {
        let circuit = json!({"format":prover::FORMAT,"inputs":{"public":1,"private":0},"operations":[],"constraints":[{"op":"bits","wire":0,"bits":bits}]});
        for (value, accepted) in [
            (0, true),
            ((1u32 << bits) - 1, true),
            (1u32 << bits, false),
            (2_130_706_432, false),
        ] {
            let job = json!({"public":[value],"private":[],"proofs":[]});
            let result = prover::prove(
                Job::parse(
                    Circuit::parse(&serde_json::to_vec(&circuit).unwrap()).unwrap(),
                    &serde_json::to_vec(&job).unwrap(),
                )
                .unwrap(),
                threads,
            );
            assert_eq!(result.is_ok(), accepted, "range {bits}, value {value}");
        }
    }
}
