#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "public cryptographic observations are direct"
)]
use proof_client_core::proof::{
    self as prover,
    family::{self, Circuit, Job},
};
use serde_json::{Value, json};
#[path = "../../../examples/merkle/support/merkle.rs"]
#[allow(dead_code)]
mod merkle;
mod support;
#[test]
#[ignore = "worker for the bounded eight-leaf family gate"]
fn family_worker() -> Result<(), proof_client_core::proof::Error> {
    let source: Value =
        serde_json::from_slice(include_bytes!("../../../examples/merkle/family.json")).unwrap();
    let started = std::time::Instant::now();
    let run = |session: &family::Session| {
        eprintln!("family preparation: {:?}", started.elapsed());
        let base_started = std::time::Instant::now();
        let description = session.description();
        let family: Vec<u32> = serde_json::from_value(description["family"].clone()).unwrap();
        let mut level = Vec::new();
        for index in 0..8 {
            let job = merkle::leaf(index);
            let mut circuit = source.clone();
            circuit["entry"] = json!("base");
            level.push(family::prove(
                Job::parse(
                    Circuit::parse(&serde_json::to_vec(&circuit)?)?,
                    &serde_json::to_vec(&job)?,
                )?,
                4.try_into().unwrap(),
            )?);
        }
        eprintln!(
            "eight base proofs (standalone preparation): {:?}",
            base_started.elapsed()
        );
        for height in 1..=3 {
            let phase_started = std::time::Instant::now();
            let mut parents = Vec::new();
            for pair in level.as_chunks::<2>().0 {
                let root = merkle::hash(
                    merkle::NODE,
                    &pair
                        .iter()
                        .flat_map(|p| p.public()[1..9].iter().copied())
                        .collect::<Vec<_>>(),
                );
                let public = std::iter::once(height)
                    .chain(root)
                    .chain(family.iter().copied())
                    .collect::<Vec<_>>();
                let mut source = source.clone();
                source["entry"] = json!(if height == 1 { "join" } else { "fold" });
                let job = json!({"public":public,"private":[],"proofs":pair});
                let proof = session.prove(Job::parse(
                    Circuit::parse(&serde_json::to_vec(&source)?)?,
                    &serde_json::to_vec(&job)?,
                )?)?;
                let role = if height == 1 { "join" } else { "fold" };
                assert_eq!(
                    proof.circuit(),
                    description["members"][role].as_str().unwrap()
                );
                parents.push(proof);
            }
            level = parents;
            eprintln!("height {height} proofs: {:?}", phase_started.elapsed());
        }
        let expected = merkle::expected(3)
            .into_iter()
            .chain(family)
            .collect::<Vec<_>>();
        let proof = level.pop().unwrap();
        assert_eq!(proof.public(), expected);
        assert_eq!(
            proof.public().len(),
            17,
            "only height, root and family are public"
        );
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
            expected,
            "the proof tables must expose no additional witness values"
        );

        let bytes = serde_json::to_vec(&proof)?;
        assert_eq!(
            session.verify(
                Circuit::parse(&serde_json::to_vec(&source)?)?,
                prover::Artifact::parse(&bytes)?
            )?,
            expected
        );
        Ok((proof, expected))
    };
    let (proof, expected) = family::with_session(
        Circuit::parse(&serde_json::to_vec(&source).unwrap()).unwrap(),
        4.try_into().unwrap(),
        run,
    )
    .unwrap();
    let verify_started = std::time::Instant::now();
    assert_eq!(
        family::verify(
            Circuit::parse(&serde_json::to_vec(&source)?)?,
            proof,
            1.try_into().unwrap()
        )?,
        expected
    );
    eprintln!(
        "independent final preparation and verification: {:?}",
        verify_started.elapsed()
    );
    let circuit: Value =
        serde_json::from_slice(include_bytes!("../../../examples/merkle/circuit.json"))?;
    let witness: Value =
        serde_json::from_slice(include_bytes!("../../../examples/merkle/leaves.json"))?;
    let public = &expected[1..9];
    let direct = prover::prove(
        prover::Job::parse(
            prover::Circuit::parse(&serde_json::to_vec(&circuit)?)?,
            &serde_json::to_vec(
                &json!({"public":public,"private":witness["private"],"proofs":[]}),
            )?,
        )?,
        1.try_into().unwrap(),
    )?;
    assert_eq!(
        direct.public(),
        public,
        "recursive and direct trees must agree"
    );
    Ok(())
}

#[test]
#[ignore = "bounded eight-leaf fixed-family proof admission"]
fn eight_leaf_family() {
    // Policy: match the CLI process budget.
    support::worker("family_worker", std::time::Duration::from_secs(600));
}
