#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "adversarial controls bypass honest witness checks"
)]
use super::*;
use crate::proof::{
    program::{Job, Session, prove},
    source::{Circuit, FORMAT, Source},
};
use serde_json::json;
use std::{collections::BTreeMap, num::NonZeroUsize};

fn source(factor: u32) -> serde_json::Value {
    json!({"format":FORMAT,"inputs":{"public":1,"private":1},"operations":[{"op":"constant","value":factor},{"op":"mul","left":1,"right":2}],"constraints":[{"op":"equal","left":0,"right":3}]})
}
fn artifact(circuit: serde_json::Value, value: u32) -> Artifact {
    prove(
        Job::parse(
            Circuit::parse(&serde_json::to_vec(&circuit).unwrap()).unwrap(),
            PublicInput::parse(&serde_json::to_vec(&[value]).unwrap()).unwrap(),
            br#"{"private":[7],"proofs":[]}"#,
        )
        .unwrap(),
        NonZeroUsize::new(4).unwrap(),
    )
    .unwrap()
}
fn prepared(value: serde_json::Value, children: BTreeMap<std::path::PathBuf, Source>) -> Prepared {
    let mut sources = children;
    sources.insert(
        "circuit.json".into(),
        Source::parse(&serde_json::to_vec(&value).unwrap()).unwrap(),
    );
    Session::new(Circuit::link("circuit.json".into(), sources).unwrap())
        .unwrap()
        .prepared
        .remove(std::path::Path::new("circuit.json"))
        .unwrap()
}

#[test]
fn parent_rejects_foreign_preprocessing_without_host_verification() {
    let trusted_proof = artifact(source(7), 49);
    let foreign_proof = artifact(source(8), 56);
    rayon::ThreadPoolBuilder::new()
        .num_threads(4)
        .build()
        .unwrap()
        .install(|| {
            let trusted = prepared(source(7), BTreeMap::new());
            let foreign = prepared(source(8), BTreeMap::new());
            let parent = prepared(
                json!({
                    "format": FORMAT,
                    "inputs": {"public": 9, "private": 0},
                    "operations": [{"op": "verify", "verifier": "child.json", "proof": 0,
                        "circuit_id_wires": [1,2,3,4,5,6,7,8]}],
                    "constraints": [{"op": "equal", "left": 0, "right": 9}]
                }),
                BTreeMap::from([(
                    "child.json".into(),
                    Source::parse(&serde_json::to_vec(&source(7)).unwrap()).unwrap(),
                )]),
            );
            assert!(matches!(
                checked_values(&foreign_proof, &trusted),
                Err(Error::Statement)
            ));
            for (child, proof, accepted) in [
                (&trusted, &trusted_proof, true),
                (&foreign, &foreign_proof, false),
            ] {
                let expected = proof
                    .public
                    .iter()
                    .copied()
                    .chain(*trusted.id.words())
                    .collect::<Vec<_>>();
                assert_recursive_constraints(
                    &parent,
                    &expected,
                    &[(child, proof, vec![])],
                    accepted,
                );
            }
        });
}
#[test]
fn coefficient_constraints_reject_extension_field_witnesses() {
    use p3_field::{BasedVectorSpace, Field};
    rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .build()
        .unwrap()
        .install(|| {
            let definition = json!({
                "format": FORMAT,
                "inputs": {"public": 1, "private": 2},
                "operations": [{"op": "mul", "left": 1, "right": 2}],
                "constraints": [{"op": "equal", "left": 0, "right": 3}]
            });
            let prepared = prepared(definition, BTreeMap::new());
            for (left, accepted) in [
                (E::from_u32(7), true),
                (
                    <E as BasedVectorSpace<F>>::ith_basis_element(1).unwrap(),
                    false,
                ),
            ] {
                let circuit = dishonest(&prepared.circuit);
                let mut runner = circuit.runner();
                runner
                    .set_private_inputs(&[E::ONE, left, left.inverse()])
                    .unwrap();
                let traces = runner.run().unwrap();
                let check = || {
                    let proof = engine::prover(engine::private_config().unwrap(), &prepared.schema)
                        .with_debug_lookups()
                        .prove_all_tables(&traces, &prepared.prover.prover_data())
                        .unwrap();
                    prepared
                        .prover
                        .verifier()
                        .verify(&proof, &[F::ONE])
                        .unwrap();
                };
                if accepted {
                    check();
                } else {
                    rejected_constraints(check);
                }
            }
        });
}

// Hints bypass witness reassignment checks without changing the prepared relation.
pub(super) fn dishonest(source: &Compiled<E>) -> Compiled<E> {
    use p3_circuit::{Op, WitnessId, ops::HintExecutor};
    #[derive(Debug, Clone)]
    struct Forget;
    impl HintExecutor<E> for Forget {
        fn execute(
            &self,
            inputs: &[WitnessId],
            outputs: &[WitnessId],
            witness: &mut [Option<E>],
        ) -> Result<(), p3_circuit::CircuitError> {
            if inputs.iter().all(|id| witness[id.0 as usize].is_some()) {
                for index in outputs {
                    witness[index.0 as usize] = None;
                }
            }
            Ok(())
        }
        fn boxed(&self) -> Box<dyn HintExecutor<E>> {
            Box::new(self.clone())
        }
    }
    #[derive(Debug)]
    struct UncheckedHint(Box<dyn HintExecutor<E>>);
    impl HintExecutor<E> for UncheckedHint {
        fn execute(
            &self,
            inputs: &[WitnessId],
            outputs: &[WitnessId],
            witness: &mut [Option<E>],
        ) -> Result<(), p3_circuit::CircuitError> {
            // Run the real hint with distinct output slots, then permit conflicting bus assignments.
            let mut local = inputs
                .iter()
                .map(|id| witness[id.0 as usize])
                .chain(std::iter::repeat_n(None, outputs.len()))
                .collect::<Vec<_>>();
            let local_inputs = (0..inputs.len())
                .map(|i| WitnessId(i as u32))
                .collect::<Vec<_>>();
            let local_outputs = (inputs.len()..local.len())
                .map(|i| WitnessId(i as u32))
                .collect::<Vec<_>>();
            self.0.execute(&local_inputs, &local_outputs, &mut local)?;
            for (id, value) in outputs.iter().zip(local.into_iter().skip(inputs.len())) {
                witness[id.0 as usize] = value;
            }
            Ok(())
        }
        fn boxed(&self) -> Box<dyn HintExecutor<E>> {
            Box::new(Self(self.0.boxed()))
        }
    }
    let mut circuit = source.clone();
    circuit.ops = source
        .ops
        .iter()
        .flat_map(|op| {
            let outputs = match op {
                Op::Const { out, .. } => vec![*out],
                Op::Public { .. } => vec![],
                Op::Alu {
                    kind,
                    a,
                    b,
                    c,
                    out,
                    intermediate_out,
                } => std::iter::once(*out)
                    .chain(intermediate_out.filter(|_| *kind == p3_circuit::AluOpKind::MulAdd))
                    .filter(|id| *id != *a && *id != *b && Some(*id) != *c)
                    .collect(),
                Op::Hint { .. } => vec![],
                Op::NonPrimitiveOpWithExecutor {
                    inputs, outputs, ..
                } => outputs
                    .iter()
                    .flatten()
                    .filter(|id| !inputs.iter().flatten().any(|input| input == *id))
                    .copied()
                    .collect(),
            };
            let inputs = match op {
                Op::Const { .. } | Op::Public { .. } => vec![],
                Op::Alu {
                    kind,
                    a,
                    b,
                    c,
                    intermediate_out,
                    ..
                } => [*a, *b]
                    .into_iter()
                    .chain(*c)
                    .chain(intermediate_out.filter(|_| *kind == p3_circuit::AluOpKind::HornerAcc))
                    .collect(),
                Op::Hint { inputs, .. } => inputs.clone(),
                Op::NonPrimitiveOpWithExecutor { inputs, .. } => {
                    inputs.iter().flatten().copied().collect()
                }
            };
            [
                Op::Hint {
                    inputs,
                    outputs,
                    executor: Box::new(Forget),
                },
                match op {
                    Op::Hint {
                        inputs,
                        outputs,
                        executor,
                    } => Op::Hint {
                        inputs: inputs.clone(),
                        outputs: outputs.clone(),
                        executor: Box::new(UncheckedHint(executor.boxed())),
                    },
                    _ => op.clone(),
                },
            ]
        })
        .collect();
    circuit.ops.push(Op::Hint {
        inputs: vec![],
        outputs: circuit
            .witness_rewrite
            .iter()
            .flat_map(|rewrite| rewrite.keys())
            .copied()
            .collect(),
        executor: Box::new(Forget),
    });
    circuit
}

pub(super) fn rejected_constraints(run: impl FnOnce()) {
    let error = std::panic::catch_unwind(std::panic::AssertUnwindSafe(run)).unwrap_err();
    let message = error
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| error.downcast_ref::<&str>().copied())
        .unwrap();
    assert!(
        message.starts_with("Lookup mismatch")
            || message.starts_with("constraints not satisfied on row "),
        "{message}"
    );
}

pub(in crate::proof) fn assert_recursive_constraints(
    parent: &Prepared,
    statement: &[u32],
    children: &[(&Prepared, &Artifact, Vec<E>)],
    accepted: bool,
) {
    let circuit = dishonest(&parent.circuit);
    let mut runner = circuit.runner();
    let mut public = Vec::new();
    let mut private = statement
        .iter()
        .copied()
        .map(E::from_u32)
        .collect::<Vec<_>>();
    for (wiring, (child, proof, extra)) in parent.wiring.iter().zip(children) {
        let verifier = child.prover.verifier();
        let values = proof.public.iter().copied().map(F::new).collect::<Vec<_>>();
        let (a, b) = wiring
            .inputs
            .try_pack_values(
                &verifier.table_public_values(&values).unwrap(),
                &proof.proof.proof,
                verifier.common_data(),
            )
            .unwrap();
        public.extend(a);
        private.extend(b);
        private.extend(extra);
        <Backend as TrustedPcsRecursionBackend<Config, BatchOnly, 4>>::set_private_data_for_trusted_batch(
            &engine::backend(), &verifier, &proof.proof, &values, &mut runner, &wiring.ops,
        ).unwrap();
    }
    runner.set_public_inputs(&public).unwrap();
    runner.set_private_inputs(&private).unwrap();
    let traces = runner.run().unwrap();
    let check = || {
        let proof = engine::prover(engine::private_config().unwrap(), &parent.schema)
            .with_table_packing(parent.prover.verifier().relation().table_packing().clone())
            .with_debug_lookups()
            .prove_all_tables(&traces, &parent.prover.prover_data())
            .unwrap();
        let values = statement.iter().copied().map(F::new).collect::<Vec<_>>();
        parent.prover.verifier().verify(&proof, &values).unwrap();
    };
    if accepted {
        check();
    } else {
        rejected_constraints(check);
    }
}
