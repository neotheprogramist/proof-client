#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "adversarial controls bypass honest witness checks"
)]
use super::*;
use serde_json::json;

fn source(factor: u32) -> serde_json::Value {
    json!({"format":FORMAT,"inputs":{"public":1,"private":1},"operations":[{"op":"constant","value":factor},{"op":"mul","left":1,"right":2}],"constraints":[{"op":"equal","left":0,"right":3}]})
}
fn artifact(circuit: serde_json::Value, value: u32) -> Artifact {
    prove(
        Job::parse(
            Circuit::from_definition(serde_json::from_value(circuit).unwrap()).unwrap(),
            &serde_json::to_vec(&json!({"public":[value],"private":[7],"proofs":[]})).unwrap(),
        )
        .unwrap(),
        NonZeroUsize::new(4).unwrap(),
    )
    .unwrap()
}

#[test]
fn parent_rejects_foreign_preprocessing_without_host_verification() {
    let trusted_proof = artifact(source(7), 49);
    let foreign_proof = artifact(source(8), 56);
    rayon::ThreadPoolBuilder::new().num_threads(4).build().unwrap().install(|| {
        let trusted=compile(&serde_json::from_value(source(7)).unwrap()).unwrap();
        let foreign=compile(&serde_json::from_value(source(8)).unwrap()).unwrap();
        let parent=compile(&serde_json::from_value(json!({"format":FORMAT,"inputs":{"public":1,"private":0},"children":[source(7)],"operations":[{"op":"verify","child":0}],"constraints":[{"op":"equal","left":0,"right":1}]})).unwrap()).unwrap();
        assert!(matches!(checked_values(&foreign_proof,&trusted), Err(Error::Statement)));
        for (child, proof, accepted) in [(&trusted,&trusted_proof,true),(&foreign,&foreign_proof,false)] {
            let verifier=child.prover.verifier();
            let values=proof.public.iter().copied().map(F::new).collect::<Vec<_>>();
            let wiring=&parent.wiring[0];
            let (public,private)=wiring.inputs.try_pack_values(&verifier.table_public_values(&values).unwrap(),&proof.proof.proof,verifier.common_data()).unwrap();
            let circuit = dishonest(&parent.circuit);
            let mut runner=circuit.runner();
            runner.set_public_inputs(&public).unwrap();
            let private=values.iter().copied().map(E::from).chain(private).collect::<Vec<_>>();
            runner.set_private_inputs(&private).unwrap();
            <Backend as TrustedPcsRecursionBackend<Config, BatchOnly, 4>>::set_private_data_for_trusted_batch(&engine::backend(),&verifier,&proof.proof,&values,&mut runner,&wiring.ops).unwrap();
            let result = runner.run();
            if accepted {
                let traces = result.unwrap();
                let proof = engine::prover(engine::private_config().unwrap(), &parent.schema).prove_all_tables(&traces, &parent.prover.prover_data()).unwrap();
                parent.prover.verifier().verify(&proof, &values).unwrap();
            } else {
                let traces = result.unwrap();
                rejected_constraints(|| {
                    let proof = engine::prover(engine::private_config().unwrap(), &parent.schema)
                        .with_debug_lookups()
                        .prove_all_tables(&traces, &parent.prover.prover_data()).unwrap();
                    parent.prover.verifier().verify(&proof, &values).unwrap();
                });
            }

        }
    });
}
#[test]
fn coefficient_constraints_reject_extension_field_witnesses() {
    use p3_field::{BasedVectorSpace, Field};
    rayon::ThreadPoolBuilder::new().num_threads(1).build().unwrap().install(|| {
        let definition=serde_json::from_value(json!({"format":FORMAT,"inputs":{"public":1,"private":2},"operations":[{"op":"mul","left":1,"right":2}],"constraints":[{"op":"equal","left":0,"right":3}]})).unwrap();
        let prepared=compile(&definition).unwrap();
        for (left,accepted) in [(E::from_u32(7),true),(<E as BasedVectorSpace<F>>::ith_basis_element(1).unwrap(),false)] {
            let circuit = dishonest(&prepared.circuit);
            let mut runner=circuit.runner();
            runner.set_private_inputs(&[E::ONE,left,left.inverse()]).unwrap();
            let result = runner.run();
            if accepted {
                let traces = result.unwrap();
                let proof = engine::prover(engine::private_config().unwrap(), &prepared.schema).prove_all_tables(&traces, &prepared.prover.prover_data()).unwrap();
                prepared.prover.verifier().verify(&proof, &[F::ONE]).unwrap();
            } else {
                let traces = result.unwrap();
                rejected_constraints(|| {
                    engine::prover(engine::private_config().unwrap(), &prepared.schema)
                        .with_debug_lookups()
                        .prove_all_tables(&traces, &prepared.prover.prover_data()).unwrap();
                });
            }

        }
    });
}

// Hints bypass witness reassignment checks without changing the prepared relation.
fn dishonest(source: &Compiled<E>) -> Compiled<E> {
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
                op.clone(),
            ]
        })
        .collect();
    circuit.ops.push(Op::Hint {
        inputs: vec![],
        outputs: circuit.witness_rewrite.iter().flat_map(|rewrite| rewrite.keys()).copied().collect(),
        executor: Box::new(Forget),
    });
    circuit
}

fn rejected_constraints(run: impl FnOnce()) {
    let error = std::panic::catch_unwind(std::panic::AssertUnwindSafe(run)).unwrap_err();
    let message = error
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| error.downcast_ref::<&str>().copied())
        .unwrap();
    assert!(
        message.starts_with("Lookup mismatch") || message.starts_with("constraints not satisfied on row "),
        "{message}"
    );
}
