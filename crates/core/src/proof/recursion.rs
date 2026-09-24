use super::{
    Error,
    compiler::{self, Child, ChildTarget, Prepared, base_words, build, equal, statement_targets},
    config::Config,
    engine::{self, E, Inputs},
    identity::{KEY, VERIFIER_SET, descriptor, descriptor_words},
    shape,
    source::{Circuit, Source, Verification, VerifierSet},
};
use p3_circuit::{Circuit as Compiled, CircuitBuilder, ExprId, NonPrimitiveOpId, StatementSchema};
use p3_circuit_prover::{CircuitVerifier, PreparedCircuitProver, TablePacking};
use serde::Deserialize;
use std::{collections::BTreeMap, path::PathBuf};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Layout {
    constants: u8,
    public: u8,
    alu: u8,
    poseidon: u8,
    challenger: u8,
    recompose: u8,
}
impl Layout {
    pub(super) fn validate(&self) -> Result<(), Error> {
        // Policy: bound prepared table heights.
        if [
            self.constants,
            self.public,
            self.alu,
            self.poseidon,
            self.challenger,
            self.recompose,
        ]
        .iter()
        .any(|height| !(9..=18).contains(height))
        {
            return Err(Error::Shape);
        }
        Ok(())
    }
    fn packing(&self) -> TablePacking {
        let mut packing = engine::packing()
            .with_const_min_height(1 << self.constants)
            .with_public_min_height(1 << self.public)
            .with_alu_min_height(1 << self.alu)
            .with_npo_min_height(
                p3_circuit::ops::NpoTypeId::recompose_with_coeff_lookups(),
                1 << self.recompose,
            )
            .with_strict_heights();
        for (config, height) in [
            (engine::POSEIDON, self.poseidon),
            (engine::POSEIDON.for_challenger(), self.challenger),
            (
                engine::POSEIDON.for_shared_challenger_table(),
                self.challenger,
            ),
        ] {
            packing = packing.with_npo_min_height(
                p3_circuit::ops::NpoTypeId::poseidon2_perm(config),
                1 << height,
            );
        }
        packing
    }
    pub(super) fn prepare(
        &self,
        circuit: &Compiled<E>,
        schema: &StatementSchema,
    ) -> Result<PreparedCircuitProver<Config>, Error> {
        engine::prepare_packed(
            circuit,
            schema,
            engine::prover(engine::canonical_config()?, schema).with_table_packing(self.packing()),
        )
    }
}

pub(super) fn compile(
    source: &Circuit,
    set: &VerifierSet,
    prepared: &BTreeMap<PathBuf, Prepared>,
) -> Result<[Prepared; 2], Error> {
    let first = compiler::compile(
        source.definition(&set.circuits[0])?,
        prepared,
        |circuit, schema| set.layout.prepare(circuit, schema),
    )?;
    let template = first.prover.verifier();
    let second_source = source.definition(&set.circuits[1])?;
    let second = build(
        second_source,
        |builder, call, wires| match source.sources.get(&call.verifier) {
            Some(Source::Circuit(_)) => compiler::fixed_child(
                builder,
                call,
                wires,
                prepared.get(&call.verifier).ok_or(Error::Shape)?,
            ),
            Some(Source::VerifierSet(_)) => {
                let (inputs, ops, words) = allocate(
                    builder,
                    call,
                    wires,
                    &template,
                    &set.verifier_set_id_positions,
                )?;
                Ok((
                    Child {
                        target: ChildTarget::Set(set.circuits.clone()),
                        proof: call.proof,
                        inputs,
                        ops,
                    },
                    words,
                ))
            }
            None => Err(Error::Shape),
        },
        |circuit, schema| set.layout.prepare(circuit, schema),
    )?;
    if descriptor(&template)? != descriptor(&second.prover.verifier())? {
        return Err(Error::Shape);
    }
    Ok([first, second])
}
fn allocate(
    builder: &mut CircuitBuilder<E>,
    call: &Verification,
    wires: &[ExprId],
    template: &CircuitVerifier<Config>,
    positions: &[usize; 8],
) -> Result<(Inputs, Vec<NonPrimitiveOpId>, Vec<ExprId>), Error> {
    let public_count = template.statement_layout().schema().base_len();
    let key_descriptor = descriptor_words(template)?;
    let set_words = positions
        .iter()
        .map(|index| wires.get(*index).copied().ok_or(Error::Shape))
        .collect::<Result<Vec<_>, _>>()?;
    let (inputs, ops) =
        shape::allocate_bound(builder, template, public_count, |builder, inputs| {
            let cap = &inputs
                .common_data
                .preprocessed_commitment()
                .ok_or(Error::Shape)?
                .cap_targets;
            let mut key_words = key_descriptor
                .iter()
                .map(|word| builder.define_const(E::from(*word)))
                .collect::<Vec<_>>();
            key_words.extend(cap.iter().flatten().copied());
            let packed = base_words(builder, &key_words)?;
            let actual = engine::circuit_hash(builder, KEY, &packed)?;
            let expected = call
                .circuit_id_wires
                .iter()
                .map(|index| wires.get(*index).copied().ok_or(Error::Shape))
                .collect::<Result<Vec<_>, _>>()?;
            for (a, b) in actual.iter().copied().zip(base_words(builder, &expected)?) {
                equal(builder, a, b);
            }
            let bit = builder.alloc_private_input("verifier-set member");
            builder.assert_bool(bit);
            let siblings = builder.alloc_private_inputs(8, "verifier-set sibling");
            let packed = base_words(builder, &siblings)?;
            let mut words = Vec::new();
            for (node, sibling) in actual.iter().copied().zip(packed.iter().copied()) {
                let delta = builder.sub(sibling, node);
                words.push(builder.mul_add(bit, delta, node));
            }
            for (node, sibling) in actual.iter().copied().zip(packed.iter().copied()) {
                let delta = builder.sub(node, sibling);
                words.push(builder.mul_add(bit, delta, sibling));
            }
            let root = engine::circuit_hash(builder, VERIFIER_SET, &words)?;
            let expected = base_words(builder, &set_words)?;
            for (a, b) in root.into_iter().zip(expected) {
                equal(builder, a, b);
            }
            Ok(())
        })?;
    let words = statement_targets(template, &inputs)?;
    for (index, parent) in positions.iter().zip(&set_words) {
        equal(builder, *words.get(*index).ok_or(Error::Shape)?, *parent);
    }
    Ok((inputs, ops, words))
}
