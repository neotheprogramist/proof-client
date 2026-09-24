use super::{
    Error,
    config::Config,
    engine::{self, Backend, E, F, Inputs},
    identity::{CircuitId, key},
    shape,
    source::{
        Constraint, Definition, InputsCount, MAX_INPUT_BYTES, MAX_RECURSIVE_CALLS, MAX_WIRES,
        Operation, Verification,
    },
};
use p3_circuit::{
    Circuit as Compiled, CircuitBuilder, ExprId, NonPrimitiveOpId, StatementExport, StatementSchema,
};
use p3_circuit_prover::{BatchStarkProof, CircuitVerifier, PreparedCircuitProver};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_recursion::{BatchOnly, TrustedPcsRecursionBackend};
use serde::{Deserialize, Serialize};

pub const MAX_PROOF_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_WITNESS_BYTES: usize = 256 * 1024 * 1024;

pub(super) fn validate_body(
    definition: &Definition,
    child_count: impl Fn(&Verification) -> Result<usize, Error>,
) -> Result<(), Error> {
    let mut wires = definition
        .inputs
        .public
        .checked_add(definition.inputs.private)
        .ok_or(Error::Shape)?;
    if wires > MAX_WIRES
        || definition.inputs.public == 0
        || definition.operations.len() > MAX_WIRES
        || definition.constraints.len() > MAX_WIRES
        || definition.verifications().count() > MAX_RECURSIVE_CALLS
    {
        return Err(Error::Shape);
    }
    let mut hash_words = 0usize;
    let mut proof_slots = vec![false; definition.verifications().count()];
    for operation in &definition.operations {
        let added = match operation {
            Operation::Constant { value } if *value < F::ORDER_U32 => 1,
            Operation::Add { left, right }
            | Operation::Sub { left, right }
            | Operation::Mul { left, right }
                if *left < wires && *right < wires =>
            {
                1
            }
            Operation::Poseidon2 { tag, inputs }
                if *tag < F::ORDER_U32
                    && !inputs.is_empty()
                    && inputs.len().is_multiple_of(8)
                    && inputs.len() <= MAX_WIRES
                    && inputs.iter().all(|wire| *wire < wires) =>
            {
                hash_words = hash_words
                    .checked_add(inputs.len())
                    .filter(|n| *n <= MAX_WIRES)
                    .ok_or(Error::Shape)?;
                8
            }
            Operation::Verify(call) => {
                let slot = proof_slots.get_mut(call.proof).ok_or(Error::Shape)?;
                if *slot || call.circuit_id_wires.iter().any(|index| *index >= wires) {
                    return Err(Error::Shape);
                }
                *slot = true;
                child_count(call)?
            }
            _ => return Err(Error::Shape),
        };
        wires = wires
            .checked_add(added)
            .filter(|n| *n <= MAX_WIRES)
            .ok_or(Error::Shape)?;
    }
    for constraint in &definition.constraints {
        match constraint {
            Constraint::Equal { left, right } if *left < wires && *right < wires => {}
            Constraint::Bits { wire, bits } if *wire < wires && (1..=30).contains(bits) => {}
            _ => return Err(Error::Shape),
        }
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Witness {
    private: Vec<u32>,
    proofs: Vec<Artifact>,
}
pub struct PublicInput(pub(super) Vec<u32>);
impl PublicInput {
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_INPUT_BYTES {
            return Err(Error::Shape);
        }
        let words: Vec<u32> = serde_json::from_slice(bytes)?;
        if words.iter().any(|word| *word >= F::ORDER_U32) {
            return Err(Error::Statement);
        }
        Ok(Self(words))
    }
}
pub(super) struct Assignment {
    pub(super) public: Vec<u32>,
    pub(super) private: Vec<u32>,
    pub(super) proofs: Vec<Artifact>,
}
impl Assignment {
    pub(super) fn parse(
        public: PublicInput,
        bytes: &[u8],
        inputs: InputsCount,
        proof_count: usize,
    ) -> Result<Self, Error> {
        if bytes.len() > MAX_WITNESS_BYTES {
            return Err(Error::Shape);
        }
        let witness: Witness = serde_json::from_slice(bytes)?;
        if public.0.len() != inputs.public
            || witness.private.len() != inputs.private
            || witness.proofs.len() != proof_count
            || witness.private.iter().any(|word| *word >= F::ORDER_U32)
        {
            return Err(Error::Shape);
        }
        Ok(Self {
            public: public.0,
            private: witness.private,
            proofs: witness.proofs,
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct Artifact {
    pub(super) circuit_id: CircuitId,
    pub(super) public: Vec<u32>,
    pub(super) proof: BatchStarkProof<Config>,
}
impl Artifact {
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_PROOF_BYTES {
            return Err(Error::Artifact);
        }
        Ok(serde_json::from_slice(bytes)?)
    }
    pub fn circuit_id(&self) -> CircuitId {
        self.circuit_id
    }
    pub fn public(&self) -> &[u32] {
        &self.public
    }
}

pub(super) enum ChildTarget {
    Circuit(std::path::PathBuf),
    Set([std::path::PathBuf; 2]),
}
pub(super) struct Child {
    pub(super) target: ChildTarget,
    pub(super) proof: usize,
    pub(super) inputs: Inputs,
    pub(super) ops: Vec<NonPrimitiveOpId>,
}
pub(super) struct Prepared {
    pub(super) inputs: InputsCount,
    pub(super) bindings: Vec<(usize, u32)>,
    pub(super) circuit: Compiled<E>,
    pub(super) schema: StatementSchema,
    pub(super) prover: PreparedCircuitProver<Config>,
    pub(super) wiring: Vec<Child>,
    pub(super) id: CircuitId,
}
impl Prepared {
    pub(super) fn check_statement(&self, public: &[u32]) -> Result<(), Error> {
        if public.len() != self.inputs.public
            || self
                .bindings
                .iter()
                .any(|(position, word)| public.get(*position) != Some(word))
        {
            return Err(Error::Statement);
        }
        Ok(())
    }
}
pub(super) fn equal(builder: &mut CircuitBuilder<E>, left: ExprId, right: ExprId) {
    // Preserve bus creators; ZERO aliases them.
    let one = builder.define_const(E::ONE);
    let shifted_left = builder.add(left, one);
    let shifted_right = builder.add(right, one);
    let difference = builder.sub(shifted_left, shifted_right);
    let negative = builder.sub(ExprId::ZERO, shifted_left);
    let zero = builder.add(shifted_left, negative);
    builder.connect(difference, zero);
}
pub(super) fn base_words(
    builder: &mut CircuitBuilder<E>,
    words: &[ExprId],
) -> Result<Vec<ExprId>, Error> {
    let mut result = Vec::new();
    for chunk in words.chunks(4) {
        let mut padded = chunk.to_vec();
        padded.resize(4, ExprId::ZERO);
        let value = builder.recompose_base_coeffs_to_ext_via_alu::<F>(&padded)?;
        let bound = builder.recompose_base_coeffs_to_ext_with_coeff_lookups::<F>(&padded)?;
        builder.connect(value, bound);
        result.push(bound);
    }
    Ok(result)
}
pub(super) fn statement_targets(
    verifier: &CircuitVerifier<Config>,
    inputs: &Inputs,
) -> Result<Vec<ExprId>, Error> {
    let index = verifier
        .statement_layout()
        .table_instance()
        .ok_or(Error::Shape)?;
    inputs
        .air_public_targets
        .get(index)
        .cloned()
        .ok_or(Error::Shape)
}
pub(super) fn fixed_child(
    builder: &mut CircuitBuilder<E>,
    call: &Verification,
    wires: &[ExprId],
    child: &Prepared,
) -> Result<(Child, Vec<ExprId>), Error> {
    let verifier = child.prover.verifier();
    let count = verifier.statement_layout().schema().base_len();
    let (inputs, ops) = shape::allocate(builder, &verifier, count)?;
    bind_circuit_id(builder, call, wires, child.id)?;
    let words = statement_targets(&verifier, &inputs)?;
    for (position, word) in &child.bindings {
        let expected = builder.define_const(E::from_u32(*word));
        equal(
            builder,
            *words.get(*position).ok_or(Error::Shape)?,
            expected,
        );
    }
    Ok((
        Child {
            target: ChildTarget::Circuit(call.verifier.clone()),
            proof: call.proof,
            inputs,
            ops,
        },
        words,
    ))
}
pub(super) fn compile(
    definition: &Definition,
    prepared: &std::collections::BTreeMap<std::path::PathBuf, Prepared>,
    prepare: impl FnOnce(&Compiled<E>, &StatementSchema) -> Result<PreparedCircuitProver<Config>, Error>,
) -> Result<Prepared, Error> {
    build(
        definition,
        |builder, call, wires| {
            fixed_child(
                builder,
                call,
                wires,
                prepared.get(&call.verifier).ok_or(Error::Shape)?,
            )
        },
        prepare,
    )
}

pub(super) fn bind_circuit_id(
    builder: &mut CircuitBuilder<E>,
    call: &Verification,
    wires: &[ExprId],
    id: CircuitId,
) -> Result<(), Error> {
    for (index, value) in call.circuit_id_wires.iter().zip(id.words()) {
        let actual = builder.define_const(E::from_u32(*value));
        equal(builder, *wires.get(*index).ok_or(Error::Shape)?, actual);
    }
    Ok(())
}

pub(super) fn build(
    definition: &Definition,
    mut child: impl FnMut(
        &mut CircuitBuilder<E>,
        &Verification,
        &[ExprId],
    ) -> Result<(Child, Vec<ExprId>), Error>,
    prepare: impl FnOnce(&Compiled<E>, &StatementSchema) -> Result<PreparedCircuitProver<Config>, Error>,
) -> Result<Prepared, Error> {
    let mut builder = engine::builder()?;
    let mut wires = builder.alloc_private_inputs(
        definition.inputs.public + definition.inputs.private,
        "circuit inputs",
    );
    base_words(&mut builder, &wires)?;
    let exports = wires
        .iter()
        .take(definition.inputs.public)
        .copied()
        .map(StatementExport::Base)
        .collect::<Vec<_>>();
    let mut wiring = Vec::new();
    for operation in &definition.operations {
        let at = |index| wires.get(index).copied().ok_or(Error::Shape);
        match operation {
            Operation::Constant { value } => wires.push(builder.define_const(E::from_u32(*value))),
            Operation::Add { left, right } => wires.push(builder.add(at(*left)?, at(*right)?)),
            Operation::Sub { left, right } => wires.push(builder.sub(at(*left)?, at(*right)?)),
            Operation::Mul { left, right } => wires.push(builder.mul(at(*left)?, at(*right)?)),
            Operation::Poseidon2 { tag, inputs } => {
                let words = inputs
                    .iter()
                    .map(|index| at(*index))
                    .collect::<Result<Vec<_>, _>>()?;
                let packed = base_words(&mut builder, &words)?;
                let root = engine::circuit_hash(&mut builder, *tag, &packed)?;
                for word in root {
                    let coefficients = builder.decompose_ext_to_base_coeffs_via_alu::<F>(word)?;
                    base_words(&mut builder, &coefficients)?;
                    wires.extend(coefficients);
                }
            }
            Operation::Verify(call) => {
                let (binding, words) = child(&mut builder, call, &wires)?;
                wires.extend(words);
                wiring.push(binding);
            }
        }
    }
    for constraint in &definition.constraints {
        match constraint {
            Constraint::Equal { left, right } => equal(
                &mut builder,
                *wires.get(*left).ok_or(Error::Shape)?,
                *wires.get(*right).ok_or(Error::Shape)?,
            ),
            Constraint::Bits { wire, bits } => {
                builder.decompose_to_bits::<F>(
                    *wires.get(*wire).ok_or(Error::Shape)?,
                    usize::from(*bits),
                )?;
            }
        }
    }
    let schema = builder.set_statement_exports::<F>(&exports)?;
    let circuit = builder.build()?;
    let prover = prepare(&circuit, &schema)?;
    let id = CircuitId::from_key(key(&prover.verifier())?);
    Ok(Prepared {
        inputs: definition.inputs,
        bindings: Vec::new(),
        circuit,
        schema,
        prover,
        wiring,
        id,
    })
}
pub(super) fn checked_values(proof: &Artifact, prepared: &Prepared) -> Result<Vec<F>, Error> {
    prepared.check_statement(&proof.public)?;
    if proof.circuit_id != prepared.id || proof.public.iter().any(|v| *v >= F::ORDER_U32) {
        return Err(Error::Statement);
    }
    let values = proof.public.iter().copied().map(F::new).collect::<Vec<_>>();
    let verifier = prepared.prover.verifier();
    <Backend as TrustedPcsRecursionBackend<Config, BatchOnly, 4>>::preflight_trusted_batch(
        &engine::backend(),
        &verifier,
        &proof.proof,
    )?;
    verifier.verify(&proof.proof, &values)?;
    Ok(values)
}
pub(super) fn prove_prepared<'a>(
    prepared: &Prepared,
    assignment: Assignment,
    resolve: impl Fn(&Child, &Artifact) -> Result<(&'a Prepared, Vec<E>), Error>,
) -> Result<Artifact, Error> {
    let Assignment {
        public: values,
        private,
        proofs,
    } = assignment;
    let children = prepared
        .wiring
        .iter()
        .map(|wiring| {
            let proof = proofs.get(wiring.proof).ok_or(Error::Shape)?;
            let (child, extra) = resolve(wiring, proof)?;
            let values = checked_values(proof, child)?;
            Ok((wiring, proof, child, extra, values))
        })
        .collect::<Result<Vec<_>, Error>>()?;
    let mut private = values
        .iter()
        .chain(&private)
        .copied()
        .map(E::from_u32)
        .collect::<Vec<_>>();
    let mut public = Vec::new();
    for (wiring, proof, child, extra, values) in &children {
        let verifier = child.prover.verifier();
        let values = verifier.table_public_values(values)?;
        let (a, b) =
            wiring
                .inputs
                .try_pack_values(&values, &proof.proof.proof, verifier.common_data())?;
        public.extend(a);
        private.extend(b);
        private.extend(extra.iter().copied());
    }
    let mut runner = prepared.circuit.runner();
    runner.set_public_inputs(&public)?;
    runner.set_private_inputs(&private)?;
    for (wiring, proof, child, _, values) in &children {
        <Backend as TrustedPcsRecursionBackend<Config, BatchOnly, 4>>::set_private_data_for_trusted_batch(
            &engine::backend(),
            &child.prover.verifier(),
            &proof.proof,
            values,
            &mut runner,
            &wiring.ops,
        )?;
    }
    let traces = runner.run()?;
    let proof = engine::prover(engine::private_config()?, &prepared.schema)
        .with_table_packing(
            prepared
                .prover
                .verifier()
                .relation()
                .table_packing()
                .clone(),
        )
        .prove_all_tables(&traces, &prepared.prover.prover_data())?;
    let artifact = Artifact {
        circuit_id: prepared.id,
        public: values,
        proof,
    };
    checked_values(&artifact, prepared)?;
    Ok(artifact)
}
#[cfg(test)]
#[path = "../../tests/controls/prover.rs"]
pub(super) mod tests;
