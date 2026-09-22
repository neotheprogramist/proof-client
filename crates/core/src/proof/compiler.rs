use crate::proof::{
    config::{Config, FRI},
    engine::{self, Backend, E, F, Inputs},
    error::Error,
    shape,
};
use p3_circuit::{
    Circuit as Compiled, CircuitBuilder, ExprId, NonPrimitiveOpId, StatementExport, StatementSchema,
};
use p3_circuit_prover::{BatchStarkProof, CircuitVerifier, PreparedCircuitProver};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_recursion::{BatchOnly, TrustedPcsRecursionBackend};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::num::NonZeroUsize;

pub const FORMAT: &str = "proof-client/circuit/1";
// Policy: bound circuit compilation.
const MAX_WIRES: usize = 4096;
const MAX_DEPTH: usize = 3;
const MAX_CIRCUITS: usize = 15;
// Policy: binary recursion fanout.
const MAX_RECURSIVE_CALLS: usize = 2;
pub const MAX_INPUT_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_PROOF_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_JOB_BYTES: usize = 256 * 1024 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Definition {
    format: String,
    inputs: InputsCount,
    #[serde(default)]
    children: Vec<Definition>,
    operations: Vec<Operation>,
    constraints: Vec<Equality>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct InputsCount {
    public: usize,
    private: usize,
}
#[derive(Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Operation {
    Constant { value: u32 },
    Add { left: usize, right: usize },
    Sub { left: usize, right: usize },
    Mul { left: usize, right: usize },
    Poseidon2 { tag: u32, inputs: Vec<usize> },
    Verify { child: usize },
}
#[derive(Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Equality {
    Equal { left: usize, right: usize },
    Bits { wire: usize, bits: u8 },
}

pub struct Circuit {
    definition: Definition,
}
impl Circuit {
    fn from_definition(definition: Definition) -> Result<Self, Error> {
        let mut remaining = MAX_CIRCUITS;
        validate(&definition, 0, &mut remaining)?;
        Ok(Self { definition })
    }
    fn public_count(&self) -> usize {
        self.definition.inputs.public
    }
}
fn identity(definition: &impl Serialize) -> Result<String, Error> {
    let encoded = serde_json::to_vec(&(
        FORMAT,
        (
            FRI.suite().as_u16(),
            FRI.log_blowup(),
            FRI.log_final_poly_len(),
            FRI.max_log_arity(),
            FRI.num_queries(),
            FRI.commit_pow_bits(),
            FRI.query_pow_bits(),
            FRI.input_cap_height(),
            FRI.commit_cap_height(),
            FRI.num_random_codewords(),
            FRI.salt_elements(),
        ),
        definition,
    ))?;
    Ok(Sha256::digest(encoded)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}
fn validate(definition: &Definition, depth: usize, remaining: &mut usize) -> Result<(), Error> {
    if definition.format != FORMAT || depth > MAX_DEPTH || *remaining == 0 {
        return Err(Error::Shape);
    }
    *remaining -= 1;
    for child in &definition.children {
        validate(child, depth + 1, remaining)?;
    }
    validate_body(
        definition,
        &definition
            .children
            .iter()
            .map(|child| child.inputs.public)
            .collect::<Vec<_>>(),
    )
}
fn validate_body(definition: &Definition, children: &[usize]) -> Result<(), Error> {
    let mut wires = definition
        .inputs
        .public
        .checked_add(definition.inputs.private)
        .ok_or(Error::Shape)?;
    if wires > MAX_WIRES
        || definition.inputs.public == 0
        || definition.operations.len() > MAX_WIRES
        || definition.constraints.len() > MAX_WIRES
        || definition.children.len() > MAX_RECURSIVE_CALLS
    {
        return Err(Error::Shape);
    }
    let mut hash_words = 0usize;
    let mut recursive_calls = 0usize;
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
            Operation::Verify { child } => {
                recursive_calls += 1;
                if recursive_calls > MAX_RECURSIVE_CALLS {
                    return Err(Error::Shape);
                }
                *children.get(*child).ok_or(Error::Shape)?
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
            Equality::Equal { left, right } if *left < wires && *right < wires => {}
            Equality::Bits { wire, bits } if *wire < wires && (1..=30).contains(bits) => {}
            _ => return Err(Error::Shape),
        }
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Assignment {
    public: Vec<u32>,
    private: Vec<u32>,
    proofs: Vec<Artifact>,
}
impl Assignment {
    fn parse(bytes: &[u8], definition: &Definition) -> Result<Self, Error> {
        if bytes.len() > MAX_JOB_BYTES {
            return Err(Error::Shape);
        }
        let assignment: Self = serde_json::from_slice(bytes)?;
        let proofs = definition
            .operations
            .iter()
            .filter(|op| matches!(op, Operation::Verify { .. }))
            .count();
        if assignment.public.len() != definition.inputs.public
            || assignment.private.len() != definition.inputs.private
            || assignment.proofs.len() != proofs
            || assignment
                .public
                .iter()
                .chain(&assignment.private)
                .any(|word| *word >= F::ORDER_U32)
        {
            return Err(Error::Shape);
        }
        Ok(assignment)
    }
}
pub struct CircuitJob<C> {
    circuit: C,
    assignment: Assignment,
}
pub type Job = CircuitJob<Circuit>;
impl Job {
    pub fn parse(circuit: Circuit, bytes: &[u8]) -> Result<Self, Error> {
        let assignment = Assignment::parse(bytes, &circuit.definition)?;
        Ok(Self {
            circuit,
            assignment,
        })
    }
}
#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct Artifact {
    circuit: String,
    public: Vec<u32>,
    proof: BatchStarkProof<Config>,
}
impl Artifact {
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_PROOF_BYTES {
            return Err(Error::Artifact);
        }
        Ok(serde_json::from_slice(bytes)?)
    }
    pub fn circuit(&self) -> &str {
        &self.circuit
    }
    pub fn public(&self) -> &[u32] {
        &self.public
    }
}

struct Child {
    index: usize,
    inputs: Inputs,
    ops: Vec<NonPrimitiveOpId>,
}
struct Prepared {
    circuit: Compiled<E>,
    schema: StatementSchema,
    prover: PreparedCircuitProver<Config>,
    children: Vec<Prepared>,
    wiring: Vec<Child>,
    id: String,
}
fn equal(builder: &mut CircuitBuilder<E>, left: ExprId, right: ExprId) {
    // Preserve bus creators; global ZERO would alias them.
    let one = builder.define_const(E::ONE);
    let shifted_left = builder.add(left, one);
    let shifted_right = builder.add(right, one);
    let difference = builder.sub(shifted_left, shifted_right);
    let negative = builder.sub(ExprId::ZERO, shifted_left);
    let zero = builder.add(shifted_left, negative);
    builder.connect(difference, zero);
}
fn base_words(builder: &mut CircuitBuilder<E>, words: &[ExprId]) -> Result<Vec<ExprId>, Error> {
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
fn statement_targets(
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
fn compile(definition: &Definition) -> Result<Prepared, Error> {
    let children = definition
        .children
        .iter()
        .map(compile)
        .collect::<Result<Vec<_>, _>>()?;
    let mut prepared = build(
        definition,
        |builder, child, _| {
            let prepared = children.get(child).ok_or(Error::Shape)?;
            let verifier = prepared.prover.verifier();
            let count = verifier.statement_layout().schema().base_len();
            let (inputs, ops) = shape::allocate(builder, &verifier, count)?;
            let words = statement_targets(&verifier, &inputs)?;
            Ok((
                Child {
                    index: child,
                    inputs,
                    ops,
                },
                words,
            ))
        },
        engine::prepare,
    )?;
    prepared.children = children;
    Ok(prepared)
}
fn build(
    definition: &Definition,
    mut child: impl FnMut(
        &mut CircuitBuilder<E>,
        usize,
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
            Operation::Verify { child: index } => {
                let (binding, words) = child(&mut builder, *index, &wires)?;
                wires.extend(words);
                wiring.push(binding);
            }
        }
    }
    for constraint in &definition.constraints {
        match constraint {
            Equality::Equal { left, right } => equal(
                &mut builder,
                *wires.get(*left).ok_or(Error::Shape)?,
                *wires.get(*right).ok_or(Error::Shape)?,
            ),
            Equality::Bits { wire, bits } => {
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
    Ok(Prepared {
        circuit,
        schema,
        prover,
        children: Vec::new(),
        wiring,
        id: identity(definition)?,
    })
}
fn checked_values(proof: &Artifact, prepared: &Prepared) -> Result<Vec<F>, Error> {
    if proof.circuit != prepared.id || proof.public.iter().any(|v| *v >= F::ORDER_U32) {
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
fn prove_prepared<'a>(
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
        .zip(&proofs)
        .map(|(wiring, proof)| resolve(wiring, proof))
        .collect::<Result<Vec<_>, _>>()?;
    let mut private = values
        .iter()
        .chain(&private)
        .copied()
        .map(E::from_u32)
        .collect::<Vec<_>>();
    let mut public = Vec::new();
    for ((wiring, proof), (child, extra)) in prepared.wiring.iter().zip(&proofs).zip(&children) {
        let values = checked_values(proof, child)?;
        let verifier = child.prover.verifier();
        let values = verifier.table_public_values(&values)?;
        let (a, b) =
            wiring
                .inputs
                .try_pack_values(&values, &proof.proof.proof, verifier.common_data())?;
        public.extend(a);
        private.extend(b);
        private.extend(extra);
    }
    let mut runner = prepared.circuit.runner();
    runner.set_public_inputs(&public)?;
    runner.set_private_inputs(&private)?;
    for ((wiring, proof), (child, _)) in prepared.wiring.iter().zip(&proofs).zip(&children) {
        let values = proof.public.iter().copied().map(F::new).collect::<Vec<_>>();
        <Backend as TrustedPcsRecursionBackend<Config,BatchOnly,4>>::set_private_data_for_trusted_batch(&engine::backend(),&child.prover.verifier(),&proof.proof,&values,&mut runner,&wiring.ops)?;
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
        circuit: prepared.id.clone(),
        public: values,
        proof,
    };
    checked_values(&artifact, prepared)?;
    Ok(artifact)
}
pub fn prove(job: Job, threads: NonZeroUsize) -> Result<Artifact, Error> {
    engine::run(threads, move || {
        let prepared = compile(&job.circuit.definition)?;
        prove_prepared(&prepared, job.assignment, |wiring, _| {
            Ok((
                prepared.children.get(wiring.index).ok_or(Error::Shape)?,
                Vec::new(),
            ))
        })
    })
}

pub fn verify(circuit: Circuit, proof: Artifact, threads: NonZeroUsize) -> Result<Vec<u32>, Error> {
    if proof.public.len() != circuit.public_count() {
        return Err(Error::Statement);
    }
    engine::run(threads, move || {
        let prepared = compile(&circuit.definition)?;
        checked_values(&proof, &prepared)?;
        Ok(proof.public)
    })
}

#[cfg(test)]
#[path = "../../tests/controls/prover.rs"]
mod tests;

#[path = "family.rs"]
pub mod family;

#[path = "program.rs"]
pub mod program;
