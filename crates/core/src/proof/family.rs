use super::*;
use p3_air::{Air, BaseAir, symbolic::AirLayout};
use p3_circuit_prover::{CircuitVerifier, TablePacking};
use p3_lookup::symbolic::InteractionSymbolicBuilder;
use p3_symmetric::{CryptographicHasher, PaddingFreeSponge};

pub const FORMAT: &str = "proof-client/family/1";
// Structural: separate verifier-key and family hashes from application Poseidon domains.
const KEY: u32 = 0x5043_0201;
const FAMILY: u32 = 0x5043_0202;

fn hash(tag: u32, words: &[F]) -> [F; 8] {
    let domain = [
        F::from_u32(tag),
        F::from_usize(words.len()),
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
    ];
    PaddingFreeSponge::<_, 16, 8, 8>::new(p3_koala_bear::default_koalabear_poseidon2_16())
        .hash_iter(domain.into_iter().chain(words.iter().copied()))
}

// Family members must share constraints and lookups, not just dimensions.
fn descriptor(verifier: &CircuitVerifier<Config>) -> Result<Vec<u8>, Error> {
    let common = verifier.common_data();
    let preprocessed = common.preprocessed.as_ref().ok_or(Error::Shape)?;
    let airs = verifier.table_airs::<4>()?;
    let constraints = airs
        .iter()
        .map(|air| {
            let layout = AirLayout::from_air::<F>(air);
            let mut builder = InteractionSymbolicBuilder::<F, E>::new(layout);
            air.eval(&mut builder);
            let constraints = (
                builder.base_constraints(),
                builder.extension_constraints(),
                builder.constraint_layout(),
            );
            (
                layout,
                constraints,
                air.main_next_row_columns(),
                air.preprocessed_next_row_columns(),
            )
        })
        .collect::<Vec<_>>();
    let relation = verifier.relation();
    let meta = preprocessed
        .instances
        .iter()
        .map(|instance| {
            instance
                .as_ref()
                .map(|instance| (instance.matrix_index, instance.width, instance.degree_bits))
        })
        .collect::<Vec<_>>();
    Ok(serde_json::to_vec(&(
        FORMAT,
        identity(&FORMAT)?,
        relation.table_packing(),
        relation.trace_degree_bits(),
        verifier.statement_layout().schema(),
        verifier.statement_layout().table_instance(),
        verifier.table_public_values(&vec![
            F::ZERO;
            verifier.statement_layout().schema().base_len()
        ])?,
        meta,
        &preprocessed.matrix_to_instance,
        &common.lookups,
        constraints,
    ))?)
}
fn descriptor_words(verifier: &CircuitVerifier<Config>) -> Result<Vec<F>, Error> {
    Ok(Sha256::digest(descriptor(verifier)?)
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| F::from_u16(u16::from_be_bytes([pair[0], pair[1]])))
        .collect())
}
fn key(verifier: &CircuitVerifier<Config>) -> Result<[F; 8], Error> {
    let mut words = descriptor_words(verifier)?;
    let common = verifier.common_data();
    let commitment = &common.preprocessed.as_ref().ok_or(Error::Shape)?.commitment;
    words.extend(commitment.roots().iter().flatten().copied());
    Ok(hash(KEY, &words))
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Layout {
    constants: u8,
    public: u8,
    alu: u8,
    poseidon: u8,
    challenger: u8,
    recompose: u8,
}
impl Layout {
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
    fn prepare(
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
#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Base,
    Join,
    Fold,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Definition {
    format: String,
    entry: Role,
    base: super::Definition,
    join: super::Definition,
    fold: super::Definition,
    layout: Layout,
}
pub struct Circuit {
    definition: Definition,
}
impl Circuit {
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        match program::Circuit::parse(bytes)? {
            program::Circuit::Family(circuit) => Ok(*circuit),
            program::Circuit::Direct(_) => Err(Error::Shape),
        }
    }
    pub(super) fn from_definition(definition: Definition) -> Result<Self, Error> {
        if definition.format != FORMAT {
            return Err(Error::Shape);
        }
        for height in [
            definition.layout.constants,
            definition.layout.public,
            definition.layout.alu,
            definition.layout.poseidon,
            definition.layout.challenger,
            definition.layout.recompose,
        ] {
            // Policy: bound family preparation heights.
            if !(9..=18).contains(&height) {
                return Err(Error::Shape);
            }
        }
        let counts = [definition.base.inputs.public, definition.join.inputs.public];
        if counts[1] < 8 || counts[1] != definition.fold.inputs.public {
            return Err(Error::Shape);
        }
        for (source, allowed) in [
            (&definition.base, None),
            (&definition.join, Some(0)),
            (&definition.fold, Some(1)),
        ] {
            if source.format != super::FORMAT || !source.children.is_empty() {
                return Err(Error::Shape);
            }
            for op in &source.operations {
                if let Operation::Verify { child } = op
                    && Some(*child) != allowed
                {
                    return Err(Error::Shape);
                }
            }
            validate_body(source, &counts)?;
        }
        Ok(Self { definition })
    }
}
pub struct Session {
    base: Prepared,
    join: Prepared,
    fold: Prepared,
    root: [u32; 8],
    keys: [[F; 8]; 2],
}
impl Session {
    fn entry(&self, role: Role) -> &Prepared {
        match role {
            Role::Base => &self.base,
            Role::Join => &self.join,
            Role::Fold => &self.fold,
        }
    }
}
fn role_id(definition: &Definition, role: Role) -> Result<String, Error> {
    identity(&(
        FORMAT,
        &definition.base,
        &definition.join,
        &definition.fold,
        &definition.layout,
        role,
    ))
}
fn compile_base(definition: &Definition) -> Result<Prepared, Error> {
    let mut base = super::compile(&definition.base)?;
    base.id = role_id(definition, Role::Base)?;
    Ok(base)
}
fn compile(definition: &Definition) -> Result<Session, Error> {
    let base = compile_base(definition)?;
    let mut join = build(
        &definition.join,
        |builder, index, _| {
            if index != 0 {
                return Err(Error::Shape);
            }
            let verifier = base.prover.verifier();
            let (inputs, ops) = shape::allocate(builder, &verifier, definition.base.inputs.public)?;
            let words = statement_targets(&verifier, &inputs)?;
            Ok((Child { index, inputs, ops }, words))
        },
        |circuit, schema| definition.layout.prepare(circuit, schema),
    )?;
    join.id = role_id(definition, Role::Join)?;
    let template = join.prover.verifier();
    let key_descriptor = descriptor_words(&template)?;
    let public_count = definition.fold.inputs.public;
    let mut fold = build(
        &definition.fold,
        |builder, index, wires| {
            if index != 1 {
                return Err(Error::Shape);
            }
            let family = wires
                .get(public_count - 8..public_count)
                .ok_or(Error::Shape)?;
            let (inputs, ops) =
                shape::allocate_bound(builder, &template, public_count, |builder, inputs| {
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
                    let bit = builder.alloc_private_input("family member");
                    builder.assert_bool(bit);
                    let siblings = builder.alloc_private_inputs(8, "family sibling");
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
                    let root = engine::circuit_hash(builder, FAMILY, &words)?;
                    let expected = base_words(builder, family)?;
                    for (a, b) in root.into_iter().zip(expected) {
                        equal(builder, a, b);
                    }
                    Ok(())
                })?;
            let words = statement_targets(&template, &inputs)?;
            for (&a, &b) in words
                .get(public_count - 8..)
                .ok_or(Error::Shape)?
                .iter()
                .zip(family)
            {
                equal(builder, a, b);
            }
            Ok((Child { index, inputs, ops }, words))
        },
        |circuit, schema| definition.layout.prepare(circuit, schema),
    )?;
    fold.id = role_id(definition, Role::Fold)?;
    if descriptor(&template)? != descriptor(&fold.prover.verifier())? {
        return Err(Error::Shape);
    }
    let keys = [key(&template)?, key(&fold.prover.verifier())?];
    let root = hash(FAMILY, &keys.iter().flatten().copied().collect::<Vec<_>>())
        .map(|word| word.as_canonical_u32());
    Ok(Session {
        base,
        join,
        fold,
        root,
        keys,
    })
}
pub type Job = CircuitJob<Circuit>;
impl Job {
    pub fn parse(circuit: Circuit, bytes: &[u8]) -> Result<Self, Error> {
        let assignment = Assignment::parse(bytes, circuit.source())?;
        Ok(Self {
            circuit,
            assignment,
        })
    }
}
impl Circuit {
    fn source(&self) -> &super::Definition {
        match self.definition.entry {
            Role::Base => &self.definition.base,
            Role::Join => &self.definition.join,
            Role::Fold => &self.definition.fold,
        }
    }
}
impl Session {
    fn new(circuit: &Circuit) -> Result<Self, Error> {
        compile(&circuit.definition)
    }
    pub fn description(&self) -> serde_json::Value {
        serde_json::json!({"family":self.root,"members":{"base":self.base.id,"join":self.join.id,"fold":self.fold.id}})
    }
    pub fn prove(&self, job: Job) -> Result<Artifact, Error> {
        let role = job.circuit.definition.entry;
        let prepared = self.entry(role);
        if role_id(&job.circuit.definition, role)? != prepared.id {
            return Err(Error::Statement);
        }
        self.check_family(role, &job.assignment.public)?;
        prove_prepared(prepared, job.assignment, |wiring, proof| {
            match wiring.index {
                0 => Ok((&self.base, Vec::new())),
                1 => {
                    let (child, index, sibling) = if proof.circuit == self.join.id {
                        (&self.join, 0, self.keys[1])
                    } else if proof.circuit == self.fold.id {
                        (&self.fold, 1, self.keys[0])
                    } else {
                        return Err(Error::Statement);
                    };
                    self.check_family(Role::Fold, &proof.public)?;
                    Ok((
                        child,
                        std::iter::once(E::from_u32(index))
                            .chain(sibling.map(E::from))
                            .collect(),
                    ))
                }
                _ => Err(Error::Shape),
            }
        })
    }
    fn check_family(&self, role: Role, values: &[u32]) -> Result<(), Error> {
        match role {
            Role::Base => Ok(()),
            Role::Join | Role::Fold => {
                let start = values.len().checked_sub(8).ok_or(Error::Statement)?;
                if values.get(start..) != Some(self.root.as_slice()) {
                    return Err(Error::Statement);
                }
                Ok(())
            }
        }
    }
    pub fn verify(&self, circuit: Circuit, proof: Artifact) -> Result<Vec<u32>, Error> {
        let role = circuit.definition.entry;
        let prepared = self.entry(role);
        if role_id(&circuit.definition, role)? != prepared.id
            || proof.public.len() != circuit.source().inputs.public
        {
            return Err(Error::Statement);
        }
        self.check_family(role, &proof.public)?;
        checked_values(&proof, prepared)?;
        Ok(proof.public)
    }
}
pub fn with_session<R: Send>(
    circuit: Circuit,
    threads: NonZeroUsize,
    run: impl FnOnce(&Session) -> Result<R, Error> + Send,
) -> Result<R, Error> {
    engine::run(threads, || run(&Session::new(&circuit)?))
}
pub fn prepare(circuit: Circuit, threads: NonZeroUsize) -> Result<serde_json::Value, Error> {
    with_session(circuit, threads, |session| Ok(session.description()))
}
pub fn prove(job: Job, threads: NonZeroUsize) -> Result<Artifact, Error> {
    engine::run(threads, || match job.circuit.definition.entry {
        Role::Base => {
            let prepared = compile_base(&job.circuit.definition)?;
            prove_prepared(&prepared, job.assignment, |_, _| Err(Error::Shape))
        }
        Role::Join | Role::Fold => Session::new(&job.circuit)?.prove(job),
    })
}
pub fn verify(circuit: Circuit, proof: Artifact, threads: NonZeroUsize) -> Result<Vec<u32>, Error> {
    if proof.public.len() != circuit.source().inputs.public {
        return Err(Error::Statement);
    }
    engine::run(threads, || match circuit.definition.entry {
        Role::Base => {
            let prepared = compile_base(&circuit.definition)?;
            checked_values(&proof, &prepared)?;
            Ok(proof.public)
        }
        Role::Join | Role::Fold => Session::new(&circuit)?.verify(circuit, proof),
    })
}

#[cfg(test)]
#[path = "../../tests/controls/family.rs"]
mod tests;
