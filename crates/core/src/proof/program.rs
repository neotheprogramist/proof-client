use super::{
    Artifact, CircuitId, Error, PublicInput, VerifierSetId,
    compiler::{self, Assignment, ChildTarget, Prepared, checked_values, prove_prepared},
    engine::{self, E, F},
    identity::{VERIFIER_SET, hash},
    recursion,
    source::{Circuit, Source},
};
use p3_field::PrimeCharacteristicRing;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    num::NonZeroUsize,
    path::{Path, PathBuf},
};

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Metadata {
    circuit_id: CircuitId,
    circuits: BTreeMap<PathBuf, CircuitId>,
    verifier_sets: BTreeMap<PathBuf, VerifierSetId>,
}
impl Metadata {
    pub fn circuit_id(&self) -> CircuitId {
        self.circuit_id
    }
    pub fn circuits(&self) -> &BTreeMap<PathBuf, CircuitId> {
        &self.circuits
    }
    pub fn verifier_sets(&self) -> &BTreeMap<PathBuf, VerifierSetId> {
        &self.verifier_sets
    }
}
pub struct Session {
    entry: PathBuf,
    pub(super) prepared: BTreeMap<PathBuf, Prepared>,
    pub(super) sets: BTreeMap<PathBuf, VerifierSetId>,
}
impl Session {
    #[tracing::instrument(name = "prepare", skip_all)]
    pub(super) fn new(source: Circuit) -> Result<Self, Error> {
        tracing::info!(phase = "preparing_contract", sources = source.order.len());
        let mut prepared = BTreeMap::new();
        let mut sets = BTreeMap::new();
        for path in &source.order {
            match source.sources.get(path).ok_or(Error::Shape)? {
                Source::Circuit(definition) => {
                    tracing::info!(phase = "circuit_inputs", source = ?path, public_words = definition.inputs.public, private_words = definition.inputs.private, child_proofs = definition.verifications().count());
                    let compiled = compiler::compile(definition, &prepared, engine::prepare)?;
                    tracing::info!(phase = "circuit_prepared", source = ?path, circuit_id = ?compiled.id.words());
                    prepared.insert(path.clone(), compiled);
                }
                Source::VerifierSet(set) => {
                    let members = recursion::compile(&source, set, &prepared)?;
                    let keys = members
                        .iter()
                        .flat_map(|member| member.id.words().iter().copied().map(F::new))
                        .collect::<Vec<_>>();
                    let root = VerifierSetId::from_root(hash(VERIFIER_SET, &keys));
                    tracing::info!(phase = "verifier_set_prepared", source = ?path, verifier_set_id = ?root.words());
                    sets.insert(path.clone(), root);
                    for (path, mut member) in set.circuits.iter().zip(members) {
                        // Bind after key derivation to avoid a self-referential set ID.
                        member.bindings = set
                            .verifier_set_id_positions
                            .into_iter()
                            .zip(*root.words())
                            .collect();
                        tracing::info!(phase = "circuit_prepared", source = ?path, circuit_id = ?member.id.words());
                        prepared.insert(path.clone(), member);
                    }
                }
            }
        }
        tracing::info!(
            phase = "contract_prepared",
            circuits = prepared.len(),
            verifier_sets = sets.len()
        );
        Ok(Self {
            entry: source.entry,
            prepared,
            sets,
        })
    }
    pub fn metadata(&self) -> Result<Metadata, Error> {
        Ok(Metadata {
            circuit_id: self.prepared.get(&self.entry).ok_or(Error::Shape)?.id,
            circuits: self
                .prepared
                .iter()
                .map(|(path, prepared)| (path.clone(), prepared.id))
                .collect(),
            verifier_sets: self.sets.clone(),
        })
    }
    pub fn prove(
        &self,
        circuit: &Path,
        public: PublicInput,
        witness: &[u8],
    ) -> Result<Artifact, Error> {
        let prepared = self.prepared.get(circuit).ok_or(Error::Shape)?;
        let assignment =
            Assignment::parse(public, witness, prepared.inputs, prepared.wiring.len())?;
        self.prove_assignment(circuit, assignment)
    }
    #[tracing::instrument(name = "prove", skip_all)]
    fn prove_assignment(&self, circuit: &Path, assignment: Assignment) -> Result<Artifact, Error> {
        let prepared = self.prepared.get(circuit).ok_or(Error::Shape)?;
        prepared.check_statement(&assignment.public)?;
        prove_prepared(prepared, assignment, |wiring, proof| match &wiring.target {
            ChildTarget::Circuit(circuit) => {
                Ok((self.prepared.get(circuit).ok_or(Error::Shape)?, Vec::new()))
            }
            ChildTarget::Set(circuits) => {
                let members = circuits
                    .iter()
                    .map(|path| self.prepared.get(path).ok_or(Error::Shape))
                    .collect::<Result<Vec<_>, _>>()?;
                let index = members
                    .iter()
                    .position(|member| member.id == proof.circuit_id)
                    .ok_or(Error::Statement)?;
                let child = *members.get(index).ok_or(Error::Shape)?;
                let sibling = members.get(1 - index).ok_or(Error::Shape)?.id;
                Ok((
                    child,
                    std::iter::once(E::from_usize(index))
                        .chain(sibling.words().iter().copied().map(E::from_u32))
                        .collect(),
                ))
            }
        })
    }
    #[tracing::instrument(skip_all)]
    pub fn verify(
        &self,
        circuit: &Path,
        public: PublicInput,
        proof: Artifact,
    ) -> Result<Vec<u32>, Error> {
        if proof.public != public.0 {
            return Err(Error::Statement);
        }
        tracing::info!(
            phase = "verifying_expected_statement",
            public_words = public.0.len()
        );
        checked_values(&proof, self.prepared.get(circuit).ok_or(Error::Shape)?)?;
        tracing::info!(phase = "proof_verified");
        Ok(public.0)
    }
}
pub fn with_session<R: Send>(
    circuit: Circuit,
    threads: NonZeroUsize,
    run: impl FnOnce(&Session) -> Result<R, Error> + Send,
) -> Result<R, Error> {
    engine::run(threads, || run(&Session::new(circuit)?))
}
pub fn prepare(circuit: Circuit, threads: NonZeroUsize) -> Result<Metadata, Error> {
    with_session(circuit, threads, Session::metadata)
}
pub fn prove(
    circuit: Circuit,
    public: PublicInput,
    witness: &[u8],
    threads: NonZeroUsize,
) -> Result<Artifact, Error> {
    let definition = circuit.definition(&circuit.entry)?;
    let assignment = Assignment::parse(
        public,
        witness,
        definition.inputs,
        definition.verifications().count(),
    )?;
    with_session(circuit, threads, |session| {
        session.prove_assignment(&session.entry, assignment)
    })
}
pub fn verify(
    circuit: Circuit,
    public: PublicInput,
    proof: Artifact,
    threads: NonZeroUsize,
) -> Result<Vec<u32>, Error> {
    with_session(circuit, threads, |session| {
        session.verify(&session.entry, public, proof)
    })
}

#[cfg(test)]
#[path = "../../tests/controls/recursion.rs"]
mod tests;
