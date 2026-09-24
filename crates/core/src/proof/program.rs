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
pub struct Job {
    circuit: Circuit,
    assignment: Assignment,
}
impl Job {
    pub fn parse(circuit: Circuit, public: PublicInput, bytes: &[u8]) -> Result<Self, Error> {
        let definition = circuit.definition(&circuit.entry)?;
        let assignment = Assignment::parse(
            public,
            bytes,
            definition.inputs,
            definition.verifications().count(),
        )?;
        Ok(Self {
            circuit,
            assignment,
        })
    }
}
pub struct Session {
    entry: PathBuf,
    pub(super) prepared: BTreeMap<PathBuf, Prepared>,
    pub(super) sets: BTreeMap<PathBuf, VerifierSetId>,
}
impl Session {
    pub(super) fn new(source: Circuit) -> Result<Self, Error> {
        let mut prepared = BTreeMap::new();
        let mut sets = BTreeMap::new();
        for path in &source.order {
            match source.sources.get(path).ok_or(Error::Shape)? {
                Source::Circuit(definition) => {
                    prepared.insert(
                        path.clone(),
                        compiler::compile(definition, &prepared, engine::prepare)?,
                    );
                }
                Source::VerifierSet(set) => {
                    let members = recursion::compile(&source, set, &prepared)?;
                    let keys = members
                        .iter()
                        .flat_map(|member| member.id.words().iter().copied().map(F::new))
                        .collect::<Vec<_>>();
                    let root = VerifierSetId::from_root(hash(VERIFIER_SET, &keys));
                    sets.insert(path.clone(), root);
                    for (path, mut member) in set.circuits.iter().zip(members) {
                        // Bind after key derivation to avoid a self-referential set ID.
                        member.bindings = set
                            .verifier_set_id_positions
                            .into_iter()
                            .zip(*root.words())
                            .collect();
                        prepared.insert(path.clone(), member);
                    }
                }
            }
        }
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
    pub fn verify(
        &self,
        circuit: &Path,
        public: PublicInput,
        proof: Artifact,
    ) -> Result<Vec<u32>, Error> {
        if proof.public != public.0 {
            return Err(Error::Statement);
        }
        checked_values(&proof, self.prepared.get(circuit).ok_or(Error::Shape)?)?;
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
pub fn prove(job: Job, threads: NonZeroUsize) -> Result<Artifact, Error> {
    with_session(job.circuit, threads, |session| {
        session.prove_assignment(&session.entry, job.assignment)
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
