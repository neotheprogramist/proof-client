use super::{Error, recursion::Layout};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

pub const FORMAT: &str = "proof-client/circuit/4";
// Policy: bound source loading and compilation.
pub const MAX_SOURCES: usize = 15;
pub const MAX_INPUT_BYTES: usize = 8 * 1024 * 1024;
pub(super) const MAX_DEPTH: usize = 3;
pub(super) const MAX_WIRES: usize = 4096;
// Policy: binary proof fanout.
pub(super) const MAX_RECURSIVE_CALLS: usize = 2;

#[derive(Deserialize)]
#[serde(tag = "format")]
pub enum Source {
    #[serde(rename = "proof-client/circuit/4")]
    Circuit(Definition),
    #[serde(rename = "proof-client/verifier-set/1")]
    VerifierSet(VerifierSet),
}
impl Source {
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_INPUT_BYTES {
            return Err(Error::Shape);
        }
        Ok(serde_json::from_slice(bytes)?)
    }
    pub fn resolve<E>(
        mut self,
        mut resolve: impl FnMut(&Path) -> Result<PathBuf, E>,
    ) -> Result<Self, E> {
        match &mut self {
            Self::Circuit(source) => {
                if let Some(verifier_set) = &mut source.verifier_set {
                    *verifier_set = resolve(verifier_set)?;
                }
                for operation in &mut source.operations {
                    if let Operation::Verify(call) = operation {
                        call.verifier = resolve(&call.verifier)?;
                    }
                }
            }
            Self::VerifierSet(source) => {
                for path in &mut source.circuits {
                    *path = resolve(path)?;
                }
            }
        }
        Ok(self)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Definition {
    pub(super) inputs: InputsCount,
    pub(super) verifier_set: Option<PathBuf>,
    pub(super) operations: Vec<Operation>,
    pub(super) constraints: Vec<Constraint>,
}
impl Definition {
    pub(super) fn verifications(&self) -> impl Iterator<Item = &Verification> {
        self.operations
            .iter()
            .filter_map(|operation| match operation {
                Operation::Verify(call) => Some(call),
                _ => None,
            })
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierSet {
    pub(super) circuits: [PathBuf; 2],
    pub(super) verifier_set_id_positions: [usize; 8],
    pub(super) layout: Layout,
}
#[derive(Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct InputsCount {
    pub(super) public: usize,
    pub(super) private: usize,
}
#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Operation {
    Constant { value: u32 },
    Add { left: usize, right: usize },
    Sub { left: usize, right: usize },
    Mul { left: usize, right: usize },
    Poseidon2 { tag: u32, inputs: Vec<usize> },
    Verify(Verification),
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Verification {
    pub(super) verifier: PathBuf,
    pub(super) proof: usize,
    pub(super) circuit_id_wires: [usize; 8],
}
#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Constraint {
    Equal { left: usize, right: usize },
    Bits { wire: usize, bits: u8 },
}

pub struct Circuit {
    pub(super) entry: PathBuf,
    pub(super) sources: BTreeMap<PathBuf, Source>,
    pub(super) order: Vec<PathBuf>,
}
impl Circuit {
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let entry = PathBuf::from("circuit.json");
        Self::link(
            entry.clone(),
            BTreeMap::from([(entry, Source::parse(bytes)?)]),
        )
    }
    pub fn link(entry: PathBuf, sources: BTreeMap<PathBuf, Source>) -> Result<Self, Error> {
        if sources.len() > MAX_SOURCES {
            return Err(Error::Shape);
        }
        let mut circuit = Self {
            entry,
            sources,
            order: Vec::new(),
        };
        circuit.definition(&circuit.entry)?;
        for (path, source) in &circuit.sources {
            match source {
                Source::Circuit(definition) => {
                    if let Some(verifier_set) = &definition.verifier_set
                        && !circuit.verifier_set(verifier_set)?.circuits.contains(path)
                    {
                        return Err(Error::Shape);
                    }
                    super::compiler::validate_body(definition, |call| {
                        match circuit.sources.get(&call.verifier) {
                            Some(Source::Circuit(child)) => Ok(child.inputs.public),
                            Some(Source::VerifierSet(set)) => {
                                if path != &set.circuits[1] {
                                    return Err(Error::Shape);
                                }
                                Ok(circuit.definition(&set.circuits[0])?.inputs.public)
                            }
                            None => Err(Error::Shape),
                        }
                    })?;
                }
                Source::VerifierSet(set) => {
                    set.layout.validate()?;
                    if set.circuits[0] == set.circuits[1] {
                        return Err(Error::Shape);
                    }
                    let count = circuit.definition(&set.circuits[0])?.inputs.public;
                    let positions = set
                        .verifier_set_id_positions
                        .iter()
                        .copied()
                        .collect::<BTreeSet<_>>();
                    if positions.len() != 8 || positions.iter().any(|index| *index >= count) {
                        return Err(Error::Shape);
                    }
                    for member in &set.circuits {
                        let source = circuit.definition(member)?;
                        if source.inputs.public != count
                            || source.verifier_set.as_ref() != Some(path)
                        {
                            return Err(Error::Shape);
                        }
                    }
                    if !circuit
                        .definition(&set.circuits[1])?
                        .verifications()
                        .any(|call| &call.verifier == path)
                    {
                        return Err(Error::Shape);
                    }
                }
            }
        }
        let mut order = Vec::new();
        circuit.visit(
            &circuit.entry,
            &mut BTreeSet::new(),
            &mut BTreeMap::new(),
            &mut order,
        )?;
        circuit.order = order;
        Ok(circuit)
    }
    pub(super) fn definition(&self, path: &Path) -> Result<&Definition, Error> {
        match self.sources.get(path) {
            Some(Source::Circuit(source)) => Ok(source),
            _ => Err(Error::Shape),
        }
    }
    pub(super) fn verifier_set(&self, path: &Path) -> Result<&VerifierSet, Error> {
        match self.sources.get(path) {
            Some(Source::VerifierSet(source)) => Ok(source),
            _ => Err(Error::Shape),
        }
    }
    fn visit(
        &self,
        path: &Path,
        active: &mut BTreeSet<PathBuf>,
        depths: &mut BTreeMap<PathBuf, usize>,
        order: &mut Vec<PathBuf>,
    ) -> Result<usize, Error> {
        let definition = self.definition(path)?;
        let node = definition.verifier_set.as_deref().unwrap_or(path);
        if let Some(depth) = depths.get(node) {
            return Ok(*depth);
        }
        if !active.insert(node.to_owned()) {
            return Err(Error::Shape);
        }
        let members = match &definition.verifier_set {
            None => vec![path.to_owned()],
            Some(verifier_set) => self.verifier_set(verifier_set)?.circuits.to_vec(),
        };
        let mut depth = 0;
        for member in members {
            for call in self.definition(&member)?.verifications() {
                match self.sources.get(&call.verifier) {
                    Some(Source::Circuit(_)) => {
                        depth = depth.max(1 + self.visit(&call.verifier, active, depths, order)?);
                    }
                    Some(Source::VerifierSet(_)) if call.verifier == node => {}
                    Some(Source::VerifierSet(_)) | None => return Err(Error::Shape),
                }
            }
        }
        if depth > MAX_DEPTH {
            return Err(Error::Shape);
        }
        active.remove(node);
        depths.insert(node.to_owned(), depth);
        order.push(node.to_owned());
        Ok(depth)
    }
}
