use super::*;

#[derive(Deserialize)]
#[serde(untagged)]
enum WireCircuit {
    Direct(super::Definition),
    Family(Box<family::Definition>),
}
impl WireCircuit {
    fn parse(self) -> Result<Circuit, Error> {
        match self {
            Self::Direct(source) => Ok(Circuit::Direct(super::Circuit::from_definition(source)?)),
            Self::Family(source) => Ok(Circuit::Family(Box::new(
                family::Circuit::from_definition(*source)?,
            ))),
        }
    }
}
pub enum Circuit {
    Direct(super::Circuit),
    Family(Box<family::Circuit>),
}
impl Circuit {
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_INPUT_BYTES {
            return Err(Error::Shape);
        }
        serde_json::from_slice::<WireCircuit>(bytes)?.parse()
    }
}
pub enum Job {
    Direct(super::Job),
    Family(Box<family::Job>),
}
impl Job {
    pub fn parse(circuit: Circuit, bytes: &[u8]) -> Result<Self, Error> {
        match circuit {
            Circuit::Direct(circuit) => super::Job::parse(circuit, bytes).map(Self::Direct),
            Circuit::Family(circuit) => family::Job::parse(*circuit, bytes)
                .map(Box::new)
                .map(Self::Family),
        }
    }
}
pub fn prove(job: Job, threads: NonZeroUsize) -> Result<Artifact, Error> {
    match job {
        Job::Direct(job) => super::prove(job, threads),
        Job::Family(job) => family::prove(*job, threads),
    }
}
pub fn verify(circuit: Circuit, proof: Artifact, threads: NonZeroUsize) -> Result<Vec<u32>, Error> {
    match circuit {
        Circuit::Direct(circuit) => super::verify(circuit, proof, threads),
        Circuit::Family(circuit) => family::verify(*circuit, proof, threads),
    }
}
