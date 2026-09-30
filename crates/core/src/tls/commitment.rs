use std::{fmt, num::NonZeroUsize, str::FromStr};
use tlsn::hash::HashAlgId;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CommitmentHash {
    #[default]
    Blake3,
    Poseidon2KoalaBear,
}

impl CommitmentHash {
    pub const fn id(self) -> HashAlgId {
        match self {
            Self::Blake3 => HashAlgId::BLAKE3,
            Self::Poseidon2KoalaBear => HashAlgId::POSEIDON2_KOALABEAR_16_PAD10_V1,
        }
    }
}

impl fmt::Display for CommitmentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Blake3 => "blake3",
            Self::Poseidon2KoalaBear => "poseidon2-koalabear-16-pad10-v1",
        })
    }
}

impl FromStr for CommitmentHash {
    type Err = CommitmentError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "blake3" => Ok(Self::Blake3),
            "poseidon2-koalabear-16-pad10-v1" => Ok(Self::Poseidon2KoalaBear),
            _ => Err(CommitmentError::Algorithm),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum CommitmentPolicy {
    Blake3,
    Poseidon2KoalaBear { max_permutations: NonZeroUsize },
}

impl CommitmentPolicy {
    pub fn new(
        hash: CommitmentHash,
        budget: Option<NonZeroUsize>,
    ) -> Result<Self, CommitmentError> {
        match (hash, budget) {
            (CommitmentHash::Blake3, None) => Ok(Self::Blake3),
            (CommitmentHash::Poseidon2KoalaBear, Some(max_permutations)) => {
                Ok(Self::Poseidon2KoalaBear { max_permutations })
            }
            (CommitmentHash::Blake3, Some(_)) => Err(CommitmentError::UnexpectedBudget),
            (CommitmentHash::Poseidon2KoalaBear, None) => Err(CommitmentError::MissingBudget),
        }
    }

    pub const fn hash(self) -> CommitmentHash {
        match self {
            Self::Blake3 => CommitmentHash::Blake3,
            Self::Poseidon2KoalaBear { .. } => CommitmentHash::Poseidon2KoalaBear,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CommitmentError {
    #[error("expected blake3 or poseidon2-koalabear-16-pad10-v1")]
    Algorithm,
    #[error("KoalaBear requires --max-commitment-permutations on serve")]
    MissingBudget,
    #[error("--max-commitment-permutations applies only to KoalaBear")]
    UnexpectedBudget,
    #[error("KoalaBear commitments exceed the verifier's permutation budget")]
    Budget,
}
