use std::{fmt, num::NonZeroUsize, str::FromStr};
use tlsn::hash::HashAlgId;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CommitmentHash {
    Blake3,
    #[default]
    Poseidon2KoalaBear,
}

impl CommitmentHash {
    pub const ALL: [Self; 2] = [Self::Blake3, Self::Poseidon2KoalaBear];
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Blake3 => "blake3",
            Self::Poseidon2KoalaBear => "poseidon2-koalabear-16-pad10-v1",
        }
    }
    pub const fn id(self) -> HashAlgId {
        match self {
            Self::Blake3 => HashAlgId::BLAKE3,
            Self::Poseidon2KoalaBear => HashAlgId::POSEIDON2_KOALABEAR_16_PAD10_V1,
        }
    }
}

pub(super) fn koalabear_permutations(bytes: usize) -> usize {
    // PROOF: callers bound selected bytes by MAX_SENT/MAX_RECEIVED; framing adds 53 bytes.
    (bytes + 36 + 16 + 1).div_ceil(3 * 8)
}

impl fmt::Display for CommitmentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for CommitmentHash {
    type Err = CommitmentError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|hash| hash.as_str() == value)
            .ok_or(CommitmentError::Algorithm)
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
    #[error(
        "KoalaBear commitments exceed the verifier's permutation budget: at least {required} required, {limit} allowed"
    )]
    Budget {
        required: usize,
        limit: NonZeroUsize,
    },
}
