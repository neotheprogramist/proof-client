use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_koala_bear::{KoalaBear as F, default_koalabear_poseidon2_16};
use p3_symmetric::{CryptographicHasher, PaddingFreeSponge};
use rand::{RngExt, SeedableRng, rngs::StdRng};

pub const MAX_HEIGHT: u32 = 3;
const LEAF: u32 = 0x504d_0101;
pub const NODE: u32 = 0x504d_0102;
pub fn hash(tag: u32, words: &[u32]) -> [u32; 8] {
    let domain = [tag, words.len() as u32, 0, 0, 0, 0, 0, 0];
    PaddingFreeSponge::<_, 16, 8, 8>::new(default_koalabear_poseidon2_16())
        .hash_iter(
            domain
                .into_iter()
                .chain(words.iter().copied())
                .map(F::from_u32),
        )
        .map(|word| word.as_canonical_u32())
}
fn sample_leaf(index: u32) -> [u32; 8] {
    // A fixed seed keeps separate public and witness commands consistent.
    StdRng::seed_from_u64(u64::from(index))
        .random::<[F; 8]>()
        .map(|word| word.as_canonical_u32())
}
pub fn leaf(index: u32) -> (Vec<u32>, Vec<u32>) {
    let private = sample_leaf(index).to_vec();
    let public = std::iter::once(0).chain(hash(LEAF, &private)).collect();
    (public, private)
}
pub fn expected(height: u32) -> Vec<u32> {
    let mut level = (0..1 << height)
        .map(|index| hash(LEAF, &sample_leaf(index)))
        .collect::<Vec<_>>();
    while level.len() > 1 {
        level = level
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| hash(NODE, &pair.iter().flatten().copied().collect::<Vec<_>>()))
            .collect();
    }
    std::iter::once(height)
        .chain(level.into_iter().flatten())
        .collect()
}
