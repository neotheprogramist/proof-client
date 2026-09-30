use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_koala_bear::{KoalaBear, default_koalabear_poseidon2_16};
use p3_symmetric::{CryptographicHasher, Increment, Pad10Sponge};

use super::{Hash, HashAlgId, HashAlgorithm};

/// The frozen poseidon2-koalabear-16-pad10-v1 byte hash.
#[derive(Debug, Default, Clone, Copy)]
pub struct Poseidon2KoalaBear;

impl HashAlgorithm for Poseidon2KoalaBear {
    fn id(&self) -> HashAlgId {
        HashAlgId::POSEIDON2_KOALABEAR_16_PAD10_V1
    }

    fn hash(&self, data: &[u8]) -> Hash {
        self.hash_prefixed(&[], data)
    }

    fn hash_prefixed(&self, prefix: &[u8], data: &[u8]) -> Hash {
        let mut bytes = b"tlsn/poseidon2/koalabear/16/pad10/v1"
            .iter()
            .chain(prefix)
            .chain(data)
            .copied()
            .chain([1]);
        let words = std::iter::from_fn(|| {
            bytes.next().map(|first| {
                let mut packed = [0; 4];
                packed[0] = first;
                for byte in &mut packed[1..3] {
                    if let Some(next) = bytes.next() {
                        *byte = next;
                    }
                }
                KoalaBear::from_u32(u32::from_le_bytes(packed))
            })
        });
        // PROOF: ONE is nonzero; Increment is a derangement over KoalaBear.
        let sponge = Pad10Sponge::<_, _, _, 16, 8, 8>::new(
            default_koalabear_poseidon2_16(),
            Increment::new(KoalaBear::ONE),
        );
        let words = sponge.hash_iter(words);
        let mut digest = [0; 32];
        for (output, word) in digest.chunks_exact_mut(4).zip(words) {
            output.copy_from_slice(&word.as_canonical_u32().to_le_bytes());
        }
        Hash::new(&digest)
    }
}
