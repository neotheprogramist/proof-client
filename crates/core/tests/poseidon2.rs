#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test observations are direct"
)]

use std::sync::LazyLock;

use mpz_circuits_core::{Circuit, circuits::poseidon2_koalabear, evaluate};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_koala_bear::{KoalaBear, default_koalabear_poseidon2_16};
use p3_symmetric::{CryptographicHasher, Increment, Pad10Sponge, Permutation};
use proptest::prelude::*;
use tlsn::hash::{HashAlgId, HashAlgorithm, HashProvider, Poseidon2KoalaBear};

static CIRCUIT: LazyLock<Circuit> = LazyLock::new(|| poseidon2_koalabear::permute().unwrap());

proptest! {
    #[test]
    fn native_hash_frames_bytes_once(data in prop::collection::vec(any::<u8>(), 0..256), split in any::<usize>()) {
        let split = split % (data.len() + 1);
        let mut framed = b"tlsn/poseidon2/koalabear/16/pad10/v1".to_vec();
        framed.extend_from_slice(&data);
        framed.push(1);
        while !framed.len().is_multiple_of(3) { framed.push(0); }
        let input = framed.as_chunks::<3>().0.iter().map(|bytes| {
            KoalaBear::from_u32(u32::from(bytes[0]) + (u32::from(bytes[1]) << 8) + (u32::from(bytes[2]) << 16))
        });
        let expected = Pad10Sponge::<_, _, _, 16, 8, 8>::new(
            default_koalabear_poseidon2_16(), Increment::new(KoalaBear::ONE),
        ).hash_iter(input).map(|word| word.as_canonical_u32().to_le_bytes()).concat();
        let provider = HashProvider::default();
        let hasher = provider.get(&HashAlgId::POSEIDON2_KOALABEAR_16_PAD10_V1).unwrap();
        let actual = hasher.hash(&data);
        let partitioned = hasher.hash_prefixed(&data[..split], &data[split..]);
        prop_assert_eq!(actual.as_bytes(), &expected);
        prop_assert_eq!(partitioned.as_bytes(), &expected);
        let mut with_zero = data;
        with_zero.push(0);
        let extended = hasher.hash(&with_zero);
        prop_assert_ne!(extended.as_bytes(), &expected);
    }

    #[test]
    fn boolean_permutation_matches_stock(input in any::<[u32; 16]>()) {
        check_permutation(input);
    }
}

fn check_permutation(input: [u32; 16]) {
    let expected = default_koalabear_poseidon2_16()
        .permute(input.map(KoalaBear::from_u32))
        .map(|word| word.as_canonical_u32());
    let actual: [u32; 16] = evaluate!(&*CIRCUIT, input).unwrap();
    assert_eq!(actual, expected);
    let increment: u32 = evaluate!(&poseidon2_koalabear::increment().unwrap(), input[0]).unwrap();
    assert_eq!(
        increment,
        (KoalaBear::from_u32(input[0]) + KoalaBear::ONE).as_canonical_u32()
    );
}

#[test]
fn frozen_profile_vectors() {
    for input in [
        [0; 16],
        [KoalaBear::ORDER_U32 - 1; 16],
        [KoalaBear::ORDER_U32; 16],
        [u32::MAX; 16],
    ] {
        check_permutation(input);
    }
    for (input, digest) in [
        (
            vec![],
            "af663c44b555121ea6a4d33e2305c44ebc670f58b19b7e55b132d75e19467e39",
        ),
        (
            vec![0],
            "c208e0047543d5603b8dfd52f8a0d37d1753af53771f2867c28c1b14fabe152d",
        ),
        (
            (0u8..11).collect(),
            "c18f6819e10c0f0ab5ccd62fccd72f76f6e44f3c24d7f97a81b9e9574ad5ac60",
        ),
        (
            (0u8..12).collect(),
            "5f20f071bdcb3806dcb28166eb564f32a85a64429b084621e2d2fd098a69c616",
        ),
    ] {
        let actual = Poseidon2KoalaBear
            .hash(&input)
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert_eq!(actual, digest);
    }
}
