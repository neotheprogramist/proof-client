use super::{
    Error,
    config::{AUXILIARY_POW_BITS, Config, FRI},
    engine::{E, F},
    source::FORMAT,
};
use p3_air::{Air, BaseAir, symbolic::AirLayout};
use p3_circuit_prover::CircuitVerifier;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_lookup::symbolic::InteractionSymbolicBuilder;
use p3_symmetric::{CryptographicHasher, Increment, Pad10Sponge, PaddingFreeSponge};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "[u32; 8]")]
pub struct CircuitId([u32; 8]);
impl CircuitId {
    pub fn words(&self) -> &[u32; 8] {
        &self.0
    }
    pub(super) fn from_key(key: [F; 8]) -> Self {
        Self(key.map(|word| word.as_canonical_u32()))
    }
}
impl TryFrom<[u32; 8]> for CircuitId {
    type Error = Error;
    fn try_from(words: [u32; 8]) -> Result<Self, Error> {
        if words.iter().any(|word| *word >= F::ORDER_U32) {
            return Err(Error::Artifact);
        }
        Ok(Self(words))
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "[u32; 8]")]
pub struct VerifierSetId([u32; 8]);
impl VerifierSetId {
    pub fn words(&self) -> &[u32; 8] {
        &self.0
    }
    pub(super) fn from_root(root: [F; 8]) -> Self {
        Self(root.map(|word| word.as_canonical_u32()))
    }
}
impl TryFrom<[u32; 8]> for VerifierSetId {
    type Error = Error;
    fn try_from(words: [u32; 8]) -> Result<Self, Error> {
        if words.iter().any(|word| *word >= F::ORDER_U32) {
            return Err(Error::Artifact);
        }
        Ok(Self(words))
    }
}
pub(super) const KEY: u32 = 0x5043_0201;
pub(super) const VERIFIER_SET: u32 = 0x5043_0202;
pub(super) const DESCRIPTOR: u32 = 0x5043_0203;
const BACKEND_PROFILE: &str = "proof-client/plonky3-0.8/2";

pub(super) fn hash(tag: u32, words: &[F]) -> [F; 8] {
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

// Bind constraints and lookups, not only dimensions.
pub(super) fn descriptor(verifier: &CircuitVerifier<Config>) -> Result<Vec<u8>, Error> {
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
        (
            BACKEND_PROFILE,
            (
                FRI.suite().as_u16(),
                FRI.log_blowup(),
                FRI.log_final_poly_len(),
                FRI.max_log_arity(),
                FRI.num_queries(),
                FRI.commit_pow_bits(),
                FRI.query_pow_bits(),
                FRI.input_cap_height(),
                FRI.commit_cap_height(),
                FRI.num_random_codewords(),
                FRI.salt_elements(),
            ),
            AUXILIARY_POW_BITS,
        ),
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
pub(super) fn descriptor_digest(verifier: &CircuitVerifier<Config>) -> Result<[F; 8], Error> {
    let mut bytes = descriptor(verifier)?;
    bytes.push(1);
    let words = bytes.chunks(3).map(|chunk| {
        // PROOF: three little-endian bytes fit below the KoalaBear modulus.
        F::from_u32(
            chunk
                .iter()
                .rev()
                .fold(0, |word, byte| (word << 8) | u32::from(*byte)),
        )
    });
    let domain = [
        F::from_u32(DESCRIPTOR),
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
    ];
    // PROOF: ONE is nonzero; Increment is a derangement over KoalaBear.
    Ok(Pad10Sponge::<_, _, _, 16, 8, 8>::new(
        p3_koala_bear::default_koalabear_poseidon2_16(),
        Increment::new(F::ONE),
    )
    .hash_iter(domain.into_iter().chain(words)))
}
pub(super) fn key(verifier: &CircuitVerifier<Config>) -> Result<[F; 8], Error> {
    let mut words = descriptor_digest(verifier)?.to_vec();
    let common = verifier.common_data();
    let commitment = &common.preprocessed.as_ref().ok_or(Error::Shape)?.commitment;
    words.extend(commitment.roots().iter().flatten().copied());
    Ok(hash(KEY, &words))
}
