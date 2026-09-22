use p3_circuit::{
    CircuitBuilder, CircuitRunner, NonPrimitiveOpId,
    ops::{Poseidon2Config, generate_poseidon2_trace, generate_recompose_trace},
};
use p3_commit::{ExtensionMmcs, Pcs};
use p3_field::{Field, extension::BinomialExtensionField};
use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear, default_koalabear_poseidon2_16};
use p3_lookup::logup::LogUpGadget;
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_poseidon2_circuit_air::KoalaBearD4Width16;
use p3_recursion::{
    FriRecursionConfig, FriVerifierParams, NativeFriParams, RecursionInput, RecursiveAir,
    builtin_config::{
        BuiltinConfigError, FriConfigV1, KoalaBearD4Poseidon2SaltedConfig, SuiteIdV1,
        koala_bear_d4_poseidon2_salted,
    },
    generation::{OpeningTranscript, merge_hiding_random_openings, observe_opened_values},
    pcs::{
        HidingFriProofTargets, InputProofTargets, MerkleCapTargets, RecExtensionValMmcs,
        RecValHidingMmcs, Witness, restore_hiding_fri_query_paths, set_fri_mmcs_private_data,
    },
    verifier::{VerificationError, VerifierLimits},
};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::StarkGenericConfig;
use rand::{SeedableRng, rngs::StdRng};

type F = KoalaBear;
type E = BinomialExtensionField<F, 4>;
type Inner = KoalaBearD4Poseidon2SaltedConfig<StdRng>;
type Perm = Poseidon2KoalaBear<16>;
type Hash = PaddingFreeSponge<Perm, 16, 8, 8>;
type Compress = TruncatedPermutation<Perm, 2, 8, 16>;
type Mmcs = MerkleTreeHidingMmcs<
    <F as Field>::Packing,
    <F as Field>::Packing,
    Hash,
    Compress,
    StdRng,
    2,
    8,
    4,
>;
type RecursiveMmcs = RecValHidingMmcs<F, 8, 4, Hash, Compress, StdRng>;
type Input = InputProofTargets<F, E, RecursiveMmcs>;
type Opening =
    HidingFriProofTargets<F, E, RecExtensionValMmcs<F, E, 8, RecursiveMmcs>, Input, Witness<F>>;

// Policy: one explicit hiding FRI profile; this is not a composed-security claim.
pub const FRI: FriConfigV1 = FriConfigV1::new(
    SuiteIdV1::KoalaBearD4Poseidon2SaltedFri,
    2,
    6,
    2,
    56,
    0,
    15,
    0,
    0,
    2,
    4,
);

#[derive(Clone)]
pub struct Config {
    inner: Inner,
    params: FriVerifierParams,
}
impl Config {
    pub fn new(
        input: StdRng,
        commit: StdRng,
        codeword: StdRng,
    ) -> Result<Self, BuiltinConfigError> {
        let inner = koala_bear_d4_poseidon2_salted(
            &FRI,
            &VerifierLimits::default(),
            input,
            commit,
            codeword,
        )?;
        let params = inner.fri_verifier_params();
        Ok(Self { inner, params })
    }
}
impl StarkGenericConfig for Config {
    type Pcs = <Inner as StarkGenericConfig>::Pcs;
    type Challenge = E;
    type Challenger = <Inner as StarkGenericConfig>::Challenger;
    fn pcs(&self) -> &Self::Pcs {
        self.inner.pcs()
    }
    fn initialise_challenger(&self) -> Self::Challenger {
        self.inner.initialise_challenger()
    }
}
impl FriRecursionConfig for Config {
    type Commitment = MerkleCapTargets<F, 8>;
    type InputProof = Input;
    type OpeningProof = Opening;
    type RawOpeningProof = <Self::Pcs as Pcs<E, Self::Challenger>>::Proof;
    const DIGEST_ELEMS: usize = 8;
    fn native_fri_validation_params(&self) -> Option<NativeFriParams> {
        Some(self.inner.native_fri_params())
    }
    fn with_fri_opening_proof<'a, A, R>(
        prev: &RecursionInput<'a, Self, A>,
        f: impl FnOnce(&Self::RawOpeningProof) -> R,
    ) -> R
    where
        A: RecursiveAir<F, E, LogUpGadget>,
    {
        match prev {
            RecursionInput::UniStark { proof, .. } => f(&proof.opening_proof),
            RecursionInput::BatchStark { proof, .. } => f(&proof.proof.opening_proof),
        }
    }
    fn prepare_circuit_for_verification(
        &self,
        circuit: &mut CircuitBuilder<E>,
    ) -> Result<(), VerificationError> {
        circuit.enable_poseidon2_perm::<KoalaBearD4Width16, _>(
            generate_poseidon2_trace::<E, KoalaBearD4Width16>,
            default_koalabear_poseidon2_16(),
        );
        circuit.enable_recompose::<F>(generate_recompose_trace::<F, E>);
        circuit.set_recompose_coeff_ctl_for_decompose_links(true);
        Ok(())
    }
    fn pcs_verifier_params(&self) -> &FriVerifierParams {
        &self.params
    }
    fn set_fri_private_data(
        _config: &Self,
        runner: &mut CircuitRunner<'_, E>,
        ops: &[NonPrimitiveOpId],
        proof: &Self::RawOpeningProof,
        transcript: OpeningTranscript<Self>,
    ) -> Result<(), &'static str> {
        let OpeningTranscript {
            mut challenger,
            mut commitments_with_opening_points,
        } = transcript;
        if merge_hiding_random_openings::<Self>(&mut commitments_with_opening_points, &proof.0)
            .is_err()
        {
            return Err("hiding opening shape mismatch");
        }
        observe_opened_values::<Self>(&mut challenger, &commitments_with_opening_points);
        let permutation = default_koalabear_poseidon2_16();
        // Verification-only RNG; never used for commitments.
        let mmcs = Mmcs::new(
            Hash::new(permutation.clone()),
            Compress::new(permutation),
            0,
            StdRng::seed_from_u64(0),
        );
        let params = fri_parameters(mmcs.clone());
        let permutation = default_koalabear_poseidon2_16();
        let tree = p3_merkle_tree::MerkleTreeMmcs::<_, _, _, _, 2, 8>::new(
            Hash::new(permutation.clone()),
            Compress::new(permutation),
            0,
        );
        let paths = match restore_hiding_fri_query_paths(
            &params,
            &mmcs,
            &tree,
            &tree,
            &proof.1,
            &mut challenger,
            &commitments_with_opening_points,
        ) {
            Ok(paths) => paths,
            Err(_) => return Err("FRI opening path restoration failed"),
        };
        set_fri_mmcs_private_data::<F, E, 8>(
            runner,
            ops,
            &paths,
            Poseidon2Config::KOALA_BEAR_D4_W16,
        )
    }
}

fn fri_parameters(mmcs: Mmcs) -> p3_fri::FriParameters<ExtensionMmcs<F, E, Mmcs>> {
    p3_fri::FriParameters {
        log_blowup: FRI.log_blowup() as usize,
        log_final_poly_len: FRI.log_final_poly_len() as usize,
        max_log_arity: FRI.max_log_arity() as usize,
        num_queries: FRI.num_queries() as usize,
        commit_proof_of_work_bits: FRI.commit_pow_bits() as usize,
        query_proof_of_work_bits: FRI.query_pow_bits() as usize,
        mmcs: ExtensionMmcs::new(mmcs),
    }
}
