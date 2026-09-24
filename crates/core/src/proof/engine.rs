use p3_circuit::{Circuit, CircuitBuilder, ExprId, StatementSchema, ops::Poseidon2Config};
use p3_circuit_prover::{
    BatchStarkProver, ConstraintProfile, PreparedCircuitProver, StatementAirBuilder,
    StatementPreprocessor, StatementProver, TablePacking,
};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, extension::BinomialExtensionField};
use p3_koala_bear::KoalaBear;
use p3_recursion::{
    BatchOnly, BatchStarkVerifierInputsBuilder, FriRecursionBackend, FriRecursionConfig,
    PcsRecursionBackend,
};
use rand::{
    SeedableRng,
    rngs::{StdRng, SysRng},
};

pub(crate) type F = KoalaBear;
pub(crate) type E = BinomialExtensionField<F, 4>;
use crate::proof::config::{Config, FRI};
pub(crate) type Backend =
    p3_recursion::backend::FriRecursionBackendForExt<4, 16, 8, Poseidon2Config>;
pub(crate) type Inputs = BatchStarkVerifierInputsBuilder<
    Config,
    <Config as FriRecursionConfig>::Commitment,
    <Config as FriRecursionConfig>::OpeningProof,
>;

use crate::proof::error::Error;
pub(crate) const POSEIDON: Poseidon2Config = Poseidon2Config::KOALA_BEAR_D4_W16;
pub(crate) fn pack(words: &[F]) -> Result<E, Error> {
    E::from_basis_coefficients_slice(words).ok_or(Error::Shape)
}

pub(crate) fn backend() -> Backend {
    FriRecursionBackend::<16, 8, _>::new(POSEIDON).for_extension_degree::<4>()
}

pub(crate) fn canonical_config() -> Result<Config, Error> {
    // Public preprocessing; witness RNGs are independent.
    Ok(Config::new(
        StdRng::seed_from_u64(0),
        StdRng::seed_from_u64(1),
        StdRng::seed_from_u64(2),
    )?)
}

pub(crate) fn private_config() -> Result<Config, Error> {
    Ok(Config::new(
        StdRng::try_from_rng(&mut SysRng)?,
        StdRng::try_from_rng(&mut SysRng)?,
        StdRng::try_from_rng(&mut SysRng)?,
    )?)
}

pub(crate) fn builder() -> Result<CircuitBuilder<E>, Error> {
    let mut builder = CircuitBuilder::new();
    canonical_config()?.prepare_circuit_for_verification(&mut builder)?;
    Ok(builder)
}

pub(crate) fn circuit_hash(
    builder: &mut CircuitBuilder<E>,
    tag: u32,
    input: &[ExprId],
) -> Result<[ExprId; 2], Error> {
    let first = pack(&[
        F::from_u32(tag),
        F::from_usize(input.len() * 4),
        F::ZERO,
        F::ZERO,
    ])?;
    let prefix = [builder.define_const(first), builder.define_const(E::ZERO)];
    let targets = prefix
        .into_iter()
        .chain(input.iter().copied())
        .collect::<Vec<_>>();
    builder
        .add_hash_slice(&POSEIDON, &targets, true)?
        .try_into()
        .or(Err(Error::Shape))
}

pub(crate) fn packing() -> TablePacking {
    // Policy: use upstream's binomial-D4 packing.
    TablePacking::new(1, 3)
        .with_horner_pack_k(4)
        .with_fri_params(FRI.log_final_poly_len() as usize, FRI.log_blowup() as usize)
}

pub(crate) fn prover(config: Config, schema: &StatementSchema) -> BatchStarkProver<Config> {
    let mut prover = BatchStarkProver::new(config).with_table_packing(packing());
    for table in
        <Backend as PcsRecursionBackend<Config, BatchOnly, 4>>::non_primitive_provers(&backend(), 4)
    {
        prover.register_table_prover(table);
    }
    prover.register_table_prover(Box::new(StatementProver::<4>::new(schema.clone())));
    prover
}

pub(crate) fn prepare(
    circuit: &Circuit<E>,
    schema: &StatementSchema,
) -> Result<PreparedCircuitProver<Config>, Error> {
    prepare_packed(circuit, schema, prover(canonical_config()?, schema))
}

pub(crate) fn prepare_packed(
    circuit: &Circuit<E>,
    schema: &StatementSchema,
    prover: BatchStarkProver<Config>,
) -> Result<PreparedCircuitProver<Config>, Error> {
    let mut preprocessors =
        <Backend as PcsRecursionBackend<Config, BatchOnly, 4>>::non_primitive_preprocessors(
            &backend(),
        );
    let mut airs =
        <Backend as PcsRecursionBackend<Config, BatchOnly, 4>>::non_primitive_air_builders(
            &backend(),
        );
    preprocessors.push(Box::new(StatementPreprocessor::new(schema.clone())));
    airs.push(Box::new(StatementAirBuilder::<4>::new(schema.clone())));
    Ok(prover.prepare_circuit::<E, 4>(
        circuit,
        &preprocessors,
        &airs,
        ConstraintProfile::Standard,
    )?)
}

pub(crate) fn run<R: Send>(
    threads: std::num::NonZeroUsize,
    operation: impl FnOnce() -> Result<R, Error> + Send,
) -> Result<R, Error> {
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads.get())
        .build()?
        .install(operation)
}
