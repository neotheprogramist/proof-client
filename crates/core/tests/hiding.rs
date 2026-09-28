#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test observations are direct by contract"
)]
use p3_challenger::DuplexChallenger;
use p3_commit::{ExtensionMmcs, Pcs, PolynomialSpace, UnivariateStarkPcs};
use p3_dft::Radix2DitParallel;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};
use p3_fri::{FriParameters, HidingFriPcs};
use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear, default_koalabear_poseidon2_16};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
type Element = p3_field::extension::BinomialExtensionField<KoalaBear, 4>;
use rand::{SeedableRng, TryCryptoRng, TryRng, rngs::StdRng};
use rayon::prelude::*;
use std::time::Duration;
mod support;

struct ScheduledRng(StdRng);
impl SeedableRng for ScheduledRng {
    type Seed = <StdRng as SeedableRng>::Seed;
    fn from_seed(seed: Self::Seed) -> Self {
        Self(StdRng::from_seed(seed))
    }
}
impl TryRng for ScheduledRng {
    type Error = std::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        rayon::yield_local();
        self.0.try_next_u32()
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        rayon::yield_local();
        self.0.try_next_u64()
    }
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), Self::Error> {
        self.0.try_fill_bytes(bytes)
    }
}
// PROOF: yielding changes scheduling, not the bytes delegated to StdRng.
impl TryCryptoRng for ScheduledRng {}

fn nested(action: impl Fn() + Sync) {
    rayon::scope(|scope| {
        for _ in 0..2 {
            scope.spawn(|_| action());
        }
    });
}

type Perm = Poseidon2KoalaBear<16>;
type Hash = PaddingFreeSponge<Perm, 16, 8, 8>;
type Compress = TruncatedPermutation<Perm, 2, 8, 16>;
type Mmcs = MerkleTreeHidingMmcs<
    <KoalaBear as Field>::Packing,
    <KoalaBear as Field>::Packing,
    Hash,
    Compress,
    ScheduledRng,
    2,
    8,
    4,
>;
type PcsType = HidingFriPcs<
    KoalaBear,
    Radix2DitParallel<KoalaBear>,
    Mmcs,
    ExtensionMmcs<KoalaBear, Element, Mmcs>,
    ScheduledRng,
>;
type Challenger = DuplexChallenger<KoalaBear, Perm, 16, 8>;

// Policy: this tiny admission diagnostic must finish promptly; bound and reap a deadlocked child.
const DEADLINE: Duration = Duration::from_secs(10);

#[test]
#[ignore = "parallel hiding lock-scope regression gate"]
fn parallel_hiding_admission() {
    support::worker("hiding_worker", DEADLINE);
}

#[test]
#[ignore = "subprocess fixture; parent enforces deadline and cleanup"]
fn hiding_worker() {
    assert_eq!(
        std::env::var("PROOF_CLIENT_WORKER").unwrap(),
        "hiding_worker"
    );
    let perm = default_koalabear_poseidon2_16();
    let mmcs = Mmcs::new(
        Hash::new(perm.clone()),
        Compress::new(perm),
        0,
        ScheduledRng::seed_from_u64(1),
    );
    let params = FriParameters {
        log_blowup: 1,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: 2,
        batch_proof_of_work_bits: 0,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: ExtensionMmcs::new(mmcs.clone()),
    };
    rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .build()
        .unwrap()
        .install(|| {
            nested(|| {
                use p3_commit::Mmcs as _;
                let (commitment, _) =
                    mmcs.commit(vec![RowMajorMatrix::new(vec![KoalaBear::ONE; 16], 1)]);
                assert!(!commitment.roots().is_empty());
            });
        });
    let pcs = PcsType::new(
        Radix2DitParallel::default(),
        mmcs,
        params,
        <Element as BasedVectorSpace<KoalaBear>>::DIMENSION,
        ScheduledRng::seed_from_u64(2),
    );
    rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .build()
        .unwrap()
        .install(|| {
            let domain = <PcsType as Pcs<Element, Challenger>>::natural_domain_for_degree(&pcs, 32);
            nested(|| {
                let (commitment, _) = <PcsType as Pcs<Element, Challenger>>::commit(
                    &pcs,
                    [(domain, RowMajorMatrix::new(vec![KoalaBear::ONE; 16], 1))],
                )
                .unwrap();
                assert!(!commitment.roots().is_empty());
            });
            nested(|| {
                let evaluations = domain
                    .split_domains(2)
                    .into_iter()
                    .map(|d| (d, RowMajorMatrix::new(vec![KoalaBear::ONE; d.size()], 1)));
                assert_eq!(
                    <PcsType as UnivariateStarkPcs<Element, Challenger>>::get_quotient_ldes(
                        &pcs,
                        evaluations,
                        2
                    )
                    .unwrap()
                    .len(),
                    2
                );
            });
        });
    let domain = <PcsType as Pcs<Element, Challenger>>::natural_domain_for_degree(&pcs, 4096);
    let commitment_domain =
        <PcsType as Pcs<Element, Challenger>>::natural_domain_for_degree(&pcs, 8192);
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(4)
        .build()
        .unwrap();
    eprintln!("starting the parallel commitment and quotient workload");
    pool.install(|| {
        (0..64).into_par_iter().for_each(|_| {
            let values = (0..domain.size() * 3).map(KoalaBear::from_usize).collect();
            let (commitment, _) = <PcsType as Pcs<Element, Challenger>>::commit(
                &pcs,
                [(commitment_domain, RowMajorMatrix::new(values, 3))],
            )
            .unwrap();
            assert!(!commitment.roots().is_empty());
            let evaluations = domain.split_domains(2).into_iter().map(|domain| {
                let values = (0..domain.size() * 3).map(KoalaBear::from_usize).collect();
                (domain, RowMajorMatrix::new(values, 3))
            });
            let output = <PcsType as UnivariateStarkPcs<Element, Challenger>>::get_quotient_ldes(
                &pcs,
                evaluations,
                2,
            )
            .unwrap();
            assert_eq!(output.len(), 2);
            for matrix in output {
                assert_eq!(matrix.height(), 8192);
                assert_eq!(
                    matrix.width(),
                    3 + <Element as BasedVectorSpace<KoalaBear>>::DIMENSION
                );
            }
        })
    });
    eprintln!("parallel commitment and quotient workload completed");
}
