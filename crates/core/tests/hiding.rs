#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test observations are direct by contract"
)]
use p3_challenger::DuplexChallenger;
use p3_commit::{ExtensionMmcs, Pcs, PolynomialSpace};
use p3_dft::Radix2DitParallel;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_fri::{FriParameters, HidingFriPcs};
use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear, default_koalabear_poseidon2_16};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
type Element = p3_field::extension::BinomialExtensionField<KoalaBear, 4>;
use rand::{SeedableRng, rngs::StdRng};
use rayon::prelude::*;
use std::time::Duration;
mod support;

type Perm = Poseidon2KoalaBear<16>;
type Hash = PaddingFreeSponge<Perm, 16, 8, 8>;
type Compress = TruncatedPermutation<Perm, 2, 8, 16>;
type Mmcs = MerkleTreeHidingMmcs<
    <KoalaBear as Field>::Packing,
    <KoalaBear as Field>::Packing,
    Hash,
    Compress,
    StdRng,
    2,
    8,
    4,
>;
type PcsType = HidingFriPcs<
    KoalaBear,
    Radix2DitParallel<KoalaBear>,
    Mmcs,
    ExtensionMmcs<KoalaBear, Element, Mmcs>,
    StdRng,
>;
type Challenger = DuplexChallenger<KoalaBear, Perm, 16, 8>;

// Policy: this tiny admission diagnostic must finish promptly; bound and reap a deadlocked child.
const DEADLINE: Duration = Duration::from_secs(10);

#[test]
#[ignore = "upstream hiding/parallel admission gate; may fail on the pinned dependency"]
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
        StdRng::seed_from_u64(1),
    );
    let params = FriParameters {
        log_blowup: 1,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: 2,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: ExtensionMmcs::new(mmcs.clone()),
    };
    let pcs = PcsType::new(
        Radix2DitParallel::default(),
        mmcs,
        params,
        2,
        StdRng::seed_from_u64(2),
    );
    let domain = <PcsType as Pcs<Element, Challenger>>::natural_domain_for_degree(&pcs, 4096);
    let commitment_domain =
        <PcsType as Pcs<Element, Challenger>>::natural_domain_for_degree(&pcs, 8192);
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(4)
        .build()
        .unwrap();
    eprintln!("starting the parallel commitment and quotient workload");
    pool.install(|| {
        let small_domain =
            <PcsType as Pcs<Element, Challenger>>::natural_domain_for_degree(&pcs, 16);
        // Lazy input evaluation can schedule a second call on the same PCS.
        let evaluations = std::iter::once_with(|| {
            let (values, (nested, _)) = rayon::join(
                || vec![KoalaBear::ONE; 8],
                || {
                    <PcsType as Pcs<Element, Challenger>>::commit(
                        &pcs,
                        [(
                            small_domain,
                            RowMajorMatrix::new(vec![KoalaBear::ONE; 8], 1),
                        )],
                    )
                },
            );
            assert!(!nested.roots().is_empty());
            (small_domain, RowMajorMatrix::new(values, 1))
        });
        let (commitment, _) = <PcsType as Pcs<Element, Challenger>>::commit(&pcs, evaluations);
        assert!(!commitment.roots().is_empty());
        (0..64).into_par_iter().for_each(|_| {
            let values = (0..domain.size() * 3).map(KoalaBear::from_usize).collect();
            let (commitment, _) = <PcsType as Pcs<Element, Challenger>>::commit(
                &pcs,
                [(commitment_domain, RowMajorMatrix::new(values, 3))],
            );
            assert!(!commitment.roots().is_empty());
            let evaluations = domain.split_domains(2).into_iter().map(|domain| {
                let values = (0..domain.size() * 3).map(KoalaBear::from_usize).collect();
                (domain, RowMajorMatrix::new(values, 3))
            });
            let output =
                <PcsType as Pcs<Element, Challenger>>::get_quotient_ldes(&pcs, evaluations, 2);
            assert_eq!(output.len(), 2);
            for matrix in output {
                assert_eq!(matrix.height(), 8192);
                assert_eq!(matrix.width(), 5);
            }
        })
    });
    eprintln!("parallel commitment and quotient workload completed");
}
