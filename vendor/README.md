# Vendor sources

The vendor directories contain complete upstream repository trees at
the exact commits in [sources.json](sources.json), including original manifests,
examples, documentation and licenses. They are nested upstream workspaces excluded
from the consumer workspace. [patches.toml](patches.toml) selects the dependency graph through
`.cargo/config.toml`'s single required `include`.

The cryptographic patches change five source files:

- `Plonky3/fri/src/hiding_pcs.rs`: release the hiding RNG lock before nested Rayon work.
- `Plonky3/merkle-tree/src/hiding_mmcs.rs`: the same lock-scope correction for salts.
- `Plonky3-recursion/recursion/src/types/proof.rs`: constrain a recursive child's
  preprocessing commitment to its independently prepared verifier, and expose those exact
  targets for checked in-circuit verifier-set membership.
- `Plonky3-recursion/circuit/src/builder/compiler/optimizer/dedup.rs`: apply
  final witness rewrites to earlier operations after deduplication.
- `Plonky3-recursion/circuit-prover/src/batch_stark_prover.rs`: export prepared
  proving data without generating an unused proof.

TLSNotary alpha.15 also needs these patches:

- `tlsn-utils/mux/`: upstream [PR #111](https://github.com/tlsnotary/tlsn-utils/pull/111)
  at `42e4ea94`, including the driver wakeup fix: bounded active streams, retained
  unclaimed data, ordered closes and teardown wakeups. Its SYN opening frames change
  the mux protocol; both peers must use this patched build.
- `mpz/crates/common/src/context.rs`: backport bounded, ordered map scheduling from
  upstream [PR #403](https://github.com/privacy-ethereum/mpz/pull/403). Unbounded
  scheduling still exhausted the patched mux in the sparse-disclosure fixture.
  Local context/executor fixes return cancellation errors and drain tasks queued
  during shutdown. Executor ownership precedes worker spawning; startup errors unwind
  partially started workers.
- `tlsn/crates/tlsn/src/session.rs`: propagate fallible executor startup through
  `Session::new`, with call sites updated to handle the error.
- `tlsn/crates/tlsn/src/transcript_internal/auth.rs`: reject reveal/commit ranges
  beyond the authenticated transcript before plaintext allocation or indexing.

The complete forward differences are in [patches](patches). No source is patched
at build time. Never run consumer formatting over these upstream trees.
The TLSNotary patch also unignores its harness index so clones retain the complete tree.

The provenance test checks the patched tree and patch SHA-256, reverses each patch
in a temporary directory, and compares the reconstructed tree to the pinned-source
hash. The tree hash is SHA-256 of sorted UTF-8 relative file names, each followed
by a zero byte and the SHA-256 of its contents. These revisions contain no symlinks.
Executable file paths are recorded separately and checked on Unix. The hashes detect
local drift; the commit and upstream archive identify the source of authority.

The workspace tests include the provenance check; see [setup and checks](../README.md#setup-and-checks).
