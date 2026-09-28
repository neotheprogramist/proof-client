# Vendor sources

The vendor directories contain complete upstream repository trees at
the exact commits in [sources.json](sources.json), including original manifests,
examples, documentation and licenses. They are nested upstream workspaces excluded
from the consumer workspace. [patches.toml](patches.toml) selects the dependency graph through
`.cargo/config.toml`'s single required `include`.

Cryptographic patches:

- `Plonky3/fri/src/hiding_pcs.rs`: release the hiding RNG lock before nested Rayon work.
- `Plonky3/merkle-tree/src/hiding_mmcs.rs`: the same lock-scope correction for salts.
- `Plonky3-recursion/recursion/src/types/proof.rs`: expose preprocessing commitment
  targets; the consumer binds them to a fixed verifier or checked verifier-set membership.
- `Plonky3-recursion/circuit/src/builder/compiler/optimizer/dedup.rs`: apply
  final witness rewrites to earlier operations after deduplication.
- `Plonky3-recursion/circuit-prover/src/batch_stark_prover.rs`: export prepared
  proving data without generating an unused proof.

`tlsn-mux` uses upstream `tlsn-utils` at `67aab0bc`, pinned in `tlsn/Cargo.toml`.
Its SYN frames and MPZ's bounded channel lanes require matching peers;
the consumer's QUIC `ALPN` rejects older builds.

TLSNotary alpha.15 also needs these patches:

- `mpz/crates/common/`: notify suspended consumers on pool shutdown, reject new
  contexts, and drain work queued after shutdown. Upstream supplies bounded map
  lanes and partial worker-startup cleanup.
- `mpz/crates/circuits-data/`: generate circuit binaries in Cargo's `OUT_DIR`.
- `tlsn/Cargo.toml` and MPC consumers: pin the updated MPZ crates and use rand 0.10
  for their RNG inputs. TLS primitives retain rand 0.9.
- `tlsn/crates/tlsn/src/session.rs`: own a dedicated MPZ pool per TLS session;
  dropping the owner shuts down outstanding work. `Session::new` remains fallible.
- `tlsn/crates/tlsn/src/transcript_internal/auth.rs`: reject reveal/commit ranges
  beyond the authenticated transcript before plaintext allocation or indexing.

The complete forward differences are in [patches](patches). No source is patched
at build time. Never run consumer formatting over these upstream trees.
Preserve tracked upstream files even when upstream ignore rules match them.

The provenance test checks each tree against its upstream hash, reversing recorded
patches in a temporary directory after checking their SHA-256.
The tree hash is SHA-256 of sorted UTF-8 relative file names, each followed
by a zero byte and the SHA-256 of its contents. These revisions contain no symlinks.
Executable file paths are recorded separately and checked on Unix. The hashes detect
local drift; the commit and upstream archive identify the source of authority.

Regression gates are `hiding`, the recursive-verifier controls, `transport`, `attest`
and CLI `tls`; `vendor` checks provenance. See [verification](../README.md#verification).
