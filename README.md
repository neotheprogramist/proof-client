# Proof Client

The CLI is the primary interface for running, auditing and reproducing project workflows. Commands show their purpose, observed stages, verification scope and output artifacts. Rust libraries own parsing and cryptography; Chrome is an optional adapter to the same operations.

| Command   | Purpose                                                 | Result                                               |
| --------- | ------------------------------------------------------- | ---------------------------------------------------- |
| `prepare` | Inspect the trusted circuit contract                    | Derived circuit and verifier-set IDs                 |
| `prove`   | Prove supplied public input with a private witness      | Self-verified proof artifact                         |
| `verify`  | Check against independently expected public input       | Verified circuit ID and public words                 |
| `serve`   | Accept one live disclosure for an expected HTTPS target | Authenticated transcript ranges and commitments      |
| `attest`  | Send a new HTTPS request and apply a disclosure policy  | Matching verifier receipt and private opening record |
| `inspect` | Read a saved TLS record                                 | Untrusted recorded evidence; no live verification    |

Circuit proofs and TLS disclosure are independent workflows. A circuit proof does not establish TLS provenance; authenticated transcript bytes do not establish hidden JSON relationships.

`crates/core/` owns proof and TLS validation; `crates/cli/` owns arguments, files and terminal/native I/O. `extension/` is plain JavaScript with JSDoc. Examples live in `examples/`; [vendor/README.md](vendor/README.md) records dependency patches and provenance.

## Setup

CLI prerequisites: Git, rustup and a native C toolchain. Extension development and JavaScript checks also require Node.js 26+ with npm. Rust is pinned in `rust-toolchain.toml`; JavaScript tools are locked in `package-lock.json`.

Run zsh/bash examples from the repository root. Cargo builds each command as needed. Proof runs use fresh directories; TLS runs reuse local identities. There is no browser build step or CI.

Agents may install repository dependencies and development tools. Install Cargo tools with a repository-local `--root` under `target/`; do not install globally or change persistent PATH settings. The owner performs Chrome registration, commits and pushes manually.

```sh
cargo fetch --locked
cargo run --release --locked --bin proof-client -- --help
```

## Reading CLI output

Human-readable reports are the default. Stderr records observed stages; stdout contains the final report.

- `--format json` emits one `completed` JSON event. TLS results contain disclosed evidence, never private response bodies or commitment openings.
- `attest --format raw` emits the exact private response body. It adds no newline; zsh may display `%` after an unterminated line. Other commands reject raw output before I/O.
- Reports show byte ranges as `[start, end)`, escaping control and non-ASCII bytes. Live `attest` reports print every transcript byte, including cookies and committed values; disclosure labels describe what the verifier receives. `serve` and `inspect` print plaintext only for revealed ranges. Displayed text is not reconstructed JSON.

Progress reports input paths and trust configuration, workers, prepared circuit/set IDs, framed response lengths, selector-to-wire ranges, required/admitted commitment work, verification, receipt matching and publication. These observations appear as each stage completes, including before later failures. Selector labels are local interpretations, not authenticated ancestry. Stderr never includes witness or request values; selector names and source paths are visible. Library callers install their own tracing subscriber.

Inspect the exact metadata path printed by `serve` or `attest`, including custom `--metadata-output` files:

```sh
record='.data/runs/REPLACE_WITH_REPORTED_RUN_NAME/metadata.json'
cargo run --release --locked --bin proof-client -- inspect "$record"
```

TLS records retain disclosed bytes and offsets, lengths and commitments. Prover records also retain private openings and normalized selector-to-range mappings; inspection omits openings. Inspection checks range bounds and mapping consistency; it does not re-evaluate selector meanings. Older records without mappings or disclosed segments remain readable. Records are mutable local evidence, not portable attestations; inspection never repeats TLS verification.

For reproduction, retain trusted circuit sources, expected public inputs and required private inputs explicitly. `--locked` uses the checked-in dependency lock. Fresh proofs and blinded commitments need not have identical bytes. Attestation sends a new request; the remote response may change. Full requests, hidden transcripts and response bodies are not saved automatically.

## Serve / attest

Both peers must use this patched build; its mux protocol differs from unpatched TLSNotary alpha.15. Verifier endpoints are loopback-only and use QUIC/TLS 1.3. The target uses TLSN’s TLS 1.2/HTTP/1.1 baseline and Mozilla roots, or a replacement `--target-ca` bundle. Attest trusts the local verifier certificate, or `--verifier-ca`. Each connection carries one attestation; local clients are not authenticated.

Only user-selected authenticated transcript ranges may be disclosed to the verifier. Requests, witnesses and undisclosed response bytes remain local. Selected commitment ranges and blinded digests are public; protocol metadata and transcript lengths are part of the disclosure baseline.

`attest` accepts one HTTPS URL, `-X`/`--request`, repeated `-H`/`--header`, inline `-b`/`--cookie`, and repeated `--data-raw`. The URL may be positional or supplied with `--url`. Data implies POST unless `-X` overrides the method; repeated `-X` uses the last value; without data the default is GET. Repeated data appends `&` only when the accumulated body is nonempty; `@` is literal. Data defaults to `application/x-www-form-urlencoded` unless a header overrides or suppresses it. `-H 'Name:'` suppresses a default header and `-H 'Name;'` sends an empty value. These follow [curl's request conventions](https://curl.se/docs/manpage.html).

Host must match the URL and Content-Length must match the body; suppressing either is unsupported. Explicit Connection accepts `close` or `keep-alive`; Accept-Encoding accepts only `identity`. Compressed responses, redirects, retries, proxying, file uploads, curl configuration files and multiple URLs are unsupported. Unsupported options fail explicitly; there is no general curl-command parser or shell execution. Request arguments can appear in shell history and process listings; `cargo run` also prints them.

Use `serve --help` and `attest --help` for flags and defaults. `serve --server-name` is the independently expected HTTPS target; it is distinct from the local verifier's TLS name. Missing identities fail; commands never create or trust certificates implicitly.

Metadata uses `<data-dir>/runs/{attest,serve}.<random>/metadata.json`, or `--metadata-output`. Publication reports the exact path and never overwrites an existing destination. Prover records contain private openings. Runtime artifacts belong under `.data/`; builds use `target/`.

Omitting `--disclosure` hides all transcript bytes and creates no explicit commitments. A supplied [policy](examples/mbank/disclosure.json) has symmetric `reveal` and `commit` objects, each containing `sent` and `received` selections. Omitted objects/directions and empty arrays select nothing; `{}` hides everything. Unknown fields, missing selectors and overlapping reveal/commit ranges fail. Revealed ranges form a union. Each distinct committed selection produces one independently openable blinded commitment (BLAKE3 by default). Identical selections share a commitment; empty or partially overlapping committed selections fail. All wire ranges of one selection, including across HTTP chunks, share its digest and blinder. The per-session count limit is `MAX_COMMITMENTS` in `crates/core/src/tls/mod.rs`.

Live commitment numbers follow transcript order, sent before received. Match openings to commitments by direction and ranges, not array position. The prover's selector report uses the same mapping; these local labels do not authenticate JSON ancestry. Earlier saved records retain their original grouping.

| Selection                               | Meaning                                                               |
| --------------------------------------- | --------------------------------------------------------------------- |
| `{"bytes": [start, end]}`               | Nonempty half-open range in the original transcript                   |
| `"start_line"`                          | Request line or final status line, including CRLF                     |
| `{"header": "content-type"}`            | Every matching complete header line, including CRLF; case insensitive |
| `"body"`                                | Payload bytes, excluding chunk framing                                |
| `{"json": "/products/0/balance"}`       | Object member, or value at the root/array index                       |
| `{"json_key": "/products/0/account"}`   | Quoted object key; root/array elements have no key                    |
| `{"json_value": "/products/0/account"}` | Serialized value, including quotes for strings                        |

Selectors use JSON Pointer escaping (`~0` for `~`, `~1` for `/`). Original bytes, including decimal spelling and string escapes, are preserved across HTTP chunks. Duplicate decoded keys fail. There are no wildcard queries, implicit structural disclosures or policy-file discovery.

TLSN authenticates selected bytes and positions, not hidden JSON ancestry, account ownership, freshness or completeness. Application statements require authenticated context or a separate proof. Only live verification or a matched receipt constructs `VerifiedReport`; saved records carry no verification authority. Native messaging displays hidden/committed bytes as 🙈/🔒.

Receipt validation, QUIC closure, metadata publication and stdout delivery are separate transitions. Metadata is saved before stdout; a save or broken pipe failure can follow successful remote verification. Published files remain. There are no automatic retries.

Idle listeners wait for a client. `SESSION_TIMEOUT` in `crates/core/src/tls/attest.rs` bounds the connected session; Quinn's default idle timeout can expire sooner during silent computation. Synchronous circuit work is not preempted by a cooperative deadline. After closure, `draining_transport` waits for Quinn’s RTT-dependent three-PTO timer, outside the session deadline; `transport_drained` confirms shutdown. HTTP framing can finish before EOF, but completing the TLS session still requires peer closure. Use `Connection: close`; keep-alive can wait until the session deadline. Surplus HTTP bytes are discarded.

### KoalaBear commitments

BLAKE3 remains the default. To select the experimental Plonky3 suite, add `--commitment-hash poseidon2-koalabear-16-pad10-v1` to both `serve` and `attest`. Serve also requires `--max-commitment-permutations N`, where `N` is a positive operator-selected budget. Mismatched algorithms and excess work are rejected before either peer schedules commitment hashes; no algorithm is substituted.

For selections of lengths `n_i`, the required budget is `sum(ceil((n_i + 53) / 24))`. Count each distinct commitment separately and add its discontiguous range lengths. For example, separate 34- and 90-byte selections need ten permutations. This bounds work, not peak memory; see the [measurements](#verification) before choosing a budget.

The frozen suite uses private TLSNotary ID 128, stock Plonky3 v0.8.0 KoalaBear Poseidon2 (`p = 2130706433`, width/rate/capacity 16/8/8, eight full and twenty partial rounds, cubic S-box), and eight canonical little-endian `u32` digest words. Its generic collision ceiling is approximately 124 bits. Frozen byte-hash vectors live in `crates/core/tests/poseidon2.rs`.

Hash the domain `tlsn/poseidon2/koalabear/16/pad10/v1`, selected bytes in transcript order, the independent 16-byte blinder, and byte `01`; zero-fill to a multiple of three bytes and pack each triple little-endian. Apply stock `Pad10Sponge` with overwrite absorption and `Increment(ONE)`. Partial final blocks append field one and zeros; full final blocks increment the first capacity element. Update boundaries introduce no separators.

Circuit `poseidon2` uses a separate encoding and cannot directly verify TLS openings. Opening-proof circuits are not shipped. Consumers must bind canonical digests, suites and selections to accepted TLS evidence; saved metadata supplies no authority. SDK/WASM mappings are unchanged.

### Local fixture

Open three terminals at the repository root. Repeat the same commands for another attestation; existing identities are reused and metadata goes into new runs.

Terminal 1: create the verifier identity, then start the HTTPS fixture:

```sh
set -e
cargo run --release --locked --example certificates
cargo run --release --locked --example fixture
```

The verifier identity lives in `.data/identity/`; the fixture has a separate target identity in `.data/fixture/`. Neither is installed in a system trust store. Examples lock initialization, validate existing pairs and create only absent pairs; partial pairs fail without repair. Unix private keys are owner-only. Use `--directory` for isolated runs and wait for the fixture's `ready` event.

Terminal 2: start Serve:

```sh
cargo run --release --locked --bin proof-client -- serve \
  --target-ca .data/fixture/target.pem --server-name localhost
```

Check Serve's expected target and wait for its `ready` event on stderr. Terminal 3: run Attest. The cookie is a synthetic placeholder, not a fixture credential; the fixture does not authenticate clients. The checked-in policy hides cookies, reveals balance/currency and the account key, and commits the account value.

```sh
cargo run --release --locked --bin proof-client -- attest \
  --target-ca .data/fixture/target.pem \
  --disclosure examples/mbank/disclosure.json \
  --url https://localhost:7443/balance \
  -H 'content-type: application/json' \
  -H 'Connection: close' \
  -b 'session=SYNTHETIC_PLACEHOLDER' \
  --data-raw '{}'
```

Check the disclosed balance/currency bytes, range totals and matching commitment digests. Serve omits cookie/account plaintext; Attest shows all local plaintext and saves private openings. All three processes exit after one completed attestation.

### Request copied from Chrome

In DevTools → Network, choose **Copy → Copy as cURL (bash)**. Attest sends a new request; it cannot attest a captured response.

Create the local verifier identity with the `certificates` example. Copy [the disclosure policy](examples/mbank/disclosure.json) to `.data/bank-disclosure.json` and edit its selectors for your response. Start `serve --server-name '<target hostname>'` and wait for `ready`.

Replace the leading `curl` with `cargo run --release --locked --bin proof-client -- attest --disclosure .data/bank-disclosure.json`. Preserve supported URL, method, header, cookie and body arguments, including shell quoting. Replace any `Connection: keep-alive` with `Connection: close`. Unsupported curl options fail; remove `--compressed` and request identity encoding. Do not use the fixture's target CA for a real target.

## Prepare / prove / verify

This example proves leaf 0 of the checked-in Merkle base circuit. Private values are pseudorandom placeholder data, not wire indices; a fixed seed per leaf keeps public input and witness generation consistent.

```sh
(
set -eC
mkdir -p .data
run_dir=$(mktemp -d .data/base.XXXXXX)
printf 'Outputs: %s\n' "$run_dir"
cargo run --release --locked --example merkle -- leaf --index 0 public > "$run_dir/public.json"
cargo run --release --locked --example merkle -- leaf --index 0 witness > "$run_dir/witness.json"
cargo run --release --locked --bin proof-client -- prepare --circuit examples/merkle/base.json --output "$run_dir/metadata.json"
cargo run --release --locked --bin proof-client -- prove --circuit examples/merkle/base.json --public "$run_dir/public.json" --witness "$run_dir/witness.json" --output "$run_dir/proof.json"
cargo run --release --locked --bin proof-client -- verify --circuit examples/merkle/base.json --public "$run_dir/public.json" --proof "$run_dir/proof.json"
)
```

Check prepared IDs/input counts, proof self-verification and the published path, then compare verified public words with `public.json`. `prepare` is optional inspection; every command prepares trusted sources independently.

Public input is a JSON array. The private witness contains `private` field words and a `proofs` array. Verification requires the independently expected public input; a proof cannot choose the verifier's claim. `prepare` derives circuit and verifier-set IDs from the supplied definitions. Metadata assists input construction; it is not verification authority.

`proof-client/circuit/4` declares `inputs: {"public":1,"private":1}`, `operations` and `constraints`. Registers number public fields, private scalar fields, then operation outputs. Proof slots are a separate indexed collection; their count is derived from `verify` operations, with slots `0..count` each verified exactly once.

| Operation           | Parameters                                                            | Output                           |
| ------------------- | --------------------------------------------------------------------- | -------------------------------- |
| `constant`          | `value`                                                               | one field word                   |
| `add`, `sub`, `mul` | `left`, `right` wire indices                                          | one field word                   |
| `poseidon2`         | `tag`, `inputs`: a nonempty multiple of eight wires                   | eight digest words               |
| `verify`            | `verifier` source path, `proof` slot, `circuit_id_wires`: eight wires | authenticated child public words |
| constraint `equal`  | `left`, `right`                                                       | none                             |
| constraint `bits`   | `wire`, `bits` in 1–30                                                | none                             |

`verify.verifier` references a circuit or verifier-set JSON file relative to the containing file; its `format` identifies the kind. The trusted source graph and compiled-in proving profile determine the verifier. Every `verify` embeds the recursive STARK verifier and binds the prepared child key to the circuit-ID wires. Fixed references also constrain the child’s required public bindings, including its verifier-set ID. Child statement wires remain private to the parent unless exported through its public statement. Proof bytes and backend witness packing are not scalar inputs.

Circuit IDs contain eight canonical KoalaBear words and commit to the prepared verification contract: protocol profile, AIR constraints, lookups, statement layout, table dimensions and preprocessing commitments. They are not hashes of JSON formatting or names. Artifacts carry `circuit_id`, `public` and `proof`. The verifier independently prepares trusted definitions.

Words are canonical KoalaBear elements; arithmetic is modular. Admission limits live in `crates/core/src/proof/{source,compiler}.rs`; the hiding profile lives in `crates/core/src/proof/config.rs`. Regenerate metadata and proofs when circuit IDs change. Output files are never overwritten. The proving profile is experimental and unaudited; no composed soundness or zero-knowledge guarantee is claimed. Circuit verification alone does not establish TLSN provenance.

## Merkle example

Eight sample leaves each contain eight pseudorandom field elements. Ordered Poseidon2 hashing uses separate leaf/node domains.

| Circuit                                                      | Public fields                                                          | Witness          |
| ------------------------------------------------------------ | ---------------------------------------------------------------------- | ---------------- |
| [base.json](examples/merkle/base.json)                       | height 0, root (8)                                                     | leaf values      |
| [merge-bases.json](examples/merkle/merge-bases.json)         | height 1, root (8), expected child circuit ID (8), verifier-set ID (8) | two base proofs  |
| [merge-recursive.json](examples/merkle/merge-recursive.json) | height, root (8), expected child circuit ID (8), verifier-set ID (8)   | two merge proofs |

[merge-verifier.json](examples/merkle/merge-verifier.json) is the shared verification contract (`proof-client/verifier-set/1`): two ordered circuit references, `verifier_set_id_positions` (eight public input indices) and explicit table heights. The first member supplies the fixed-child verifier template; the second verifies either member. Both declare `"verifier_set":"merge-verifier.json"`; set verification derives its public root wires from the set’s positions. Preparation requires compatible merge descriptors; it does not search for a layout.

Set verification constrains actual-key membership and propagates the set ID from child to parent. The set ID hashes the two prepared keys and is pinned at native verification and fixed recursive references, avoiding a self-referential key constant. Both children use the same expected circuit ID. Merkle hashing, equal child heights and bounded increasing parent heights are ordinary DSL constraints.

The [recursive session workflow](crates/core/tests/recursion.rs) builds all eight leaves and three merge levels while reusing preparation. To construct parent inputs through the CLI, use `cargo run --release --locked --example merkle -- parent --help`: it consumes two child proofs and prepared metadata, emitting either public input or a witness. Prove height 1 with `merge-bases.json`, later heights with `merge-recursive.json`. Generate the final expected statement independently with the example's `public --height 3 --metadata <file>` command, then run `verify` against the recursive circuit.

Metadata is derived once and read thereafter; it is not verification authority. Final verification needs the final proof, trusted sources and expected public input. IDs do not depend on filenames. Library sessions reuse preparation; CLI invocations prepare independently.

## Chrome

Run `npm ci` for extension development and checks. Load `extension/` in Chrome 124+ through `chrome://extensions` → Developer mode → Load unpacked. Record its ID. Obtain the binary's absolute path from the `compiler-artifact` message's `executable` field:

```sh
cargo build --release --locked --bin proof-client --message-format=json
```

Register this native-host manifest:

```json
{
  "name": "io.github.neotheprogramist.proof_client",
  "description": "Local proofs and live TLS disclosure",
  "path": "ABSOLUTE_PATH_TO_BUILT_PROOF_CLIENT",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://YOUR_ACTUAL_EXTENSION_ID/"]
}
```

| Platform            | Manifest registration                                                                                                                                                           |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| macOS Google Chrome | `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/io.github.neotheprogramist.proof_client.json`                                                                 |
| Linux Google Chrome | `~/.config/google-chrome/NativeMessagingHosts/io.github.neotheprogramist.proof_client.json`                                                                                     |
| Windows             | Save a manifest locally; set the default value of `HKEY_CURRENT_USER\Software\Google\Chrome\NativeMessagingHosts\io.github.neotheprogramist.proof_client` to its absolute path. |

Chrome does not expand `~` or environment variables. Escape Windows backslashes. See [native messaging registration](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging) for custom profiles.

Click the toolbar action. All native file paths must be absolute; terminal paths may be relative. Verify the base example using `examples/merkle/base.json` and the `public.json` and `proof.json` files in its printed output directory, converted to absolute paths. To prove again, use that directory’s `witness.json` and a new proof output path. For TLS, follow the local fixture identity/setup commands, start the fixture in a terminal, then start Serve in the form using the absolute data directory and explicit target-CA path, wait for Ready, then enter its curl-style request arguments as one JSON array, for example `["--url", "https://localhost:7443/balance", "-b", "session=SYNTHETIC_PLACEHOLDER", "--data-raw", "{}"]`. Empty strings are preserved. The array is appended after the connection and data-directory arguments and parsed by the CLI.

Check Cancel and tab close while Serve waits: its port becomes reusable and no metadata is published. Forced process termination can leave an empty run directory. After success, published files remain. Each operation owns one native port/process; tab close disconnects them. Only `nativeMessaging` permission is required.

Each port sends one invocation, `{"protocol":"proof-client/11","args":[...]}`, using CLI arguments. Frames are UTF-8 JSON with a native-endian four-byte length, bounded by `MAX_FRAME_BYTES` in `crates/cli/src/stdio.rs`. Serve emits Ready, then every invocation emits Completed or Failed and exits. Terminal commands default to human reports; `--format json` selects JSON events and `attest --format raw` selects response bytes. Ready and progress use stderr; errors use stderr and failure status. Native TLS results contain `stdout_base64` and the metadata path. Arguments never pass through a shell.

Installed Chrome cancellation and live-target acceptance require manual verification.

## Verification

Earlier isolated MPC measurements on macOS arm64 (2026-09-29) reached 6.27 GiB peak RSS for separate 34- and 90-byte commitments. The standalone cost harness has been removed; this is historical sizing evidence, not a deployment limit. The CLI TLS workflow exercises both commitment suites with the real MPC stack.

With dependencies cached:

```sh
cargo fmt --package proof-client --package proof-client-core --check
cargo clippy --locked --offline --workspace --all-targets --all-features -- -D warnings
cargo test --locked --offline --workspace
cargo test --locked --offline -p proof-client-core --test recursion eight_leaf_recursion -- --ignored --exact --nocapture
cargo test --locked --offline -p proof-client-core --lib verifier_set_membership_is_enforced_without_host_admission -- --ignored --nocapture
```

Format only consumer packages; `cargo fmt --all` visits vendor trees. Run the two ignored gates sequentially for proof changes; the workspace suite skips them. Adversarial controls bypass witness checks and exercise the emitted constraints.

```sh
npm run fmt:check
npm run lint
npm run typecheck
npm test
```

Tests also document usage: [CLI prepare/prove/verify](crates/cli/tests/e2e.rs), [TLS disclose/commit/inspect](crates/cli/tests/tls.rs), [recursive library proof session](crates/core/tests/recursion.rs), and [HTTP receive/resolve](crates/core/tests/disclosure.rs). Independent cryptographic conformance and adversarial proof checks remain because matching peers can share a bug. Mutation testing is not required.

`npm test` exercises native-port ordering, cancellation, cleanup and page workflows through a fake Chrome boundary and JSDOM; installed Chrome remains a manual check.
