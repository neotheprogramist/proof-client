# Proof Client

The CLI is the primary interface for running, auditing and reproducing project workflows. Commands show their purpose, observed stages, verification scope and output artifacts. Rust libraries own parsing and cryptography; Chrome is an optional adapter to the same operations.

| Command   | Purpose                                                 | Result                                               |
| --------- | ------------------------------------------------------- | ---------------------------------------------------- |
| `prepare` | Inspect the trusted circuit contract                    | Derived circuit and verifier-set IDs                 |
| `prove`   | Prove supplied public input with a private witness      | Self-verified proof artifact                         |
| `verify`  | Check against independently expected public input       | Verified circuit ID and public words                 |
| `serve`   | Accept one live disclosure for an expected HTTPS target | Authenticated transcript ranges and commitments      |
| `attest`  | Send a new HTTPS request and apply a disclosure policy  | Matching verifier receipt and private opening record |
| `inspect` | Read a saved TLS run                                    | Untrusted recorded evidence; no live verification    |

Circuit proofs and TLS disclosure are independent workflows. A circuit proof does not establish TLS provenance; authenticated transcript bytes do not establish hidden JSON relationships.

`crates/core/` owns proof and TLS validation; `crates/cli/` owns arguments, files and terminal/native I/O. `extension/` is plain JavaScript with JSDoc. Examples live in `examples/`; [vendor/README.md](vendor/README.md) records dependency patches and provenance.

## Setup

CLI prerequisites: Git, rustup and a native C toolchain. Extension development and JavaScript checks also require Node.js 26+ with npm. Rust is pinned in `rust-toolchain.toml`; JavaScript tools are locked in `package-lock.json`.

Run zsh/bash examples from the repository root. Cargo builds each command as needed. Walkthroughs preserve earlier artifacts: proof runs use fresh directories; TLS runs reuse local identities. Attesting sends a new HTTP request. There is no browser build step or CI.

Agents may install repository dependencies and development tools. Install Cargo tools with a repository-local `--root` under `target/`; do not install globally or change persistent PATH settings. The owner performs Chrome registration, commits and pushes manually.

```sh
cargo fetch --locked
cargo run --release --locked --bin proof-client -- --help
```

## Reading CLI output

Human-readable reports are the default. Stderr records observed execution stages; stdout contains the final report. There are no prompts, inferred output modes or automatic retries.

- `--format json` emits one `completed` JSON event. TLS results contain disclosed evidence, never private response bodies or commitment openings.
- `attest --format raw` emits the exact private response body. It adds no newline; zsh may display `%` after an unterminated line. Other commands reject raw output before I/O.
- Reports show byte ranges as `[start, end)`, escaping control and non-ASCII bytes. Live `attest` reports print every transcript byte, including cookies and committed values; disclosure labels describe what the verifier receives. `serve` and `inspect` print plaintext only for revealed ranges. Displayed text is not reconstructed JSON.

Proof progress identifies contract preparation, input counts, child-proof checks, witness evaluation, proof generation and self-verification. TLS progress identifies connection, disclosure resolution, verification, receipt matching and closure as each occurs. Publication is a separate event: a later output failure does not undo a successful verification or published file.

Inspect a run by replacing the placeholder with the parent directory of the reported metadata file:

```sh
run_dir='.data/runs/REPLACE_WITH_REPORTED_RUN_NAME'
cargo run --release --locked --bin proof-client -- inspect --run "$run_dir"
cargo run --release --locked --bin proof-client -- inspect --run "$run_dir" --format json
```

TLS records retain disclosed bytes and offsets, lengths and commitments. Prover records also retain private openings and normalized selector-to-range mappings; inspection omits openings. Older records without disclosed segments show only their recorded summary. Records are mutable local evidence, not portable attestations; inspection never repeats TLS verification.

For reproduction, retain trusted circuit sources, expected public inputs and required private inputs explicitly. `--locked` uses the checked-in dependency lock. Fresh proofs and blinded commitments need not have identical bytes. Attestation sends a new request; the remote response may change. Full requests, hidden transcripts and response bodies are not saved automatically.

## Serve / attest

Both peers must use this patched build; the mux protocol differs from unpatched TLSNotary alpha.15. Both verifier endpoints use loopback addresses. QUIC authenticates the verifier using TLS 1.3; the prover opens the target socket using TLSN's TLS 1.2/HTTP/1.1 baseline. Target certificates use the pinned Mozilla roots unless `--target-ca` supplies a replacement bundle. Attest trusts the prepared local verifier certificate unless `--verifier-ca` explicitly supplies another bundle. Idle listeners wait for a client; the connected-session deadline starts at acceptance. Application lifecycle events use standard text `tracing` on stderr; terminal stdout follows the selected report format. Tracing records contain operation names, listener addresses, byte counts and output paths; request values and witnesses are excluded; circuit source paths and input counts may be shown. Library consumers install their own subscriber. Each connection carries one attestation; local clients are not authenticated.

Only user-selected authenticated transcript ranges may be disclosed to the verifier. Requests, witnesses and undisclosed response bytes remain local. Selected commitment ranges and blinded digests are public; protocol metadata and transcript lengths are part of the disclosure baseline.

`attest` accepts one HTTPS URL, `-X`/`--request`, repeated `-H`/`--header`, inline `-b`/`--cookie`, and repeated `--data-raw`. The URL may be positional or supplied with `--url`. Data implies POST unless `-X` overrides the method; repeated `-X` uses the last value; without data the default is GET. Repeated data appends `&` only when the accumulated body is nonempty; `@` is literal. Data defaults to `application/x-www-form-urlencoded` unless a header overrides or suppresses it. `-H 'Name:'` suppresses a default header and `-H 'Name;'` sends an empty value. These follow [curl's request conventions](https://curl.se/docs/manpage.html).

Host must match the URL and Content-Length must match the body; suppressing either is unsupported. Explicit Connection accepts `close` or `keep-alive`; Accept-Encoding accepts only `identity`. Compressed responses, redirects, retries, proxying, file uploads, curl configuration files and multiple URLs are unsupported. Unsupported options fail explicitly; there is no general curl-command parser or shell execution. Request arguments can appear in shell history and process listings; `cargo run` also prints them.

The CLI defaults to `--data-dir .data`, verifier address `127.0.0.1:7047`, verifier TLS name `localhost`, and identity files `identity/verifier.pem` and `identity/verifier.key` beneath the data directory. `serve --server-name` independently specifies the expected HTTPS target. Missing identity files fail; nothing generates or trusts a certificate implicitly. Existing path/address flags override these defaults.

Each invocation saves pretty-printed metadata under `<data-dir>/runs/attest.<datetime>/metadata.json` or `serve.<datetime>/metadata.json` and reports its path on stderr. Run names use UTC; collisions fail without overwriting. `--metadata-output` supplies an explicit unused destination when needed. Private metadata contains commitment openings and local selector mappings; verifier metadata contains neither. Output files are never overwritten. Runtime artifacts are ignored under `.data/`; builds use `target/`.

Omitting `--disclosure` hides all transcript bytes and creates no explicit commitments. A supplied [policy](examples/mbank/disclosure.json) has symmetric `reveal` and `commit` objects, each containing `sent` and `received` selections. Omitted objects/directions and empty arrays select nothing; `{}` hides everything. Unknown fields, missing selectors and overlapping reveal/commit ranges fail. Revealed ranges form a union. Each distinct committed selection produces one independently openable blinded BLAKE3 commitment. Identical selections share a commitment; empty or partially overlapping committed selections fail. All wire ranges of one selection, including across HTTP chunks, share its digest and blinder. The per-session count limit is `MAX_COMMITMENTS` in `crates/core/src/tls/mod.rs`.

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

Terminal reports show revealed, committed and hidden byte ranges with counts and full commitment digests. Native messaging retains its bytewise 🙈/🔒 transcript representation. Neither view is an authoritative JSON document. A prover-selected pointer does not establish JSON ancestry to the verifier when context is hidden. TLSN authenticates selected bytes and positions; application statements require authenticated context or a separate proof. Successful live operations construct `VerifiedReport` and `Receipt`; deserialized `ReportData` is untrusted. Results are not portable signed attestations and establish neither account ownership nor independent freshness or completeness.

Receipt validation, successful QUIC closure, metadata publication and stdout delivery are separate transitions. The `published` event records only metadata publication. Each CLI saves metadata before writing stdout. A local save or stdout failure can follow a successful remote verification or target request; metadata can remain after a broken pipe or cancellation. Nothing retries automatically. One framed HTTP response completes without waiting for connection closure; surplus bytes are discarded, never interpreted as another response. Admission budgets live in `crates/core/src/tls/attest.rs`.

### Local fixture

Open three terminals at the repository root. Repeat the same commands for another attestation; existing identities are reused and metadata goes into new runs.

Terminal 1: create the verifier identity, then start the HTTPS fixture:

```sh
set -e
cargo run --release --locked --example certificates
cargo run --release --locked --example fixture
```

The `certificates` example gets or creates a self-signed `localhost` certificate and private key in `.data/identity/` **only to authenticate the local verifier**. QUIC uses TLS 1.3: Serve presents this identity and Attest trusts it through `--verifier-ca`. These files do not authenticate the HTTPS target. No certificate is installed in a system trust store.

The fixture gets or creates its own HTTPS identity, `.data/fixture/target.pem` and `target.key`. Both examples create a pair only when both files are absent and validate existing pairs before reuse. Partial or invalid identities fail without replacement. Interruption between the two file publications can leave a partial pair; initialization never repairs it. Initialization is serialized by a file lock; private keys are created with owner-only permissions on Unix. `--directory` overrides each example's default for isolated workflows. The fixture writes no commands to stdout. Wait for its `ready` tracing event on stderr.

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

Both reports show the disclosed HTTP lines, `"AvailableBalance":42.1200` and `"currency":"PLN"` as escaped bytes, and the account commitment ranges. Check that counts reconcile with transcript lengths and that the commitment digest matches between peers. Serve must omit cookie and account plaintext; Attest prints every range's plaintext and the local selector mapping. The mapping is not proof of JSON ancestry. The account value is retained in private opening metadata. Response cookie and account values are reproducible synthetic placeholders. All three processes exit after one completed attestation. Mismatched identity/trust or an occupied metadata destination fails.

### Attest a request copied from Chrome

In Chrome DevTools, open **Network**, select a successful HTTPS request, then right-click it and choose **Copy → Copy as cURL (bash)**. Attest sends that request again through TLSNotary; it cannot attest a previously captured response.

Terminal 1: get or create the local verifier identity:

```sh
cargo run --release --locked --example certificates
```

Create `.data/bank-disclosure.json` before running Attest. This example expects a `products` array whose first object has `AvailableBalance`, `currency`, `id` and `number` fields. Adjust the [selectors](#serve--attest) to your response; missing fields fail. The command preserves an existing file; edit it to change the policy.

```sh
(
set -eC
mkdir -p .data
cat > .data/bank-disclosure.json <<'JSON'
{
  "reveal": {
    "sent": ["start_line"],
    "received": [
      "start_line",
      {"json": "/products/0/AvailableBalance"},
      {"json": "/products/0/currency"},
      {"json_key": "/products/0/id"},
      {"json_key": "/products/0/number"}
    ]
  },
  "commit": {
    "received": [
      {"json_value": "/products/0/id"},
      {"json_value": "/products/0/number"}
    ]
  }
}
JSON
)
```

This reveals the HTTP start lines, balance/currency members and ID/number keys, and creates two independently openable commitments to the ID/number values. All other bytes stay hidden from the verifier. These selections do not establish JSON ancestry or account ownership.

Start Serve with the hostname from the copied URL, without the scheme, port or path:

```sh
cargo run --release --locked --bin proof-client -- serve --server-name '<target hostname>'
```

Wait for the `ready` event. In terminal 2:

1. Paste the copied command and remove only the leading `curl` command name.
2. Keep its URL, headers, cookies, method and body arguments, including their shell quoting.
3. Ensure there is one `-H 'Connection: close'` header: add it if absent, or replace the copied `Connection: keep-alive` header.
4. Place those arguments after the `attest` command and disclosure option shown below.

Keep-alive can leave the prover apparently stuck waiting for the target connection to close, until the session deadline.

The ellipses represent your copied arguments, not literal shell input:

```sh
cargo run --release --locked --bin proof-client -- attest \
  --disclosure .data/bank-disclosure.json \
  -H 'Connection: close' \
  --url ... -H ... ...
```

The copied URL can remain positional or follow `--url`. Preserve `-X` and body arguments when present; do not add them to a request that has none. Unsupported options such as `--compressed` fail explicitly; this baseline requires identity encoding.

The target presents its own HTTPS certificate, checked against the pinned Mozilla roots. The local verifier certificate does not replace it; do not use the fixture's `--target-ca` for a real target. Repeat the walkthrough for another attestation. To emit the private response instead of the report, select `--format raw` when executing and redirect stdout to a new file. This sends a new request; `inspect` cannot recover a response that was not retained.

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

After `prepare`, check the circuit IDs and input counts. After `prove`, check the self-verification stage and published artifact path. After `verify`, compare the reported public words with the independently constructed `public.json`. Add `--format json` for the machine representation.

`prepare` is optional inspection; `prove` and `verify` independently prepare trusted sources. Its metadata is not a cached verification authority.

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

Run the complete tree walkthrough:

```sh
(
set -eC
mkdir -p .data
run_dir=$(mktemp -d .data/tree.XXXXXX)
printf 'Outputs: %s\n' "$run_dir"
cargo run --release --locked --bin proof-client -- prepare --circuit examples/merkle/merge-recursive.json --output "$run_dir/metadata.json"
for i in 0 1 2 3 4 5 6 7; do
  cargo run --release --locked --example merkle -- leaf --index "$i" public > "$run_dir/0-$i.public.json"
  cargo run --release --locked --example merkle -- leaf --index "$i" witness > "$run_dir/0-$i.witness.json"
  cargo run --release --locked --bin proof-client -- prove --circuit examples/merkle/base.json --public "$run_dir/0-$i.public.json" --witness "$run_dir/0-$i.witness.json" --output "$run_dir/0-$i.proof.json"
done
for height in 1 2 3; do
  previous=$((height - 1))
  count=$((8 >> height))
  if [ "$height" -eq 1 ]; then circuit=merge-bases; else circuit=merge-recursive; fi
  i=0
  while [ "$i" -lt "$count" ]; do
    left=$((2 * i))
    right=$((left + 1))
    for output in public witness; do
      cargo run --release --locked --example merkle -- parent --left "$run_dir/$previous-$left.proof.json" --right "$run_dir/$previous-$right.proof.json" --metadata "$run_dir/metadata.json" "$output" > "$run_dir/$height-$i.$output.json"
    done
    cargo run --release --locked --bin proof-client -- prove --circuit "examples/merkle/$circuit.json" --public "$run_dir/$height-$i.public.json" --witness "$run_dir/$height-$i.witness.json" --output "$run_dir/$height-$i.proof.json"
    i=$((i + 1))
  done
done
cargo run --release --locked --example merkle -- public --height 3 --metadata "$run_dir/metadata.json" > "$run_dir/expected.json"
cargo run --release --locked --bin proof-client -- verify --circuit examples/merkle/merge-recursive.json --public "$run_dir/expected.json" --proof "$run_dir/3-0.proof.json"
)
```

`metadata.json` in the printed output directory is created once by `prepare` and only read thereafter. The example computes the expected root independently. Final verification needs the final proof, trusted circuit sources and expected statement. Metadata paths are relative to the entry directory where possible; IDs do not depend on filenames. Library sessions reuse preparation; CLI invocations prepare independently.

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

With dependencies cached:

```sh
cargo fmt --package proof-client --package proof-client-core --check
cargo clippy --locked --offline --workspace --all-targets --all-features -- -D warnings
cargo test --locked --offline --workspace
cargo test --locked --offline -p proof-client-core --test hiding parallel_hiding_admission -- --ignored --exact --nocapture
cargo test --locked --offline -p proof-client-core --test recursion eight_leaf_recursion -- --ignored --exact --nocapture
cargo test --locked --offline -p proof-client-core --lib verifier_set_membership_is_enforced_without_host_admission -- --ignored --nocapture
```

Format only consumer packages; `cargo fmt --all` visits vendor trees. Run all three ignored gates sequentially for proof changes; the workspace suite skips them. Adversarial controls bypass witness checks and exercise the emitted constraints.

```sh
npm run fmt:check
npm run lint
npm run typecheck
npm test
npm run mutate
```

For Rust behavior changes, run a consumer mutation shard. Install cargo-mutants locally and add it to the current shell's PATH:

```sh
cargo install cargo-mutants --version 27.1.0 --locked --root target/tools
export PATH="$PWD/target/tools/bin:$PATH"
cargo mutants --workspace --test-package proof-client --copy-target=false --profile test --cargo-arg=--package=proof-client --cargo-arg="--target-dir=$PWD/target/mutation-build" --cargo-arg=--locked --cargo-arg=--offline --cargo-arg=--test=audit --file crates/core/src/tls/evidence.rs --shard 2/4 --sharding round-robin
```

This scope mutates the core record boundary and runs its CLI consumer tests; the explicit Cargo package argument also selects that integration target during the build. Rotate the consumer file, tests and shard on subsequent changes. For the complete diagnostic, remove `--test-package`, `--cargo-arg=--package=proof-client`, `--cargo-arg=--test=audit`, `--file`, `--shard` and `--sharding`, and add `--test-workspace=true`. The full JavaScript mutation scope is `extension/*.mjs`. `npm test` exercises native-port ownership and the page/toolbar using a fake Chrome API and a DOM implementation; installed Chrome remains a manual integration check. Stryker uses its default workers and reporters; reports appear under ignored `reports/`. Its configuration selects the extension, excludes runtime/build data and requires every non-equivalent mutant to be caught. Only unreachable or behaviorally equivalent branches have documented exclusions.
