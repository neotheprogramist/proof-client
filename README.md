# Proof Client

Rust owns cryptography and metadata; the CLI and Chrome expose the same library.

| Flow               | Input                                                               | Result                                                        |
| ------------------ | ------------------------------------------------------------------- | ------------------------------------------------------------- |
| `prove` / `verify` | Circuit, public input and witness / circuit, public input and proof | Proof artifact / verified public words                        |
| `serve` / `attest` | Verifier identity / HTTPS request and disclosure policy             | Redacted HTTP exchange / private response body, plus metadata |

`crates/core/` is the reusable library: `proof::{prepare, prove, verify, with_session}` handles generic circuits; `tls::quic::Verifier::{bind, verify}` and `tls::quic::attest` handle serve/attest. Core owns circuit and protocol validation and must not depend on the CLI. `crates/cli/` is a thin wrapper for arguments, file I/O, process runtime and terminal/native messages, including manual testing. Example-specific logic stays in `examples/`, which contains the Merkle and mBank demos. [vendor/README.md](vendor/README.md) records upstream provenance and patches.

The Cargo workspace lives in `crates/`; the npm workspace contains `extension/`, a manually loaded Chrome demo using plain `.mjs` and JSDoc. Declare npm development dependencies at the root, commit `package-lock.json`, and use standard npm resolution. Keep tooling configuration minimal.

## Setup and checks

Prerequisites: Git, rustup, a native C toolchain, and Node.js 22.12+ with npm. Rust is pinned in `rust-toolchain.toml`; JavaScript tools are locked in `package-lock.json`.

Shell examples use zsh or bash. Run every terminal from the repository root. CLI examples use `cargo run --release --locked --quiet --bin proof-client -- ...`. `--quiet` prevents Cargo from echoing private request arguments. No browser build step, browser tests, custom lint-rule suite or CI. Examples create files under ignored `target/manual/`. Each run requires a fresh output directory; existing artifacts are never overwritten. Proof examples use `2 × available CPUs + 1` worker threads, derived with Node.js.

Agents may install repository dependencies and development tools. Install Cargo tools with a repository-local `--root` under `target/`; do not install globally or change persistent PATH settings. The owner performs Chrome registration, commits and pushes manually.

```sh
cargo fetch --locked
cargo build --release --locked --examples
cargo build --release --locked --bin proof-client
cargo run --release --locked --quiet --bin proof-client -- --help
npm ci
```

Development checks use rustfmt, Clippy, Rust tests, Oxfmt, Oxlint and JSDoc type checking. To try the CLI first, continue to [Prepare / prove / verify](#prepare--prove--verify). With dependencies cached:

```sh
cargo fmt --package proof-client --package proof-client-core --check
cargo clippy --locked --offline --workspace --all-targets --all-features -- -D warnings
cargo test --locked --offline --workspace
cargo test --locked --offline -p proof-client-core --test hiding parallel_hiding_admission -- --ignored --exact --nocapture
cargo test --locked --offline -p proof-client-core --test recursion eight_leaf_recursion -- --ignored --exact --nocapture
cargo test --locked --offline -p proof-client-core --lib verifier_set_membership_is_enforced_without_host_admission -- --ignored --nocapture
```

Format only consumer packages; `cargo fmt --all` visits vendor trees. Run the three ignored gates sequentially. Adversarial controls bypass witness checks and exercise the emitted constraints.

```sh
npm run fmt:check
npm run lint
npm run typecheck
```

For Rust behavior changes, run a consumer mutation shard. Install cargo-mutants locally and add it to the current shell's PATH:

```sh
cargo install cargo-mutants --version 27.1.0 --locked --root target/tools
export PATH="$PWD/target/tools/bin:$PATH"
cargo mutants --workspace --test-workspace=true --copy-target=false --profile test --cargo-arg="--target-dir=$PWD/target/mutation-build" --cargo-arg=--locked --cargo-arg=--offline --cargo-arg=--lib --cargo-arg=--test=generic --file crates/core/src/proof/source.rs --shard 3/4 --sharding round-robin
```

Rotate the consumer file, tests and shard on subsequent changes. For the complete diagnostic, remove `--file`, `--shard`, `--sharding`, `--cargo-arg=--lib` and `--cargo-arg=--test=generic`. The Chrome demo is excluded from JavaScript mutation testing.

## Prepare / prove / verify

This example proves leaf 0 of the checked-in Merkle base circuit. Private values are pseudorandom placeholder data, not wire indices; a fixed seed per leaf keeps public input and witness generation consistent. It creates both inputs before preparing, proving and verifying:

```sh
(
set -eC
threads=$(node -p 'require("node:os").availableParallelism() * 2 + 1')
mkdir -p target/manual
mkdir target/manual/base
cargo run --release --locked --example merkle -- leaf --index 0 public > target/manual/base/public.json
cargo run --release --locked --example merkle -- leaf --index 0 witness > target/manual/base/witness.json
cargo run --release --locked --quiet --bin proof-client -- prepare --circuit examples/merkle/base.json --output target/manual/base/metadata.json --threads "$threads"
cargo run --release --locked --quiet --bin proof-client -- prove --circuit examples/merkle/base.json --public target/manual/base/public.json --witness target/manual/base/witness.json --output target/manual/base/proof.json --threads "$threads"
cargo run --release --locked --quiet --bin proof-client -- verify --circuit examples/merkle/base.json --public target/manual/base/public.json --proof target/manual/base/proof.json --threads "$threads"
)
```

Successful verification reports `circuit_id` and the same `public` words as `target/manual/base/public.json`. There is no root-level `circuit.json`; custom circuits must be created explicitly and supplied through `--circuit`.

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

Words are canonical KoalaBear elements; arithmetic is modular. Admission limits live in `crates/core/src/proof/{source,compiler}.rs`; the hiding profile lives in `crates/core/src/proof/config.rs`. Circuit format 4 replaces earlier formats; regenerate proofs from their original inputs. Output files are never overwritten. The proving profile is experimental and unaudited; no composed soundness or zero-knowledge guarantee is claimed. Circuit verification alone does not establish TLSN provenance.

## Merkle example

Eight sample leaves each contain eight pseudorandom field elements. Ordered Poseidon2 hashing uses separate leaf/node domains.

| Circuit                                                      | Public fields                                                          | Witness          |
| ------------------------------------------------------------ | ---------------------------------------------------------------------- | ---------------- |
| [base.json](examples/merkle/base.json)                       | height 0, root (8)                                                     | leaf values      |
| [merge-bases.json](examples/merkle/merge-bases.json)         | height 1, root (8), expected child circuit ID (8), verifier-set ID (8) | two base proofs  |
| [merge-recursive.json](examples/merkle/merge-recursive.json) | height, root (8), expected child circuit ID (8), verifier-set ID (8)   | two merge proofs |

[merge-verifier.json](examples/merkle/merge-verifier.json) is the shared verification contract (`proof-client/verifier-set/1`): two ordered circuit references, `verifier_set_id_positions` (eight public input indices) and explicit table heights. The first member supplies the fixed-child verifier template; the second verifies either member. Both declare `"verifier_set":"merge-verifier.json"`; set verification derives its public root wires from the set’s positions. Preparation requires compatible merge descriptors; it does not search for a layout.

Set verification constrains actual-key membership and propagates the set ID from child to parent. The set ID hashes the two prepared keys and is pinned at native verification and fixed recursive references, avoiding a self-referential key constant. Both children use the same expected circuit ID. Merkle hashing, equal child heights and bounded increasing parent heights are ordinary DSL constraints.

Build the tree with fresh output paths:

```sh
(
set -eC
threads=$(node -p 'require("node:os").availableParallelism() * 2 + 1')
mkdir -p target/manual
mkdir target/manual/tree
cargo run --release --locked --quiet --bin proof-client -- prepare --circuit examples/merkle/merge-recursive.json --output target/manual/tree/metadata.json --threads "$threads"
for i in 0 1 2 3 4 5 6 7; do
  cargo run --release --locked --example merkle -- leaf --index "$i" public > "target/manual/tree/0-$i.public.json"
  cargo run --release --locked --example merkle -- leaf --index "$i" witness > "target/manual/tree/0-$i.witness.json"
  cargo run --release --locked --quiet --bin proof-client -- prove --circuit examples/merkle/base.json --public "target/manual/tree/0-$i.public.json" --witness "target/manual/tree/0-$i.witness.json" --output "target/manual/tree/0-$i.proof.json" --threads "$threads"
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
      cargo run --release --locked --example merkle -- parent --left "target/manual/tree/$previous-$left.proof.json" --right "target/manual/tree/$previous-$right.proof.json" --metadata target/manual/tree/metadata.json "$output" > "target/manual/tree/$height-$i.$output.json"
    done
    cargo run --release --locked --quiet --bin proof-client -- prove --circuit "examples/merkle/$circuit.json" --public "target/manual/tree/$height-$i.public.json" --witness "target/manual/tree/$height-$i.witness.json" --output "target/manual/tree/$height-$i.proof.json" --threads "$threads"
    i=$((i + 1))
  done
done
cargo run --release --locked --example merkle -- public --height 3 --metadata target/manual/tree/metadata.json > target/manual/tree/expected.json
cargo run --release --locked --quiet --bin proof-client -- verify --circuit examples/merkle/merge-recursive.json --public target/manual/tree/expected.json --proof target/manual/tree/3-0.proof.json --threads "$threads"
)
```

`target/manual/tree/metadata.json` is created once by `prepare` and only read thereafter. The example computes the expected root independently. Final verification needs the final proof, trusted circuit sources and expected statement. Metadata paths are relative to the entry directory where possible; IDs do not depend on filenames. Library sessions reuse preparation; CLI invocations prepare independently. The ignored recursion gate exercises eight leaves and three levels, including reuse of `merge-recursive`.

## Serve / attest

Both peers must use this patched build; the mux protocol differs from unpatched TLSNotary alpha.15. Both verifier endpoints use loopback addresses. QUIC authenticates the verifier using TLS 1.3; the prover opens the target socket using TLSN's TLS 1.2/HTTP/1.1 baseline. Explicit CA bundles replace the pinned Mozilla roots for that peer. Each connection carries one attestation; local clients are not authenticated.

Only user-selected authenticated transcript ranges may be disclosed to the verifier. Private requests, witnesses and undisclosed response bytes remain local. Selected commitment ranges and blinded digests are public; protocol metadata and transcript lengths are part of the disclosure baseline.

`attest` accepts one HTTPS URL, `-X`/`--request`, repeated `-H`/`--header`, inline `-b`/`--cookie`, and repeated `--data-raw`. The URL may be positional or supplied with `--url`. Data implies POST unless `-X` overrides the method; without data the default is GET. Repeated data appends `&` only when the accumulated body is nonempty; `@` is literal. Data defaults to `application/x-www-form-urlencoded` unless a header overrides or suppresses it. `-H 'Name:'` suppresses a default header and `-H 'Name;'` sends an empty value. These follow [curl's request conventions](https://curl.se/docs/manpage.html).

Host must match the URL and Content-Length must match the body; suppressing either is unsupported. Explicit Connection accepts `close` or `keep-alive`; Accept-Encoding accepts only `identity`. Compressed responses, redirects, retries, proxying, file uploads, curl configuration files and multiple URLs are unsupported. Unsupported options fail explicitly; there is no general curl-command parser or shell execution. Request arguments can appear in shell history and process listings.

A [disclosure policy](examples/mbank/disclosure.json) supplies `sent` and `received` reveal selections. Optional `commit: {"sent": [...], "received": [...]}` uses the same selectors; omitting it requests no explicit commitments. Empty arrays select nothing. Unselected bytes stay hidden. Reveal and commit selections must be disjoint. TLSNotary authenticates one blinded BLAKE3 commitment over the selected ranges in each direction, in transcript order.

| Selection                          | Meaning                                                               |
| ---------------------------------- | --------------------------------------------------------------------- |
| `{"bytes": [start, end]}`          | nonempty half-open range in the original transcript                   |
| `"start_line"`                     | HTTP request line or final response status line, including CRLF       |
| `{"header": "content-type"}`       | every matching complete header line, including CRLF; case insensitive |
| `"body"`                           | body payload, excluding chunk framing and trailers                    |
| `{"json": "/products/0/currency"}` | original JSON member key/value, or array element                      |

Structured selectors require nonempty CRLF-terminated start lines, including interim responses. JSON pointers use RFC 6901 escaping (`~1`, `~0`); the empty pointer selects the root. Numeric spelling is preserved and chunk offsets map back to the transcript. Duplicate decoded keys, missing selectors, ambiguous framing and compressed structured bodies fail. Overlapping/adjacent ranges merge; gaps remain hidden.

`attest` prints the response body to stdout after live verification and metadata publication. HTTP chunk framing is removed; body bytes and numeric spelling remain unchanged. HTTP error statuses do not themselves fail the command, but a missing disclosure selector does. Nothing is printed as a successful response if attestation fails.

`serve` prints the authenticated sent and received transcripts with direction labels. `HIDDEN_BYTE` (🙈) and `COMMITTED_BYTE` (🔒), defined in `crates/core/src/tls/attest.rs`, replace each hidden or committed byte. These are display views, not replayable HTTP messages or portable proofs. Terminal readiness and diagnostics go to stderr.

Both commands require one new `--metadata-output` path. JSON is pretty-printed and published without overwriting. Verifier metadata contains the target server, original transcript lengths and commitment digests/ranges. Attest metadata additionally contains private openings: the selected committed plaintext bytes and blinding secrets. Private openings never go to the verifier. No transcript files are created; use shell stdout redirection to retain the response (`set -C` prevents overwriting in zsh/bash).

The protocol receipt acknowledges verification, not filesystem publication. Each CLI saves metadata before writing stdout. A local save or stdout failure can follow a successful remote verification or target request; metadata can remain after a broken pipe or cancellation. Nothing retries automatically. One framed HTTP response completes without waiting for connection closure; surplus bytes are discarded, never interpreted as another response. Admission budgets live in `crates/core/src/tls/attest.rs`.

### Local fixture

Complete the setup builds before starting timed sessions; binary and example dependency features differ. Open three terminals at the repository root and use a fresh `target/manual/fixture` directory.

In terminal 1, start the HTTPS fixture. It generates the disclosure policy and certificates, and prints the Attest command. Cookie and account values are synthetic and reproducible; disclosure is controlled exclusively by `disclosure.json`:

```sh
(
set -eC
mkdir -p target/manual
mkdir target/manual/fixture
cargo run --release --locked --example fixture -- --directory target/manual/fixture --listen 127.0.0.1:7443
)
```

Wait for `fixture listening on 127.0.0.1:7443`; certificates and disclosure policy now exist. In terminal 2:

```sh
cargo run --release --locked --quiet --bin proof-client -- serve --listen 127.0.0.1:7047 --cert target/manual/fixture/verifier.pem --key target/manual/fixture/verifier.key --target-ca target/manual/fixture/target.pem --server-name localhost --metadata-output target/manual/fixture/verified-metadata.json
```

Wait for Serve's Ready event on stderr. In terminal 3, paste the cookie value following `-b` in the fixture's output, without surrounding quotes:

```sh
printf 'Fixture cookie: '
IFS= read -r fixture_cookie
```

Then send the request using curl-style arguments:

```sh
cargo run --release --locked --quiet --bin proof-client -- attest \
  --verifier 127.0.0.1:7047 --verifier-name localhost \
  --verifier-ca target/manual/fixture/verifier.pem \
  --target-ca target/manual/fixture/target.pem \
  --disclosure target/manual/fixture/disclosure.json \
  --metadata-output target/manual/fixture/private-metadata.json \
  --url 'https://localhost:7443/balance' \
  -H 'content-type: application/json' \
  -H 'Connection: keep-alive' \
  -b "$fixture_cookie" \
  --data-raw '{}'
```

Attest prints the full response body. Serve prints disclosed HTTP lines, `"AvailableBalance":42.1200` and `"currency":"PLN"`, 🙈 for hidden bytes (including cookies), and 🔒 for the committed account field. The account value is retained in private opening metadata. All three processes exit after one completed attestation. Mismatched identity/trust or an occupied metadata destination fails.

### mBank balance bytes

In browser DevTools, select a successful request and choose **Copy as cURL (bash)**. Keep the URL, headers, cookies and `--data-raw` arguments; replace the leading `curl` as shown below. The copied request is sent again through TLSNotary; a previously captured response cannot be attested.

Create a local verifier identity:

```sh
mkdir -p target/manual
cargo run --release --locked --example certificates -- --directory target/manual/bank
```

Prepare a disclosure JSON file matching the actual response. For the selected product, reveal its balance and currency and commit its `id` and `number`; the synthetic fixture's `account` field is not a real mBank selector. Use its actual JSON pointers and save the policy under ignored local storage.

Set `target_host` to the hostname from the copied URL, then start Serve:

```sh
cargo run --release --locked --quiet --bin proof-client -- serve \
  --listen 127.0.0.1:7047 \
  --cert target/manual/bank/verifier.pem --key target/manual/bank/verifier.key \
  --server-name "$target_host" \
  --metadata-output target/manual/bank/verified-metadata.json
```

Wait for Ready. Put the verifier, disclosure and metadata arguments first, then append the supported arguments from the copied curl command, without the leading `curl`. For a JSON POST request, the complete command has this form; replace the placeholders and retain the headers from your browser capture:

```sh
cargo run --release --locked --quiet --bin proof-client -- attest \
  --verifier 127.0.0.1:7047 --verifier-name localhost \
  --verifier-ca target/manual/bank/verifier.pem \
  --disclosure target/manual/bank/disclosure.json \
  --metadata-output target/manual/bank/private-metadata.json \
  --url '<copied HTTPS URL>' \
  -H 'content-type: application/json' \
  -b '<copied cookies>' \
  --data-raw '<copied request body>'
```

Preserve an explicit `-X` method when present; omit `--data-raw` for requests without a body. Unsupported flags such as `--compressed` fail; request identity encoding for this baseline rather than advertising compression. Do not add the fixture's `--target-ca`: real targets use the pinned Mozilla roots. Use fresh metadata paths for each run. Append `> response.txt` to save stdout; the application has no response-saving option.

Success authenticates selected balance/currency bytes. It does not establish account ownership, hidden request context, JSON ancestry, independent freshness or completeness. Metadata and transcript lengths remain visible. The result is live verification, not a portable signed attestation. In the library, only successful live operations construct `VerifiedReport` and `Receipt`; deserialized `ReportData` is untrusted.

## Chrome

Load `extension/` in Chrome 124+ through `chrome://extensions` → Developer mode → Load unpacked. Record its ID. Obtain the binary's absolute path from the `compiler-artifact` message's `executable` field:

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

Click the toolbar action. All native file paths must be absolute; terminal paths may be relative. Verify the base example using `examples/merkle/base.json`, `target/manual/base/public.json` and `target/manual/base/proof.json`, converted to absolute paths. To prove again, use `target/manual/base/witness.json` and a new proof output path. For TLS, start a fresh fixture in a terminal, start Serve in the form, wait for Ready, then enter its curl-style request arguments as one JSON array, for example `["--url", "https://localhost:7443/balance", "-b", "COPIED_FIXTURE_COOKIE", "--data-raw", "{}"]`. Empty strings are preserved. The array is appended after the protocol and metadata arguments and parsed by the CLI.

Check Cancel and tab close while Serve waits: its port becomes reusable and no output appears. After success, published files remain. Each operation owns one native port/process; tab close disconnects them. Only `nativeMessaging` permission is required.

Each port sends one invocation, `{"protocol":"proof-client/10","args":[...]}`, using CLI arguments. Frames are UTF-8 JSON with a native-endian four-byte length, bounded by `MAX_FRAME_BYTES` in `crates/cli/src/stdio.rs`. Serve emits Ready, then every invocation emits Completed or Failed and exits. Proof commands use terminal JSON events. TLS commands print HTTP output on stdout and Ready on stderr; errors use stderr and failure status. Native TLS results contain `stdout_base64` and the metadata path. Arguments never pass through a shell.

Installed Chrome cancellation and live mBank acceptance require manual verification.
