# Proof Client

Rust owns proof files and cryptography; Chrome supplies local paths and receives receipts.

| Flow               | Input                                                               | Result                                               |
| ------------------ | ------------------------------------------------------------------- | ---------------------------------------------------- |
| `prove` / `verify` | Circuit, public input and witness / circuit, public input and proof | Proof artifact / verified public words               |
| `serve` / `attest` | Verifier identity / HTTPS request and disclosure policy             | Redacted verifier log / private response and receipt |

`crates/core/` is the reusable library: `proof::{prepare, prove, verify, with_session}` handles generic circuits; `tls::quic::Verifier::{bind, verify}` and `tls::quic::attest` handle serve/attest. Core owns circuit and protocol validation and must not depend on the CLI. `crates/cli/` is a thin wrapper for arguments, file I/O, process runtime and terminal/native messages, including manual testing. Example-specific logic stays in `examples/`, which contains the Merkle and mBank demos. [vendor/README.md](vendor/README.md) records upstream provenance and patches.

The Cargo workspace lives in `crates/`; the npm workspace contains `extension/`, a manually loaded Chrome demo using plain `.mjs` and JSDoc. Declare npm development dependencies at the root, commit `package-lock.json`, and use standard npm resolution. Keep tooling configuration minimal.

## Setup and checks

Prerequisites: Git, rustup, a native C toolchain, and Node.js 22.12+ with npm. Rust is pinned in `rust-toolchain.toml`; JavaScript tools are locked in `package-lock.json`.

Shell examples use zsh or bash. Run every terminal from the repository root. CLI examples use `cargo run --release --locked --bin proof-client -- ...`. No browser build step, browser tests, custom lint-rule suite or CI. Examples create files under ignored `target/manual/`; use fresh output paths when repeating a run.

Agents may install repository dependencies and development tools. Install Cargo tools with a repository-local `--root` under `target/`; do not install globally or change persistent PATH settings. The owner performs Chrome registration, commits and pushes manually.

```sh
cargo fetch --locked
cargo build --release --locked --bin proof-client --examples
cargo run --release --locked --bin proof-client -- --help
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
set -e
mkdir -p target/manual/base
cargo run --release --locked --example merkle -- leaf --index 0 public > target/manual/base/public.json
cargo run --release --locked --example merkle -- leaf --index 0 witness > target/manual/base/witness.json
cargo run --release --locked --bin proof-client -- prepare --circuit examples/merkle/base.json --output target/manual/base/metadata.json --threads 4
cargo run --release --locked --bin proof-client -- prove --circuit examples/merkle/base.json --public target/manual/base/public.json --witness target/manual/base/witness.json --output target/manual/base/proof.json --threads 4
cargo run --release --locked --bin proof-client -- verify --circuit examples/merkle/base.json --public target/manual/base/public.json --proof target/manual/base/proof.json --threads 1
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

Words are canonical KoalaBear elements; arithmetic is modular. Admission limits live in `crates/core/src/proof/{source,compiler}.rs`; the hiding profile lives in `crates/core/src/proof/config.rs`. Circuit format 4 replaces earlier formats; regenerate proofs from their original inputs. Output files are never overwritten. The cryptosystem is unaudited. Circuit verification alone does not establish TLSN provenance.

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
set -e
mkdir -p target/manual/tree
cargo run --release --locked --bin proof-client -- prepare --circuit examples/merkle/merge-recursive.json --output target/manual/tree/metadata.json --threads 4
for i in 0 1 2 3 4 5 6 7; do
  cargo run --release --locked --example merkle -- leaf --index "$i" public > "target/manual/tree/0-$i.public.json"
  cargo run --release --locked --example merkle -- leaf --index "$i" witness > "target/manual/tree/0-$i.witness.json"
  cargo run --release --locked --bin proof-client -- prove --circuit examples/merkle/base.json --public "target/manual/tree/0-$i.public.json" --witness "target/manual/tree/0-$i.witness.json" --output "target/manual/tree/0-$i.proof.json" --threads 4
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
    cargo run --release --locked --bin proof-client -- prove --circuit "examples/merkle/$circuit.json" --public "target/manual/tree/$height-$i.public.json" --witness "target/manual/tree/$height-$i.witness.json" --output "target/manual/tree/$height-$i.proof.json" --threads 4
    i=$((i + 1))
  done
done
cargo run --release --locked --example merkle -- public --height 3 --metadata target/manual/tree/metadata.json > target/manual/tree/expected.json
cargo run --release --locked --bin proof-client -- verify --circuit examples/merkle/merge-recursive.json --public target/manual/tree/expected.json --proof target/manual/tree/3-0.proof.json --threads 1
)
```

The example computes the expected root independently. Final verification needs the final proof, trusted circuit sources and expected statement. Metadata paths are relative to the entry directory where possible; IDs do not depend on filenames. Library sessions reuse preparation; CLI invocations prepare independently. The ignored recursion gate exercises eight leaves and three levels, including reuse of `merge-recursive`.

## Serve / attest

Both peers must use this patched build; the mux protocol differs from unpatched TLSNotary alpha.15. Both verifier endpoints use loopback addresses. QUIC authenticates the verifier using TLS 1.3; the prover opens the target socket using TLSN's TLS 1.2/HTTP/1.1 baseline. Explicit CA bundles replace the pinned Mozilla roots for that peer. Session IDs correlate runs; they do not authenticate local users.

Only user-selected authenticated transcript ranges may be disclosed to the verifier. Private requests, witnesses and undisclosed response bytes remain local; protocol metadata and transcript lengths are part of the disclosure baseline.

The [request template](examples/mbank/request.json) contains `method`, HTTPS `url`, `headers` as name/value pairs, and `body_base64`. The engine owns Host, Content-Length, Connection and Accept-Encoding; conflicting framing/control headers fail. Redirects, retries and transport fallbacks are unsupported.

A [disclosure policy](examples/mbank/disclosure.json) supplies `sent` and `received` selections. Empty arrays disclose nothing.

| Selection                          | Meaning                                             |
| ---------------------------------- | --------------------------------------------------- |
| `{"bytes": [start, end]}`          | nonempty half-open range in the original transcript |
| `"start_line"`                     | HTTP request line or final response status line     |
| `{"header": "content-type"}`       | every matching header name/value, case insensitive  |
| `"body"`                           | body payload, excluding chunk framing and trailers  |
| `{"json": "/products/0/currency"}` | original JSON member key/value, or array element    |

Structured selectors require nonempty CRLF-terminated start lines, including interim responses. JSON pointers use RFC 6901 escaping (`~1`, `~0`); the empty pointer selects the root. Numeric spelling is preserved and chunk offsets map back to the transcript. Duplicate decoded keys, missing selectors, ambiguous framing and compressed structured bodies fail. Overlapping/adjacent ranges merge; gaps remain hidden.

`serve` publishes its redacted log before acknowledging it. `attest` checks the receipt against its transcript, then publishes the **full private response** and receipt. Logs contain the session, authenticated server, transcript lengths and selected `{start, bytes}` segments, not a continuous HTTP document. Limits and deadlines live in `crates/core/src/tls/{attest,quic}.rs`.

Publication and delivery are not atomic: a verifier log may exist without client acknowledgement. Requests may affect the target before failure. Nothing retries automatically. On failure/cancellation, inspect output paths; forced termination during publication can leave a private temporary file. Published files survive cancellation. Filesystem access is outside the privacy boundary.

### Local fixture

Open three terminals at the repository root before starting; the fixture and verifier have session deadlines. Use a fresh `target/manual/fixture` directory.

In terminal 1, create the synthetic request and start the HTTPS fixture:

```sh
mkdir -p target/manual/fixture
cat > target/manual/fixture/request.json <<'JSON'
{
  "method": "POST",
  "url": "https://localhost:7443/balance",
  "headers": [["content-type", "application/json"], ["cookie", "SECRET"]],
  "body_base64": "e30="
}
JSON
cargo run --release --locked --example fixture -- --directory target/manual/fixture --listen 127.0.0.1:7443
```

Wait for `fixture listening on 127.0.0.1:7443`; the certificates and disclosure policy now exist. In terminal 2:

```sh
cargo run --release --locked --bin proof-client -- serve --listen 127.0.0.1:7047 --cert target/manual/fixture/verifier.pem --key target/manual/fixture/verifier.key --target-ca target/manual/fixture/target.pem --server-name localhost --session fixture --output target/manual/fixture/verified.json
```

Wait for the Ready event, then in terminal 3:

```sh
cargo run --release --locked --bin proof-client -- attest --request target/manual/fixture/request.json --disclosure target/manual/fixture/disclosure.json --verifier 127.0.0.1:7047 --verifier-name localhost --verifier-ca target/manual/fixture/verifier.pem --target-ca target/manual/fixture/target.pem --session fixture --output target/manual/fixture/private.json
```

Expect disclosed `"AvailableBalance":42.1200` and `"currency":"PLN"`, without cookies or `PRIVATE`. The private output includes the hidden account field. All three processes exit after one completed attestation. Mismatched identity/session/trust or an occupied destination fails.

### mBank balance bytes

The request template is not a verified endpoint. Log in manually, capture a successful request in DevTools, and supply its URL, method, application headers/cookies and exact body. Adapt the disclosure policy to the response; keep personal files under ignored local storage.

Create a verifier identity:

```sh
mkdir -p target/manual
cargo run --release --locked --example certificates -- --directory target/manual/bank
```

Use the fixture's Serve/Attest commands with these verifier files, fresh outputs/session, the captured request/policy, and Serve's `--server-name` set to the target host. Omit `--target-ca` from both commands; retain `--verifier-ca` for localhost.

Success authenticates selected balance/currency bytes. It does not establish account ownership, hidden request context, JSON ancestry, independent freshness or completeness. Metadata and transcript lengths remain visible. The result is live verification, not a portable signed attestation.

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

Click the toolbar action. All native file paths must be absolute; terminal paths may be relative. Verify the base example using `examples/merkle/base.json`, `target/manual/base/public.json` and `target/manual/base/proof.json`, converted to absolute paths. To prove again, use `target/manual/base/witness.json` and a new proof output path. For TLS, start a fresh fixture in a terminal, start Serve in the form, wait for Ready, then start Attest.

Check Cancel and tab close while Serve waits: its port becomes reusable and no output appears. After success, published files remain. Each operation owns one native port/process; tab close disconnects them. Only `nativeMessaging` permission is required.

Each port sends one invocation, `{"protocol":"proof-client/7","args":[...]}`, using CLI arguments. Frames are UTF-8 JSON with a native-endian four-byte length, bounded by `MAX_FRAME_BYTES` in `crates/cli/src/stdio.rs`. Serve emits Ready, then every invocation emits Completed or Failed and exits. Terminal events use JSON lines; terminal errors use stderr and failure status. Arguments never pass through a shell.

Installed Chrome cancellation and live mBank acceptance require manual verification.
