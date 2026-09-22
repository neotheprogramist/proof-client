# Proof Client

One Rust binary, two independent engines, four commands. Chrome passes local paths and receives small receipts; Rust owns files and cryptography.

| Flow               | Input                                                   | Result                                               |
| ------------------ | ------------------------------------------------------- | ---------------------------------------------------- |
| `prove` / `verify` | KoalaBear circuit and witness / circuit and proof       | Proof artifact / verified public words               |
| `serve` / `attest` | Verifier identity / HTTPS request and disclosure policy | Redacted verifier log / private response and receipt |

`crates/core/` owns the engines, `crates/cli/` the commands and native protocol, `extension/` the Chrome forms, and `examples/` the Merkle and mBank demos. [vendor/README.md](vendor/README.md) records upstream provenance and patches.

## Setup and checks

Run from the repository root. Tool versions live in `rust-toolchain.toml` and `package-lock.json`. No browser build step, browser tests or CI.

```sh
cargo fetch --locked
cargo build --release --locked --bin proof-client --examples
cargo run --release --locked --bin proof-client -- --help
npm ci
```

With dependencies cached:

```sh
cargo fmt --package proof-client --package proof-client-core --check
cargo clippy --locked --offline --workspace --all-targets --all-features -- -D warnings
cargo test --locked --offline --workspace
cargo test --locked --offline -p proof-client-core --test hiding parallel_hiding_admission -- --ignored --exact --nocapture
cargo test --locked --offline -p proof-client-core --test family eight_leaf_family -- --ignored --exact --nocapture
cargo test --locked --offline -p proof-client-core --lib family_membership_is_enforced_without_host_admission -- --ignored --nocapture
```

Format only consumer packages; `cargo fmt --all` visits vendor trees. Run the three ignored gates sequentially. Adversarial controls bypass witness checks and exercise the emitted constraints.

```sh
npm run fmt:check
npm run lint
npm run typecheck
```

Install cargo-mutants locally and run a consumer shard:

```sh
cargo install cargo-mutants --version 27.1.0 --locked --root target/tools
./target/tools/bin/cargo-mutants mutants --workspace --copy-target=false --profile test --cargo-arg="--target-dir=$PWD/target/mutation-build" --cargo-arg=--locked --cargo-arg=--offline --cargo-arg=--workspace --cargo-arg=--lib --cargo-arg=--test=tls --file crates/core/src/tls/quic.rs --shard 1/4 --sharding round-robin
```

Rotate the consumer file, tests and shard on subsequent changes. For the complete diagnostic, remove `--file`, `--shard`, `--sharding`, `--cargo-arg=--lib` and `--cargo-arg=--test=tls`. The Chrome demo is excluded from JavaScript mutation testing.

## Prove / verify

```sh
cargo run --release --locked --bin proof-client -- prove --circuit circuit.json --witness witness.json --output proof.json --threads 4
cargo run --release --locked --bin proof-client -- verify --circuit circuit.json --proof proof.json --threads 1
```

Witness shape: `{"public":[49],"private":[7],"proofs":[]}`. Registers number public inputs, private inputs, then operation outputs. `proof-client/circuit/1` supports:

| Operation           | Parameters                                              | Output               |
| ------------------- | ------------------------------------------------------- | -------------------- |
| `constant`          | `value`                                                 | one field word       |
| `add`, `sub`, `mul` | `left`, `right` register indices                        | one field word       |
| `poseidon2`         | `tag`, `inputs`, a nonempty multiple of eight registers | eight digest words   |
| `verify`            | `child` index in the source's `children`                | child's public words |
| constraint `equal`  | `left`, `right`                                         | none                 |
| constraint `bits`   | `wire`, `bits` in 1–30                                  | none                 |

Words are canonical KoalaBear elements; arithmetic is modular. Recursive artifacts follow `verify` operation order. Child public values become parent wires; the supplied circuit fixes verification authority.

`prove` creates a new file. `verify` independently compiles the circuit and returns its ID and verified public words. **Compare those words with the intended claim.** Verification certifies the circuit’s constraints over its declared public words; it does not establish TLSN provenance.

Admission limits live in `crates/core/src/proof/compiler.rs`; the fixed hiding profile lives in `crates/core/src/proof/config.rs`. Format/profile changes require regenerating proofs. The cryptosystem is unaudited.

## Merkle example

Eight sample leaves contain words 0–63. Ordered Poseidon2 hashing uses separate leaf/node domains and produces an eight-word root.

```sh
mkdir -p target/manual/merkle
cargo run --release --locked --example merkle -- direct witness > target/manual/merkle/witness.json
cargo run --release --locked --example merkle -- direct public > target/manual/merkle/expected.json
cargo run --release --locked --bin proof-client -- prove --circuit examples/merkle/circuit.json --witness target/manual/merkle/witness.json --output target/manual/merkle/proof.json --threads 4
cargo run --release --locked --bin proof-client -- verify --circuit examples/merkle/circuit.json --proof target/manual/merkle/proof.json --threads 1
```

Expect `result.public` to equal `expected.json`, computed independently of the circuit interpreter. Altering a claimed public word must fail verification. Reusing an output path must fail without changing the file.

The recursive [family.json](examples/merkle/family.json) has fixed `base`, `join` and `fold` roles. Fold enforces key membership, family identity and equal child heights. Build the same tree with fresh paths:

```sh
set -e
mkdir -p target/manual/tree
cargo run --release --locked --example merkle -- prepare --threads 4 > target/manual/tree/family.json
for height in 0 1 2 3; do
  cargo run --release --locked --example merkle -- circuit --height "$height" > "target/manual/tree/circuit-$height.json"
done
for i in 0 1 2 3 4 5 6 7; do
  cargo run --release --locked --example merkle -- leaf --index "$i" > "target/manual/tree/0-$i.witness.json"
  cargo run --release --locked --bin proof-client -- prove --circuit target/manual/tree/circuit-0.json --witness "target/manual/tree/0-$i.witness.json" --output "target/manual/tree/0-$i.proof.json" --threads 4
done
for height in 1 2 3; do
  previous=$((height - 1))
  count=$((8 >> height))
  i=0
  while [ "$i" -lt "$count" ]; do
    left=$((2 * i))
    right=$((left + 1))
    cargo run --release --locked --example merkle -- parent --left "target/manual/tree/$previous-$left.proof.json" --right "target/manual/tree/$previous-$right.proof.json" --family target/manual/tree/family.json > "target/manual/tree/$height-$i.witness.json"
    cargo run --release --locked --bin proof-client -- prove --circuit "target/manual/tree/circuit-$height.json" --witness "target/manual/tree/$height-$i.witness.json" --output "target/manual/tree/$height-$i.proof.json" --threads 4
    i=$((i + 1))
  done
done
cargo run --release --locked --example merkle -- public --height 3 --family target/manual/tree/family.json > target/manual/tree/expected.json
cargo run --release --locked --bin proof-client -- verify --circuit target/manual/tree/circuit-3.json --proof target/manual/tree/3-0.proof.json --threads 1
```

Expect `[height, root (8 words), family (8 words)]`, equal to `expected.json`; the root matches the direct example. Verification needs only the final proof and trusted circuit. Recursive proving is memory-intensive; the library gate reuses preparation, while CLI invocations prepare independently. Height three is the tested scope.

## Serve / attest

Both peers must use this patched build; the mux protocol differs from unpatched TLSNotary alpha.15. Both verifier endpoints use loopback addresses. QUIC authenticates the verifier using TLS 1.3; the prover opens the target socket using TLSN's TLS 1.2/HTTP/1.1 baseline. Explicit CA bundles replace the pinned Mozilla roots for that peer. Session IDs correlate runs; they do not authenticate local users.

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

In terminal 1:

```sh
cargo run --release --locked --example fixture -- --directory target/manual/fixture --listen 127.0.0.1:7443
```

After readiness, copy the request template to `target/manual/fixture/request.json`; set URL `https://localhost:7443/balance`, Cookie `SECRET`, and body `e30=`. The fixture creates target/verifier certificates and a disclosure policy. In terminal 2:

```sh
cargo run --release --locked --bin proof-client -- serve --listen 127.0.0.1:7047 --cert target/manual/fixture/verifier.pem --key target/manual/fixture/verifier.key --target-ca target/manual/fixture/target.pem --server-name localhost --session fixture --output target/manual/fixture/verified.json
```

Wait for the Ready event, then in terminal 3:

```sh
cargo run --release --locked --bin proof-client -- attest --request target/manual/fixture/request.json --disclosure target/manual/fixture/disclosure.json --verifier 127.0.0.1:7047 --verifier-name localhost --verifier-ca target/manual/fixture/verifier.pem --target-ca target/manual/fixture/target.pem --session fixture --output target/manual/fixture/private.json
```

Expect disclosed `"AvailableBalance":42.1200` and `"currency":"PLN"`, without cookies or `PRIVATE`. The private output includes the hidden account field. Both processes exit after one session. Mismatched identity/session/trust or an occupied destination fails.

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

Click the toolbar action. All native file paths must be absolute; terminal paths may be relative. Run Prove → Verify with the Merkle inputs and compare the root. For TLS, run the fixture in a terminal, start Serve in the form, wait for Ready, then start Attest.

Check Cancel and tab close while Serve waits: its port becomes reusable and no output appears. After success, published files remain. Each operation owns one native port/process; tab close disconnects them. Only `nativeMessaging` permission is required.

Each port sends one invocation, `{"protocol":"proof-client/5","args":[...]}`, using CLI arguments. Frames are UTF-8 JSON with a native-endian four-byte length, bounded by `MAX_FRAME_BYTES` in `crates/cli/src/stdio.rs`. Serve emits Ready, then every invocation emits Completed or Failed and exits. Terminal events use JSON lines; terminal errors use stderr and failure status. Arguments never pass through a shell.

For host errors, check the manifest, executable and extension ID. Rebuild/reload after changes; update registration after moving the binary. Installed Chrome cancellation and live mBank acceptance require manual verification.
