#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test observations are direct"
)]
#[path = "../../../examples/mbank/support/fixture.rs"]
mod fixture;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::{
    fs,
    process::{Output, Stdio},
};
use tlsn::{rangeset::set::RangeSet, transcript::Direction};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader},
    process::{Child, Command},
};

const OUTPUT_LIMIT: usize = proof_client::stdio::MAX_FRAME_BYTES;

async fn bounded(reader: impl AsyncRead + Unpin) -> Vec<u8> {
    let mut bytes = Vec::new();
    reader
        .take((OUTPUT_LIMIT + 1) as u64)
        .read_to_end(&mut bytes)
        .await
        .unwrap();
    assert!(
        bytes.len() <= OUTPUT_LIMIT,
        "subprocess output exceeds limit"
    );
    bytes
}

async fn finish(
    mut child: Child,
    stdout: impl AsyncRead + Unpin,
    stderr: impl AsyncRead + Unpin,
) -> Output {
    let (status, stdout, stderr) = tokio::join!(child.wait(), bounded(stdout), bounded(stderr));
    Output {
        status: status.unwrap(),
        stdout,
        stderr,
    }
}

fn proof_client() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_proof-client"));
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    command
}

async fn launch(mut command: Command, native: bool) -> Child {
    if !native {
        return command.spawn().unwrap();
    }
    let args = command
        .as_std()
        .get_args()
        .map(|arg| arg.to_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    let mut child = proof_client()
        .arg("chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/")
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    let mut bytes = Vec::new();
    proof_client::stdio::write_frame(
        &mut bytes,
        &json!({"protocol":proof_client::stdio::PROTOCOL,"args":args}),
    )
    .unwrap();
    child.stdin.take().unwrap().write_all(&bytes).await.unwrap();
    child
}
async fn readiness(reader: &mut (impl tokio::io::AsyncBufRead + Unpin), native: bool) -> Value {
    if native {
        let mut prefix = [0; 4];
        reader.read_exact(&mut prefix).await.unwrap();
        let len = u32::from_ne_bytes(prefix) as usize;
        assert!(len > 0 && len <= OUTPUT_LIMIT);
        let mut bytes = vec![0; len];
        reader.read_exact(&mut bytes).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    } else {
        let mut line = String::new();
        loop {
            assert!(reader.read_line(&mut line).await.unwrap() > 0);
            if line.contains("event=\"ready\"") {
                break;
            }
            line.clear();
        }
        let address = line.split("address=").nth(1).unwrap().trim();
        json!({"event":"ready", "address":address})
    }
}
fn terminal_event(bytes: &[u8]) -> Value {
    let mut cursor = std::io::Cursor::new(bytes);
    let frame = proof_client::stdio::read_frame(&mut cursor).unwrap();
    assert_eq!(cursor.position() as usize, bytes.len());
    serde_json::from_slice(&frame).unwrap()
}
fn output_bytes(output: &Output, native: bool) -> Vec<u8> {
    if native {
        let event = terminal_event(&output.stdout);
        assert_eq!(event["event"], "completed", "{event}");
        STANDARD
            .decode(event["result"]["stdout_base64"].as_str().unwrap())
            .unwrap()
    } else {
        output.stdout.clone()
    }
}

fn metadata_path(root: &std::path::Path, prefix: &str) -> std::path::PathBuf {
    let paths = fs::read_dir(root.join("runs"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with(prefix)
        })
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 1);
    paths[0].join("metadata.json")
}

fn assert_openings(
    metadata: &Value,
    request: &[u8],
    response: &[u8],
    committed: &[(Direction, RangeSet<usize>)],
) {
    let hashes: Vec<tlsn::transcript::hash::PlaintextHash> =
        serde_json::from_value(metadata["commitments"].clone()).unwrap();
    let openings = metadata["openings"].as_array().unwrap();
    assert_eq!(
        hashes
            .iter()
            .map(|hash| (hash.direction, hash.idx.clone()))
            .collect::<Vec<_>>(),
        committed
    );
    assert_eq!(openings.len(), hashes.len());
    let mut blinders = std::collections::HashSet::new();
    for opening in openings.iter().rev() {
        let secret: tlsn::transcript::TranscriptSecret =
            serde_json::from_value(opening["secret"].clone()).unwrap();
        let tlsn::transcript::TranscriptSecret::Hash(secret) = secret else {
            panic!("unsupported secret")
        };
        let hash = hashes
            .iter()
            .find(|hash| hash.direction == secret.direction && hash.idx == secret.idx)
            .unwrap();
        assert_eq!(hash.hash.alg, secret.alg);
        assert!(blinders.insert(secret.blinder.as_bytes().to_vec()));
        let source = match hash.direction {
            Direction::Sent => request,
            Direction::Received => response,
        };
        let plaintext: Vec<u8> = serde_json::from_value(opening["plaintext"].clone()).unwrap();
        assert_eq!(
            plaintext,
            hash.idx
                .iter()
                .flat_map(|r| source[r].to_vec())
                .collect::<Vec<_>>()
        );
        let digest = tlsn::transcript::hash::hash_plaintext(
            &tlsn::hash::Blake3::default(),
            &plaintext,
            &secret.blinder,
        );
        assert_eq!(digest, hash.hash);
    }
}

fn assert_private_transcript(
    report: &str,
    direction: Direction,
    bytes: &[u8],
    revealed: &[usize],
    committed: &[(Direction, RangeSet<usize>)],
) {
    let mut end = 0;
    for line in report
        .lines()
        .skip_while(|line| !line.starts_with(&format!("{direction:?}:")))
        .skip(1)
        .take_while(|line| line.starts_with("  ["))
    {
        let (range, rendered) = line.strip_prefix("  [").unwrap().split_once(")  ").unwrap();
        let (start, stop) = range.split_once(", ").unwrap();
        let start = start.parse::<usize>().unwrap();
        let stop = stop.parse::<usize>().unwrap();
        assert_eq!(start, end);
        assert!(start < stop && stop <= bytes.len());
        let label = if (start..stop).all(|i| revealed.contains(&i)) {
            "revealed  ".to_owned()
        } else if let Some((index, _)) = committed.iter().enumerate().find(|(_, (dir, ranges))| {
            *dir == direction && (start..stop).all(|i| ranges.contains(&i))
        }) {
            format!("committed  commitment {}", index + 1)
        } else {
            assert!((start..stop).all(|i| {
                !revealed.contains(&i)
                    && !committed
                        .iter()
                        .any(|(dir, ranges)| *dir == direction && ranges.contains(&i))
            }));
            "hidden".to_owned()
        };
        assert_eq!(
            rendered,
            format!("{label} \"{}\"", bytes[start..stop].escape_ascii())
        );
        end = stop;
    }
    assert_eq!(end, bytes.len());
}

#[tokio::test]
async fn native_quic_attestation_binds_identity_and_disclosure() {
    let data = fixture::sample_data();
    let request_cookie = format!("session={:016x}", rand::random::<u64>());
    let body = data.body();
    #[derive(Clone, Copy, Debug)]
    enum Case {
        Fields,
        Empty,
        MixedStartLine,
        Overlap,
        CombinedCommitmentLimit,
        ReceiveLimit,
        ExcessResponse,
        WrongVerifier,
        WrongTarget,
        WrongTrust,
        Collision,
        BrokenPipe,
    }
    for (case, native) in [
        (Case::Fields, true),
        (Case::Fields, false),
        (Case::Empty, true),
        (Case::MixedStartLine, true),
        (Case::Overlap, true),
        (Case::CombinedCommitmentLimit, false),
        (Case::ReceiveLimit, false),
        (Case::ExcessResponse, false),
        (Case::WrongVerifier, false),
        (Case::WrongTarget, false),
        (Case::WrongTrust, false),
        (Case::Collision, false),
        (Case::BrokenPipe, false),
    ] {
        let verifier_name = if matches!(case, Case::WrongVerifier) {
            "wrong.invalid"
        } else {
            "localhost"
        };
        let expected_target = match case {
            Case::WrongTarget => "wrong.invalid",
            Case::Fields if native => "LOCALHOST",
            _ => "localhost",
        };
        let target_ca = if matches!(case, Case::WrongTrust) {
            "verifier.pem"
        } else {
            "target.pem"
        };
        let success = matches!(
            case,
            Case::Fields | Case::Empty | Case::ReceiveLimit | Case::BrokenPipe
        );
        let collision = matches!(case, Case::Collision);
        let automatic = matches!(case, Case::Fields | Case::Empty);
        let started = std::time::Instant::now();
        eprintln!("CASE {case:?} native={native}");
        let scenario = async {
            let dir = tempfile::tempdir().unwrap();
            fixture::verifier_identity(dir.path()).unwrap();
            let fixture = fixture::Fixture::bind(dir.path(), "127.0.0.1:0".parse().unwrap())
                .await
                .unwrap();
            let verified_metadata = dir.path().join("verified-metadata.json");
            let private_metadata = dir.path().join("private-metadata.json");
            let mut verifier_command = proof_client();
            verifier_command.arg("--data-dir").arg(dir.path());
            verifier_command
                .args([
                    "serve",
                    "--listen",
                    "127.0.0.1:0",
                    "--server-name",
                    expected_target,
                ])
                .arg("--cert")
                .arg(dir.path().join("verifier.pem"))
                .arg("--key")
                .arg(dir.path().join("verifier.key"))
                .arg("--target-ca")
                .arg(dir.path().join(target_ca));
            if !automatic {
                verifier_command
                    .arg("--metadata-output")
                    .arg(&verified_metadata);
            }
            let mut verifier = launch(verifier_command, native).await;
            let mut stdout = BufReader::new(verifier.stdout.take().unwrap());
            let mut stderr = BufReader::new(verifier.stderr.take().unwrap());
            let ready = if native {
                readiness(&mut stdout, true).await
            } else {
                readiness(&mut stderr, false).await
            };
            assert_eq!(ready["event"], "ready");
            let address = ready["address"].as_str().unwrap();
            let verified_metadata = if automatic {
                metadata_path(dir.path(), "serve.")
            } else {
                verified_metadata
            };
            if collision {
                fs::write(&verified_metadata, b"another writer").unwrap();
            }
            let response_bytes = if matches!(case, Case::ReceiveLimit | Case::ExcessResponse) {
                let mut bytes = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n".to_vec();
                bytes.extend_from_slice(body.as_bytes());
                bytes.resize(
                    proof_client_core::tls::attest::MAX_RECEIVED
                        + usize::from(matches!(case, Case::ExcessResponse)),
                    b' ',
                );
                bytes
            } else if matches!(case, Case::MixedStartLine) {
                format!(
                    "HTTP/1.1 200 OK\nSet-Cookie: {}\r\n\r\n{body}",
                    data.response_cookie
                )
                .into_bytes()
            } else {
                fixture::response()
            };
            let body_start = response_bytes.len() - body.len();
            let policy = match case {
                Case::Fields => json!({
                    "reveal":{"sent":["start_line", {"header":"content-type"}], "received":["start_line", {"header":"content-length"}, {"json":"/products/0/AvailableBalance"}, {"json_key":"/products/0/account"}]},
                    "commit":{"sent":[{"header":"cookie"}], "received":[{"json_value":"/products/0/account"}, {"json_value":"/products/0/currency"}, {"json_value":"/products/0/account"}]}
                }),
                Case::Collision => serde_json::from_str::<Value>(include_str!(
                    "../../../examples/mbank/disclosure.json"
                ))
                .unwrap(),
                Case::Empty | Case::ReceiveLimit | Case::ExcessResponse => {
                    json!({"reveal":{"sent":[],"received":[]}})
                }
                Case::Overlap => {
                    json!({"reveal":{"sent":[],"received":["body"]} ,"commit":{"sent":[],"received":["body"]}})
                }
                Case::CombinedCommitmentLimit => json!({"commit": {
                    "sent": (0..proof_client_core::tls::MAX_COMMITMENTS).map(|i| json!({"bytes":[i,i+1]})).collect::<Vec<_>>(),
                    "received": [{"bytes":[0,1]}]
                }}),
                Case::MixedStartLine => json!({"reveal":{"sent":[],"received":["start_line"]}}),
                Case::BrokenPipe | Case::WrongVerifier | Case::WrongTarget | Case::WrongTrust => {
                    json!({"reveal":{"sent":[],"received":["body"]}})
                }
            };
            fs::write(
                dir.path().join("disclosure.json"),
                serde_json::to_vec_pretty(&policy).unwrap(),
            )
            .unwrap();
            let before = fs::read_dir(dir.path()).unwrap().count();
            let mut client_command = proof_client();
            client_command
                .arg("--data-dir")
                .arg(dir.path())
                .args([
                    "attest",
                    "--verifier",
                    address,
                    "--verifier-name",
                    verifier_name,
                ])
                .arg("--verifier-ca")
                .arg(dir.path().join("verifier.pem"))
                .arg("--target-ca")
                .arg(dir.path().join(target_ca))
                .arg("--url")
                .arg(format!(
                    "https://localhost:{}/balance",
                    fixture.address().unwrap().port()
                ))
                .args([
                    "-H",
                    "content-type: application/json",
                    "-H",
                    "Connection: keep-alive",
                    "-b",
                    &request_cookie,
                    "--data-raw",
                    "{}",
                ]);
            if !automatic {
                client_command
                    .arg("--metadata-output")
                    .arg(&private_metadata);
            }
            if !matches!(case, Case::Empty) {
                client_command
                    .arg("--disclosure")
                    .arg(dir.path().join("disclosure.json"));
            }
            if !native && !matches!(case, Case::Fields) {
                client_command.args(["--format", "raw"]);
            }
            let mut client = launch(client_command, native).await;
            let client_stdout: Box<dyn AsyncRead + Unpin> = if matches!(case, Case::BrokenPipe) {
                drop(client.stdout.take());
                Box::new(tokio::io::empty())
            } else {
                Box::new(client.stdout.take().unwrap())
            };
            let client_stderr = client.stderr.take().unwrap();
            let client = async {
                let output = finish(client, client_stdout, client_stderr).await;
                assert_eq!(
                    output.status.success(),
                    native || (success && !matches!(case, Case::BrokenPipe)) || collision,
                    "{case:?}: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                if native {
                    assert_eq!(
                        terminal_event(&output.stdout)["event"],
                        if success || collision {
                            "completed"
                        } else {
                            "failed"
                        },
                        "{}",
                        terminal_event(&output.stdout)
                    );
                }
                output
            };
            let peers = async { tokio::join!(client, finish(verifier, stdout, stderr)) };
            tokio::pin!(peers);
            let target = fixture.serve(&response_bytes);
            tokio::pin!(target);
            let ((client, verifier), request) = tokio::select! {
                biased;
                request = &mut target => (peers.await, request.ok()),
                peers = &mut peers => (peers, None),
            };
            let private_metadata = if automatic {
                metadata_path(dir.path(), "attest.")
            } else {
                private_metadata
            };
            let verifier_errors = String::from_utf8_lossy(&verifier.stderr);
            assert_eq!(
                verifier.status.success(),
                native || success,
                "{verifier_errors}"
            );
            for value in [&request_cookie, &data.response_cookie, &data.account] {
                for output in [&client.stderr, &verifier.stderr] {
                    assert!(
                        !output
                            .windows(value.len())
                            .any(|bytes| bytes == value.as_bytes())
                    );
                }
            }
            assert_eq!(verified_metadata.exists(), success || collision);
            assert_eq!(private_metadata.exists(), success || collision);
            if collision {
                assert_eq!(fs::read(&verified_metadata).unwrap(), b"another writer");
                assert_eq!(output_bytes(&client, native), body.as_bytes());
                assert!(verifier.stdout.is_empty());
                return;
            }
            if success {
                assert!(verifier_errors.contains("phase=\"verified\""));
                let request = request.unwrap();
                let expected_body = if matches!(case, Case::ReceiveLimit) {
                    response_bytes[response_bytes
                        .windows(4)
                        .position(|w| w == b"\r\n\r\n")
                        .unwrap()
                        + 4..]
                        .to_vec()
                } else {
                    body.as_bytes().to_vec()
                };
                if matches!(case, Case::BrokenPipe) {
                    assert!(client.stdout.is_empty());
                } else if native || !matches!(case, Case::Fields) {
                    assert_eq!(output_bytes(&client, native), expected_body);
                } else {
                    let report = String::from_utf8(client.stdout.clone()).unwrap();
                    assert!(
                        report
                            .starts_with("Live TLS disclosure accepted; verifier receipt matched")
                    );
                    assert!(report.contains("Local selector resolution"));
                    assert!(report.contains(&data.account));
                    assert!(report.contains(&request_cookie));
                    assert!(report.contains(&data.response_cookie));
                }
                let positions = |bytes: &[u8], field: &[u8]| {
                    let start = bytes
                        .windows(field.len())
                        .position(|slice| slice == field)
                        .unwrap();
                    start..start + field.len()
                };
                let sent_positions = match case {
                    Case::Fields => positions(&request, b"POST /balance HTTP/1.1\r\n")
                        .chain(positions(&request, b"content-type: application/json\r\n"))
                        .collect(),
                    _ => Vec::new(),
                };
                let recv_positions = match case {
                    Case::Fields => [
                        b"HTTP/1.1 200 OK\r\n".as_slice(),
                        format!("Content-Length: {}\r\n", body.len()).as_bytes(),
                        br#""AvailableBalance":42.1200"#.as_slice(),
                        br#""account""#.as_slice(),
                    ]
                    .into_iter()
                    .flat_map(|field| positions(&response_bytes, field))
                    .collect::<Vec<_>>(),
                    Case::BrokenPipe => (body_start..response_bytes.len()).collect(),
                    Case::Empty | Case::ReceiveLimit => Vec::new(),
                    Case::WrongVerifier
                    | Case::WrongTarget
                    | Case::WrongTrust
                    | Case::Collision
                    | Case::ExcessResponse
                    | Case::MixedStartLine
                    | Case::CombinedCommitmentLimit
                    | Case::Overlap => unreachable!(),
                };
                let committed = if matches!(case, Case::Fields) {
                    positions(&response_bytes, format!(r#""{}""#, data.account).as_bytes())
                } else {
                    0..0
                };
                let groups = if matches!(case, Case::Fields) {
                    vec![
                        (
                            Direction::Sent,
                            RangeSet::from(positions(
                                &request,
                                format!("cookie: {request_cookie}\r\n").as_bytes(),
                            )),
                        ),
                        (
                            Direction::Received,
                            RangeSet::from(positions(&response_bytes, br#""PLN""#)),
                        ),
                        (Direction::Received, RangeSet::from(committed.clone())),
                    ]
                } else {
                    Vec::new()
                };
                if !native && matches!(case, Case::Fields) {
                    let report = std::str::from_utf8(&client.stdout).unwrap();
                    for (selector, number) in [
                        (r#"{"header":"cookie"}"#, 1),
                        (r#"{"json_value":"/products/0/currency"}"#, 2),
                        (r#"{"json_value":"/products/0/account"}"#, 3),
                    ] {
                        let lines = report
                            .lines()
                            .filter(|line| line.contains(selector))
                            .collect::<Vec<_>>();
                        assert!(!lines.is_empty());
                        assert!(
                            lines
                                .iter()
                                .all(|line| line.ends_with(&format!("-> commitment {number}")))
                        );
                    }
                }
                let mut expected_transcript = b"--- Sent ---\n".to_vec();
                for (index, (bytes, positions, direction)) in [
                    (&request, sent_positions, Direction::Sent),
                    (&response_bytes, recv_positions, Direction::Received),
                ]
                .into_iter()
                .enumerate()
                {
                    if !native && matches!(case, Case::Fields) {
                        assert_private_transcript(
                            std::str::from_utf8(&client.stdout).unwrap(),
                            direction,
                            bytes,
                            &positions,
                            &groups,
                        );
                    }
                    if index == 1 {
                        expected_transcript.extend_from_slice(b"\n--- Received ---\n");
                    }
                    expected_transcript.extend(bytes.iter().enumerate().flat_map(|(i, byte)| {
                        if positions.contains(&i) {
                            vec![*byte]
                        } else if groups
                            .iter()
                            .any(|(dir, ranges)| *dir == direction && ranges.contains(&i))
                        {
                            "🔒".as_bytes().to_vec()
                        } else {
                            "🙈".as_bytes().to_vec()
                        }
                    }));
                }
                if native {
                    assert_eq!(output_bytes(&verifier, native), expected_transcript);
                } else {
                    let report = String::from_utf8(verifier.stdout.clone()).unwrap();
                    assert!(report.starts_with("Live TLS disclosure accepted"));
                    assert!(report.contains(
                        "JSON relationships, account ownership and freshness: not established"
                    ));
                    if !matches!(case, Case::BrokenPipe) {
                        assert!(!report.contains(&data.account));
                    }
                    assert!(!report.contains(&request_cookie));
                    assert!(!report.contains(&data.response_cookie));
                    if matches!(case, Case::Fields) {
                        assert!(report.contains("BLAKE3"));
                        assert!(report.contains(&format!(
                            "[{}, {})  committed",
                            committed.start, committed.end
                        )));
                        assert!(report.contains("42.1200"));
                    }
                }
                let metadata: Value =
                    serde_json::from_slice(&fs::read(&private_metadata).unwrap()).unwrap();
                let mut public_metadata = metadata.clone();
                public_metadata.as_object_mut().unwrap().remove("openings");
                public_metadata
                    .as_object_mut()
                    .unwrap()
                    .remove("selections");
                assert_eq!(
                    serde_json::from_slice::<Value>(&fs::read(&verified_metadata).unwrap())
                        .unwrap(),
                    public_metadata
                );
                assert!(metadata.get("session").is_none());
                assert_eq!(metadata["server_name"], "localhost");
                assert_eq!(metadata["sent_len"], request.len());
                assert_eq!(metadata["received_len"], response_bytes.len());
                if matches!(case, Case::Fields) {
                    assert_eq!(
                        metadata["selections"]["received"]["commit"][0]["selector"],
                        json!({"json_value":"/products/0/account"})
                    );
                    assert_eq!(
                        metadata["selections"]["received"]["commit"][0]["ranges"],
                        json!([{"start":committed.start,"end":committed.end}])
                    );
                }
                for (name, raw) in [
                    ("sent", request.as_slice()),
                    ("received", response_bytes.as_slice()),
                ] {
                    for segment in metadata[name].as_array().unwrap() {
                        let start = segment["start"].as_u64().unwrap() as usize;
                        let bytes =
                            serde_json::from_value::<Vec<u8>>(segment["bytes"].clone()).unwrap();
                        assert_eq!(bytes, &raw[start..start + bytes.len()]);
                    }
                }
                assert_openings(&metadata, &request, &response_bytes, &groups);
                for path in [&verified_metadata, &private_metadata] {
                    let raw = fs::read(path).unwrap();
                    assert!(raw.ends_with(b"\n"));
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        assert_eq!(
                            fs::metadata(path).unwrap().permissions().mode() & 0o777,
                            0o600
                        );
                    }
                }
                let request = String::from_utf8(request).unwrap();
                assert!(request.starts_with("POST /balance HTTP/1.1\r\n"));
                assert!(request.contains(&format!("cookie: {}\r\n", request_cookie)));
                assert!(request.contains("connection: keep-alive\r\n"));
                assert!(request.ends_with("\r\n\r\n{}"));
                if native {
                    for (output, metadata) in [
                        (&client, &private_metadata),
                        (&verifier, &verified_metadata),
                    ] {
                        assert_eq!(
                            terminal_event(&output.stdout)["result"]["metadata_output"],
                            json!(metadata.canonicalize().unwrap())
                        );
                    }
                }
                for output in [&client, &verifier] {
                    assert!(String::from_utf8_lossy(&output.stderr).contains("published"));
                }
            } else {
                if matches!(case, Case::CombinedCommitmentLimit) {
                    assert!(
                        String::from_utf8_lossy(&client.stderr)
                            .contains("transcript commitment count exceeds the session budget")
                    );
                }
                for output in [&client, &verifier] {
                    if native {
                        let event = terminal_event(&output.stdout);
                        assert_eq!(event["event"], "failed");
                        assert!(!output.stderr.is_empty());
                    } else {
                        assert!(!output.stderr.is_empty());
                        assert!(output.stdout.is_empty());
                    }
                }
                assert_eq!(
                    fs::read_dir(dir.path()).unwrap().count(),
                    before,
                    "no partial output or temporary files"
                );
            }
        };
        tokio::time::timeout(
            proof_client_core::tls::attest::SESSION_TIMEOUT + std::time::Duration::from_secs(10),
            scenario,
        )
        .await
        .unwrap();
        eprintln!("CASE elapsed={:?}", started.elapsed());
    }
}

#[tokio::test]
async fn terminating_a_waiting_native_host_releases_its_port_without_temporary_files() {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let dir = tempfile::tempdir().unwrap();
        fixture::verifier_identity(dir.path()).unwrap();
        let fixture = fixture::Fixture::bind(dir.path(), "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let names = || {
            let mut names = fs::read_dir(dir.path())
                .unwrap()
                .map(|e| e.unwrap().file_name())
                .collect::<Vec<_>>();
            names.sort();
            names
        };
        let before = names();
        let mut command = proof_client();
        command
            .arg("--data-dir")
            .arg(dir.path())
            .args([
                "serve",
                "--listen",
                "127.0.0.1:0",
                "--server-name",
                "localhost",
            ])
            .arg("--cert")
            .arg(dir.path().join("verifier.pem"))
            .arg("--key")
            .arg(dir.path().join("verifier.key"))
            .arg("--metadata-output")
            .arg(dir.path().join("metadata.json"));
        let mut child = launch(command, true).await;
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let ready = readiness(&mut stdout, true).await;
        let address = ready["address"].as_str().unwrap();
        assert_eq!(names(), before);
        child.kill().await.unwrap();
        let socket = tokio::net::UdpSocket::bind(address).await.unwrap();
        assert_eq!(socket.local_addr().unwrap().to_string(), address);
        assert_eq!(names(), before);
        drop(fixture);
    })
    .await
    .unwrap();
}
