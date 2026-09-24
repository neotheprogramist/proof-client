#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test observations are direct"
)]
#[path = "../../../examples/mbank/support/fixture.rs"]
mod fixture;
use serde_json::{Value, json};
use std::{
    fs,
    process::{Output, Stdio},
};
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

async fn finish(mut child: Child, stdout: impl AsyncRead + Unpin) -> Output {
    let stderr = child.stderr.take();
    let (status, stdout, stderr) = tokio::join!(child.wait(), bounded(stdout), async {
        match stderr {
            Some(stderr) => bounded(stderr).await,
            None => Vec::new(),
        }
    });
    Output {
        status: status.unwrap(),
        stdout,
        stderr,
    }
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
    let mut child = Command::new(env!("CARGO_BIN_EXE_proof-client"))
        .arg("chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
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
async fn readiness(reader: &mut BufReader<tokio::process::ChildStdout>, native: bool) -> Value {
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
        reader.read_line(&mut line).await.unwrap();
        serde_json::from_str(&line).unwrap()
    }
}
fn terminal_event(bytes: &[u8], native: bool) -> Value {
    if native {
        let mut cursor = std::io::Cursor::new(bytes);
        let frame = proof_client::stdio::read_frame(&mut cursor).unwrap();
        assert_eq!(cursor.position() as usize, bytes.len());
        serde_json::from_slice(&frame).unwrap()
    } else {
        serde_json::from_slice(bytes).unwrap()
    }
}

#[tokio::test]
async fn native_quic_attestation_binds_identity_session_and_disclosure() {
    #[derive(Clone, Copy, Debug)]
    enum Case {
        Body,
        Fields,
        Bytes,
        Empty,
        SentOnly,
        MixedStartLine,
        ReceiveLimit,
        ExcessResponse,
        WrongVerifier,
        WrongTarget,
        WrongSession,
        WrongTrust,
        Collision,
    }
    for (case, native) in [
        (Case::Body, false),
        (Case::Fields, true),
        (Case::Bytes, true),
        (Case::Empty, true),
        (Case::SentOnly, false),
        (Case::MixedStartLine, true),
        (Case::ReceiveLimit, false),
        (Case::ExcessResponse, false),
        (Case::WrongVerifier, false),
        (Case::WrongTarget, false),
        (Case::WrongSession, true),
        (Case::WrongTrust, false),
        (Case::Collision, false),
    ] {
        let verifier_name = if matches!(case, Case::WrongVerifier) {
            "wrong.invalid"
        } else {
            "localhost"
        };
        let expected_target = if matches!(case, Case::WrongTarget) {
            "wrong.invalid"
        } else {
            "localhost"
        };
        let session = if matches!(case, Case::WrongSession) {
            "other"
        } else {
            "manual"
        };
        let target_ca = if matches!(case, Case::WrongTrust) {
            "verifier.pem"
        } else {
            "target.pem"
        };
        let success = matches!(
            case,
            Case::Body
                | Case::Fields
                | Case::Bytes
                | Case::Empty
                | Case::SentOnly
                | Case::ReceiveLimit
        );
        let collision = matches!(case, Case::Collision);
        let started = std::time::Instant::now();
        eprintln!("CASE {case:?} native={native}");
        tokio::time::timeout(
            proof_client_core::tls::attest::SESSION_TIMEOUT + std::time::Duration::from_secs(10),
            async {
                let dir = tempfile::tempdir().unwrap();
                let fixture = fixture::Fixture::bind(dir.path(), "127.0.0.1:0".parse().unwrap())
                    .await
                    .unwrap();
                let target = fixture.address().unwrap();
                let report_path = dir.path().join("verified.json");
                let receipt_path = dir.path().join("receipt.json");
                let mut verifier_command = Command::new(env!("CARGO_BIN_EXE_proof-client"));
                verifier_command
                    .args([
                        "serve",
                        "--listen",
                        "127.0.0.1:0",
                        "--server-name",
                        expected_target,
                        "--session",
                        "manual",
                    ])
                    .arg("--cert")
                    .arg(dir.path().join("verifier.pem"))
                    .arg("--key")
                    .arg(dir.path().join("verifier.key"))
                    .arg("--target-ca")
                    .arg(dir.path().join(target_ca))
                    .arg("--output")
                    .arg(&report_path)
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .kill_on_drop(true);
                let mut verifier = launch(verifier_command, native).await;
                let mut stdout = BufReader::new(verifier.stdout.take().unwrap());
                let ready = readiness(&mut stdout, native).await;
                assert_eq!(ready["event"], "ready");
                let address = ready["address"].as_str().unwrap();
                assert_eq!(fs::read_dir(dir.path()).unwrap().count(),4,"waiting for a peer creates no temporary log");
                if collision { fs::write(&report_path, b"another writer").unwrap(); }
                let request_path = dir.path().join("request.json");
                fs::write(&request_path,serde_json::to_vec_pretty(&json!({"method":"POST","url":format!("https://localhost:{}/balance",target.port()),"headers":[["content-type","application/json"],["cookie","SECRET"]],"body_base64":"e30="})).unwrap()).unwrap();
                let response_bytes=if matches!(case, Case::ReceiveLimit | Case::ExcessResponse) {
                    let mut bytes=b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n".to_vec();
                    bytes.extend_from_slice(fixture::BODY.as_bytes());
                    bytes.resize(proof_client_core::tls::attest::MAX_RECEIVED + usize::from(matches!(case, Case::ExcessResponse)), b' ');
                    bytes
                } else if matches!(case, Case::MixedStartLine) {
                    format!("HTTP/1.1 200 OK\nSet-Cookie: SECRET\r\n\r\n{}", fixture::BODY).into_bytes()
                } else { fixture::response() };
                let body_start=response_bytes.len()-fixture::BODY.len();
                let policy=match case {
                    Case::Fields | Case::Collision => serde_json::from_str::<Value>(fixture::DISCLOSURE).unwrap(),
                    Case::Bytes => json!({"sent":[{"bytes":[0,1]},{"bytes":[2,3]}],"received":(body_start..response_bytes.len()).step_by(2).map(|i|json!({"bytes":[i,i+1]})).collect::<Vec<_>>()}),
                    Case::Empty | Case::ReceiveLimit | Case::ExcessResponse => json!({"sent":[],"received":[]}),
                    Case::MixedStartLine => json!({"sent":[],"received":["start_line"]}),
                    Case::SentOnly => json!({"sent":[{"bytes":[0,1]},{"bytes":[2,3]}],"received":[]}),
                    Case::Body | Case::WrongVerifier | Case::WrongTarget | Case::WrongSession | Case::WrongTrust => json!({"sent":[],"received":["body"]}),
                };
                fs::write(dir.path().join("disclosure.json"),serde_json::to_vec_pretty(&policy).unwrap()).unwrap();
                let mut client_command = Command::new(env!("CARGO_BIN_EXE_proof-client"));
                client_command
                    .args([
                        "attest",
                        "--verifier",
                        address,
                        "--verifier-name",
                        verifier_name,
                        "--session",
                        session,
                    ])
                    .arg("--verifier-ca")
                    .arg(dir.path().join("verifier.pem"))
                    .arg("--target-ca")
                    .arg(dir.path().join(target_ca))
                    .arg("--disclosure").arg(dir.path().join("disclosure.json"))
                    .arg("--request").arg(&request_path)
                    .arg("--output").arg(&receipt_path)
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .kill_on_drop(true);
                let mut client = launch(client_command, native).await;
                let client_stdout = client.stdout.take().unwrap();
                let client = async {
                    let output = finish(client, client_stdout).await;
                    assert_eq!(output.status.success(), native || success, "{case:?}: {}", String::from_utf8_lossy(&output.stderr));
                    if native { assert_eq!(terminal_event(&output.stdout, true)["event"], if success { "completed" } else { "failed" }); }
                    output
                };
                let peers = async { tokio::join!(client, finish(verifier, stdout)) };
                tokio::pin!(peers);
                let target = fixture.serve(&response_bytes);
                tokio::pin!(target);
                let ((client, verifier), request) = tokio::select! {
                    biased;
                    request = &mut target => (peers.await, request.ok()),
                    peers = &mut peers => (peers, None),
                };
                let verifier_errors = String::from_utf8_lossy(&verifier.stderr);
                assert_eq!(verifier.status.success(), native || success, "{verifier_errors}");
                assert!(!String::from_utf8_lossy(&client.stderr).contains("SECRET"));
                assert!(!verifier_errors.contains("SECRET"));
                assert_eq!(report_path.exists(), success || collision);
                if collision { assert_eq!(fs::read(&report_path).unwrap(), b"another writer"); }
                assert_eq!(receipt_path.exists(), success);
                if success {
                    let receipt: Value =
                        serde_json::from_slice(&fs::read(&receipt_path).unwrap()).unwrap();
                    let verified: Value =
                        serde_json::from_slice(&fs::read(&report_path).unwrap()).unwrap();
                    assert_eq!(receipt["receipt"], verified);
                    let response = receipt["response"].as_array().unwrap().iter().map(|byte|byte.as_u64().unwrap() as u8).collect::<Vec<_>>();
                    assert!(String::from_utf8(response).unwrap().contains("PRIVATE"));
                    let receipt = &receipt["receipt"];
                    assert_eq!(receipt["session"], "manual");
                    assert_eq!(receipt["report"]["kind"], "live-verifier-accepted");
                    assert_eq!(receipt["report"]["server_name"], "localhost");
                    assert_eq!(receipt["report"]["received_len"], response_bytes.len());
                    assert_eq!(receipt["report"]["sent"], if matches!(case, Case::Bytes | Case::SentOnly) {json!([{"start":0,"bytes":[80]},{"start":2,"bytes":[83]}])} else {json!([])});
                    let disclosed = receipt["report"]["received"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .flat_map(|range| {
                            range["bytes"]
                                .as_array()
                                .unwrap()
                                .iter()
                                .map(|b| b.as_u64().unwrap() as u8)
                        })
                        .collect::<Vec<_>>();
                    let expected=match case {
                        Case::Fields => br#""AvailableBalance":42.1200"currency":"PLN""#.to_vec(),
                        Case::Body => fixture::BODY.as_bytes().to_vec(),
                        Case::Bytes => fixture::BODY.bytes().step_by(2).collect(),
                        Case::Empty | Case::SentOnly | Case::ReceiveLimit => Vec::new(),
                        Case::WrongVerifier | Case::WrongTarget | Case::WrongSession | Case::WrongTrust | Case::Collision | Case::ExcessResponse | Case::MixedStartLine => unreachable!(),
                    };
                    assert_eq!(disclosed,expected);
                    let request = String::from_utf8(request.unwrap()).unwrap();
                    assert!(request.starts_with("POST /balance HTTP/1.1\r\n"));
                    assert!(request.contains("cookie: SECRET\r\n"));
                    assert!(request.contains("accept-encoding: identity\r\n"));
                    assert!(request.ends_with("\r\n\r\n{}"));
                    for (output, path) in [
                        (&client.stdout, &receipt_path),
                        (&verifier.stdout, &report_path),
                    ] {
                        #[cfg(unix)] {
                            use std::os::unix::fs::PermissionsExt;
                            assert_eq!(fs::metadata(path).unwrap().permissions().mode() & 0o777,0o600);
                        }
                        let published = terminal_event(output, native);
                        assert_eq!(published["event"],"completed");
                        assert_eq!(
                            published["result"]["output"],
                            path.canonicalize().unwrap().to_str().unwrap()
                        );
                    }
                    assert!(client.stderr.is_empty());
                    assert!(verifier_errors.is_empty());
                } else {
                    for output in [&client, &verifier] {
                        if native {
                            let event = terminal_event(&output.stdout, true);
                            assert_eq!(event["event"], "failed");
                            assert!(!event.to_string().contains("SECRET"));
                            assert!(output.stderr.is_empty());
                        } else {
                            assert!(!output.stderr.is_empty());
                            assert!(output.stdout.is_empty());
                        }
                    }
                    assert_eq!(
                        fs::read_dir(dir.path()).unwrap().count(),
                        if collision { 6 } else { 5 },
                        "no partial output or temporary files"
                    );
                }
            },
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
        let mut command = Command::new(env!("CARGO_BIN_EXE_proof-client"));
        command
            .args([
                "serve",
                "--listen",
                "127.0.0.1:0",
                "--server-name",
                "localhost",
                "--session",
                "cancel",
            ])
            .arg("--cert")
            .arg(dir.path().join("verifier.pem"))
            .arg("--key")
            .arg(dir.path().join("verifier.key"))
            .arg("--output")
            .arg(dir.path().join("verified.json"))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
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
