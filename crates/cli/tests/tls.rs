#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "public TLS workflow"
)]
#[path = "../../../examples/mbank/support/fixture.rs"]
mod fixture;
mod support;
use serde_json::{Value, json};
use std::fs;
use tlsn::{
    hash::HashProvider,
    transcript::{
        Direction, Transcript, TranscriptCommitment, TranscriptProofBuilder, TranscriptSecret,
    },
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};

#[tokio::test]
async fn attest_disclose_open_and_inspect() {
    for hash in ["blake3", "poseidon2-koalabear-16-pad10-v1"] {
        let dir = tempfile::tempdir().unwrap();
        fixture::verifier_identity(&dir.path().join("identity")).unwrap();
        let target = fixture::Fixture::bind(dir.path(), "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let url = format!(
            "https://localhost:{}/balance",
            target.address().unwrap().port()
        );
        let private_path = dir.path().join("metadata.json");
        let public_path = dir.path().join("verified.json");
        let policy_path = dir.path().join("disclosure.json");
        fs::write(&policy_path, serde_json::to_vec(&json!({
            "reveal":{"sent":["start_line"],"received":["start_line",{"json":"/products/0/AvailableBalance"},{"json_key":"/products/0/number"}]},
            "commit":{"sent":[{"header":"x-proof"}],"received":[{"json_value":"/products/0/number"},{"json_value":"/products/0/currency"}]}
        })).unwrap()).unwrap();
        let mut serve = support::command();
        serve
            .args([
                "serve",
                "--listen",
                "127.0.0.1:0",
                "--server-name",
                "localhost",
            ])
            .arg("--data-dir")
            .arg(dir.path())
            .arg("--target-ca")
            .arg(dir.path().join("target.pem"))
            .arg("--metadata-output")
            .arg(&public_path);
        if hash == "blake3" {
            serve.args(["--commitment-hash", hash]);
        } else {
            serve.args(["--max-commitment-permutations", "12"]);
        }
        let mut verifier = serve.spawn().unwrap();
        let mut stderr = BufReader::new(verifier.stderr.take().unwrap());
        let address =
            tokio::time::timeout(proof_client_core::tls::attest::SESSION_TIMEOUT, async {
                loop {
                    let mut line = String::new();
                    assert_ne!(stderr.read_line(&mut line).await.unwrap(), 0);
                    if line.contains("event=\"ready\"") {
                        break line.split_once("address=").unwrap().1.trim().to_owned();
                    }
                }
            })
            .await
            .unwrap();
        let mut attest = support::command();
        attest
            .args(["attest", "--verifier", &address, "--url", &url])
            .arg("--data-dir")
            .arg(dir.path())
            .arg("--target-ca")
            .arg(dir.path().join("target.pem"))
            .arg("--disclosure")
            .arg(&policy_path)
            .arg("--metadata-output")
            .arg(&private_path)
            .args([
                "-H",
                "X-Proof: first",
                "-H",
                "Content-Type: application/json",
                "-H",
                "X-Proof: second",
                "-H",
                "Connection: close",
                "-b",
                "session=PRIVATE_COOKIE",
                "--data-raw",
                "{}",
            ]);
        if hash == "blake3" {
            attest.args(["--commitment-hash", hash]);
        }
        let client = attest.spawn().unwrap();
        let response = fixture::response();
        let mut log = Vec::new();
        let (client, verifier, request, drained) =
            tokio::time::timeout(proof_client_core::tls::attest::SESSION_TIMEOUT, async {
                tokio::join!(
                    support::finish(client),
                    support::finish(verifier),
                    target.serve(&response),
                    stderr.read_to_end(&mut log)
                )
            })
            .await
            .unwrap();
        drained.unwrap();
        for output in [&client, &verifier] {
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let request = request.unwrap();
        assert!(request.starts_with(b"POST /balance HTTP/1.1\r\n"));
        assert!(request.ends_with(b"\r\n\r\n{}"));
        let private: Value = serde_json::from_slice(&fs::read(&private_path).unwrap()).unwrap();
        let public: Value = serde_json::from_slice(&fs::read(&public_path).unwrap()).unwrap();
        let mut disclosed = private.clone();
        disclosed.as_object_mut().unwrap().remove("openings");
        disclosed.as_object_mut().unwrap().remove("selections");
        assert_eq!(disclosed, public);
        assert_eq!(public["server_name"], "localhost");
        assert_eq!(public["sent_len"], request.len());
        assert_eq!(public["received_len"], response.len());
        for (name, source, expected) in [
            ("sent", &request, b"POST /balance HTTP/1.1\r\n".as_slice()),
            (
                "received",
                &response,
                b"HTTP/1.1 200 OK\r\n\"AvailableBalance\":42.1200\"number\"".as_slice(),
            ),
        ] {
            let mut visible = Vec::new();
            for segment in public[name].as_array().unwrap() {
                let start = segment["start"].as_u64().unwrap() as usize;
                let bytes: Vec<u8> = serde_json::from_value(segment["bytes"].clone()).unwrap();
                assert_eq!(bytes, source[start..start + bytes.len()]);
                visible.extend(bytes);
            }
            assert_eq!(visible, expected);
        }
        let hashes: Vec<tlsn::transcript::hash::PlaintextHash> =
            serde_json::from_value(public["commitments"].clone()).unwrap();
        let expected_algorithm = if hash == "blake3" {
            tlsn::hash::HashAlgId::BLAKE3
        } else {
            tlsn::hash::HashAlgId::POSEIDON2_KOALABEAR_16_PAD10_V1
        };
        assert!(hashes.iter().all(|h| h.hash.alg == expected_algorithm));
        let openings = private["openings"].as_array().unwrap();
        assert_eq!(hashes.len(), 3);
        assert_eq!(openings.len(), hashes.len());
        let transcript = Transcript::new(request, response);
        let mut blinders = std::collections::HashSet::new();
        let mut plaintexts = Vec::new();
        for (index, opening) in openings.iter().enumerate() {
            let secret: TranscriptSecret =
                serde_json::from_value(opening["secret"].clone()).unwrap();
            let TranscriptSecret::Hash(secret_hash) = &secret else {
                unreachable!()
            };
            assert!(blinders.insert(secret_hash.blinder.as_bytes().to_vec()));
            let hash = hashes
                .iter()
                .find(|h| h.direction == secret_hash.direction && h.idx == secret_hash.idx)
                .unwrap();
            let mut builder = TranscriptProofBuilder::new(&transcript, [&secret]);
            builder.reveal(&hash.idx, hash.direction).unwrap();
            let proof = builder.build().unwrap();
            let opened = proof
                .clone()
                .verify_with_provider(
                    &HashProvider::default(),
                    &transcript.length(),
                    [&TranscriptCommitment::Hash(hash.clone())],
                )
                .unwrap();
            if index == 0 {
                let mut changed = hash.clone();
                changed.hash.value = HashProvider::default()
                    .get(&changed.hash.alg)
                    .unwrap()
                    .hash(b"wrong opening");
                assert!(
                    proof
                        .verify_with_provider(
                            &HashProvider::default(),
                            &transcript.length(),
                            [&TranscriptCommitment::Hash(changed)]
                        )
                        .is_err()
                );
            }
            let (bytes, ranges) = match hash.direction {
                Direction::Sent => (opened.sent_unsafe(), opened.sent_authed()),
                Direction::Received => (opened.received_unsafe(), opened.received_authed()),
            };
            let plaintext: Vec<u8> = serde_json::from_value(opening["plaintext"].clone()).unwrap();
            assert_eq!(ranges, &hash.idx);
            assert_eq!(
                plaintext,
                ranges
                    .iter()
                    .flat_map(|r| bytes[r].to_vec())
                    .collect::<Vec<_>>()
            );
            plaintexts.push(plaintext);
        }
        let data = fixture::sample_data();
        for expected in [
            b"x-proof: first\r\nx-proof: second\r\n".to_vec(),
            br#""PLN""#.to_vec(),
            format!("\"{}\"", data.number).into_bytes(),
        ] {
            assert!(plaintexts.contains(&expected));
        }
        let prover = String::from_utf8(client.stdout).unwrap();
        let verified = String::from_utf8(verifier.stdout).unwrap();
        assert!(prover.contains("verifier receipt matched"));
        assert!(verified.contains("42.1200"));
        assert!(verified.contains("not established"));
        for secret in ["PRIVATE_COOKIE", &data.number, &data.response_cookie] {
            assert!(prover.contains(secret));
            assert!(!verified.contains(secret));
            assert!(!String::from_utf8_lossy(&client.stderr).contains(secret));
            assert!(!String::from_utf8_lossy(&log).contains(secret));
        }
        let inspected = support::output(support::command().arg("inspect").arg(&private_path)).await;
        assert!(
            inspected.status.success(),
            "{}",
            String::from_utf8_lossy(&inspected.stderr)
        );
        let text = String::from_utf8(inspected.stdout).unwrap();
        assert!(text.contains("live verification was not performed"));
        assert!(!text.contains(&data.number));
        assert_eq!(
            serde_json::from_slice::<Value>(&fs::read(&private_path).unwrap()).unwrap(),
            private
        );
    }
}
