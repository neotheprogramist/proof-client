#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "public CLI workflow"
)]
use serde_json::{Value, json};
use std::{fs, process::Stdio};
use tokio::io::AsyncWriteExt;
mod support;

#[tokio::test]
async fn prepare_prove_verify_and_native_verify() {
    let dir = tempfile::tempdir().unwrap();
    let circuit = dir.path().join("circuit.json");
    let public = dir.path().join("public.json");
    let witness = dir.path().join("witness.json");
    let metadata = dir.path().join("metadata.json");
    let proof = dir.path().join("proof.json");
    fs::write(
        &circuit,
        serde_json::to_vec(&json!({
            "format":proof_client_core::proof::FORMAT,
            "inputs":{"public":1,"private":1},
            "operations":[{"op":"mul","left":1,"right":1}],
            "constraints":[{"op":"equal","left":0,"right":2}]
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(&public, b"[49]").unwrap();
    fs::write(&witness, br#"{"private":[7],"proofs":[]}"#).unwrap();

    for args in [
        vec![
            "prepare",
            "--circuit",
            circuit.to_str().unwrap(),
            "--output",
            metadata.to_str().unwrap(),
        ],
        vec![
            "prove",
            "--circuit",
            circuit.to_str().unwrap(),
            "--public",
            public.to_str().unwrap(),
            "--witness",
            witness.to_str().unwrap(),
            "--output",
            proof.to_str().unwrap(),
        ],
    ] {
        let output =
            support::output(support::command().args(["--format", "json"]).args(args)).await;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let event: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(event["event"], "completed");
    }
    let prepared: Value = serde_json::from_slice(&fs::read(&metadata).unwrap()).unwrap();
    let saved = fs::read(&proof).unwrap();
    let artifact: Value = serde_json::from_slice(&saved).unwrap();
    assert_eq!(artifact["circuit_id"], prepared["circuit_id"]);
    assert_eq!(artifact["public"], json!([49]));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&proof).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let args = [
        "verify",
        "--circuit",
        circuit.to_str().unwrap(),
        "--public",
        public.to_str().unwrap(),
        "--proof",
        proof.to_str().unwrap(),
    ];
    let output = support::output(support::command().args(args)).await;
    assert!(output.status.success());
    let report = String::from_utf8(output.stdout).unwrap();
    assert!(report.contains("Public words: [49]"));

    let mut host = support::command()
        .arg("chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/")
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = Vec::new();
    for _ in 0..2 {
        proof_client::stdio::write_frame(
            &mut input,
            &json!({"protocol":proof_client::stdio::PROTOCOL,"args":args}),
        )
        .unwrap();
    }
    let mut stdin = host.stdin.take().unwrap();
    stdin.write_all(&input).await.unwrap();
    let output = support::finish(host).await;
    drop(stdin);
    assert!(output.status.success());
    let mut frames = std::io::Cursor::new(&output.stdout);
    let event: Value =
        serde_json::from_slice(&proof_client::stdio::read_frame(&mut frames).unwrap()).unwrap();
    assert_eq!(event["event"], "completed");
    assert_eq!(event["result"], report);
    assert_eq!(frames.position() as usize, output.stdout.len());

    let output = support::output(
        support::command()
            .args(["prove", "--circuit"])
            .arg(&circuit)
            .arg("--public")
            .arg(&public)
            .arg("--witness")
            .arg(&witness)
            .arg("--output")
            .arg(&proof),
    )
    .await;
    assert!(!output.status.success());
    assert_eq!(fs::read(&proof).unwrap(), saved);
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 5);
}
