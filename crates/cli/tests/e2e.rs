#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test observations are direct"
)]
use proof_client::stdio::MAX_FRAME_BYTES;
use std::{
    io::{self, Write},
    process::Command,
};
mod support;
#[test]
fn subprocess_deadline_and_output_controls_fail_visibly() {
    for (scenario, expected) in [
        ("silence", io::ErrorKind::TimedOut),
        ("input", io::ErrorKind::TimedOut),
        ("stdout", io::ErrorKind::FileTooLarge),
        ("stderr", io::ErrorKind::FileTooLarge),
    ] {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--ignored",
                "--exact",
                "subprocess_failure_fixture",
                "--nocapture",
            ])
            .env("PROOF_CLIENT_PROCESS_CONTROL", scenario);
        let deadline = if matches!(scenario, "silence" | "input") {
            1
        } else {
            10
        };
        let result = if scenario == "input" {
            support::exchange(
                &mut command,
                std::time::Duration::from_secs(deadline),
                Some(&vec![0; 2 * MAX_FRAME_BYTES]),
                true,
            )
        } else {
            support::run(&mut command, std::time::Duration::from_secs(deadline))
        };
        assert_eq!(result.unwrap_err().kind(), expected);
    }
}

#[test]
#[ignore = "executed as a child by the subprocess negative controls"]
fn subprocess_failure_fixture() {
    let scenario = std::env::var("PROOF_CLIENT_PROCESS_CONTROL").unwrap();
    match scenario.as_str() {
        "silence" | "input" => loop {
            std::thread::park();
        },
        "stdout" => {
            let _ = io::stdout().write_all(&vec![b'x'; 2 * MAX_FRAME_BYTES]);
        }
        "stderr" => {
            let _ = io::stderr().write_all(&vec![b'x'; 2 * MAX_FRAME_BYTES]);
        }
        _ => unreachable!("control case is selected by its parent test"),
    }
}

#[path = "../../../examples/merkle/support/merkle.rs"]
#[allow(dead_code)]
mod merkle;
use serde_json::{Value, json};
use std::{fs, path::Path};

#[derive(Clone, Copy)]
enum Launch {
    Cli,
    Native,
}
fn exchange(mode: Launch, args: &[&str]) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_proof-client"));
    let input = match mode {
        Launch::Cli => {
            command.args(args);
            None
        }
        Launch::Native => {
            command.arg("chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/");
            let mut input = Vec::new();
            let request = json!({"protocol":proof_client::stdio::PROTOCOL,"args":args});
            proof_client::stdio::write_frame(&mut input, &request).unwrap();
            // A second invocation must not run, even while stdin remains open.
            proof_client::stdio::write_frame(&mut input, &request).unwrap();
            Some(input)
        }
    };
    support::exchange(
        &mut command,
        std::time::Duration::from_secs(600),
        input.as_deref(),
        false,
    )
    .unwrap()
}
fn event(mode: Launch, output: &[u8]) -> Value {
    let bytes = match mode {
        Launch::Cli => output.to_vec(),
        Launch::Native => {
            let mut cursor = io::Cursor::new(output);
            let bytes = proof_client::stdio::read_frame(&mut cursor).unwrap();
            assert_eq!(cursor.position() as usize, output.len());
            bytes
        }
    };
    serde_json::from_slice(&bytes).unwrap()
}
fn call(mode: Launch, args: &[&str]) -> Value {
    let output = exchange(mode, args);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let event = event(mode, &output.stdout);
    assert_eq!(event["event"], "completed", "{event}");
    event["result"].clone()
}
fn square() -> (Value, Value, Value) {
    (
        json!({"format":proof_client_core::proof::FORMAT,"inputs":{"public":1,"private":1},"operations":[{"op":"mul","left":1,"right":1}],"constraints":[{"op":"equal","left":0,"right":2}]}),
        json!([49]),
        json!({"private":[7],"proofs":[]}),
    )
}
fn inputs(dir: &Path, job: &(Value, Value, Value)) {
    for (name, value) in [
        ("circuit.json", &job.0),
        ("public.json", &job.1),
        ("witness.json", &job.2),
    ] {
        fs::write(dir.join(name), serde_json::to_vec_pretty(value).unwrap()).unwrap();
    }
}

fn prove(mode: Launch, dir: &Path, path: &Path) -> Value {
    let circuit = dir.join("circuit.json");
    let public = dir.join("public.json");
    let witness = dir.join("witness.json");
    let args = vec![
        "prove",
        "--circuit",
        circuit.to_str().unwrap(),
        "--public",
        public.to_str().unwrap(),
        "--witness",
        witness.to_str().unwrap(),
        "--threads",
        "4",
        "--output",
        path.to_str().unwrap(),
    ];
    call(mode, &args)
}
fn verify(mode: Launch, dir: &Path, path: &Path) -> Value {
    let circuit = dir.join("circuit.json");
    let public = dir.join("public.json");
    let args = vec![
        "verify",
        "--circuit",
        circuit.to_str().unwrap(),
        "--public",
        public.to_str().unwrap(),
        "--proof",
        path.to_str().unwrap(),
        "--threads",
        "1",
    ];
    call(mode, &args)
}
#[test]
fn ambiguous_inputs_are_rejected_without_publishing() {
    for mode in [Launch::Cli, Launch::Native] {
        let dir = tempfile::tempdir().unwrap();
        inputs(dir.path(), &square());
        fs::write(
            dir.path().join("public.json"),
            serde_json::to_vec_pretty(&[49, 50]).unwrap(),
        )
        .unwrap();
        let path = dir.path().join("proof.json");
        let output = exchange(
            mode,
            &[
                "prove",
                "--circuit",
                dir.path().join("circuit.json").to_str().unwrap(),
                "--public",
                dir.path().join("public.json").to_str().unwrap(),
                "--witness",
                dir.path().join("witness.json").to_str().unwrap(),
                "--output",
                path.to_str().unwrap(),
            ],
        );
        match mode {
            Launch::Cli => {
                assert!(!output.status.success());
                assert!(output.stdout.is_empty());
            }
            Launch::Native => assert_eq!(event(mode, &output.stdout)["event"], "failed"),
        }
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 3);
    }
}
#[test]
fn both_launches_publish_and_verify_proofs() {
    for mode in [Launch::Cli, Launch::Native] {
        let job = square();
        {
            let dir = tempfile::tempdir().unwrap();
            inputs(dir.path(), &job);
            let path = dir.path().join("proof.json");
            let metadata_path = dir.path().join("metadata.json");
            let prepared = call(
                mode,
                &[
                    "prepare",
                    "--circuit",
                    dir.path().join("circuit.json").to_str().unwrap(),
                    "--output",
                    metadata_path.to_str().unwrap(),
                    "--threads",
                    "4",
                ],
            );
            let metadata: Value =
                serde_json::from_slice(&fs::read(&metadata_path).unwrap()).unwrap();
            assert_eq!(prepared["metadata"], metadata);
            let receipt = prove(mode, dir.path(), &path);
            assert_eq!(receipt["circuit_id"], metadata["circuit_id"]);
            let bytes = fs::read(&path).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::{PermissionsExt, symlink};
                assert_eq!(
                    fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                    0o600
                );
                let alias = dir.path().join("alias.json");
                symlink(&path, &alias).unwrap();
                let result = proof_client::app::invoke(
                    vec![
                        "prove".into(),
                        "--circuit".into(),
                        dir.path().join("circuit.json").to_str().unwrap().into(),
                        "--public".into(),
                        dir.path().join("public.json").to_str().unwrap().into(),
                        "--witness".into(),
                        dir.path().join("witness.json").to_str().unwrap().into(),
                        "--output".into(),
                        alias.to_str().unwrap().into(),
                    ],
                    |_| Ok(()),
                );
                assert!(matches!(
                    result,
                    Err(proof_client::app::CliError::Files(
                        proof_client::FileError::Output
                    ))
                ));
                assert_eq!(fs::read(&path).unwrap(), bytes);
                fs::remove_file(alias).unwrap();
            }

            assert_eq!(
                receipt["output"],
                path.canonicalize().unwrap().to_str().unwrap()
            );
            assert_eq!(receipt["public"], job.1);
            assert_eq!(
                verify(mode, dir.path(), &path),
                json!({"circuit_id":receipt["circuit_id"],"public":job.1})
            );
            assert!(
                proof_client::app::invoke(
                    vec![
                        "prove".into(),
                        "--circuit".into(),
                        dir.path().join("circuit.json").to_str().unwrap().into(),
                        "--public".into(),
                        dir.path().join("public.json").to_str().unwrap().into(),
                        "--witness".into(),
                        dir.path().join("witness.json").to_str().unwrap().into(),
                        "--output".into(),
                        path.to_str().unwrap().into()
                    ],
                    |_| Ok(())
                )
                .is_err()
            );
            assert_eq!(fs::read(path).unwrap(), bytes);
            assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 5);
        }
    }
}
#[test]
fn referenced_circuits_use_the_generic_cli() {
    let dir = tempfile::tempdir().unwrap();
    for name in [
        "base.json",
        "merge-bases.json",
        "merge-recursive.json",
        "merge-verifier.json",
    ] {
        fs::copy(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../examples/merkle")
                .join(name),
            dir.path().join(name),
        )
        .unwrap();
    }
    let metadata_path = dir.path().join("metadata.json");
    call(
        Launch::Cli,
        &[
            "prepare",
            "--circuit",
            dir.path().join("merge-recursive.json").to_str().unwrap(),
            "--output",
            metadata_path.to_str().unwrap(),
            "--threads",
            "4",
        ],
    );
    let metadata: proof_client_core::proof::Metadata =
        serde_json::from_slice(&fs::read(&metadata_path).unwrap()).unwrap();
    let mut proofs = Vec::new();
    for index in 0..2 {
        let (public, private) = merkle::leaf(index);
        let source =
            serde_json::from_slice(&fs::read(dir.path().join("base.json")).unwrap()).unwrap();
        inputs(
            dir.path(),
            &(
                source,
                json!(public),
                json!({"private":private,"proofs":[]}),
            ),
        );
        let path = dir.path().join(format!("leaf-{index}.proof.json"));
        prove(Launch::Cli, dir.path(), &path);
        proofs.push(serde_json::from_slice::<Value>(&fs::read(path).unwrap()).unwrap());
    }
    let public = merkle::expected(1)
        .into_iter()
        .chain(*metadata.circuits()[Path::new("base.json")].words())
        .chain(*metadata.verifier_sets()[Path::new("merge-verifier.json")].words())
        .collect::<Vec<_>>();
    // Preserve the referenced member's identity while exercising the native launch.
    fs::write(
        dir.path().join("public.json"),
        serde_json::to_vec_pretty(&public).unwrap(),
    )
    .unwrap();
    fs::write(
        dir.path().join("witness.json"),
        serde_json::to_vec_pretty(&json!({"private":[],"proofs":proofs})).unwrap(),
    )
    .unwrap();
    let proof = dir.path().join("merged.proof.json");
    let source = dir.path().join("merge-bases.json");
    let statement = dir.path().join("public.json");
    let witness = dir.path().join("witness.json");
    let receipt = call(
        Launch::Native,
        &[
            "prove",
            "--circuit",
            source.to_str().unwrap(),
            "--public",
            statement.to_str().unwrap(),
            "--witness",
            witness.to_str().unwrap(),
            "--output",
            proof.to_str().unwrap(),
            "--threads",
            "4",
        ],
    );
    let verified = call(
        Launch::Native,
        &[
            "verify",
            "--circuit",
            source.to_str().unwrap(),
            "--public",
            statement.to_str().unwrap(),
            "--proof",
            proof.to_str().unwrap(),
            "--threads",
            "1",
        ],
    );
    assert_eq!(receipt["public"], json!(public));
    assert_eq!(verified["public"], json!(public));
    assert_eq!(
        receipt["circuit_id"],
        json!(metadata.circuits()[Path::new("merge-bases.json")])
    );
    let artifact: Value = serde_json::from_slice(&fs::read(&proof).unwrap()).unwrap();
    assert_eq!(artifact["public"], json!(public));
    assert_eq!(verified["circuit_id"], artifact["circuit_id"]);
}

#[test]
fn source_loading_resolves_relative_aliases_and_bounds_the_graph() {
    use proof_client_core::proof::{MAX_INPUT_BYTES, MAX_SOURCES};
    for case in ["relative", "missing", "cycle", "count", "bytes"] {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("nested")).unwrap();
        let verify = |path: &str, proof: usize| json!({"op":"verify","verifier":path,"proof":proof,"circuit_id_wires":[0,1,2,3,4,5,6,7]});
        let mut source = json!({"format":proof_client_core::proof::FORMAT,"inputs":{"public":8,"private":0},"operations":[],"constraints":[]});
        let mut child = source.clone();
        source["operations"] = json!([verify("nested/child.json", 0)]);
        match case {
            "relative" => {
                child["operations"] = json!([
                    verify("../leaf.json", 0),
                    verify("../nested/../leaf.json", 1)
                ]);
                fs::write(
                    dir.path().join("leaf.json"),
                    serde_json::to_vec_pretty(&square().0).unwrap(),
                )
                .unwrap();
            }
            "missing" => child["operations"] = json!([verify("missing.json", 0)]),
            "cycle" => child["operations"] = json!([verify("../circuit.json", 0)]),
            "count" => {
                let mut calls = Vec::new();
                for index in 0..MAX_SOURCES {
                    let name = format!("{index}.json");
                    fs::write(
                        dir.path().join(&name),
                        serde_json::to_vec_pretty(&square().0).unwrap(),
                    )
                    .unwrap();
                    calls.push(verify(&name, index));
                }
                source["operations"] = json!(calls);
            }
            "bytes" => {}
            _ => unreachable!(),
        }
        for (name, value) in [("circuit.json", source), ("nested/child.json", child)] {
            let mut bytes = serde_json::to_vec_pretty(&value).unwrap();
            if case == "bytes" {
                bytes.resize(MAX_INPUT_BYTES / 2 + 1, b' ');
            }
            fs::write(dir.path().join(name), bytes).unwrap();
        }
        let paths = [
            dir.path().join("circuit.json"),
            dir.path().join("metadata.json"),
        ];
        let result = proof_client::app::invoke(
            vec![
                "prepare".into(),
                "--circuit".into(),
                paths[0].to_str().unwrap().into(),
                "--output".into(),
                paths[1].to_str().unwrap().into(),
                "--threads".into(),
                "1".into(),
            ],
            |_| Ok(()),
        );
        if case == "relative" {
            let result = result.unwrap();
            let metadata: Value = serde_json::from_slice(&fs::read(&paths[1]).unwrap()).unwrap();
            assert_eq!(result["metadata"], metadata);
            let circuits = metadata["circuits"].as_object().unwrap();
            assert_eq!(circuits.len(), 3);
            for path in ["circuit.json", "nested/child.json", "leaf.json"] {
                assert!(circuits.contains_key(path));
            }
        } else {
            if matches!(case, "count" | "bytes") {
                assert!(
                    matches!(
                        result,
                        Err(proof_client::app::CliError::Files(
                            proof_client::FileError::Limit
                        ))
                    ),
                    "{case}: {result:?}"
                );
            } else {
                assert!(result.is_err(), "{case}");
            }
            assert!(!paths[1].exists());
        }
    }
}
