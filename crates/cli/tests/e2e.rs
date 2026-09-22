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
fn square() -> (Value, Value) {
    (
        json!({"format":"proof-client/circuit/1","inputs":{"public":1,"private":1},"operations":[{"op":"mul","left":1,"right":1}],"constraints":[{"op":"equal","left":0,"right":2}]}),
        json!({"public":[49],"private":[7],"proofs":[]}),
    )
}
fn inputs(dir: &Path, job: &(Value, Value)) {
    for (name, value) in [("circuit.json", &job.0), ("witness.json", &job.1)] {
        fs::write(dir.join(name), serde_json::to_vec(value).unwrap()).unwrap();
    }
}

fn prove(mode: Launch, dir: &Path, path: &Path) -> Value {
    call(
        mode,
        &[
            "prove",
            "--circuit",
            dir.join("circuit.json").to_str().unwrap(),
            "--witness",
            dir.join("witness.json").to_str().unwrap(),
            "--threads",
            "4",
            "--output",
            path.to_str().unwrap(),
        ],
    )
}
fn verify(mode: Launch, dir: &Path, path: &Path) -> Value {
    call(
        mode,
        &[
            "verify",
            "--circuit",
            dir.join("circuit.json").to_str().unwrap(),
            "--proof",
            path.to_str().unwrap(),
            "--threads",
            "1",
        ],
    )
}
#[test]
fn ambiguous_inputs_are_rejected_without_publishing() {
    for mode in [Launch::Cli, Launch::Native] {
        for (file, old, new) in [
            (
                "circuit.json",
                r#""format":"proof-client/circuit/1""#,
                r#""format":"unsupported","format":"proof-client/circuit/1""#,
            ),
            (
                "circuit.json",
                r#""private":1"#,
                r#""private":2,"private":1"#,
            ),
            (
                "witness.json",
                r#""public":[49]"#,
                r#""public":[50],"public":[49]"#,
            ),
            (
                "witness.json",
                r#""private":[7]"#,
                r#""private":[8],"private":[7]"#,
            ),
        ] {
            let dir = tempfile::tempdir().unwrap();
            inputs(dir.path(), &square());
            let text = fs::read_to_string(dir.path().join(file)).unwrap();
            let invalid = text.replacen(old, new, 1);
            assert_ne!(text, invalid);
            fs::write(dir.path().join(file), invalid).unwrap();
            let path = dir.path().join("proof.json");
            let output = exchange(
                mode,
                &[
                    "prove",
                    "--circuit",
                    dir.path().join("circuit.json").to_str().unwrap(),
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
            assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
        }
    }
}
#[test]
fn both_launches_publish_and_verify_direct_and_family_proofs() {
    let mut source: Value =
        serde_json::from_slice(include_bytes!("../../../examples/merkle/family.json")).unwrap();
    source["entry"] = json!("base");
    let family = (source, merkle::leaf(0));
    for mode in [Launch::Cli, Launch::Native] {
        for job in [square(), family.clone()] {
            let dir = tempfile::tempdir().unwrap();
            inputs(dir.path(), &job);
            let path = dir.path().join("proof.json");
            let receipt = prove(mode, dir.path(), &path);
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
            assert_eq!(receipt["public"], job.1["public"]);
            assert_eq!(
                verify(mode, dir.path(), &path),
                json!({"circuit":receipt["circuit"],"public":job.1["public"]})
            );
            assert!(
                proof_client::app::invoke(
                    vec![
                        "prove".into(),
                        "--circuit".into(),
                        dir.path().join("circuit.json").to_str().unwrap().into(),
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
            assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 3);
        }
    }
}
#[test]
fn independent_subtrees_use_the_same_generic_cli() {
    tree(1);
}
#[test]
#[ignore = "bounded eight-leaf direct recursion CLI diagnostic"]
fn eight_leaf_admission() {
    tree(merkle::MAX_HEIGHT);
}
fn tree(height: u32) {
    let dir = tempfile::tempdir().unwrap();
    let mut level = Vec::new();
    let mut last = (Value::Null, Value::Null);
    let mut last_path = dir.path().join("unused");
    let mut node = |job: (Value, Value), name: String| {
        inputs(dir.path(), &job);
        let path = dir.path().join(name);
        let receipt = prove(Launch::Cli, dir.path(), &path);
        let proof: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(receipt["public"], job.1["public"]);
        assert_eq!(proof["public"], job.1["public"]);
        assert_eq!(
            proof["proof"]["non_primitives"]
                .as_array()
                .unwrap()
                .iter()
                .map(|table| table["public_values"].as_array().unwrap().len())
                .sum::<usize>(),
            9
        );
        last = job;
        last_path = path;
        proof
    };
    for index in 0..1 << height {
        level.push(node(
            (merkle::circuit(0), merkle::leaf(index)),
            format!("0-{index}.json"),
        ));
    }
    for current in 1..=height {
        level = level
            .as_chunks::<2>()
            .0
            .iter()
            .enumerate()
            .map(|(index, pair)| {
                node(
                    merkle::parent(current, pair[0].clone(), pair[1].clone()).unwrap(),
                    format!("{current}-{index}.json"),
                )
            })
            .collect();
    }
    assert_eq!(last.1["public"], json!(merkle::expected(height)));
    assert_eq!(
        verify(Launch::Cli, dir.path(), &last_path)["public"],
        last.1["public"]
    );
    assert_eq!(
        fs::read_dir(dir.path()).unwrap().count(),
        2 * (1 << height) + 1
    );
}
