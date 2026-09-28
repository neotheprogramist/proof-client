#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "public subprocess observations"
)]
use proptest::prelude::*;
use serde_json::{Value, json};
use std::{fs, path::Path, process::Command};
use tlsn::{
    hash::{Hash, HashAlgId, TypedHash},
    rangeset::set::RangeSet,
    transcript::{Direction, hash::PlaintextHash},
};

fn inspect(run: &Path, json: bool) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_proof-client"));
    command.arg("inspect").arg("--run").arg(run);
    if json {
        command.args(["--format", "json"]);
    }
    command.output().unwrap()
}
fn record(bytes: &[u8], hidden: usize) -> Value {
    let end = hidden + bytes.len();
    let commitment = PlaintextHash {
        direction: Direction::Received,
        idx: RangeSet::from(end..end + 5),
        hash: TypedHash {
            alg: HashAlgId::BLAKE3,
            value: Hash::try_from(vec![42; 32]).unwrap(),
        },
    };
    json!({
        "server_name":"localhost", "sent_len":0, "received_len":end + 12,
        "sent":[], "received":[{"start":hidden,"bytes":bytes}],
        "commitments":[commitment],
        "selections": {
            "sent": {"reveal":[], "commit":[]},
            "received": {
                "reveal":[{"selector":{"bytes":[hidden,end]}, "ranges":[{"start":hidden,"end":end}]}],
                "commit":[{"selector":{"bytes":[end,end+5]}, "ranges":[{"start":end,"end":end+5}]}]
            }
        },
        "openings":[{"plaintext":"PRIVATE_OPENING","blinder":"PRIVATE_BLINDER"}],
        "future_field":"durable records admit additional fields"
    })
}
proptest! {
    #![proptest_config(ProptestConfig::with_cases(12))]
    #[test]
    fn inspection_preserves_evidence_without_claiming_verification(
        bytes in prop::collection::vec(any::<u8>(), 1..80), hidden in 1usize..60,
    ) {
        let dir = tempfile::tempdir().unwrap();
        // Enumerate control bytes on every case; the vector strategy shrinks extra data.
        let bytes = (0..=255).chain(bytes).collect::<Vec<_>>();
        let saved = record(&bytes, hidden);
        fs::write(dir.path().join("metadata.json"), serde_json::to_vec(&saved).unwrap()).unwrap();
        let output = inspect(dir.path(), false);
        prop_assert!(output.status.success(), "{:?}", output.stderr);
        let text = String::from_utf8(output.stdout).unwrap();
        prop_assert!(text.contains("live verification was not performed"));
        prop_assert!(text.contains("HTTPS target: \"localhost\""));
        prop_assert!(text.contains(&format!("{} revealed; 5 committed; {} hidden", bytes.len(), hidden + 7)), "byte accounting");
        prop_assert!(text.contains(&format!("[{}, {})  revealed", hidden, hidden + bytes.len())), "revealed offsets");
        prop_assert!(text.contains(&format!("[{}, {})  committed", hidden + bytes.len(), hidden + bytes.len() + 5)), "commitment offsets");
        prop_assert!(text.contains("\\x1b"));
        prop_assert!(!text.contains('\u{1b}'), "terminal escape");
        prop_assert!(!text.contains("PRIVATE_"));
        prop_assert!(text.ends_with('\n'));
        let output = inspect(dir.path(), true);
        prop_assert!(output.status.success());
        let json: Value = serde_json::from_slice(&output.stdout).unwrap();
        prop_assert_eq!(&json["result"]["record"]["received"], &saved["received"]);
        prop_assert_eq!(&json["result"]["record"]["commitments"], &saved["commitments"]);
        prop_assert_eq!(&json["result"]["record"]["selections"], &saved["selections"]);
        prop_assert!(text.contains("Direction  Action  Selector -> wire ranges"));
        prop_assert_eq!(&json["result"]["verification"], "not-performed");
        prop_assert!(json["result"]["record"].get("openings").is_none());
        prop_assert_eq!(serde_json::from_slice::<Value>(&fs::read(dir.path().join("metadata.json")).unwrap()).unwrap(), saved);
    }
}

#[test]
fn record_boundary_controls_reject_invalid_evidence_and_read_legacy_summaries() {
    let dir = tempfile::tempdir().unwrap();
    let original = record(b"abc", 2);
    let mut controls = Vec::new();
    let mut changed = original.clone();
    changed["received"][0]["bytes"] = json!([]);
    controls.push(changed);
    let mut changed = original.clone();
    changed["received_len"] = json!(1);
    controls.push(changed);
    let mut changed = original.clone();
    changed["received"][0]["start"] = json!(usize::MAX);
    controls.push(changed);
    let mut changed = original.clone();
    changed["received"][0]["start"] = json!(5);
    controls.push(changed);
    let mut changed = original.clone();
    changed["received"]
        .as_array_mut()
        .unwrap()
        .push(original["received"][0].clone());
    controls.push(changed);
    let mut changed = original.clone();
    changed["commitments"]
        .as_array_mut()
        .unwrap()
        .push(original["commitments"][0].clone());
    controls.push(changed);
    let mut changed = original.clone();
    changed.as_object_mut().unwrap().remove("sent");
    controls.push(changed);
    for invalid in controls {
        fs::write(
            dir.path().join("metadata.json"),
            serde_json::to_vec(&invalid).unwrap(),
        )
        .unwrap();
        let output = inspect(dir.path(), false);
        assert!(!output.status.success(), "{invalid}");
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("invalid transcript"));
    }
    let mut legacy = original;
    for field in ["sent", "received"] {
        legacy.as_object_mut().unwrap().remove(field);
    }
    fs::write(
        dir.path().join("metadata.json"),
        serde_json::to_vec(&legacy).unwrap(),
    )
    .unwrap();
    let output = inspect(dir.path(), false);
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("not recorded by this older format"));
    assert!(!text.contains("0 revealed"));
}

#[test]
fn argument_controls_are_actionable_without_echoing_private_values() {
    for (args, expected) in [
        (vec!["serve"], "--server-name"),
        (
            vec!["inspect", "--run", "missing", "--format", "raw"],
            "raw requires the attest command",
        ),
        (
            vec![
                "attest",
                "--url",
                "https://localhost",
                "--private-unknown=SECRET",
            ],
            "invalid command line",
        ),
        (vec!["serve", "--listen", "SECRET"], "invalid command line"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_proof-client"))
            .args(args)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(error.contains(expected), "{error}");
        assert!(!error.contains("SECRET"), "{error}");
    }
}
