#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "direct boundary observations"
)]
use proof_client::{
    identity::parse_origin,
    stdio::{self, MAX_FRAME_BYTES},
};
use proptest::prelude::*;
use serde_json::{Value, json};
use std::io::{self, Cursor, Read, Write};
struct Fragmented<R> {
    inner: R,
    chunk: usize,
}
impl<R: Read> Read for Fragmented<R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let length = bytes.len().min(self.chunk);
        self.inner.read(&mut bytes[..length])
    }
}
fn response(bytes: &[u8]) -> Value {
    let mut input = (bytes.len() as u32).to_ne_bytes().to_vec();
    input.extend_from_slice(bytes);
    let mut output = Vec::new();
    stdio::run(&mut Cursor::new(input), &mut output).unwrap();
    let mut output = Cursor::new(output);
    let value = serde_json::from_slice(&stdio::read_frame(&mut output).unwrap()).unwrap();
    assert_eq!(output.position() as usize, output.get_ref().len());
    value
}
proptest! {
    #[test]
    fn native_frames_preserve_payload_under_fragmentation(value in "[a-zA-Z0-9]{0,128}", chunk in 1usize..32) {
        let mut bytes = Vec::new();
        stdio::write_frame(&mut bytes, &value).unwrap();
        let mut reader = Fragmented {inner: Cursor::new(bytes), chunk};
        let output = stdio::read_frame(&mut reader).unwrap();
        prop_assert_eq!(serde_json::from_slice::<String>(&output).unwrap(), value);
        prop_assert!(stdio::read_frame(&mut reader).is_err());
    }
}
#[test]
fn admission_rejects_ambiguity_without_reflecting_private_arguments() {
    for input in [
        "{",
        "[]",
        r#"{"protocol":"proof-client/5","args":[],"args":[]}"#,
        r#"{"protocol":"other","args":[]}"#,
        r#"{"protocol":"proof-client/5","args":[],"secret":"SYNTHETIC_SECRET"}"#,
    ] {
        let result = response(input.as_bytes());
        assert_eq!(result["event"], "failed");
        assert!(!result.to_string().contains("SYNTHETIC_SECRET"));
    }
    for args in [
        vec!["serve"],
        vec!["--SYNTHETIC_SECRET"],
        vec!["attest", "--cookie", "SYNTHETIC_SECRET"],
    ] {
        let result = response(
            &serde_json::to_vec(&json!({"protocol":stdio::PROTOCOL,"args":args})).unwrap(),
        );
        assert_eq!(result["event"], "failed");
        assert!(!result.to_string().contains("SYNTHETIC_SECRET"));
    }
    for suffix in ["?x=secret", "#secret", "child", "\n"] {
        assert!(parse_origin(&format!("chrome-extension://{}/{suffix}", "a".repeat(32))).is_err());
    }
    for id in [
        "a".repeat(31),
        "a".repeat(33),
        "q".repeat(32),
        "A".repeat(32),
    ] {
        assert!(parse_origin(&format!("chrome-extension://{id}/")).is_err());
    }
}
#[test]
fn frame_limits_precede_payload_io_and_publication() {
    struct Prefix(Cursor<Vec<u8>>);
    impl Read for Prefix {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            assert!(self.0.position() < 4, "oversized frame read its payload");
            self.0.read(bytes)
        }
    }
    for size in [0, MAX_FRAME_BYTES as u32 + 1, u32::MAX] {
        assert!(matches!(
            stdio::read_frame(&mut Prefix(Cursor::new(size.to_ne_bytes().to_vec()))),
            Err(stdio::FrameError::Length)
        ));
    }
    let mut frame = Vec::new();
    stdio::write_frame(&mut frame, &json!({"x":1})).unwrap();
    for end in 0..frame.len() {
        assert!(stdio::read_frame(&mut Cursor::new(&frame[..end])).is_err());
    }
    let mut output = Vec::new();
    assert!(matches!(
        stdio::write_frame(&mut output, &"x".repeat(MAX_FRAME_BYTES)),
        Err(stdio::FrameError::Length)
    ));
    assert!(output.is_empty());
    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    assert!(matches!(
        stdio::write_frame(&mut Broken, &true),
        Err(stdio::FrameError::Write(_))
    ));
}

#[test]
fn native_protocol_boundary_and_error_classes_are_observable() {
    // Chrome's host message bound is independent of the implementation constant under mutation.
    let payload = "x".repeat((1 << 20) - 2);
    let mut bytes = Vec::new();
    stdio::write_frame(&mut bytes, &payload).unwrap();
    assert_eq!(bytes.len(), (1 << 20) + 4);
    let decoded = stdio::read_frame(&mut Cursor::new(bytes)).unwrap();
    assert_eq!(serde_json::from_slice::<String>(&decoded).unwrap(), payload);
    struct Refused;
    impl Read for Refused {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::ErrorKind::PermissionDenied.into())
        }
    }
    assert!(
        matches!(stdio::read_frame(&mut Refused),Err(stdio::FrameError::Read(error)) if error.kind()==io::ErrorKind::PermissionDenied)
    );
    struct Invalid;
    impl serde::Serialize for Invalid {
        fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
            Err(serde::ser::Error::custom("synthetic encoding error"))
        }
    }
    let mut output = Vec::new();
    assert!(matches!(
        stdio::write_frame(&mut output, &Invalid),
        Err(stdio::FrameError::Encode(_))
    ));
    assert!(output.is_empty());
}

#[test]
fn every_native_file_argument_requires_an_absolute_path() {
    let dir = tempfile::tempdir().unwrap();
    let absolute = dir.path().join("missing").to_str().unwrap().to_owned();
    for (command, files, rest) in [
        ("prove", vec!["circuit", "witness", "output"], vec![]),
        ("verify", vec!["circuit", "proof"], vec![]),
        (
            "serve",
            vec!["cert", "key", "target-ca", "output"],
            vec![
                "--listen",
                "127.0.0.1:0",
                "--server-name",
                "localhost",
                "--session",
                "test",
            ],
        ),
        (
            "attest",
            vec![
                "request",
                "disclosure",
                "verifier-ca",
                "target-ca",
                "output",
            ],
            vec![
                "--verifier",
                "127.0.0.1:7047",
                "--verifier-name",
                "localhost",
                "--session",
                "test",
            ],
        ),
    ] {
        for relative in &files {
            let mut args = vec![command.to_owned()];
            args.extend(rest.iter().map(|s| (*s).to_owned()));
            for file in &files {
                args.push(format!("--{file}"));
                args.push(if file == relative {
                    "relative-secret".to_owned()
                } else {
                    absolute.clone()
                });
            }
            let result = response(
                &serde_json::to_vec(&json!({"protocol":stdio::PROTOCOL,"args":args})).unwrap(),
            );
            assert_eq!(
                result,
                json!({"event":"failed","message":"native file arguments must use absolute paths"})
            );
        }
    }
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}
