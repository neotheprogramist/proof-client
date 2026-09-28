#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "direct boundary observations"
)]
#[path = "../../../examples/mbank/support/identity.rs"]
mod identity;
use std::{fs, sync::Barrier};

#[test]
fn identity_initialization_is_shared_and_existing_files_are_immutable() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("identity");
    let barrier = Barrier::new(8);
    let certificates = std::thread::scope(|scope| {
        let workers = (0..8)
            .map(|_| {
                scope.spawn(|| {
                    barrier.wait();
                    identity::get_or_create(&directory, "verifier")
                        .unwrap()
                        .cert
                })
            })
            .collect::<Vec<_>>();
        workers
            .into_iter()
            .map(|w| w.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert!(certificates.windows(2).all(|pair| pair[0] == pair[1]));
    let cert = fs::read(directory.join("verifier.pem")).unwrap();
    let key = fs::read(directory.join("verifier.key")).unwrap();
    identity::get_or_create(&directory, "verifier").unwrap();
    assert_eq!(fs::read(directory.join("verifier.pem")).unwrap(), cert);
    assert_eq!(fs::read(directory.join("verifier.key")).unwrap(), key);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(directory.join("verifier.key"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[test]
fn incomplete_invalid_and_mismatched_identities_are_never_replaced() {
    let root = tempfile::tempdir().unwrap();
    identity::get_or_create(root.path(), "first").unwrap();
    identity::get_or_create(root.path(), "second").unwrap();
    let cert = fs::read(root.path().join("first.pem")).unwrap();
    let key = fs::read(root.path().join("first.key")).unwrap();
    let other_key = fs::read(root.path().join("second.key")).unwrap();
    for (cert, key) in [
        (Some(cert.as_slice()), None),
        (None, Some(key.as_slice())),
        (Some(b"".as_slice()), Some(key.as_slice())),
        (Some(b"invalid".as_slice()), Some(key.as_slice())),
        (Some(cert.as_slice()), Some(b"invalid".as_slice())),
        (Some(cert.as_slice()), Some(other_key.as_slice())),
    ] {
        let dir = tempfile::tempdir().unwrap();
        for (name, bytes) in [("verifier.pem", cert), ("verifier.key", key)] {
            if let Some(bytes) = bytes {
                fs::write(dir.path().join(name), bytes).unwrap();
            }
        }
        assert!(identity::get_or_create(dir.path(), "verifier").is_err());
        for (name, bytes) in [("verifier.pem", cert), ("verifier.key", key)] {
            assert_eq!(fs::read(dir.path().join(name)).ok().as_deref(), bytes);
        }
    }
}
