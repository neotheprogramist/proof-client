#![allow(clippy::unwrap_used, reason = "test observations are direct")]
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Deserialize)]
struct Source {
    name: String,
    base: String,
    tree: String,
    patch: String,
    executables: Vec<String>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn files(root: &Path, path: &Path, output: &mut BTreeMap<String, PathBuf>) {
    for entry in fs::read_dir(path).unwrap() {
        let entry = entry.unwrap();
        let kind = entry.file_type().unwrap();
        if kind.is_dir() {
            files(root, &entry.path(), output);
        } else {
            assert!(kind.is_file(), "vendor payload cannot contain symlinks");
            let relative = entry
                .path()
                .strip_prefix(root)
                .unwrap()
                .components()
                .map(|part| part.as_os_str().to_str().unwrap().to_owned())
                .collect::<Vec<_>>()
                .join("/");
            output.insert(relative, entry.path());
        }
    }
}
fn tree(root: &Path) -> (String, BTreeMap<String, PathBuf>) {
    let mut entries = BTreeMap::new();
    files(root, root, &mut entries);
    let mut hash = Sha256::new();
    for (name, path) in &entries {
        hash.update(name.as_bytes());
        hash.update([0]);
        hash.update(Sha256::digest(fs::read(path).unwrap()));
    }
    (hex(&hash.finalize()), entries)
}

#[test]
fn every_vendor_patch_reconstructs_its_pinned_source() {
    let vendor = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../vendor")
        .canonicalize()
        .unwrap();
    let sources: Vec<Source> =
        serde_json::from_slice(&fs::read(vendor.join("sources.json")).unwrap()).unwrap();
    let mut names = sources
        .iter()
        .map(|source| source.name.clone())
        .collect::<Vec<_>>();
    names.sort();
    let mut directories = fs::read_dir(&vendor)
        .unwrap()
        .map(Result::unwrap)
        .filter(|entry| entry.file_type().unwrap().is_dir() && entry.file_name() != "patches")
        .map(|entry| entry.file_name().into_string().unwrap())
        .collect::<Vec<_>>();
    directories.sort();
    assert_eq!(names, directories);
    for source in sources {
        let (hash, entries) = tree(&vendor.join(&source.name));
        assert_eq!(hash, source.tree, "{} payload drift", source.name);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let executable = entries
                .iter()
                .filter(|(_, path)| fs::metadata(path).unwrap().permissions().mode() & 0o111 != 0)
                .map(|(name, _)| name.clone())
                .collect::<Vec<_>>();
            assert_eq!(executable, source.executables);
        }
        let patch = vendor
            .join("patches")
            .join(format!("{}.patch", source.name));
        assert_eq!(
            hex(&Sha256::digest(fs::read(&patch).unwrap())),
            source.patch
        );
        let original = tempfile::tempdir().unwrap();
        for (name, path) in entries {
            let destination = original.path().join(name);
            fs::create_dir_all(destination.parent().unwrap()).unwrap();
            fs::copy(path, destination).unwrap();
        }
        let output = Command::new("git")
            .args(["apply", "--reverse", "--whitespace=nowarn"])
            .arg(patch)
            .current_dir(original.path())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            tree(original.path()).0,
            source.base,
            "{} original source drift",
            source.name
        );
    }
}
