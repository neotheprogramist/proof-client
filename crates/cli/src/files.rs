use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};
pub(crate) fn read(path: &Path, limit: usize) -> Result<Vec<u8>, FileError> {
    let mut bytes = Vec::new();
    io_at(
        "read",
        path,
        File::open(path).and_then(|file| file.take((limit + 1) as u64).read_to_end(&mut bytes)),
    )?;
    if bytes.len() > limit {
        return Err(FileError::Limit);
    }
    Ok(bytes)
}
#[derive(Debug, thiserror::Error)]
pub enum FileError {
    #[error("input exceeds its admission limit")]
    Limit,
    #[error("output path must not already exist")]
    Output,
    #[error("cannot encode artifact {path}")]
    Json {
        path: String,
        source: serde_json::Error,
    },
    #[error("cannot {operation} {path}: {source}")]
    Io {
        operation: &'static str,
        path: std::path::PathBuf,
        source: io::Error,
    },
    #[error("cannot publish artifact {path} without overwriting: {source}")]
    Persist {
        path: String,
        source: tempfile::PersistError,
    },
}
fn io_at<T>(operation: &'static str, path: &Path, result: io::Result<T>) -> Result<T, FileError> {
    match result {
        Ok(value) => Ok(value),
        Err(source) => Err(FileError::Io {
            operation,
            path: path.to_owned(),
            source,
        }),
    }
}
enum Directory {
    Existing(std::path::PathBuf),
    Run(tempfile::TempDir),
}
impl Directory {
    fn path(&self) -> &Path {
        match self {
            Self::Existing(path) => path,
            Self::Run(directory) => directory.path(),
        }
    }
}
pub(crate) struct Output {
    path: String,
    directory: Directory,
}
impl Output {
    pub(crate) fn metadata(
        path: Option<&Path>,
        root: &Path,
        operation: &str,
    ) -> Result<Self, FileError> {
        if let Some(path) = path {
            return Self::prepare(path);
        }
        let runs = root.join("runs");
        io_at(
            "create runs directory",
            &runs,
            std::fs::create_dir_all(&runs),
        )?;
        let directory = io_at(
            "create run",
            &runs,
            tempfile::Builder::new()
                .prefix(&format!("{operation}."))
                .tempdir_in(&runs),
        )?;
        let mut output = Self::prepare(&directory.path().join("metadata.json"))?;
        output.directory = Directory::Run(directory);
        Ok(output)
    }

    pub(crate) fn path(&self) -> &str {
        &self.path
    }
    pub(crate) fn prepare(path: &Path) -> Result<Self, FileError> {
        let parent = path.parent().ok_or(FileError::Output)?;
        let parent = if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        };
        let parent = io_at("resolve output directory", parent, parent.canonicalize())?;
        let path = parent.join(path.file_name().ok_or(FileError::Output)?);
        match path.symlink_metadata() {
            Ok(_) => return Err(FileError::Output),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(FileError::Io {
                    operation: "inspect output",
                    path,
                    source,
                });
            }
        }
        let path = path
            .into_os_string()
            .into_string()
            .or(Err(FileError::Output))?;
        Ok(Self {
            path,
            directory: Directory::Existing(parent),
        })
    }
    pub(crate) fn publish(self, value: &impl serde::Serialize) -> Result<(), FileError> {
        let mut file = io_at(
            "prepare artifact",
            self.directory.path(),
            tempfile::NamedTempFile::new_in(self.directory.path()),
        )?;
        if let Err(source) = serde_json::to_writer_pretty(file.as_file_mut(), value) {
            return Err(FileError::Json {
                path: self.path,
                source,
            });
        }
        io_at(
            "write artifact",
            Path::new(&self.path),
            file.write_all(b"\n"),
        )?;
        io_at(
            "sync artifact",
            Path::new(&self.path),
            file.as_file().sync_all(),
        )?;
        if let Err(source) = file.persist_noclobber(&self.path) {
            return Err(FileError::Persist {
                path: self.path,
                source,
            });
        }
        if let Directory::Run(directory) = self.directory {
            drop(directory.keep());
        }
        tracing::info!(event = "published", output = ?self.path);
        Ok(())
    }
}

pub(crate) fn circuit(
    path: &Path,
) -> Result<proof_client_core::proof::Circuit, crate::app::CliError> {
    use proof_client_core::proof::{Circuit, MAX_INPUT_BYTES, MAX_SOURCES, Source};
    use std::collections::BTreeMap;
    let absolute = io_at("resolve circuit", path, path.canonicalize())?;
    let root = absolute.parent().ok_or(FileError::Output)?.to_owned();
    let entry = absolute.file_name().ok_or(FileError::Output)?.into();
    let mut pending = vec![absolute];
    let mut sources = BTreeMap::new();
    let mut size = 0;
    let mut index = 0;
    while let Some(path) = pending.get(index).cloned() {
        let bytes = read(&path, MAX_INPUT_BYTES - size)?;
        size += bytes.len();
        let parent = path.parent().ok_or(FileError::Output)?;
        let source = Source::parse(&bytes)?.resolve(|reference| {
            let dependency = parent.join(reference);
            let dependency = io_at(
                "resolve circuit dependency",
                &dependency,
                dependency.canonicalize(),
            )?;
            if !pending.contains(&dependency) {
                if pending.len() == MAX_SOURCES {
                    return Err(FileError::Limit);
                }
                pending.push(dependency.clone());
            }
            Ok::<_, FileError>(source_name(&root, &dependency))
        })?;
        sources.insert(source_name(&root, &path), source);
        index += 1;
    }
    Ok(Circuit::link(entry, sources)?)
}
fn source_name(root: &Path, path: &Path) -> std::path::PathBuf {
    match path.strip_prefix(root) {
        Ok(relative) => relative.to_owned(),
        Err(_) => path.to_owned(),
    }
}
