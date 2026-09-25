use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};
pub(crate) fn read(path: &Path, limit: usize) -> Result<Vec<u8>, FileError> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(FileError::Limit);
    }
    Ok(bytes)
}
#[derive(Debug, thiserror::Error)]
pub enum FileError {
    #[error("input exceeds its admission limit")]
    Limit,
    #[error("output paths must be distinct and must not already exist")]
    Output,
    #[error("cannot render transcript: {0}")]
    Transcript(#[from] proof_client_core::tls::attest::AttestError),
    #[error("cannot encode artifact")]
    Json(#[from] serde_json::Error),
    #[error("local file I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("cannot publish artifact without overwriting: {0}")]
    Persist(#[from] tempfile::PersistError),
}
pub(crate) struct Output {
    path: String,
    parent: std::path::PathBuf,
}
impl Output {
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
        let parent = parent.canonicalize()?;
        let path = parent.join(path.file_name().ok_or(FileError::Output)?);
        match path.symlink_metadata() {
            Ok(_) => return Err(FileError::Output),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(FileError::Io(error)),
        }
        let path = path
            .into_os_string()
            .into_string()
            .or(Err(FileError::Output))?;
        Ok(Self { parent, path })
    }
    pub(crate) fn publish(self, value: &impl serde::Serialize) -> Result<(), FileError> {
        self.write(|file| {
            serde_json::to_writer_pretty(&mut *file, value)?;
            file.write_all(b"\n")?;
            Ok(())
        })
    }
    pub(crate) fn publish_bytes(self, bytes: &[u8]) -> Result<(), FileError> {
        self.write(|file| Ok(file.write_all(bytes)?))
    }
    fn write(
        self,
        write: impl FnOnce(&mut File) -> Result<(), FileError>,
    ) -> Result<(), FileError> {
        let mut file = tempfile::NamedTempFile::new_in(self.parent)?;
        write(file.as_file_mut())?;
        file.as_file().sync_all()?;
        file.persist_noclobber(self.path)?;
        Ok(())
    }
}

pub(crate) fn circuit(
    path: &Path,
) -> Result<proof_client_core::proof::Circuit, crate::app::CliError> {
    use proof_client_core::proof::{Circuit, MAX_INPUT_BYTES, MAX_SOURCES, Source};
    use std::collections::BTreeMap;
    let absolute = path.canonicalize()?;
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
            let dependency = parent.join(reference).canonicalize()?;
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

pub(crate) fn distinct_outputs<const N: usize>(
    outputs: [Output; N],
) -> Result<[Output; N], FileError> {
    if outputs.iter().enumerate().any(|(i, output)| {
        outputs
            .iter()
            .take(i)
            .any(|other| other.path() == output.path())
    }) {
        return Err(FileError::Output);
    }
    Ok(outputs)
}
