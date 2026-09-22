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
        let mut file = tempfile::NamedTempFile::new_in(self.parent)?;
        serde_json::to_writer(&mut file, value)?;
        file.write_all(b"\n")?;
        file.as_file().sync_all()?;
        file.persist_noclobber(self.path)?;
        Ok(())
    }
}
