use futures_rustls::rustls::{
    self,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
};
use std::{fs, fs::OpenOptions, io::Write, path::Path};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("local identity I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("cannot generate local identity: {0}")]
    Generate(#[from] rcgen::Error),
    #[error("invalid local identity PEM: {0}")]
    Pem(#[from] rustls::pki_types::pem::Error),
    #[error("invalid local identity: {0}")]
    Tls(#[from] rustls::Error),
    #[error("cannot publish local identity: {0}")]
    Persist(#[from] tempfile::PersistError),
}

pub fn get_or_create(directory: &Path, name: &str) -> Result<rustls::sign::CertifiedKey, Error> {
    fs::create_dir_all(directory)?;
    let lock = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(directory.join(format!("{name}.lock")))?;
    // The file owns the pair's initialization lock until this function returns.
    lock.lock()?;
    let cert_path = directory.join(format!("{name}.pem"));
    let key_path = directory.join(format!("{name}.key"));
    let (cert, key) = match (fs::read(&cert_path), fs::read(&key_path)) {
        (Ok(cert), Ok(key)) => (cert, key),
        (Err(cert), Err(key))
            if cert.kind() == std::io::ErrorKind::NotFound
                && key.kind() == std::io::ErrorKind::NotFound =>
        {
            let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
            let cert = identity.cert.pem().into_bytes();
            let key = identity.signing_key.serialize_pem().into_bytes();
            for (path, contents) in [(&key_path, &key), (&cert_path, &cert)] {
                let mut file = tempfile::NamedTempFile::new_in(directory)?;
                file.write_all(contents)?;
                file.as_file().sync_all()?;
                file.persist_noclobber(path)?;
            }
            (cert, key)
        }
        (Err(error), _) | (_, Err(error)) => return Err(Error::Io(error)),
    };
    let cert = CertificateDer::pem_slice_iter(&cert).collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_slice(&key)?;
    Ok(rustls::sign::CertifiedKey::from_der(
        cert,
        key,
        &rustls::crypto::ring::default_provider(),
    )?)
}
