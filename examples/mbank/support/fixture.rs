use futures::{AsyncReadExt, AsyncWriteExt};
use futures_rustls::{
    TlsAcceptor,
    rustls::{
        self,
        pki_types::{CertificateDer, PrivateKeyDer},
    },
};
use rand::{RngExt, SeedableRng, rngs::StdRng};
use std::{fs::OpenOptions, io::Write, net::SocketAddr, path::Path, sync::Arc};
use tokio::net::TcpListener;
use tokio_util::compat::TokioAsyncReadCompatExt;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("fixture I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("fixture identity failed: {0}")]
    Certificate(#[from] rcgen::Error),
    #[error("fixture TLS failed: {0}")]
    Tls(#[from] rustls::Error),
    #[error("fixture HTTP failed: {0}")]
    Http(#[from] httparse::Error),
    #[error("invalid fixture header: {0}")]
    Utf8(#[from] std::str::Utf8Error),
    #[error("invalid fixture length: {0}")]
    Length(#[from] std::num::ParseIntError),
    #[error("fixture deadline exceeded: {0}")]
    Timeout(#[from] tokio::time::error::Elapsed),
    #[error("invalid fixture request: {0}")]
    Request(&'static str),
}
pub const DISCLOSURE: &str = include_str!("../disclosure.json");

pub struct SampleData {
    pub request_cookie: String,
    pub response_cookie: String,
    pub account: String,
}
impl SampleData {
    pub fn body(&self) -> String {
        format!(
            r#"{{"products":[{{"AvailableBalance":42.1200,"currency":"PLN","account":"{}"}}]}}"#,
            self.account
        )
    }
}
pub fn sample_data() -> SampleData {
    // Policy: a fixed seed makes synthetic fixture values reproducible.
    const SEED: u64 = 0;
    let mut rng = StdRng::seed_from_u64(SEED);
    SampleData {
        request_cookie: format!("session={:016x}", rng.random::<u64>()),
        response_cookie: format!("session={:016x}", rng.random::<u64>()),
        account: format!("demo-account-{:016x}", rng.random::<u64>()),
    }
}

pub struct Fixture {
    listener: TcpListener,
    tls: TlsAcceptor,
}
impl Fixture {
    pub async fn bind(directory: &Path, address: SocketAddr) -> Result<Self, Error> {
        std::fs::create_dir_all(directory)?;
        let target = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let verifier = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let listener = TcpListener::bind(address).await?;
        for (name, bytes) in [
            ("target.pem", target.cert.pem()),
            ("verifier.pem", verifier.cert.pem()),
            ("verifier.key", verifier.signing_key.serialize_pem()),
            ("disclosure.json", DISCLOSURE.to_owned()),
        ] {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            options
                .open(directory.join(name))?
                .write_all(bytes.as_bytes())?;
        }
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS12])?
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(target.cert.der().to_vec())],
            PrivateKeyDer::Pkcs8(target.signing_key.serialize_der().into()),
        )?;
        Ok(Self {
            listener,
            tls: TlsAcceptor::from(Arc::new(config)),
        })
    }
    pub fn address(&self) -> Result<SocketAddr, Error> {
        Ok(self.listener.local_addr()?)
    }
    pub async fn serve(self, response: &[u8]) -> Result<Vec<u8>, Error> {
        let (socket, _) = self.listener.accept().await?;
        let mut tls = self.tls.accept(socket.compat()).await?;
        let mut request = Vec::new();
        let mut byte = [0];
        while !request.ends_with(b"\r\n\r\n") {
            if request.len() >= proof_client_core::tls::attest::MAX_SENT {
                return Err(Error::Request("fixture request exceeds limit"));
            }
            tls.read_exact(&mut byte).await?;
            request.extend_from_slice(&byte);
        }
        let (body_length, keep_alive) = {
            let mut headers = [httparse::EMPTY_HEADER; 64];
            let mut parsed = httparse::Request::new(&mut headers);
            if !parsed.parse(&request)?.is_complete() || parsed.path != Some("/balance") {
                return Err(Error::Request("fixture expects /balance"));
            }
            for header in parsed
                .headers
                .iter()
                .filter(|h| h.name.eq_ignore_ascii_case("cookie"))
            {
                if header.value != sample_data().request_cookie.as_bytes() {
                    return Err(Error::Request("fixture cookie does not match"));
                }
            }
            let keep_alive = parsed.headers.iter().any(|h| {
                h.name.eq_ignore_ascii_case("connection")
                    && h.value.eq_ignore_ascii_case(b"keep-alive")
            });
            let length = parsed
                .headers
                .iter()
                .find(|h| h.name.eq_ignore_ascii_case("content-length"))
                .map(|h| -> Result<usize, Error> { Ok(std::str::from_utf8(h.value)?.parse()?) })
                .transpose()?
                .unwrap_or(0);
            (length, keep_alive)
        };
        if body_length > proof_client_core::tls::attest::MAX_SENT {
            return Err(Error::Request("fixture body exceeds limit"));
        }
        let mut body = vec![0; body_length];
        tls.read_exact(&mut body).await?;
        request.extend(body);
        tls.write_all(response).await?;
        tls.flush().await?;
        if keep_alive
            && !response
                .windows(b"Connection: close".len())
                .any(|w| w == b"Connection: close")
            && tls.read(&mut byte).await? != 0
        {
            return Err(Error::Request("unexpected pipelined request"));
        }
        tls.close().await?;
        Ok(request)
    }
}

pub fn response() -> Vec<u8> {
    let data = sample_data();
    let body = data.body();
    format!("HTTP/1.1 103 Early Hints\r\nLink: </assets/app.css>; rel=preload; as=style\r\n\r\nHTTP/1.1 200 OK\r\nSet-Cookie: {}\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{body}", data.response_cookie, body.len()).into_bytes()
}
