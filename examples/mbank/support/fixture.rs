use futures::{AsyncReadExt, AsyncWriteExt};
#[path = "identity.rs"]
mod identity;
use futures_rustls::{TlsAcceptor, rustls};
use rand::{RngExt, SeedableRng, rngs::StdRng};
use std::{net::SocketAddr, path::Path, sync::Arc};
use tokio::net::TcpListener;
use tokio_util::compat::TokioAsyncReadCompatExt;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("fixture I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("fixture identity failed: {0}")]
    Certificate(#[from] identity::Error),
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

pub struct SampleData {
    pub response_cookie: String,
    pub number: String,
}
impl SampleData {
    pub fn body(&self) -> String {
        format!(
            r#"{{"products":[{{"AvailableBalance":42.1200,"currency":"PLN","number":"{}"}}]}}"#,
            self.number
        )
    }
}
pub fn sample_data() -> SampleData {
    // Policy: a fixed seed makes synthetic fixture values reproducible.
    const SEED: u64 = 0;
    let mut rng = StdRng::seed_from_u64(SEED);
    SampleData {
        response_cookie: format!("session={:016x}", rng.random::<u64>()),
        number: "00 0000 0000 0000 0000 0000 0000".into(),
    }
}

enum Connection {
    Close,
    KeepAlive,
}
// Policy: bound fixture header storage independently of its transcript budget.
const MAX_HEADERS: usize = 64;
pub struct Fixture {
    listener: TcpListener,
    tls: TlsAcceptor,
}
impl Fixture {
    pub async fn bind(directory: &Path, address: SocketAddr) -> Result<Self, Error> {
        let listener = TcpListener::bind(address).await?;
        let identity = identity::get_or_create(directory, "target")?;
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS12])?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(identity)));
        Ok(Self {
            listener,
            tls: TlsAcceptor::from(Arc::new(config)),
        })
    }
    pub fn address(&self) -> Result<SocketAddr, Error> {
        Ok(self.listener.local_addr()?)
    }
    pub async fn accept(self) -> Result<Accepted, Error> {
        let (socket, _) = self.listener.accept().await?;
        Ok(Accepted {
            socket,
            tls: self.tls,
            deadline: tokio::time::Instant::now() + proof_client_core::tls::attest::SESSION_TIMEOUT,
        })
    }
    pub async fn serve(self, response: &[u8]) -> Result<Vec<u8>, Error> {
        self.accept().await?.respond(response).await
    }
}
pub struct Accepted {
    socket: tokio::net::TcpStream,
    tls: TlsAcceptor,
    deadline: tokio::time::Instant,
}
impl Accepted {
    pub async fn respond(self, response: &[u8]) -> Result<Vec<u8>, Error> {
        tokio::time::timeout_at(self.deadline, async {
            let mut tls = self.tls.accept(self.socket.compat()).await?;
            let mut request = Vec::new();
            let mut byte = [0];
            while !request.ends_with(b"\r\n\r\n") {
                if request.len() >= proof_client_core::tls::attest::MAX_SENT {
                    return Err(Error::Request("fixture request exceeds limit"));
                }
                tls.read_exact(&mut byte).await?;
                request.extend_from_slice(&byte);
            }
            let (body_length, connection) = {
                let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
                let mut parsed = httparse::Request::new(&mut headers);
                if !parsed.parse(&request)?.is_complete() || parsed.path != Some("/balance") {
                    return Err(Error::Request("fixture expects /balance"));
                }
                let connection = if parsed.headers.iter().any(|h| {
                    h.name.eq_ignore_ascii_case("connection")
                        && h.value.eq_ignore_ascii_case(b"keep-alive")
                }) {
                    Connection::KeepAlive
                } else {
                    Connection::Close
                };
                let length = parsed
                    .headers
                    .iter()
                    .find(|h| h.name.eq_ignore_ascii_case("content-length"))
                    .map(|h| -> Result<usize, Error> { Ok(std::str::from_utf8(h.value)?.parse()?) })
                    .transpose()?
                    .unwrap_or(0);
                (length, connection)
            };
            if body_length > proof_client_core::tls::attest::MAX_SENT - request.len() {
                return Err(Error::Request("fixture request exceeds limit"));
            }
            let mut body = vec![0; body_length];
            tls.read_exact(&mut body).await?;
            request.extend(body);
            tls.write_all(response).await?;
            tls.flush().await?;
            match (connection, response_connection(response)?) {
                (Connection::KeepAlive, Connection::KeepAlive) => {
                    if tls.read(&mut byte).await? != 0 {
                        return Err(Error::Request("unexpected pipelined request"));
                    }
                }
                (Connection::Close, _) | (_, Connection::Close) => {}
            }
            tls.close().await?;
            Ok(request)
        })
        .await?
    }
}

pub fn response() -> Vec<u8> {
    let data = sample_data();
    let body = data.body();
    format!("HTTP/1.1 103 Early Hints\r\nLink: </assets/app.css>; rel=preload; as=style\r\n\r\nHTTP/1.1 200 OK\r\nSet-Cookie: {}\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{body}", data.response_cookie, body.len()).into_bytes()
}

#[cfg(test)]
pub fn verifier_identity(directory: &Path) -> Result<(), Error> {
    identity::get_or_create(directory, "verifier")?;
    Ok(())
}

fn response_connection(mut response: &[u8]) -> Result<Connection, Error> {
    loop {
        let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
        let mut parsed = httparse::Response::new(&mut headers);
        let httparse::Status::Complete(end) = parsed.parse(response)? else {
            return Err(Error::Request("incomplete fixture response"));
        };
        if parsed.code.is_some_and(|code| (100..200).contains(&code)) {
            response = response
                .get(end..)
                .ok_or(Error::Request("invalid fixture response"))?;
            continue;
        }
        return Ok(
            if parsed.headers.iter().any(|header| {
                header.name.eq_ignore_ascii_case("connection")
                    && header.value.eq_ignore_ascii_case(b"close")
            }) {
                Connection::Close
            } else {
                Connection::KeepAlive
            },
        );
    }
}
