use crate::tls::{
    attest::{self, AttestError, Report, Request},
    disclosure::Disclosure,
};
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use quinn::{
    Endpoint,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
    sync::Arc,
    time::Duration,
};
use tlsn::{connection::DnsName, webpki::RootCertStore};
use tokio_util::compat::TokioAsyncReadCompatExt;

pub const ALPN: &[u8] = b"proof-client-tlsn/5";
// Policy: bound correlation metadata before allocating a cryptographic session.
const MAX_SESSION_BYTES: usize = 128;
const MAX_START_BYTES: usize = br#"{"session":""}"#.len() + MAX_SESSION_BYTES;
// Policy: bound QUIC close draining.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(thiserror::Error)]
pub enum QuicError {
    #[error("QUIC I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid certificate configuration")]
    Tls(#[from] rustls::Error),
    #[error("invalid PEM certificate or key")]
    Pem(#[from] rustls::pki_types::pem::Error),
    #[error("QUIC requires an initial TLS cipher suite")]
    Cipher(#[from] quinn::crypto::rustls::NoInitialCipherSuite),
    #[error("QUIC connection could not start")]
    Connect(#[from] quinn::ConnectError),
    #[error("QUIC connection failed")]
    Connection(#[from] quinn::ConnectionError),
    #[error("invalid verifier or target DNS name")]
    Name(#[from] tlsn::connection::InvalidDnsNameError),
    #[error("QUIC session exceeded its deadline")]
    Timeout(#[from] tokio::time::error::Elapsed),
    #[error("QUIC operation failed and its shutdown exceeded the drain deadline")]
    Shutdown {
        operation: Box<QuicError>,
        shutdown: tokio::time::error::Elapsed,
    },
    #[error("invalid QUIC control frame")]
    Json(#[from] serde_json::Error),
    #[error("QUIC frame length exceeds the protocol representation")]
    Length(#[from] std::num::TryFromIntError),
    #[error("QUIC control frame exceeds its bound or is empty")]
    Frame,
    #[error("session ID must contain 1..128 ASCII letters, digits, hyphens or underscores")]
    Session,
    #[error("QUIC session, target identity or verifier receipt does not match")]
    Mismatch,
    #[error("QUIC peer ended the protocol unexpectedly")]
    Closed,
    #[error("verifier must use a loopback address")]
    Loopback,
    #[error("certificate chain must not be empty")]
    Certificate,
    #[error(transparent)]
    Attest(#[from] AttestError),
}
impl std::fmt::Debug for QuicError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SessionId(String);
impl TryFrom<String> for SessionId {
    type Error = QuicError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.is_empty()
            || value.len() > MAX_SESSION_BYTES
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(QuicError::Session);
        }
        Ok(Self(value))
    }
}
impl FromStr for SessionId {
    type Err = QuicError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        value.to_owned().try_into()
    }
}
impl From<SessionId> for String {
    fn from(value: SessionId) -> Self {
        value.0
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Start {
    session: SessionId,
}
#[derive(Serialize, Deserialize)]
pub struct Receipt {
    session: SessionId,
    report: Report,
}

#[derive(Serialize)]
pub struct Metadata<'a> {
    session: &'a SessionId,
    server_name: &'a str,
    sent_len: usize,
    received_len: usize,
    commitments: &'a [tlsn::transcript::hash::PlaintextHash],
}

impl Receipt {
    pub fn metadata(&self) -> Metadata<'_> {
        let (sent_len, received_len) = self.report.lengths();
        Metadata {
            session: &self.session,
            server_name: self.report.server_name(),
            sent_len,
            received_len,
            commitments: self.report.commitments(),
        }
    }

    pub fn report(&self) -> &Report {
        &self.report
    }
}

pub fn roots(pem: Option<&[u8]>) -> Result<RootCertStore, QuicError> {
    match pem {
        None => Ok(RootCertStore::mozilla()),
        Some(pem) => Ok(RootCertStore {
            roots: certificates(pem)?
                .into_iter()
                .map(|cert| tlsn::webpki::CertificateDer(cert.to_vec()))
                .collect(),
        }),
    }
}
fn certificates(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, QuicError> {
    let certs = CertificateDer::pem_slice_iter(pem).collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        return Err(QuicError::Certificate);
    }
    Ok(certs)
}
fn transport() -> quinn::TransportConfig {
    let mut config = quinn::TransportConfig::default();
    config.max_concurrent_bidi_streams(1u8.into());
    config.max_concurrent_uni_streams(0u8.into());
    config.datagram_receive_buffer_size(None);
    config
}
pub fn server_config(cert: &[u8], key: &[u8]) -> Result<quinn::ServerConfig, QuicError> {
    let mut crypto = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_no_client_auth()
    .with_single_cert(certificates(cert)?, PrivateKeyDer::from_pem_slice(key)?)?;
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    crypto.max_early_data_size = 0;
    let mut config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(crypto)?));
    config.transport_config(Arc::new(transport()));
    Ok(config)
}
pub struct Peer {
    address: SocketAddr,
    name: DnsName,
    config: quinn::ClientConfig,
}
impl Peer {
    pub fn new(address: SocketAddr, name: &str, roots: RootCertStore) -> Result<Self, QuicError> {
        if !address.ip().is_loopback() {
            return Err(QuicError::Loopback);
        }
        let name = DnsName::try_from(name)?;
        let mut store = rustls::RootCertStore::empty();
        for cert in roots.roots {
            store.add(CertificateDer::from(cert.0))?;
        }
        let mut crypto = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(store)
        .with_no_client_auth();
        crypto.alpn_protocols = vec![ALPN.to_vec()];
        crypto.enable_early_data = false;
        let mut config = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(crypto)?));
        let mut limits = transport();
        limits.max_concurrent_bidi_streams(0u8.into());
        config.transport_config(Arc::new(limits));
        Ok(Self {
            address,
            name,
            config,
        })
    }
}

async fn complete<T>(
    socket: &Endpoint,
    result: Result<Result<T, QuicError>, tokio::time::error::Elapsed>,
) -> Result<T, QuicError> {
    let result = match result {
        Ok(result) => result,
        Err(error) => Err(error.into()),
    };
    let code = if result.is_ok() { 0u8 } else { 1u8 };
    socket.close(code.into(), b"operation ended");
    let drained = tokio::time::timeout(DRAIN_TIMEOUT, socket.wait_idle()).await;
    match (result, drained) {
        (Ok(receipt), Ok(())) => Ok(receipt),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error.into()),
        (Err(operation), Err(shutdown)) => Err(QuicError::Shutdown {
            operation: Box::new(operation),
            shutdown,
        }),
    }
}
struct Channel(quinn::Connection);
impl Drop for Channel {
    fn drop(&mut self) {
        self.0.close(1u8.into(), b"session failed");
    }
}

#[derive(Serialize)]
pub struct Attestation {
    transcript: tlsn::transcript::Transcript,
    secrets: Vec<tlsn::transcript::TranscriptSecret>,
    receipt: Receipt,
}

impl Attestation {
    pub fn transcript(&self) -> &tlsn::transcript::Transcript {
        &self.transcript
    }

    pub fn secrets(&self) -> &[tlsn::transcript::TranscriptSecret] {
        &self.secrets
    }

    pub fn receipt(&self) -> &Receipt {
        &self.receipt
    }
}

pub async fn attest(
    request: Request,
    disclosure: Disclosure,
    peer: Peer,
    session: SessionId,
    target_roots: RootCertStore,
) -> Result<Attestation, QuicError> {
    let ip = match peer.address.ip() {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    let socket = Endpoint::client(SocketAddr::new(ip, 0))?;
    let result = tokio::time::timeout(attest::SESSION_TIMEOUT, async {
        let connection = socket
            .connect_with(peer.config, peer.address, peer.name.as_str())?
            .await?;
        let connection = Channel(connection);
        let (send, recv) = connection.0.open_bi().await?;
        let mut io = tokio::io::join(recv, send).compat();
        Frame::encode(&Start {
            session: session.clone(),
        })?
        .write(&mut io)
        .await?;
        let server = tokio::net::TcpStream::connect(request.address())
            .await?
            .compat();
        let (mut io, (report, transcript, secrets)) =
            attest::attest_session(request, disclosure, io, server, target_roots).await?;
        let expected = Receipt {
            session,
            report: report.accepted(),
        };
        let encoded = Frame::encode(&expected)?;
        // PROOF: both peers encode the same transcript-derived receipt.
        let receipt: Receipt = read_frame(&mut io, encoded.bytes.len()).await?;
        if receipt.session != expected.session || receipt.report != expected.report {
            return Err(QuicError::Mismatch);
        }
        expect_end(&mut io).await?;
        io.close().await?;
        match connection.0.closed().await {
            quinn::ConnectionError::ApplicationClosed(close) if close.error_code == 0u8.into() => {}
            error => return Err(error.into()),
        }
        Ok(Attestation {
            transcript,
            secrets,
            receipt,
        })
    })
    .await;
    complete(&socket, result).await
}

#[derive(Debug, thiserror::Error)]
pub enum ServeError<E: std::error::Error + 'static> {
    #[error(transparent)]
    Protocol(#[from] QuicError),
    #[error("verified log publication failed: {0}")]
    Publication(#[source] E),
    #[error("serve failed and shutdown exceeded its deadline")]
    Shutdown {
        operation: Box<Self>,
        shutdown: tokio::time::error::Elapsed,
    },
}

impl<E: std::error::Error + 'static> From<std::io::Error> for ServeError<E> {
    fn from(source: std::io::Error) -> Self {
        Self::Protocol(source.into())
    }
}
impl<E: std::error::Error + 'static> From<quinn::ConnectionError> for ServeError<E> {
    fn from(source: quinn::ConnectionError) -> Self {
        Self::Protocol(source.into())
    }
}
impl<E: std::error::Error + 'static> From<AttestError> for ServeError<E> {
    fn from(source: AttestError) -> Self {
        Self::Protocol(source.into())
    }
}

pub struct Verifier {
    socket: Endpoint,
    session: SessionId,
    name: DnsName,
    roots: RootCertStore,
}
impl Verifier {
    pub fn bind(
        address: SocketAddr,
        config: quinn::ServerConfig,
        session: SessionId,
        server_name: &str,
        roots: RootCertStore,
    ) -> Result<Self, QuicError> {
        if !address.ip().is_loopback() {
            return Err(QuicError::Loopback);
        }
        let name = DnsName::try_from(server_name)?;
        Ok(Self {
            socket: Endpoint::server(config, address)?,
            session,
            name,
            roots,
        })
    }
    pub fn local_addr(&self) -> Result<SocketAddr, QuicError> {
        Ok(self.socket.local_addr()?)
    }
    pub async fn verify<E: std::error::Error + 'static>(
        self,
        publish: impl FnOnce(&Receipt) -> Result<(), E>,
    ) -> Result<Receipt, ServeError<E>> {
        let result = tokio::time::timeout(attest::SESSION_TIMEOUT, async {
            let incoming = self.socket.accept().await.ok_or(QuicError::Closed)?;
            self.socket.set_server_config(None);
            let connection = Channel(incoming.await?);
            let (send, recv) = connection.0.accept_bi().await?;
            let mut io = tokio::io::join(recv, send).compat();
            let start: Start = read_frame(&mut io, MAX_START_BYTES).await?;
            if start.session != self.session {
                return Err(QuicError::Mismatch.into());
            }
            let (mut io, report) = attest::verify_session(io, self.roots).await?;
            if report.server_name() != self.name.as_str() {
                return Err(QuicError::Mismatch.into());
            }
            let receipt = Receipt {
                session: self.session,
                report,
            };
            let frame = Frame::encode(&receipt)?;
            if let Err(source) = publish(&receipt) {
                return Err(ServeError::Publication(source));
            }
            frame.write(&mut io).await?;
            io.close().await?;
            expect_end(&mut io).await?;
            connection.0.close(0u8.into(), b"complete");
            Ok(receipt)
        })
        .await;
        let result = match result {
            Ok(result) => result,
            Err(error) => Err(QuicError::Timeout(error).into()),
        };
        self.socket.close(
            if result.is_ok() { 0u8 } else { 1u8 }.into(),
            b"operation ended",
        );
        let drained = tokio::time::timeout(DRAIN_TIMEOUT, self.socket.wait_idle()).await;
        match (result, drained) {
            (Ok(receipt), Ok(())) => Ok(receipt),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(error)) => Err(QuicError::Timeout(error).into()),
            (Err(operation), Err(shutdown)) => Err(ServeError::Shutdown {
                operation: Box::new(operation),
                shutdown,
            }),
        }
    }
}
async fn expect_end(io: &mut (impl AsyncRead + Unpin)) -> Result<(), QuicError> {
    if io.read(&mut [0u8; 1]).await? != 0 {
        return Err(QuicError::Closed);
    }
    Ok(())
}
async fn read_frame<T: DeserializeOwned>(
    io: &mut (impl AsyncRead + Unpin),
    limit: usize,
) -> Result<T, QuicError> {
    let mut prefix = [0; 4];
    io.read_exact(&mut prefix).await?;
    let len = u32::from_be_bytes(prefix) as usize;
    if len == 0 || len > limit {
        return Err(QuicError::Frame);
    }
    let mut bytes = vec![0; len];
    io.read_exact(&mut bytes).await?;
    Ok(serde_json::from_slice(&bytes)?)
}
struct Frame {
    prefix: [u8; 4],
    bytes: Vec<u8>,
}
impl Frame {
    fn encode(value: &impl Serialize) -> Result<Self, QuicError> {
        let bytes = serde_json::to_vec(value)?;
        let prefix = u32::try_from(bytes.len())?.to_be_bytes();
        Ok(Self { prefix, bytes })
    }
    async fn write(self, io: &mut (impl AsyncWrite + Unpin)) -> Result<(), QuicError> {
        io.write_all(&self.prefix).await?;
        io.write_all(&self.bytes).await?;
        io.flush().await?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "../../tests/controls/quic_controls.rs"]
mod tests;
