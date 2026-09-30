use crate::tls::{
    attest::{self, AttestError, Opening, ProverOutput, ReportData, Request, VerifiedReport},
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
    sync::Arc,
};
use tlsn::{connection::DnsName, webpki::RootCertStore};
use tokio_util::compat::TokioAsyncReadCompatExt;

pub const ALPN: &[u8] = b"proof-client-tlsn/8";

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
    #[error("invalid QUIC control frame")]
    Json(#[from] serde_json::Error),
    #[error("QUIC frame length exceeds the protocol representation")]
    Length(#[from] std::num::TryFromIntError),
    #[error("QUIC control frame exceeds its bound or is empty")]
    Frame,
    #[error("target identity or verifier receipt does not match")]
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

#[derive(Serialize, Deserialize)]
struct WireReceipt<T = ReportData> {
    report: T,
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
    tracing::info!(phase = "draining_transport");
    // Quinn owns the RTT-dependent close timer; a second timer can expire first.
    socket.wait_idle().await;
    tracing::info!(phase = "transport_drained");
    result
}
struct Channel(quinn::Connection);
impl Drop for Channel {
    fn drop(&mut self) {
        self.0.close(1u8.into(), b"session failed");
    }
}

pub struct Attestation {
    session: ProverOutput,
    receipt: VerifiedReport,
}

#[derive(Serialize)]
struct PrivateMetadata<'a> {
    #[serde(flatten)]
    metadata: &'a super::evidence::Evidence,
    openings: &'a [Opening],
    selections: &'a super::disclosure::SelectionAudit,
}

impl Attestation {
    pub fn selections(&self) -> &super::disclosure::SelectionAudit {
        &self.session.selections
    }
    pub fn response(&self) -> &[u8] {
        &self.session.response
    }
    pub fn metadata(&self) -> impl Serialize + '_ {
        PrivateMetadata {
            metadata: self.receipt.evidence(),
            openings: &self.session.openings,
            selections: &self.session.selections,
        }
    }
    pub fn transcript(&self) -> &tlsn::transcript::Transcript {
        &self.session.transcript
    }
    pub fn receipt(&self) -> &VerifiedReport {
        &self.receipt
    }
}

#[tracing::instrument(skip_all)]
pub async fn attest(
    request: Request,
    disclosure: Disclosure,
    peer: Peer,
    target_roots: RootCertStore,
    commitment_hash: super::commitment::CommitmentHash,
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
        tracing::info!(phase = "connected");
        let (send, recv) = connection.0.open_bi().await?;
        let io = tokio::io::join(recv, send).compat();
        let server = tokio::net::TcpStream::connect(request.address())
            .await?
            .compat();
        let (io, session) = attest::attest_session(
            request,
            disclosure,
            io,
            server,
            target_roots,
            commitment_hash,
        )
        .await?;
        let mut io = io;
        let encoded = Frame::encode(&WireReceipt {
            report: &session.report,
        })?;
        // PROOF: both peers encode the same transcript-derived receipt.
        let receipt: WireReceipt = read_frame(&mut io, encoded.bytes.len()).await?;
        if receipt.report != session.report {
            return Err(QuicError::Mismatch);
        }
        tracing::info!(phase = "receipt_matched");
        expect_end(&mut io).await?;
        io.close().await?;
        match connection.0.closed().await {
            quinn::ConnectionError::ApplicationClosed(close) if close.error_code == 0u8.into() => {
                tracing::info!(phase = "session_closed");
                Ok(Attestation {
                    session,
                    receipt: VerifiedReport {
                        report: receipt.report,
                    },
                })
            }
            error => Err(error.into()),
        }
    })
    .await;
    complete(&socket, result).await
}

pub struct Verifier {
    socket: Endpoint,
    name: DnsName,
    roots: RootCertStore,
    commitment_policy: super::commitment::CommitmentPolicy,
}
impl Verifier {
    pub fn bind(
        address: SocketAddr,
        config: quinn::ServerConfig,
        server_name: &str,
        roots: RootCertStore,
        commitment_policy: super::commitment::CommitmentPolicy,
    ) -> Result<Self, QuicError> {
        if !address.ip().is_loopback() {
            return Err(QuicError::Loopback);
        }
        let name = DnsName::try_from(server_name.to_ascii_lowercase())?;
        let socket = Endpoint::server(config, address)?;
        tracing::info!(event = "ready", address = %socket.local_addr()?);
        Ok(Self {
            socket,
            name,
            roots,
            commitment_policy,
        })
    }
    pub fn local_addr(&self) -> Result<SocketAddr, QuicError> {
        Ok(self.socket.local_addr()?)
    }
    #[tracing::instrument(skip_all)]
    pub async fn verify(self) -> Result<VerifiedReport, QuicError> {
        let incoming = self.socket.accept().await.ok_or(QuicError::Closed)?;
        self.socket.set_server_config(None);
        let result = tokio::time::timeout(attest::SESSION_TIMEOUT, async {
            let connection = Channel(incoming.await?);
            tracing::info!(phase = "connected");
            let (send, recv) = connection.0.accept_bi().await?;
            let io = tokio::io::join(recv, send).compat();
            let (mut io, report) =
                attest::verify_session(io, self.roots, self.commitment_policy).await?;
            if report.evidence().server_name() != self.name.as_str() {
                return Err(QuicError::Mismatch);
            }
            let (sent_bytes, received_bytes) = report.evidence().lengths();
            tracing::info!(phase = "verified", sent_bytes, received_bytes);
            let frame = Frame::encode(&report)?;
            frame.write(&mut io).await?;
            io.close().await?;
            expect_end(&mut io).await?;
            connection.0.close(0u8.into(), b"complete");
            Ok(report)
        })
        .await;
        complete(&self.socket, result).await
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
