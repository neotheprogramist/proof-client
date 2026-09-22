use crate::tls::disclosure::{self, Disclosure, DisclosureError};
use base64::{Engine, engine::general_purpose::STANDARD};
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, TryFutureExt};
use http::{HeaderName, HeaderValue, Method};
use serde::{Deserialize, Serialize};
use std::{future::IntoFuture, time::Duration};
use tlsn::webpki::RootCertStore;
use tlsn::{
    Session,
    config::{
        prove::ProveConfig, prover::ProverConfig, tls::TlsClientConfig,
        tls_commit::mpc::MpcTlsConfig, verifier::VerifierConfig,
    },
    connection::{DnsName, ServerName},
    verifier::VerifierCommitStart,
};

// Policy: shared MPC transcript budgets.
pub const MAX_SENT: usize = 16 * 1024;
// Policy: bound request JSON, including escaping/base64 overhead.
pub const MAX_REQUEST_BYTES: usize = 4 * MAX_SENT;
pub const MAX_RECEIVED: usize = 64 * 1024;
// Policy: decrypt only TLS control messages online; application bytes are deferred.
pub const MAX_RECEIVED_ONLINE: usize = 32;
// Policy: bound admission and MPC work per session.
pub const SESSION_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(thiserror::Error)]
pub enum AttestError {
    #[error("invalid request JSON")]
    Json(#[from] serde_json::Error),
    #[error("invalid base64 request body")]
    Base64(#[from] base64::DecodeError),
    #[error("expected an HTTPS URL without credentials or a fragment")]
    Url,
    #[error("invalid URL syntax")]
    UrlSyntax(#[from] url::ParseError),
    #[error("invalid DNS name")]
    Dns(#[from] tlsn::connection::InvalidDnsNameError),
    #[error("invalid HTTP method")]
    Method(#[from] http::method::InvalidMethod),
    #[error("invalid HTTP header name")]
    HeaderName(#[from] http::header::InvalidHeaderName),
    #[error("invalid HTTP header value")]
    HeaderValue(#[from] http::header::InvalidHeaderValue),
    #[error("invalid HTTP method or header")]
    Request,
    #[error("request exceeds the configured TLSN transcript budget")]
    Limit,
    #[error("TLSN peer requested an unsupported protocol or allocation budget")]
    Policy,
    #[error("TLSN verification did not authenticate the server and transcript")]
    Missing,
    #[error("I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("TLSN session failed")]
    Tlsn(#[from] tlsn::Error),
    #[error("invalid TLS configuration")]
    Tls(#[from] tlsn::config::tls::TlsConfigError),
    #[error("invalid MPC configuration")]
    Mpc(#[from] tlsn::config::tls_commit::mpc::MpcTlsConfigError),
    #[error("invalid TLSN prover configuration")]
    Prover(#[from] tlsn::config::prover::ProverConfigError),
    #[error("invalid TLSN verifier configuration")]
    Verifier(#[from] tlsn::config::verifier::VerifierConfigError),
    #[error("invalid TLSN disclosure configuration")]
    Prove(#[from] tlsn::config::prove::ProveConfigError),
    #[error(transparent)]
    Disclosure(#[from] DisclosureError),
}
impl std::fmt::Debug for AttestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

pub struct Request {
    domain: DnsName,
    port: u16,
    method: Method,
    bytes: Vec<u8>,
}

impl Request {
    pub(crate) fn address(&self) -> (&str, u16) {
        (self.domain.as_str(), self.port)
    }

    pub fn parse(input: &[u8]) -> Result<Self, AttestError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireRequest {
            method: String,
            url: String,
            headers: Vec<(String, String)>,
            body_base64: String,
        }
        if input.len() > MAX_REQUEST_BYTES {
            return Err(AttestError::Limit);
        }
        let WireRequest {
            method,
            url,
            headers,
            body_base64,
        } = serde_json::from_slice(input)?;
        let url = url::Url::parse(&url)?;
        if url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err(AttestError::Url);
        }
        let domain = DnsName::try_from(url.domain().ok_or(AttestError::Url)?)?;
        let method = Method::from_bytes(method.as_bytes())?;
        if method == Method::CONNECT {
            return Err(AttestError::Request);
        }
        let body = STANDARD.decode(body_base64)?;
        let port = url.port_or_known_default().ok_or(AttestError::Url)?;
        let authority = match url.port() {
            Some(port) => format!("{domain}:{port}"),
            None => domain.to_string(),
        };
        let target = &url[url::Position::BeforePath..url::Position::AfterQuery];
        let mut bytes = format!("{method} {target} HTTP/1.1\r\nhost: {authority}\r\nconnection: close\r\naccept-encoding: identity\r\ncontent-length: {}\r\n", body.len()).into_bytes();
        for (name, value) in headers {
            let name = HeaderName::from_bytes(name.as_bytes())?;
            let value = HeaderValue::from_str(&value)?;
            if matches!(
                name.as_str(),
                "host"
                    | "connection"
                    | "accept-encoding"
                    | "content-length"
                    | "transfer-encoding"
                    | "upgrade"
                    | "expect"
                    | "trailer"
                    | "te"
            ) {
                return Err(AttestError::Request);
            }
            bytes.extend_from_slice(name.as_str().as_bytes());
            bytes.extend_from_slice(b": ");
            bytes.extend_from_slice(value.as_bytes());
            bytes.extend_from_slice(b"\r\n");
        }
        bytes.extend_from_slice(b"\r\n");
        bytes.extend_from_slice(&body);
        if bytes.len() > MAX_SENT {
            return Err(AttestError::Limit);
        }
        Ok(Self {
            domain,
            port,
            method,
            bytes,
        })
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Segment {
    start: usize,
    bytes: Vec<u8>,
}
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum ReportKind {
    ProverDisclosure,
    LiveVerifierAccepted,
}
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    kind: ReportKind,
    server_name: String,
    sent_len: usize,
    received_len: usize,
    sent: Vec<Segment>,
    received: Vec<Segment>,
}

impl Report {
    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    pub(crate) fn accepted(mut self) -> Self {
        self.kind = ReportKind::LiveVerifierAccepted;
        self
    }
}

fn segments(
    bytes: &[u8],
    ranges: impl IntoIterator<Item = std::ops::Range<usize>>,
) -> Result<Vec<Segment>, AttestError> {
    ranges
        .into_iter()
        .map(|range| {
            let selected = bytes.get(range.clone()).ok_or(AttestError::Missing)?;
            Ok(Segment {
                start: range.start,
                bytes: selected.to_vec(),
            })
        })
        .collect()
}

pub async fn attest_session<T, S>(
    request: Request,
    disclosure: Disclosure,
    verifier_socket: T,
    server_socket: S,
    roots: RootCertStore,
) -> Result<(T, (Report, Vec<u8>)), AttestError>
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let session = Session::new(verifier_socket)?;
    let (driver, mut handle) = session.split();
    let operation = async {
        let prover = handle
            .new_prover(ProverConfig::builder().build()?)?
            .commit(
                MpcTlsConfig::builder()
                    .max_sent_data(MAX_SENT)
                    .max_recv_data(MAX_RECEIVED)
                    .max_recv_data_online(MAX_RECEIVED_ONLINE)
                    .build()?,
            )
            .await?;
        let server_name = ServerName::Dns(request.domain.clone());
        let (mut connection, prover) = prover.connect(
            TlsClientConfig::builder()
                .server_name(server_name)
                .root_store(roots)
                .build()?,
            server_socket,
        )?;
        let exchange = async {
            connection.write_all(&request.bytes).await?;
            connection.flush().await?;
            let received = futures::io::copy(
                &mut (&mut connection).take((MAX_RECEIVED + 1) as u64),
                &mut futures::io::sink(),
            )
            .await?;
            if received > MAX_RECEIVED as u64 {
                return Err(AttestError::Limit);
            }
            connection.close().await?;
            Ok::<_, AttestError>(())
        };
        let (mut prover, ()) =
            futures::try_join!(prover.into_future().err_into::<AttestError>(), exchange)?;
        let transcript = prover.transcript();
        let sent = disclosure::select(
            transcript.sent(),
            disclosure::Direction::Request,
            &disclosure.sent,
        )?;
        let received = disclosure::select(
            transcript.received(),
            disclosure::Direction::Response(&request.method),
            &disclosure.received,
        )?;
        let report = Report {
            kind: ReportKind::ProverDisclosure,
            server_name: request.domain.to_string(),
            sent_len: transcript.sent().len(),
            received_len: transcript.received().len(),
            sent: segments(transcript.sent(), sent.iter())?,
            received: segments(transcript.received(), received.iter())?,
        };
        let response = transcript.received().to_vec();
        let mut config = ProveConfig::builder(transcript);
        config.server_identity();
        config.reveal_sent(&sent)?;
        config.reveal_recv(&received)?;
        prover.prove(&config.build()?).await?;
        prover.close().await?;
        handle.close();
        Ok::<_, AttestError>((report, response))
    };
    futures::try_join!(driver.err_into::<AttestError>(), operation)
}

pub async fn verify_session<T>(socket: T, roots: RootCertStore) -> Result<(T, Report), AttestError>
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let session = Session::new(socket)?;
    let (driver, mut handle) = session.split();
    let operation = async {
        let verifier = handle
            .new_verifier(VerifierConfig::builder().root_store(roots).build()?)?
            .commit()
            .await?;
        let verifier = match verifier {
            VerifierCommitStart::Mpc(verifier) => verifier,
            VerifierCommitStart::Proxy(verifier) => {
                verifier.reject(Some("unsupported protocol")).await?;
                return Err(AttestError::Policy);
            }
        };
        let mpc = verifier.config();
        if mpc.max_sent_data() > MAX_SENT
            || mpc.max_recv_data() > MAX_RECEIVED
            || mpc.max_recv_data_online() > MAX_RECEIVED_ONLINE
            || mpc.max_sent_records().is_some()
            || mpc.max_recv_records_online().is_some()
            || !mpc.defer_decryption_from_start()
        {
            verifier.reject(Some("unsupported budget")).await?;
            return Err(AttestError::Policy);
        }
        let verifier = verifier.accept().await?.run().await?.verify().await?;
        if !verifier.request().server_identity() {
            return Err(AttestError::Missing);
        }
        let (output, verifier) = verifier.accept().await?;
        verifier.close().await?;
        handle.close();
        let transcript = output.transcript.ok_or(AttestError::Missing)?;
        Ok(Report {
            kind: ReportKind::LiveVerifierAccepted,
            server_name: output.server_name.ok_or(AttestError::Missing)?.to_string(),
            sent_len: transcript.len_sent(),
            received_len: transcript.len_received(),
            sent: segments(transcript.sent_unsafe(), transcript.sent_authed().iter())?,
            received: segments(
                transcript.received_unsafe(),
                transcript.received_authed().iter(),
            )?,
        })
    };
    futures::try_join!(driver.err_into::<AttestError>(), operation)
}
