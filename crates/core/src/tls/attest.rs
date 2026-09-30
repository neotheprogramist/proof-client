use super::commitment::{
    CommitmentError, CommitmentHash, CommitmentPolicy, koalabear_permutations,
};
use crate::tls::disclosure::{self, Disclosure, DisclosureError};
use futures::{AsyncRead, AsyncWrite, AsyncWriteExt, TryFutureExt};
use http::{HeaderName, HeaderValue, Method};
use serde::{Deserialize, Serialize};
use std::{future::IntoFuture, time::Duration};
use tlsn::{
    Session,
    config::{
        prove::ProveConfig, prover::ProverConfig, tls::TlsClientConfig,
        tls_commit::mpc::MpcTlsConfig, verifier::VerifierConfig,
    },
    connection::{DnsName, ServerName},
    verifier::VerifierCommitStart,
};
use tlsn::{
    rangeset::ops::Set,
    transcript::{
        Direction, Transcript, TranscriptCommitConfig, TranscriptCommitment,
        TranscriptCommitmentKind, TranscriptSecret, hash::PlaintextHash,
    },
    webpki::RootCertStore,
};

// Policy: shared MPC transcript budgets.
pub const MAX_SENT: usize = 16 * 1024;
pub const MAX_RECEIVED: usize = 64 * 1024;
// Policy: bound admission and MPC work per session.
pub const SESSION_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(thiserror::Error)]
pub enum AttestError {
    #[error(transparent)]
    Commitment(#[from] CommitmentError),
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
    #[error("invalid transcript commitment configuration")]
    Commit(#[from] tlsn::transcript::TranscriptCommitConfigBuilderError),
    #[error("invalid transcript ranges or length")]
    Transcript,
    #[error("I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("TLSN session failed ({})", tlsn_category(.0))]
    Tlsn(#[from] tlsn::Error),
    #[error("{reason}; session failed while rejecting: {source}")]
    Rejection {
        reason: Box<Self>,
        #[source]
        source: Box<Self>,
    },
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
fn tlsn_category(error: &tlsn::Error) -> &'static str {
    if error.is_io() {
        "I/O"
    } else if error.is_config() {
        "configuration"
    } else if error.is_user() {
        "user/protocol"
    } else {
        "internal"
    }
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

    pub fn new(
        url: &str,
        method: Method,
        headers: Vec<(HeaderName, HeaderValue)>,
        body: Vec<u8>,
    ) -> Result<Self, AttestError> {
        let url = url::Url::parse(url)?;
        if url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err(AttestError::Url);
        }
        let domain = DnsName::try_from(url.domain().ok_or(AttestError::Url)?)?;
        if method == Method::CONNECT {
            return Err(AttestError::Request);
        }
        let port = url.port_or_known_default().ok_or(AttestError::Url)?;
        let authority = match url.port() {
            Some(port) => format!("{domain}:{port}"),
            None => domain.to_string(),
        };
        let mut host = false;
        let mut length = false;
        let target = &url[url::Position::BeforePath..url::Position::AfterQuery];
        let mut bytes = format!("{method} {target} HTTP/1.1\r\n").into_bytes();
        for (name, value) in headers {
            match name.as_str() {
                "host" => {
                    if host || !value.as_bytes().eq_ignore_ascii_case(authority.as_bytes()) {
                        return Err(AttestError::Request);
                    }
                    host = true;
                }
                "content-length" => {
                    if length || value.as_bytes() != body.len().to_string().as_bytes() {
                        return Err(AttestError::Request);
                    }
                    length = true;
                }
                "connection"
                    if value.as_bytes().eq_ignore_ascii_case(b"close")
                        || value.as_bytes().eq_ignore_ascii_case(b"keep-alive") => {}
                "accept-encoding" if value.as_bytes().eq_ignore_ascii_case(b"identity") => {}
                "connection" | "accept-encoding" | "transfer-encoding" | "upgrade" | "expect"
                | "trailer" | "te" => return Err(AttestError::Request),
                _ => {}
            }
            bytes.extend_from_slice(name.as_str().as_bytes());
            bytes.extend_from_slice(b": ");
            bytes.extend_from_slice(value.as_bytes());
            bytes.extend_from_slice(b"\r\n");
        }
        if !host {
            bytes.extend_from_slice(format!("host: {authority}\r\n").as_bytes());
        }
        if !length && !body.is_empty() {
            bytes.extend_from_slice(format!("content-length: {}\r\n", body.len()).as_bytes());
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

    pub fn server_name(&self) -> &str {
        self.domain.as_str()
    }
    pub fn method(&self) -> &Method {
        &self.method
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Segment {
    pub(super) start: usize,
    pub(super) bytes: Vec<u8>,
}
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum ReportKind {
    LiveVerifierAccepted,
}
// Retain the existing peer wire format; verification is represented by VerifiedReport.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct ReportData {
    kind: ReportKind,
    #[serde(flatten)]
    evidence: super::evidence::Evidence,
}

#[derive(Serialize)]
pub struct VerifiedReport {
    pub(super) report: ReportData,
}
impl VerifiedReport {
    pub fn evidence(&self) -> &super::evidence::Evidence {
        &self.report.evidence
    }
}

#[derive(Serialize)]
pub(super) struct Opening {
    #[serde(serialize_with = "serialize_hash_secret")]
    secret: tlsn::transcript::hash::PlaintextHashSecret,
    plaintext: Vec<u8>,
}
fn serialize_hash_secret<S: serde::Serializer>(
    secret: &tlsn::transcript::hash::PlaintextHashSecret,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_newtype_variant("TranscriptSecret", 0, "Hash", secret)
}
impl Opening {
    fn new(secret: TranscriptSecret, transcript: &Transcript) -> Result<Self, AttestError> {
        let TranscriptSecret::Hash(secret) = secret else {
            return Err(AttestError::Policy);
        };
        let bytes = match secret.direction {
            Direction::Sent => transcript.sent(),
            Direction::Received => transcript.received(),
        };
        let mut plaintext = Vec::new();
        for range in secret.idx.iter() {
            plaintext.extend_from_slice(bytes.get(range).ok_or(AttestError::Transcript)?);
        }
        Ok(Self { secret, plaintext })
    }
}

pub(super) struct ProverOutput {
    pub(super) report: ReportData,
    pub(super) transcript: Transcript,
    pub(super) openings: Vec<Opening>,
    pub(super) response: Vec<u8>,
    pub(super) selections: disclosure::SelectionAudit,
}

fn hashes(commitments: Vec<TranscriptCommitment>) -> Result<Vec<PlaintextHash>, AttestError> {
    let mut hashes = commitments
        .into_iter()
        .map(|commitment| match commitment {
            TranscriptCommitment::Hash(hash) => Ok(hash),
            _ => Err(AttestError::Policy),
        })
        .collect::<Result<Vec<_>, _>>()?;
    hashes.sort_by_key(|hash| {
        (
            match hash.direction {
                Direction::Sent => 0,
                Direction::Received => 1,
            },
            hash.idx
                .iter()
                .map(|range| (range.start, range.end))
                .collect::<Vec<_>>(),
        )
    });
    Ok(hashes)
}

fn admit_commitments(
    request: &tlsn::config::prove::ProveRequest,
    policy: CommitmentPolicy,
) -> Result<usize, AttestError> {
    let (sent, received) = request.reveal().ok_or(AttestError::Missing)?;
    let mut sent_committed = tlsn::rangeset::set::RangeSet::default();
    let mut recv_committed = tlsn::rangeset::set::RangeSet::default();
    let mut permutations = 0;
    for (index, (direction, ranges, algorithm)) in request
        .transcript_commit()
        .into_iter()
        .flat_map(|c| c.iter_hash())
        .enumerate()
    {
        let (revealed, occupied, limit) = match direction {
            Direction::Sent => (sent, &mut sent_committed, MAX_SENT),
            Direction::Received => (received, &mut recv_committed, MAX_RECEIVED),
        };
        if *algorithm != policy.hash().id()
            || index >= super::MAX_COMMITMENTS
            || ranges.is_empty()
            || ranges.end().ok_or(AttestError::Transcript)? > limit
            || !ranges.is_disjoint(revealed)
            || !ranges.is_disjoint(&*occupied)
        {
            return Err(AttestError::Policy);
        }
        occupied.union_mut(ranges);
        if let CommitmentPolicy::Poseidon2KoalaBear { max_permutations } = policy {
            permutations += koalabear_permutations(ranges.len());
            if permutations > max_permutations.get() {
                return Err(CommitmentError::Budget {
                    required: permutations,
                    limit: max_permutations,
                }
                .into());
            }
        }
    }
    Ok(permutations)
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

#[tracing::instrument(skip_all)]
pub(super) async fn attest_session<T, S>(
    request: Request,
    disclosure: Disclosure,
    verifier_socket: T,
    server_socket: S,
    roots: RootCertStore,
    commitment_hash: CommitmentHash,
) -> Result<(T, ProverOutput), AttestError>
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
                    .max_recv_data_online(MAX_RECEIVED)
                    .defer_decryption_from_start(false)
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
            let response =
                disclosure::receive(&mut connection, &request.method, MAX_RECEIVED).await?;
            connection.close().await?;
            Ok::<_, AttestError>(response)
        };
        let (mut prover, response) =
            futures::try_join!(prover.into_future().err_into::<AttestError>(), exchange)?;
        let transcript = prover.transcript();
        tracing::info!(
            phase = "response_received",
            sent_bytes = transcript.sent().len(),
            received_bytes = transcript.received().len()
        );
        let (sent, commit_sent, sent_selections) = disclosure::resolve(
            transcript.sent(),
            disclosure::Direction::Request,
            &disclosure.reveal.sent,
            &disclosure.commit.sent,
        )?
        .into_parts();
        let (received, commit_recv, received_selections) = response
            .resolve(&disclosure.reveal.received, &disclosure.commit.received)?
            .into_parts();
        if commit_sent.len() + commit_recv.len() > super::MAX_COMMITMENTS {
            return Err(DisclosureError::CommitmentLimit.into());
        }
        let selections = disclosure::SelectionAudit {
            sent: sent_selections,
            received: received_selections,
        };
        for (direction, action, selector, ranges) in selections.entries() {
            tracing::info!(phase = "selection_resolved", direction, action, selector = %selector, ?ranges);
        }
        if commitment_hash == CommitmentHash::Poseidon2KoalaBear {
            let permutations = commit_sent
                .iter()
                .chain(&commit_recv)
                .map(|r| koalabear_permutations(r.len()))
                .sum::<usize>();
            tracing::info!(
                phase = "commitment_work_required",
                koalabear_permutations = permutations
            );
        }
        tracing::info!(
            phase = "disclosure_resolved",
            sent_bytes = transcript.sent().len(),
            received_bytes = transcript.received().len(),
            revealed_sent = sent.len(),
            committed_sent = commit_sent.iter().map(|ranges| ranges.len()).sum::<usize>(),
            revealed_received = received.len(),
            committed_received = commit_recv.iter().map(|ranges| ranges.len()).sum::<usize>()
        );
        let mut commitments = TranscriptCommitConfig::builder(transcript);
        commitments.default_kind(TranscriptCommitmentKind::Hash {
            alg: commitment_hash.id(),
        });
        for ranges in &commit_sent {
            commitments.commit_sent(ranges)?;
        }
        for ranges in &commit_recv {
            commitments.commit_recv(ranges)?;
        }
        let private = transcript.clone();
        let mut config = ProveConfig::builder(transcript);
        config.server_identity();
        config.reveal_sent(&sent)?;
        config.reveal_recv(&received)?;
        config.transcript_commit(commitments.build()?);
        let output = prover.prove(&config.build()?).await?;
        let report = ReportData {
            kind: ReportKind::LiveVerifierAccepted,
            evidence: super::evidence::Evidence {
                server_name: request.domain.to_string(),
                sent_len: private.sent().len(),
                received_len: private.received().len(),
                sent: segments(private.sent(), sent.iter())?,
                received: segments(private.received(), received.iter())?,
                commitments: hashes(output.transcript_commitments)?,
            },
        };
        prover.close().await?;
        handle.close();
        let openings = output
            .transcript_secrets
            .into_iter()
            .map(|secret| Opening::new(secret, &private))
            .collect::<Result<Vec<_>, _>>()?;
        Ok::<_, AttestError>(ProverOutput {
            report,
            transcript: private,
            openings,
            selections,
            response: response.into_body(),
        })
    };
    futures::try_join!(driver.err_into::<AttestError>(), operation)
}

#[tracing::instrument(skip_all)]
pub async fn verify_session<T>(
    socket: T,
    roots: RootCertStore,
    policy: CommitmentPolicy,
) -> Result<(T, VerifiedReport), AttestError>
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let session = Session::new(socket)?;
    let (driver, mut handle) = session.split();
    // The session driver may fail while the rejection is being written.
    let mut rejection = None;
    let operation = async {
        let verifier = handle
            .new_verifier(VerifierConfig::builder().root_store(roots).build()?)?
            .commit()
            .await?;
        let verifier = match verifier {
            VerifierCommitStart::Mpc(verifier) => verifier,
            VerifierCommitStart::Proxy(verifier) => {
                rejection = Some(AttestError::Policy);
                verifier.reject(Some("unsupported protocol")).await?;
                return Err(AttestError::Policy);
            }
        };
        let mpc = verifier.config();
        if mpc.max_sent_data() > MAX_SENT
            || mpc.max_recv_data() > MAX_RECEIVED
            || mpc.max_recv_data_online() != mpc.max_recv_data()
            || mpc.max_sent_records().is_some()
            || mpc.max_recv_records_online().is_some()
            || mpc.defer_decryption_from_start()
        {
            rejection = Some(AttestError::Policy);
            verifier.reject(Some("unsupported budget")).await?;
            return Err(AttestError::Policy);
        }
        let verifier = verifier.accept().await?.run().await?.verify().await?;
        if !verifier.request().server_identity() {
            return Err(AttestError::Missing);
        }
        let permutations = match admit_commitments(verifier.request(), policy) {
            Ok(permutations) => permutations,
            Err(error) => {
                tracing::info!(phase = "commitments_rejected", reason = %error);
                rejection = Some(error);
                verifier.reject(Some("commitment policy rejected")).await?;
                return Err(AttestError::Policy);
            }
        };
        tracing::info!(phase = "commitments_admitted", commitment_hash = %policy.hash(), koalabear_permutations = permutations);
        let (output, verifier) = verifier.accept().await?;
        verifier.close().await?;
        handle.close();
        let transcript = output.transcript.ok_or(AttestError::Missing)?;
        Ok(VerifiedReport {
            report: ReportData {
                kind: ReportKind::LiveVerifierAccepted,
                evidence: super::evidence::Evidence {
                    server_name: output.server_name.ok_or(AttestError::Missing)?.to_string(),
                    sent_len: transcript.len_sent(),
                    received_len: transcript.len_received(),
                    sent: segments(transcript.sent_unsafe(), transcript.sent_authed().iter())?,
                    received: segments(
                        transcript.received_unsafe(),
                        transcript.received_authed().iter(),
                    )?,
                    commitments: hashes(output.transcript_commitments)?,
                },
            },
        })
    };
    let result = futures::try_join!(driver.err_into::<AttestError>(), operation);
    match (rejection, result) {
        (Some(reason), Err(AttestError::Policy)) => Err(reason),
        (Some(reason), Err(source)) => Err(AttestError::Rejection {
            reason: Box::new(reason),
            source: Box::new(source),
        }),
        (_, result) => result,
    }
}
