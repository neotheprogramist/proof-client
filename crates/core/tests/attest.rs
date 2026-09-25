#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "direct boundary observations"
)]
#[path = "../../../examples/mbank/support/fixture.rs"]
mod fixture;
use proof_client_core::tls::attest::Request;
use serde_json::json;
#[test]
fn request_boundaries_reject_unsupported_framing_and_enforce_budget() {
    use http::{HeaderName, HeaderValue, Method};
    use proof_client_core::tls::attest::{AttestError, MAX_SENT};
    for url in [
        "http://example.com",
        "https://user:pass@example.com",
        "https://user@example.com",
        "https://:pass@example.com",
        "https://example.com/#fragment",
        "https://127.0.0.1",
    ] {
        assert!(Request::new(url, Method::GET, vec![], vec![]).is_err());
    }
    for (name, value) in [
        ("transfer-encoding", "chunked"),
        ("expect", "100-continue"),
        ("host", "evil.invalid"),
        ("content-length", "2"),
        ("accept-encoding", "gzip"),
        ("upgrade", "h2c"),
    ] {
        assert!(
            Request::new(
                "https://example.invalid",
                Method::GET,
                vec![(
                    HeaderName::from_bytes(name.as_bytes()).unwrap(),
                    HeaderValue::from_str(value).unwrap()
                )],
                vec![]
            )
            .is_err()
        );
    }
    let framing = b"GET / HTTP/1.1\r\nx: \r\nhost: example.invalid\r\n\r\n";
    for length in [MAX_SENT - 1, MAX_SENT, MAX_SENT + 1] {
        let result = Request::new(
            "https://example.invalid",
            Method::GET,
            vec![(
                HeaderName::from_static("x"),
                HeaderValue::from_str(&"v".repeat(length - framing.len())).unwrap(),
            )],
            vec![],
        );
        if length <= MAX_SENT {
            assert_eq!(result.unwrap().bytes().len(), length);
        } else {
            assert!(matches!(result, Err(AttestError::Limit)));
        }
    }
}

async fn rejected_protocol(config: impl tlsn::ProtocolConfig) {
    use proof_client_core::tls::attest::{AttestError, verify_session};
    use tlsn::{Session, config::prover::ProverConfig, webpki::RootCertStore};
    use tokio_util::compat::TokioAsyncReadCompatExt;

    let (prover, verifier) = tokio::io::duplex(4096);
    let peer = async {
        let (driver, mut handle) = Session::new(prover.compat()).unwrap().split();
        let commit = async {
            handle
                .new_prover(ProverConfig::builder().build().unwrap())?
                .commit(config)
                .await?;
            handle.close();
            Ok::<_, tlsn::Error>(())
        };
        futures::try_join!(driver, commit)
    };
    let (peer, verifier) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::join!(
            peer,
            verify_session(verifier.compat(), RootCertStore::empty())
        )
    })
    .await
    .unwrap();
    assert!(peer.is_err());
    assert!(matches!(verifier, Err(AttestError::Policy)));
}

#[tokio::test]
async fn rejects_proxy_and_each_unsupported_mpc_budget_before_setup() {
    use proof_client_core::tls::attest::{MAX_RECEIVED, MAX_SENT};
    use tlsn::config::tls_commit::{mpc::MpcTlsConfig, proxy::ProxyTlsConfig};

    let baseline = || {
        MpcTlsConfig::builder()
            .max_sent_data(MAX_SENT)
            .max_recv_data(MAX_RECEIVED)
            .max_recv_data_online(MAX_RECEIVED)
            .defer_decryption_from_start(false)
    };
    for config in [
        baseline().max_sent_data(MAX_SENT + 1),
        baseline().max_recv_data(MAX_RECEIVED + 1),
        baseline().max_recv_data_online(MAX_RECEIVED - 1),
        baseline().max_sent_records(1),
        baseline().max_recv_records_online(1),
        baseline().defer_decryption_from_start(true),
    ] {
        rejected_protocol(config.build().unwrap()).await;
    }
    rejected_protocol(
        ProxyTlsConfig::builder()
            .server_name("localhost".try_into().unwrap())
            .build()
            .unwrap(),
    )
    .await;
}

proptest::proptest! {
    #[test]
    fn redacted_transcripts_preserve_disclosed_bytes(
        sent in proptest::collection::vec((proptest::num::u8::ANY, 0u8..3), 0..256),
        received in proptest::collection::vec((proptest::num::u8::ANY, 0u8..3), 0..256)
    ) {
        use tlsn::{hash::{Blake3, Blinder}, transcript::{Direction, hash::{PlaintextHash, hash_plaintext}}};
        let sample=|bytes: &[(u8,u8)], direction| {
            let segments=bytes.iter().enumerate().filter(|(_, (_, state))| *state == 2)
                .map(|(start, (byte, _))| json!({"start":start,"bytes":[byte]})).collect::<Vec<_>>();
            let blinder: Blinder=serde_json::from_value(json!(vec![0;16])).unwrap();
            let hash=PlaintextHash {
                direction,
                idx: bytes.iter().enumerate().filter(|(_, (_, state))| *state == 1).map(|(i,_)|i..i+1).collect(),
                hash:hash_plaintext(&Blake3::default(),b"synthetic",&blinder),
            };
            let text=bytes.iter().flat_map(|(byte, state)| match state {
                0 => "🙈".as_bytes().to_vec(), 1 => "🔒".as_bytes().to_vec(), 2 => vec![*byte], _ => unreachable!(),
            }).collect::<Vec<_>>();
            (segments,hash,text)
        };
        let (sent_segments,sent_hash,sent_text)=sample(&sent,Direction::Sent);
        let (recv_segments,recv_hash,recv_text)=sample(&received,Direction::Received);
        let report: proof_client_core::tls::attest::ReportData = serde_json::from_value(json!({
            "kind":"live-verifier-accepted", "server_name":"localhost",
            "sent_len":sent.len(), "received_len":received.len(), "sent":sent_segments, "received":recv_segments, "commitments":[sent_hash,recv_hash]
        })).unwrap();
        let transcript = report.redacted().unwrap();
        proptest::prop_assert_eq!(transcript.sent(), &sent_text);
        proptest::prop_assert_eq!(transcript.received(), &recv_text);
    }
}

#[test]
fn redacted_transcripts_enforce_lengths_and_disjoint_ranges() {
    use proof_client_core::tls::attest::{AttestError, MAX_RECEIVED, MAX_SENT, ReportData};
    let boundary: ReportData = serde_json::from_value(json!({"kind":"live-verifier-accepted","server_name":"localhost","sent_len":MAX_SENT,"received_len":MAX_RECEIVED,"sent":[],"received":[],"commitments":[]})).unwrap();
    let text = boundary.redacted().unwrap();
    assert_eq!(text.sent(), "🙈".repeat(MAX_SENT).as_bytes());
    assert_eq!(text.received(), "🙈".repeat(MAX_RECEIVED).as_bytes());
    for (length, segments) in [
        (MAX_RECEIVED + 1, json!([])),
        (1, json!([{"start":2,"bytes":[]}])),
        (1, json!([{"start":0,"bytes":[1,2]}])),
        (1, json!([{"start":usize::MAX,"bytes":[1]}])),
        (
            2,
            json!([{"start":0,"bytes":[1,2]},{"start":1,"bytes":[3]}]),
        ),
    ] {
        for (direction, limit) in [("sent", MAX_SENT), ("received", MAX_RECEIVED)] {
            let mut value = json!({"kind":"live-verifier-accepted", "server_name":"localhost", "sent_len":0,"received_len":0,"sent":[],"received":[],"commitments":[]});
            value[format!("{direction}_len")] = json!(if length > MAX_RECEIVED {
                limit + 1
            } else {
                length
            });
            value[direction] = segments.clone();
            let report: ReportData = serde_json::from_value(value).unwrap();
            assert!(matches!(report.redacted(), Err(AttestError::Transcript)));
        }
    }
}

#[tokio::test]
async fn commitments_past_the_authenticated_transcript_are_rejected_without_panicking() {
    use futures::{AsyncReadExt, AsyncWriteExt, FutureExt};
    use proof_client_core::tls::{
        attest::{self, MAX_RECEIVED, MAX_SENT},
        quic,
    };
    use std::{future::IntoFuture, panic::AssertUnwindSafe};
    use tlsn::{
        Session,
        config::{
            prove::ProveConfig, prover::ProverConfig, tls::TlsClientConfig,
            tls_commit::mpc::MpcTlsConfig,
        },
        connection::ServerName,
        transcript::{Transcript, TranscriptCommitConfig},
    };
    use tokio_util::compat::TokioAsyncReadCompatExt;

    let dir = tempfile::tempdir().unwrap();
    let fixture = fixture::Fixture::bind(dir.path(), "127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let address = fixture.address().unwrap();
    let ca = std::fs::read(dir.path().join("target.pem")).unwrap();
    let (prover_socket, verifier_socket) = tokio::io::duplex(4096);
    let request = b"GET /balance HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n";
    let prover = async {
        let (driver, mut handle) = Session::new(prover_socket.compat()).unwrap().split();
        let operation = async {
            let prover = handle
                .new_prover(ProverConfig::builder().build().unwrap())?
                .commit(
                    MpcTlsConfig::builder()
                        .max_sent_data(MAX_SENT)
                        .max_recv_data(MAX_RECEIVED)
                        .max_recv_data_online(MAX_RECEIVED)
                        .defer_decryption_from_start(false)
                        .build()
                        .unwrap(),
                )
                .await?;
            let server = tokio::net::TcpStream::connect(address).await.unwrap();
            let (mut stream, prover) = prover.connect(
                TlsClientConfig::builder()
                    .server_name(ServerName::Dns("localhost".try_into().unwrap()))
                    .root_store(quic::roots(Some(&ca)).unwrap())
                    .build()
                    .unwrap(),
                server.compat(),
            )?;
            let exchange = async {
                stream.write_all(request).await.unwrap();
                stream.flush().await.unwrap();
                let mut received = Vec::new();
                stream.read_to_end(&mut received).await.unwrap();
                stream.close().await.unwrap();
            };
            let (prover, ()) = futures::join!(prover.into_future(), exchange);
            let mut prover = prover?;
            let fabricated = Transcript::new(
                vec![0; request.len() + 1],
                prover.transcript().received().to_vec(),
            );
            let mut commits = TranscriptCommitConfig::builder(&fabricated);
            commits
                .commit_sent(&(request.len()..request.len() + 1))
                .unwrap();
            let mut config = ProveConfig::builder(&fabricated);
            config
                .server_identity()
                .reveal_sent(&(0..request.len()))
                .unwrap()
                .reveal_recv(&(0..0))
                .unwrap()
                .transcript_commit(commits.build().unwrap());
            let result = prover.prove(&config.build().unwrap()).await;
            handle.close();
            result.map(|_| ())
        };
        futures::try_join!(driver, operation)
    };
    let response = fixture::response();
    let (_, verifier, observed) = tokio::time::timeout(attest::SESSION_TIMEOUT, async {
        futures::join!(
            AssertUnwindSafe(prover).catch_unwind(),
            AssertUnwindSafe(attest::verify_session(
                verifier_socket.compat(),
                quic::roots(Some(&ca)).unwrap()
            ))
            .catch_unwind(),
            fixture.serve(&response)
        )
    })
    .await
    .unwrap();
    assert_eq!(observed.unwrap(), request);
    assert!(
        verifier.is_ok(),
        "verifier panicked on a peer-supplied commitment range"
    );
    assert!(verifier.unwrap().is_err());
}
