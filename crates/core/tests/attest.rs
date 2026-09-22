#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "direct boundary observations"
)]
use proof_client_core::tls::attest::Request;
use serde_json::json;
#[test]
fn rejects_unsafe_or_ambiguous_request_boundaries() {
    let valid = json!({"url":"https://example.invalid", "method":"POST", "headers":[["cookie","SECRET"]], "body_base64":"e30="});
    assert!(Request::parse(&serde_json::to_vec(&valid).unwrap()).is_ok());
    for url in [
        "http://example.com",
        "https://user:pass@example.com",
        "https://user@example.com",
        "https://:pass@example.com",
        "https://example.com/#fragment",
    ] {
        let mut input = valid.clone();
        input["url"] = json!(url);
        assert!(Request::parse(&serde_json::to_vec(&input).unwrap()).is_err());
    }
    for (name, value) in [
        ("broken name", "x"),
        ("a", "x\r\nCookie: SECRET"),
        ("transfer-encoding", "chunked"),
        ("expect", "100-continue"),
        ("host", "evil.invalid"),
        ("content-length", "2"),
        ("connection", "keep-alive"),
        ("accept-encoding", "gzip"),
        ("upgrade", "h2c"),
    ] {
        let mut input = valid.clone();
        input["headers"] = json!([[name, value]]);
        assert!(Request::parse(&serde_json::to_vec(&input).unwrap()).is_err());
    }
    for body in ["%", "e30", "e31="] {
        let mut input = valid.clone();
        input["body_base64"] = json!(body);
        assert!(Request::parse(&serde_json::to_vec(&input).unwrap()).is_err());
    }
}
#[test]
fn request_budgets_accept_their_upper_boundaries() {
    use proof_client_core::tls::attest::{AttestError, MAX_REQUEST_BYTES, MAX_SENT};

    let framing = b"GET / HTTP/1.1\r\nhost: example.invalid\r\nconnection: close\r\naccept-encoding: identity\r\ncontent-length: 0\r\nx: \r\n\r\n";
    for length in [MAX_SENT - 1, MAX_SENT, MAX_SENT + 1] {
        let input = json!({"url":"https://example.invalid","method":"GET","headers":[["x","v".repeat(length-framing.len())]],"body_base64":""});
        let result = Request::parse(&serde_json::to_vec(&input).unwrap());
        if length <= MAX_SENT {
            assert!(result.is_ok());
        } else {
            assert!(matches!(result, Err(AttestError::Limit)));
        }
    }
    let encoded =
        br#"{"url":"https://example.invalid","method":"GET","headers":[],"body_base64":""}"#;
    for length in [
        MAX_REQUEST_BYTES,
        MAX_REQUEST_BYTES + 1,
        MAX_REQUEST_BYTES + 2,
    ] {
        let mut input = encoded.to_vec();
        input.resize(length, b' ');
        let result = Request::parse(&input);
        if length == MAX_REQUEST_BYTES {
            assert!(result.is_ok());
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
    use proof_client_core::tls::attest::{MAX_RECEIVED, MAX_RECEIVED_ONLINE, MAX_SENT};
    use tlsn::config::tls_commit::{mpc::MpcTlsConfig, proxy::ProxyTlsConfig};

    let baseline = || {
        MpcTlsConfig::builder()
            .max_sent_data(MAX_SENT)
            .max_recv_data(MAX_RECEIVED)
            .max_recv_data_online(MAX_RECEIVED_ONLINE)
    };
    for config in [
        baseline().max_sent_data(MAX_SENT + 1),
        baseline().max_recv_data(MAX_RECEIVED + 1),
        baseline().max_recv_data_online(MAX_RECEIVED_ONLINE + 1),
        baseline().max_sent_records(1),
        baseline().max_recv_records_online(1),
        baseline().defer_decryption_from_start(false),
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
