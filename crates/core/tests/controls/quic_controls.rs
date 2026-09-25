#![allow(clippy::unwrap_used, reason = "direct protocol boundary observations")]
use super::*;

fn certificate() -> rcgen::CertifiedKey<rcgen::KeyPair> {
    rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap()
}

#[tokio::test]
async fn cancelling_a_connecting_verifier_closes_the_peer_without_completion() {
    let cert = certificate();
    let pem = cert.cert.pem();
    let verifier = Verifier::bind(
        "127.0.0.1:0".parse().unwrap(),
        server_config(pem.as_bytes(), cert.signing_key.serialize_pem().as_bytes()).unwrap(),
        "localhost",
        roots(None).unwrap(),
    )
    .unwrap();
    let peer = Peer::new(
        verifier.local_addr().unwrap(),
        "localhost",
        roots(Some(pem.as_bytes())).unwrap(),
    )
    .unwrap();
    let endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let connection = {
        let operation = verifier.verify();
        let connected = endpoint
            .connect_with(peer.config, peer.address, peer.name.as_str())
            .unwrap();
        let selected = tokio::time::timeout(
            Duration::from_secs(5),
            futures::future::select(connected, Box::pin(operation)),
        )
        .await
        .unwrap();
        let futures::future::Either::Left((connection, operation)) = selected else {
            unreachable!("verifier cannot finish before the client starts its session")
        };
        let connection = connection.unwrap();
        drop(operation);
        connection
    };
    let closed = tokio::time::timeout(Duration::from_secs(5), connection.closed())
        .await
        .unwrap();
    assert!(match closed {
        quinn::ConnectionError::ApplicationClosed(_) => true,
        quinn::ConnectionError::ConnectionClosed(close) =>
            close.error_code == quinn::TransportErrorCode::APPLICATION_ERROR,
        _ => false,
    });
    endpoint.wait_idle().await;
}

#[tokio::test(start_paused = true)]
async fn idle_verifier_deadline_includes_waiting_for_a_connection() {
    let cert = certificate();
    let verifier = Verifier::bind(
        "127.0.0.1:0".parse().unwrap(),
        server_config(
            cert.cert.pem().as_bytes(),
            cert.signing_key.serialize_pem().as_bytes(),
        )
        .unwrap(),
        "localhost",
        roots(None).unwrap(),
    )
    .unwrap();
    let start = tokio::time::Instant::now();
    assert!(matches!(
        verifier.verify().await,
        Err(QuicError::Timeout(_))
    ));
    assert_eq!(start.elapsed(), attest::SESSION_TIMEOUT);
}

#[tokio::test]
async fn receipt_framing_rejects_truncated_and_invalid_payloads() {
    for bytes in [
        Vec::new(),
        vec![0, 0],
        vec![0, 0, 0, 10, b'{'],
        vec![0, 0, 0, 1, b'{'],
    ] {
        assert!(matches!(
            read_frame::<WireReceipt>(&mut futures::io::Cursor::new(bytes), 10).await,
            Err(QuicError::Io(_) | QuicError::Json(_))
        ));
    }
}

#[tokio::test]
async fn verifier_topology_rejects_non_loopback_before_binding() {
    let cert = certificate();
    for address in ["0.0.0.0:0", "192.0.2.1:0", "[::]:0", "[2001:db8::1]:0"] {
        let address = address.parse().unwrap();
        assert!(matches!(
            Peer::new(address, "localhost", roots(None).unwrap()),
            Err(QuicError::Loopback)
        ));
        assert!(matches!(
            Verifier::bind(
                address,
                server_config(
                    cert.cert.pem().as_bytes(),
                    cert.signing_key.serialize_pem().as_bytes()
                )
                .unwrap(),
                "localhost",
                roots(None).unwrap()
            ),
            Err(QuicError::Loopback)
        ));
    }
}

#[tokio::test]
async fn fragmented_receipt_fits_the_transcript_budget() {
    use serde_json::json;
    let segments = |n| {
        (0..n)
            .step_by(2)
            .map(|start| json!({"start":start,"bytes":[255]}))
            .collect::<Vec<_>>()
    };
    let receipt: WireReceipt = serde_json::from_value(json!({"report":{
        "kind":"live-verifier-accepted","server_name":"localhost","sent_len":attest::MAX_SENT,"received_len":attest::MAX_RECEIVED,
        "sent":segments(attest::MAX_SENT),"received":segments(attest::MAX_RECEIVED),"commitments":[]
    }})).unwrap();
    let mut io = futures::io::Cursor::new(Vec::new());
    Frame::encode(&receipt)
        .unwrap()
        .write(&mut io)
        .await
        .unwrap();
    assert!(io.get_ref().len() > 1024 * 1024);
    io.set_position(0);
    let limit = serde_json::to_vec(&receipt).unwrap().len();
    let received: WireReceipt = read_frame(&mut io, limit).await.unwrap();
    assert_eq!(
        serde_json::to_value(received).unwrap(),
        serde_json::to_value(receipt).unwrap()
    );
}

#[tokio::test]
async fn control_frame_limits_are_enforced_before_payload_io() {
    use futures::task::{Context, Poll};
    use std::{io, pin::Pin};
    struct Prefix(futures::io::Cursor<Vec<u8>>);
    impl AsyncRead for Prefix {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bytes: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            assert!(self.0.position() < 4, "rejected frame read its payload");
            Pin::new(&mut self.0).poll_read(cx, bytes)
        }
    }
    let admitted = 10;
    for size in [0, admitted + 1, u32::MAX as usize] {
        assert!(matches!(
            read_frame::<WireReceipt>(
                &mut Prefix(futures::io::Cursor::new(
                    (size as u32).to_be_bytes().to_vec()
                )),
                admitted
            )
            .await,
            Err(QuicError::Frame)
        ));
    }
}
#[path = "../../../../examples/mbank/support/fixture.rs"]
mod fixture;
#[tokio::test]
async fn attester_rejects_each_changed_acknowledgement_field() {
    use serde_json::json;
    use std::fs;
    for changed in [
        None,
        Some(("/report/kind", json!("prover-disclosure"))),
        Some(("/report/server_name", json!("localhosx"))),
        Some(("/report/sent_len", json!(0))),
        Some(("/report/received_len", json!(0))),
        Some(("/report/sent/0/start", json!(1))),
        Some(("/report/sent/0/bytes/0", json!(0))),
        Some(("/report/received/0/start", json!(0))),
        Some(("/report/received/0/bytes/0", json!(0))),
        Some(("/report/commitments", json!([]))),
        Some(("/report/commitments/0/direction", json!("Received"))),
        Some(("/report/commitments/0/hash/value", json!(vec![0; 32]))),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let target = fixture::Fixture::bind(dir.path(), "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let cert = fs::read(dir.path().join("verifier.pem")).unwrap();
        let key = fs::read(dir.path().join("verifier.key")).unwrap();
        let target_ca = fs::read(dir.path().join("target.pem")).unwrap();
        let endpoint = Endpoint::server(
            server_config(&cert, &key).unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let peer = Peer::new(
            endpoint.local_addr().unwrap(),
            "localhost",
            roots(Some(&cert)).unwrap(),
        )
        .unwrap();
        let request = Request::new(
            &format!(
                "https://localhost:{}/balance",
                target.address().unwrap().port()
            ),
            http::Method::GET,
            vec![],
            vec![],
        )
        .unwrap();
        let disclosure =
            Disclosure::parse(br#"{"sent":[{"bytes":[0,1]}],"received":["body"],"commit":{"sent":[{"bytes":[1,2]}],"received":[]}}"#).unwrap();
        let verifier = async {
            let connection = endpoint.accept().await.unwrap().await.unwrap();
            let (send, recv) = connection.accept_bi().await.unwrap();
            let io = tokio::io::join(recv, send).compat();
            let (mut io, report) = attest::verify_session(io, roots(Some(&target_ca)).unwrap())
                .await
                .unwrap();
            let mut receipt = serde_json::to_value(Receipt { report }).unwrap();
            if let Some((path, value)) = &changed {
                *receipt.pointer_mut(path).unwrap() = value.clone();
            }
            Frame::encode(&receipt)
                .unwrap()
                .write(&mut io)
                .await
                .unwrap();
            io.close().await.unwrap();
            assert!(matches!(
                expect_end(&mut io).await,
                Ok(()) | Err(QuicError::Io(_))
            ));
            connection.close(0u8.into(), b"complete");
            endpoint.close(0u8.into(), b"complete");
            endpoint.wait_idle().await;
        };
        let response = fixture::response();
        let ((), request, result) = tokio::time::timeout(attest::SESSION_TIMEOUT, async {
            tokio::join!(
                verifier,
                target.serve(&response),
                attest(request, disclosure, peer, roots(Some(&target_ca)).unwrap())
            )
        })
        .await
        .unwrap();
        assert!(request.unwrap().starts_with(b"GET /balance HTTP/1.1\r\n"));
        if changed.is_none() {
            result.unwrap();
        } else {
            assert!(
                matches!(result, Err(QuicError::Mismatch | QuicError::Frame)),
                "{:?}",
                result.err()
            );
        }
    }
}

#[tokio::test]
async fn cancelling_active_mpc_closes_target_and_verifier_without_completion() {
    use tokio::io::AsyncReadExt;

    tokio::time::timeout(attest::SESSION_TIMEOUT, async {
        let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let cert = certificate();
        let pem = cert.cert.pem();
        let verifier = Verifier::bind(
            "127.0.0.1:0".parse().unwrap(),
            server_config(pem.as_bytes(), cert.signing_key.serialize_pem().as_bytes()).unwrap(),
            "localhost",
            roots(None).unwrap(),
        )
        .unwrap();
        let address = verifier.local_addr().unwrap();
        let peer = Peer::new(address, "localhost", roots(Some(pem.as_bytes())).unwrap()).unwrap();
        let request = Request::new(
            &format!(
                "https://localhost:{}/balance",
                target.local_addr().unwrap().port()
            ),
            http::Method::GET,
            vec![],
            vec![],
        )
        .unwrap();
        let client = async {
            let operation = Box::pin(attest(
                request,
                Disclosure::parse(br#"{"sent":[],"received":[]}"#).unwrap(),
                peer,
                roots(None).unwrap(),
            ));
            let hello = Box::pin(async {
                let (mut socket, _) = target.accept().await.unwrap();
                assert_eq!(socket.read_u8().await.unwrap(), 22);
                socket
            });
            let futures::future::Either::Left((mut socket, operation)) =
                futures::future::select(hello, operation).await
            else {
                unreachable!("MPC must reach the target handshake before completing")
            };
            drop(operation);
            let mut remaining = Vec::new();
            socket.read_to_end(&mut remaining).await.unwrap();
        };
        let ((), result) = tokio::join!(client, verifier.verify());
        assert!(result.is_err());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn cancellation_after_receipt_never_signals_success() {
    tokio::time::timeout(attest::SESSION_TIMEOUT, async {
        let dir = tempfile::tempdir().unwrap();
        let target = fixture::Fixture::bind(dir.path(), "127.0.0.1:0".parse().unwrap()).await.unwrap();
        let cert = std::fs::read(dir.path().join("verifier.pem")).unwrap();
        let key = std::fs::read(dir.path().join("verifier.key")).unwrap();
        let ca = std::fs::read(dir.path().join("target.pem")).unwrap();
        let verifier = Verifier::bind("127.0.0.1:0".parse().unwrap(), server_config(&cert, &key).unwrap(), "localhost", roots(Some(&ca)).unwrap()).unwrap();
        let peer = Peer::new(verifier.local_addr().unwrap(), "localhost", roots(Some(&cert)).unwrap()).unwrap();
        let endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let request = Request::new(&format!("https://localhost:{}/balance", target.address().unwrap().port()), http::Method::GET, vec![], vec![]).unwrap();
        let (cancel, cancelled) = futures::channel::oneshot::channel();
        let server = async {
            let futures::future::Either::Right((Ok(()), operation)) =
                futures::future::select(Box::pin(verifier.verify()), cancelled).await
            else {
                unreachable!("verifier must wait for client completion")
            };
            drop(operation);
        };
        let client = async {
            let connection = endpoint.connect_with(peer.config, peer.address, peer.name.as_str()).unwrap().await.unwrap();
            let (send, recv) = connection.open_bi().await.unwrap();
            let io = tokio::io::join(recv, send).compat();
            let target = tokio::net::TcpStream::connect(request.address()).await.unwrap().compat();
            let (mut io, session) = attest::attest_session(request, Disclosure::parse(br#"{"sent":[],"received":["body"]}"#).unwrap(), io, target, roots(Some(&ca)).unwrap()).await.unwrap();
            let expected = WireReceipt { report: session.report.accepted() };
            let receipt: WireReceipt = read_frame(&mut io, Frame::encode(&expected).unwrap().bytes.len()).await.unwrap();
            assert_eq!(receipt.report, expected.report);
            expect_end(&mut io).await.unwrap();
            cancel.send(()).unwrap();
            assert!(matches!(connection.closed().await, quinn::ConnectionError::ApplicationClosed(close) if close.error_code == 1u8.into()));
            drop(io);
            drop(connection);
            endpoint.wait_idle().await;
        };
        let response = fixture::response();
        let ((), (), served) = tokio::join!(server, client, target.serve(&response));
        assert!(served.unwrap().starts_with(b"GET /balance HTTP/1.1\r\n"));
    }).await.unwrap();
}
