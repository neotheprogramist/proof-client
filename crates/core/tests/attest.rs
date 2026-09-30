#![allow(clippy::unwrap_used, reason = "malicious peer regression")]
#[path = "../../../examples/mbank/support/fixture.rs"]
#[allow(dead_code)]
mod fixture;
#[tokio::test]
async fn invalid_commitments_are_rejected_before_hash_proofs() {
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

    use proof_client_core::tls::commitment::CommitmentPolicy;
    use tlsn::hash::HashAlgId;
    for (algorithm, ranges, policy) in [
        (
            HashAlgId::BLAKE3,
            MAX_SENT..MAX_SENT + 1,
            CommitmentPolicy::Blake3,
        ),
        (HashAlgId::SHA256, 0..1, CommitmentPolicy::Blake3),
        (
            HashAlgId::POSEIDON2_KOALABEAR_16_PAD10_V1,
            0..1,
            CommitmentPolicy::Poseidon2KoalaBear {
                max_permutations: 2.try_into().unwrap(),
            },
        ),
    ] {
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
                    vec![0; MAX_SENT + 1],
                    prover.transcript().received().to_vec(),
                );
                let mut commits = TranscriptCommitConfig::builder(&fabricated);
                commits
                    .default_kind(tlsn::transcript::TranscriptCommitmentKind::Hash {
                        alg: algorithm,
                    })
                    .commit_sent(&ranges)
                    .unwrap();
                let mut config = ProveConfig::builder(&fabricated);
                config
                    .server_identity()
                    .reveal_sent(&(0..0))
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
                    quic::roots(Some(&ca)).unwrap(),
                    policy
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
        let result = verifier.unwrap();
        if matches!(policy, CommitmentPolicy::Poseidon2KoalaBear { .. }) {
            assert!(matches!(
                result,
                Err(attest::AttestError::Commitment(
                    proof_client_core::tls::commitment::CommitmentError::Budget { .. }
                ))
            ));
        } else if algorithm == HashAlgId::SHA256 {
            assert!(matches!(result, Err(attest::AttestError::Policy)));
        } else {
            assert!(result.is_err());
        }
    }
}
