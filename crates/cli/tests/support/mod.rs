use std::process::{Output, Stdio};
use tokio::process::{Child, Command};

pub fn command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_proof-client"));
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    command
}

pub async fn finish(child: Child) -> Output {
    tokio::time::timeout(
        proof_client_core::tls::attest::SESSION_TIMEOUT,
        child.wait_with_output(),
    )
    .await
    .unwrap()
    .unwrap()
}

pub async fn output(command: &mut Command) -> Output {
    finish(command.spawn().unwrap()).await
}
