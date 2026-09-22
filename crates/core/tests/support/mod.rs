use std::{
    process::{Child, Command, Stdio},
    time::Duration,
};
use wait_timeout::ChildExt;

struct Worker(Child);
impl Drop for Worker {
    fn drop(&mut self) {
        if self.0.try_wait().unwrap().is_none() {
            self.0.kill().unwrap();
        }
        self.0.wait().unwrap();
    }
}
pub fn worker(name: &str, deadline: Duration) {
    let mut child = Worker(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--ignored", "--nocapture"])
            .env("PROOF_CLIENT_WORKER", name)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let status = child.0.wait_timeout(deadline).unwrap();
    assert!(status.is_some(), "{name} exceeded its process budget");
    assert!(status.unwrap().success(), "{name} failed");
}
