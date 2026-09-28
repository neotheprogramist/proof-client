use std::{
    io::{self, Read, Write},
    process::{Child, Command, Output, Stdio},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use wait_timeout::ChildExt;

// Policy: receipts and diagnostics must each fit within one native frame.
const OUTPUT_LIMIT: usize = proof_client::stdio::MAX_FRAME_BYTES;

struct Process {
    child: Child,
    readers: Vec<JoinHandle<io::Result<Vec<u8>>>>,
    writer: Option<JoinHandle<io::Result<Option<std::process::ChildStdin>>>>,
}

impl Drop for Process {
    fn drop(&mut self) {
        if self.child.try_wait().unwrap().is_none()
            && let Err(error) = self.child.kill()
        {
            assert!(self.child.try_wait().unwrap().is_some(), "{error}");
        }
        self.child.wait().unwrap();
        if let Some(writer) = self.writer.take() {
            drop(writer.join().unwrap());
        }
        for reader in self.readers.drain(..) {
            reader.join().unwrap().unwrap();
        }
    }
}

fn drain(reader: impl Read + Send + 'static) -> JoinHandle<io::Result<Vec<u8>>> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        reader
            .take((OUTPUT_LIMIT + 1) as u64)
            .read_to_end(&mut bytes)?;
        Ok(bytes)
    })
}

pub fn run(command: &mut Command, timeout: Duration) -> io::Result<Output> {
    exchange(command, timeout, None, true)
}

pub fn exchange(
    command: &mut Command,
    timeout: Duration,
    input: Option<&[u8]>,
    close_stdin: bool,
) -> io::Result<Output> {
    let started = Instant::now();
    let mut process = Process {
        child: command
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?,
        readers: Vec::new(),
        writer: None,
    };
    process
        .readers
        .push(drain(process.child.stdout.take().unwrap()));
    process
        .readers
        .push(drain(process.child.stderr.take().unwrap()));
    if let Some(input) = input {
        let input = input.to_vec();
        let mut pipe = process.child.stdin.take().unwrap();
        process.writer = Some(thread::spawn(move || {
            pipe.write_all(&input)?;
            Ok(if close_stdin { None } else { Some(pipe) })
        }));
    }
    let status = process
        .child
        .wait_timeout(timeout.saturating_sub(started.elapsed()))?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "CLI subprocess exceeded its deadline",
            )
        })?;
    if let Some(writer) = process.writer.take() {
        drop(writer.join().unwrap()?);
    }
    let stdout = process.readers.remove(0).join().unwrap()?;
    let stderr = process.readers.remove(0).join().unwrap()?;
    if stdout.len() > OUTPUT_LIMIT || stderr.len() > OUTPUT_LIMIT {
        return Err(io::Error::new(
            io::ErrorKind::FileTooLarge,
            "CLI subprocess exceeded its output bound",
        ));
    }
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}
