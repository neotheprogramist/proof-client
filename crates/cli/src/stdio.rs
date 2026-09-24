// Policy: use Chrome's host output limit for both directions and both encodings.
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;

use std::io::{Read, Write};

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("cannot read native frame: {0}")]
    Read(std::io::Error),
    #[error("native frame length is outside the supported bound")]
    Length,
    #[error("cannot serialize native response: {0}")]
    Encode(#[from] serde_json::Error),
    #[error("cannot write native response: {0}")]
    Write(std::io::Error),
}

pub fn read_frame(reader: &mut impl Read) -> Result<Vec<u8>, FrameError> {
    let mut prefix = [0_u8; 4];
    if let Err(source) = reader.read_exact(&mut prefix) {
        return Err(FrameError::Read(source));
    }
    let size = u32::from_ne_bytes(prefix) as usize;
    if size == 0 || size > MAX_FRAME_BYTES {
        return Err(FrameError::Length);
    }
    let mut bytes = vec![0; size];
    if let Err(source) = reader.read_exact(&mut bytes) {
        return Err(FrameError::Read(source));
    }
    Ok(bytes)
}

struct FrameBuffer(Vec<u8>);
impl Write for FrameBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > MAX_FRAME_BYTES - self.0.len() {
            return Err(std::io::ErrorKind::FileTooLarge.into());
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn encode(value: &impl serde::Serialize) -> Result<Vec<u8>, FrameError> {
    let mut buffer = FrameBuffer(Vec::new());
    match serde_json::to_writer(&mut buffer, value) {
        Ok(()) => {}
        Err(source) if source.io_error_kind() == Some(std::io::ErrorKind::FileTooLarge) => {
            return Err(FrameError::Length);
        }
        Err(source) => return Err(FrameError::Encode(source)),
    }
    Ok(buffer.0)
}

pub fn write_frame(
    writer: &mut impl Write,
    value: &impl serde::Serialize,
) -> Result<(), FrameError> {
    let bytes = encode(value)?;
    // PROOF: bounded encoding fits u32.
    if let Err(source) = writer
        .write_all(&(bytes.len() as u32).to_ne_bytes())
        .and_then(|()| writer.write_all(&bytes))
        .and_then(|()| writer.flush())
    {
        return Err(FrameError::Write(source));
    }
    Ok(())
}

pub const PROTOCOL: &str = "proof-client/7";

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Invocation {
    protocol: String,
    args: Vec<String>,
}
#[derive(serde::Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    Ready { address: std::net::SocketAddr },
    Completed { result: serde_json::Value },
    Failed { message: String },
}
pub fn run(reader: &mut impl Read, writer: &mut impl Write) -> Result<(), FrameError> {
    let result = (|| {
        let bytes = read_frame(reader)?;
        let invocation: Invocation = serde_json::from_slice(&bytes)?;
        if invocation.protocol != PROTOCOL {
            return Err(crate::app::CliError::Invocation);
        }
        crate::app::invoke(invocation.args, |address| {
            write_frame(writer, &Event::Ready { address })?;
            Ok(())
        })
    })();
    let event = match result {
        Ok(result) => Event::Completed { result },
        Err(error) => Event::Failed {
            message: error.to_string(),
        },
    };
    write_frame(writer, &event)
}
