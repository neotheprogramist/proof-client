use super::attest::{AttestError, MAX_RECEIVED, MAX_SENT, Segment};
use serde::{Deserialize, Serialize};
use tlsn::transcript::{Direction, Transcript, hash::PlaintextHash};

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub(super) server_name: String,
    pub(super) sent_len: usize,
    pub(super) received_len: usize,
    pub(super) sent: Vec<Segment>,
    pub(super) received: Vec<Segment>,
    pub(super) commitments: Vec<PlaintextHash>,
}

impl Evidence {
    pub fn server_name(&self) -> &str {
        &self.server_name
    }
    pub fn lengths(&self) -> (usize, usize) {
        (self.sent_len, self.received_len)
    }
    pub fn commitments(&self) -> &[PlaintextHash] {
        &self.commitments
    }
    pub fn redacted(&self) -> Result<Transcript, AttestError> {
        let [sent, received] = self.display_bytes()?;
        Ok(Transcript::new(render(sent), render(received)))
    }
    fn display_bytes(&self) -> Result<[Vec<DisplayByte>; 2], AttestError> {
        Ok([
            display_bytes(
                self.sent_len,
                &self.sent,
                self.commitments
                    .iter()
                    .filter(|c| c.direction == Direction::Sent),
                MAX_SENT,
            )?,
            display_bytes(
                self.received_len,
                &self.received,
                self.commitments
                    .iter()
                    .filter(|c| c.direction == Direction::Received),
                MAX_RECEIVED,
            )?,
        ])
    }
    pub fn sent(&self) -> impl Iterator<Item = (usize, &[u8])> {
        self.sent.iter().map(|s| (s.start, s.bytes.as_slice()))
    }
    pub fn received(&self) -> impl Iterator<Item = (usize, &[u8])> {
        self.received.iter().map(|s| (s.start, s.bytes.as_slice()))
    }
}

#[derive(Serialize)]
#[serde(untagged)]
pub enum RecordedEvidence {
    Complete(Evidence),
    Summary {
        server_name: String,
        sent_len: usize,
        received_len: usize,
        commitments: Vec<PlaintextHash>,
    },
}

#[derive(Serialize)]
pub struct Record {
    #[serde(flatten)]
    pub evidence: RecordedEvidence,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selections: Option<super::disclosure::SelectionAudit>,
}
#[derive(Debug, thiserror::Error)]
pub enum RecordError {
    #[error("saved selector ranges are invalid or disagree with recorded evidence")]
    Selections,
    #[error("invalid saved TLS record")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Evidence(#[from] AttestError),
}
impl Record {
    pub fn parse(bytes: &[u8]) -> Result<Self, RecordError> {
        #[derive(Deserialize)]
        struct Wire {
            server_name: String,
            sent_len: usize,
            received_len: usize,
            commitments: Vec<PlaintextHash>,
            sent: Option<Vec<Segment>>,
            received: Option<Vec<Segment>>,
            selections: Option<super::disclosure::SelectionAudit>,
        }
        let wire: Wire = serde_json::from_slice(bytes)?;
        let (sent, received, complete) = match (wire.sent, wire.received) {
            (Some(sent), Some(received)) => (sent, received, true),
            (None, None) => (Vec::new(), Vec::new(), false),
            _ => return Err(AttestError::Transcript.into()),
        };
        let evidence = Evidence {
            server_name: wire.server_name,
            sent_len: wire.sent_len,
            received_len: wire.received_len,
            commitments: wire.commitments,
            sent,
            received,
        };
        evidence.display_bytes()?;
        if let Some(selections) = &wire.selections {
            selections.validate(&evidence, complete)?;
        }
        let evidence = if complete {
            RecordedEvidence::Complete(evidence)
        } else {
            RecordedEvidence::Summary {
                server_name: evidence.server_name,
                sent_len: evidence.sent_len,
                received_len: evidence.received_len,
                commitments: evidence.commitments,
            }
        };
        Ok(Self {
            evidence,
            selections: wire.selections,
        })
    }
}

// Policy: distinguish undisclosed bytes from authenticated hash commitments in text views.
const HIDDEN_BYTE: &str = "🙈";
const COMMITTED_BYTE: &str = "🔒";

#[derive(Clone, Copy)]
enum DisplayByte {
    Hidden,
    Committed,
    Disclosed(u8),
}

fn display_bytes<'a>(
    length: usize,
    segments: &[Segment],
    commitments: impl Iterator<Item = &'a PlaintextHash>,
    limit: usize,
) -> Result<Vec<DisplayByte>, AttestError> {
    if length > limit {
        return Err(AttestError::Transcript);
    }
    let mut bytes = vec![DisplayByte::Hidden; length];
    for commitment in commitments {
        for range in commitment.idx.iter() {
            for byte in bytes.get_mut(range).ok_or(AttestError::Transcript)? {
                if !matches!(byte, DisplayByte::Hidden) {
                    return Err(AttestError::Transcript);
                }
                *byte = DisplayByte::Committed;
            }
        }
    }
    for segment in segments {
        if segment.bytes.is_empty() {
            return Err(AttestError::Transcript);
        }
        let end = segment
            .start
            .checked_add(segment.bytes.len())
            .ok_or(AttestError::Transcript)?;
        let selected = bytes
            .get_mut(segment.start..end)
            .ok_or(AttestError::Transcript)?;
        for (view, byte) in selected.iter_mut().zip(&segment.bytes) {
            if !matches!(view, DisplayByte::Hidden) {
                return Err(AttestError::Transcript);
            }
            *view = DisplayByte::Disclosed(*byte);
        }
    }
    Ok(bytes)
}

fn render(bytes: Vec<DisplayByte>) -> Vec<u8> {
    let mut output = Vec::new();
    for byte in bytes {
        match byte {
            DisplayByte::Hidden => output.extend_from_slice(HIDDEN_BYTE.as_bytes()),
            DisplayByte::Committed => output.extend_from_slice(COMMITTED_BYTE.as_bytes()),
            DisplayByte::Disclosed(byte) => output.push(byte),
        }
    }
    output
}
