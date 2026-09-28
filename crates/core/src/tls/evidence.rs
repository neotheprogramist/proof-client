use super::attest::{self, AttestError, Segment};
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
        Ok(Transcript::new(
            attest::redacted(
                self.sent_len,
                &self.sent,
                self.commitments
                    .iter()
                    .filter(|c| c.direction == Direction::Sent),
                attest::MAX_SENT,
            )?,
            attest::redacted(
                self.received_len,
                &self.received,
                self.commitments
                    .iter()
                    .filter(|c| c.direction == Direction::Received),
                attest::MAX_RECEIVED,
            )?,
        ))
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
        if evidence
            .sent
            .iter()
            .chain(&evidence.received)
            .any(|segment| segment.bytes.is_empty())
        {
            return Err(AttestError::Transcript.into());
        }
        evidence.redacted()?;
        let mut occupied = std::collections::HashSet::new();
        for commitment in &evidence.commitments {
            for range in commitment.idx.iter() {
                let direction = match commitment.direction {
                    Direction::Sent => 0,
                    Direction::Received => 1,
                };
                for offset in range {
                    if !occupied.insert((direction, offset)) {
                        return Err(AttestError::Transcript.into());
                    }
                }
            }
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
