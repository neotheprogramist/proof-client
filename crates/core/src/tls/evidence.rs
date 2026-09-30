use super::attest::{AttestError, MAX_RECEIVED, MAX_SENT, Segment};
use serde::{Deserialize, Serialize};
use tlsn::transcript::{Direction, hash::PlaintextHash};

// Policy: publication and inspection share one TLS record size limit.
pub const MAX_RECORD_BYTES: usize = 8 * 1024 * 1024;

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
    #[error("TLS record exceeds its size limit")]
    Limit,
    #[error("saved selector ranges are invalid or disagree with recorded evidence")]
    Selections,
    #[error("invalid saved TLS record")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Evidence(#[from] AttestError),
}
impl Record {
    pub fn parse(bytes: &[u8]) -> Result<Self, RecordError> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(RecordError::Limit);
        }
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
        for (direction, length, segments, limit) in [
            (Direction::Sent, evidence.sent_len, &evidence.sent, MAX_SENT),
            (
                Direction::Received,
                evidence.received_len,
                &evidence.received,
                MAX_RECEIVED,
            ),
        ] {
            validate_ranges(
                length,
                segments,
                evidence
                    .commitments
                    .iter()
                    .filter(|c| c.direction == direction),
                limit,
            )?;
        }
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

fn validate_ranges<'a>(
    length: usize,
    segments: &[Segment],
    commitments: impl Iterator<Item = &'a PlaintextHash>,
    limit: usize,
) -> Result<(), AttestError> {
    if length > limit {
        return Err(AttestError::Transcript);
    }
    let mut bytes = vec![false; length];
    let disclosed = segments.iter().map(|segment| {
        segment
            .start
            .checked_add(segment.bytes.len())
            .filter(|end| *end > segment.start)
            .map(|end| segment.start..end)
            .ok_or(AttestError::Transcript)
    });
    for range in commitments
        .flat_map(|c| c.idx.iter())
        .map(Ok)
        .chain(disclosed)
    {
        let occupied = bytes.get_mut(range?).ok_or(AttestError::Transcript)?;
        if occupied.contains(&true) {
            return Err(AttestError::Transcript);
        }
        occupied.fill(true);
    }
    Ok(())
}
