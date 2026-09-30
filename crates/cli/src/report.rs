use crate::app::{CliError, Execution};
use proof_client_core::tls::evidence::{Evidence, RecordedEvidence};
use std::{io::Write, ops::Range};
use tlsn::{
    rangeset::set::RangeSet,
    transcript::{Direction, hash::PlaintextHash},
};

fn escaped(bytes: &[u8]) -> String {
    bytes
        .iter()
        .flat_map(|b| std::ascii::escape_default(*b))
        .map(char::from)
        .collect()
}

fn transcript(
    writer: &mut impl Write,
    direction: Direction,
    total: usize,
    segments: impl Iterator<Item = (usize, impl AsRef<[u8]>)>,
    evidence: &Evidence,
    private_text: &impl Fn(Direction, Range<usize>) -> Result<String, CliError>,
) -> Result<(), CliError> {
    let mut rows = segments
        .map(|(start, bytes)| {
            let bytes = bytes.as_ref();
            (
                start..start + bytes.len(),
                format!("revealed   \"{}\"", escaped(bytes)),
                true,
            )
        })
        .collect::<Vec<_>>();
    for (index, commitment) in evidence.commitments().iter().enumerate() {
        if commitment.direction == direction {
            rows.extend(
                commitment
                    .idx
                    .iter()
                    .map(|r| (r, format!("committed  commitment {}", index + 1), false)),
            );
        }
    }
    rows.sort_by_key(|(r, _, _)| r.start);
    let revealed = rows
        .iter()
        .filter(|(_, _, revealed)| *revealed)
        .map(|(r, _, _)| r.len())
        .sum::<usize>();
    let committed = rows
        .iter()
        .filter(|(_, _, revealed)| !*revealed)
        .map(|(r, _, _)| r.len())
        .sum::<usize>();
    writeln!(
        writer,
        "\n{direction:?}: {total} bytes; {revealed} revealed; {committed} committed; {} hidden",
        total - revealed - committed
    )?;
    let mut row = |range: Range<usize>, label: &str, revealed: bool| {
        let plaintext = if revealed {
            String::new()
        } else {
            private_text(direction, range.clone())?
        };
        writeln!(
            writer,
            "  [{}, {})  {label}{plaintext}",
            range.start, range.end
        )?;
        Ok::<_, CliError>(())
    };
    let mut end = 0;
    for (range, label, revealed) in rows {
        if end < range.start {
            row(end..range.start, "hidden", false)?;
        }
        row(range.clone(), &label, revealed)?;
        end = range.end;
    }
    if end < total {
        row(end..total, "hidden", false)?;
    }
    Ok(())
}
fn evidence(
    writer: &mut impl Write,
    evidence: &Evidence,
    private_text: impl Fn(Direction, Range<usize>) -> Result<String, CliError>,
) -> Result<(), CliError> {
    writeln!(writer, "HTTPS target: {:?}", evidence.server_name())?;
    writeln!(
        writer,
        "Scope: server identity and selected transcript bytes"
    )?;
    writeln!(
        writer,
        "JSON relationships, account ownership and freshness: not established"
    )?;
    let (sent, received) = evidence.lengths();
    transcript(
        writer,
        Direction::Sent,
        sent,
        evidence.sent(),
        evidence,
        &private_text,
    )?;
    transcript(
        writer,
        Direction::Received,
        received,
        evidence.received(),
        evidence,
        &private_text,
    )?;
    for (index, commitment) in evidence.commitments().iter().enumerate() {
        writeln!(
            writer,
            "\nCommitment {}: {:?}; blinded hash algorithm {}",
            index + 1,
            commitment.direction,
            if commitment.hash.alg == tlsn::hash::HashAlgId::BLAKE3 {
                "BLAKE3".to_owned()
            } else if commitment.hash.alg == tlsn::hash::HashAlgId::POSEIDON2_KOALABEAR_16_PAD10_V1
            {
                proof_client_core::tls::commitment::CommitmentHash::Poseidon2KoalaBear.to_string()
            } else {
                commitment.hash.alg.to_string()
            }
        )?;
        write!(writer, "  Digest: ")?;
        for byte in commitment.hash.value.as_bytes() {
            write!(writer, "{byte:02x}")?;
        }
        writeln!(writer)?;
        writeln!(
            writer,
            "  One blinded digest over its ranges in transcript order"
        )?;
    }
    Ok(())
}
fn selections(
    writer: &mut impl Write,
    selections: &proof_client_core::tls::disclosure::SelectionAudit,
    commitments: &[PlaintextHash],
) -> Result<(), CliError> {
    writeln!(
        writer,
        "\nLocal selector resolution (not verifier-authenticated JSON ancestry):"
    )?;
    writeln!(writer, "Direction  Action  Selector -> wire ranges")?;
    for (direction, action, selector, ranges) in selections.entries() {
        write!(writer, "{direction:9}  {action:6}  ")?;
        serde_json::to_writer(&mut *writer, selector)?;
        write!(writer, " ->")?;
        for range in ranges {
            write!(writer, " [{}, {})", range.start, range.end)?;
        }
        if action == "commit" {
            let selected = RangeSet::from(ranges.to_vec());
            for (index, commitment) in commitments.iter().enumerate() {
                let committed_direction = match commitment.direction {
                    Direction::Sent => "sent",
                    Direction::Received => "received",
                };
                if direction == committed_direction && selected == commitment.idx {
                    write!(writer, " -> commitment {}", index + 1)?;
                }
            }
        }
        writeln!(writer)?;
    }
    Ok(())
}

pub fn human(writer: &mut impl Write, result: &Execution) -> Result<(), CliError> {
    match result {
        Execution::Prepared { metadata, output } => {
            writeln!(
                writer,
                "Circuit contract prepared\nEntry circuit ID: {:?}",
                metadata.circuit_id().words()
            )?;
            for (path, id) in metadata.circuits() {
                writeln!(writer, "  {path:?}: {:?}", id.words())?;
            }
            for (path, id) in metadata.verifier_sets() {
                writeln!(writer, "  Verifier set {path:?}: {:?}", id.words())?;
            }
            writeln!(
                writer,
                "Record: {output:?}\nNo proof created. Prove and verify independently prepare trusted sources."
            )?;
        }
        Execution::Proved {
            output,
            circuit_id,
            public,
        } => {
            writeln!(
                writer,
                "Proof created and self-verified\nCircuit ID: {:?}\nPublic words: {:?}\nArtifact: {output:?}",
                circuit_id.words(),
                public
            )?;
            writeln!(
                writer,
                "Next: verify with independently expected public input. TLS provenance is not established."
            )?;
        }
        Execution::Verified { circuit_id, public } => {
            writeln!(
                writer,
                "Proof verified against trusted circuit and expected public input\nCircuit ID: {:?}\nPublic words: {public:?}\nTLS provenance is not established.",
                circuit_id.words()
            )?;
        }
        Execution::Served {
            receipt,
            metadata_output,
        } => {
            writeln!(writer, "Live TLS disclosure accepted")?;
            evidence(writer, receipt.metadata(), |_, _| Ok(String::new()))?;
            writeln!(
                writer,
                "\nRecord: {metadata_output:?}\nCommitment openings remain with the prover. This record is not a portable attestation."
            )?;
        }
        Execution::Attested {
            artifact,
            metadata_output,
        } => {
            writeln!(
                writer,
                "Live TLS disclosure accepted; verifier receipt matched"
            )?;
            writeln!(
                writer,
                "Local plaintext: all transcript bytes; labels describe disclosure to the verifier."
            )?;
            evidence(writer, artifact.receipt().metadata(), |direction, range| {
                let bytes = match direction {
                    Direction::Sent => artifact.transcript().sent(),
                    Direction::Received => artifact.transcript().received(),
                };
                let bytes = bytes
                    .get(range)
                    .ok_or(proof_client_core::tls::attest::AttestError::Transcript)?;
                Ok(format!(" \"{}\"", escaped(bytes)))
            })?;
            selections(
                writer,
                artifact.selections(),
                artifact.receipt().metadata().commitments(),
            )?;
            writeln!(
                writer,
                "\nPrivate record: {metadata_output:?}\nCommitment openings are stored locally. Response body: {} private bytes (use --format raw when executing to emit them).",
                artifact.response().len()
            )?;
        }
        Execution::Inspected { record, path } => {
            writeln!(
                writer,
                "Saved TLS record: {path:?}\nInspection only: contents are untrusted; live verification was not performed."
            )?;
            let commitments = match &record.evidence {
                RecordedEvidence::Complete(saved) => {
                    evidence(writer, saved, |_, _| Ok(String::new()))?;
                    saved.commitments()
                }
                RecordedEvidence::Summary {
                    server_name,
                    sent_len,
                    received_len,
                    commitments,
                } => {
                    writeln!(
                        writer,
                        "HTTPS target: {server_name:?}\nSent: {sent_len} bytes; received: {received_len} bytes\nCommitments: {}\nDisclosed segments: not recorded by this older format.",
                        commitments.len()
                    )?;
                    commitments.as_slice()
                }
            };
            if let Some(value) = &record.selections {
                selections(writer, value, commitments)?;
            }
        }
    }
    Ok(())
}
