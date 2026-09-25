use pest::{Parser, iterators::Pair};
use serde::Deserialize;
use std::{collections::HashSet, ops::Range};
use tlsn::rangeset::set::RangeSet;

#[derive(pest_derive::Parser)]
#[grammar = "tls/json.pest"]
struct JsonParser;

// Policy: bound HTTP metadata and parser recursion before allocating the JSON syntax tree.
const MAX_HEADERS: usize = 128;
const MAX_JSON_DEPTH: usize = 64;

#[derive(thiserror::Error)]
pub enum DisclosureError {
    #[error("HTTP I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("HTTP response exceeds the transcript budget")]
    Limit,
    #[error("invalid or unsupported HTTP framing")]
    Http,
    #[error("invalid UTF-8 or JSON")]
    Json,
    #[error("invalid UTF-8")]
    Utf8(#[from] std::str::Utf8Error),
    #[error("invalid JSON")]
    JsonSyntax(#[from] serde_json::Error),
    #[error("invalid JSON syntax")]
    Syntax(#[source] Box<pest::error::Error<Rule>>),
    #[error("invalid HTTP header selector")]
    Header(#[from] http::header::InvalidHeaderName),
    #[error("invalid HTTP syntax")]
    HttpSyntax(#[from] httparse::Error),
    #[error("invalid HTTP chunk size")]
    Chunk(httparse::InvalidChunkSize),
    #[error("invalid HTTP content length")]
    Length(#[from] std::num::ParseIntError),
    #[error("HTTP chunk size exceeds the platform limit")]
    Size(#[from] std::num::TryFromIntError),
    #[error("ambiguous JSON key or selector")]
    Ambiguous,
    #[error("disclosure selector was not found or its range is invalid")]
    Selector,
    #[error("JSON nesting exceeds the parser limit")]
    Depth,
    #[error("invalid disclosure configuration")]
    Configuration(#[source] serde_json::Error),
}

impl std::fmt::Debug for DisclosureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}
impl From<httparse::InvalidChunkSize> for DisclosureError {
    fn from(source: httparse::InvalidChunkSize) -> Self {
        Self::Chunk(source)
    }
}
impl From<pest::error::Error<Rule>> for DisclosureError {
    fn from(source: pest::error::Error<Rule>) -> Self {
        Self::Syntax(Box::new(source))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum WireSelection {
    Bytes([usize; 2]),
    StartLine,
    Header(String),
    Body,
    Json(Pointer),
}
enum Selection {
    Bytes(Range<usize>),
    StartLine,
    Header(http::HeaderName),
    Body,
    Json(Pointer),
}
#[derive(Default, Deserialize)]
#[serde(try_from = "Vec<WireSelection>")]
pub struct MessageDisclosure(Vec<Selection>);
impl TryFrom<Vec<WireSelection>> for MessageDisclosure {
    type Error = DisclosureError;
    fn try_from(input: Vec<WireSelection>) -> Result<Self, Self::Error> {
        input
            .into_iter()
            .map(|selection| {
                Ok(match selection {
                    WireSelection::Bytes([start, end]) => {
                        if start >= end {
                            return Err(DisclosureError::Selector);
                        }
                        Selection::Bytes(start..end)
                    }
                    WireSelection::StartLine => Selection::StartLine,
                    WireSelection::Header(name) => {
                        Selection::Header(http::HeaderName::from_bytes(name.as_bytes())?)
                    }
                    WireSelection::Body => Selection::Body,
                    WireSelection::Json(pointer) => Selection::Json(pointer),
                })
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Self)
    }
}

#[derive(Deserialize, PartialEq, Eq)]
#[serde(try_from = "String")]
struct Pointer(Vec<String>);
impl TryFrom<String> for Pointer {
    type Error = DisclosureError;
    fn try_from(text: String) -> Result<Self, Self::Error> {
        let mut parsed = JsonParser::parse(Rule::pointer, &text)?;
        let root = parsed.next().ok_or(DisclosureError::Selector)?;
        let tokens = root
            .into_inner()
            .filter(|part| part.as_rule() == Rule::token)
            .map(|part| part.as_str().replace("~1", "/").replace("~0", "~"))
            .collect();
        Ok(Self(tokens))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Disclosure {
    pub sent: MessageDisclosure,
    pub received: MessageDisclosure,
    #[serde(default)]
    pub commit: TranscriptSelections,
}
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TranscriptSelections {
    pub sent: MessageDisclosure,
    pub received: MessageDisclosure,
}
impl Disclosure {
    pub fn parse(bytes: &[u8]) -> Result<Self, DisclosureError> {
        match serde_json::from_slice(bytes) {
            Ok(value) => Ok(value),
            Err(source) => Err(DisclosureError::Configuration(source)),
        }
    }
}

fn check_depth(value: &serde_json::Value, depth: usize) -> Result<(), DisclosureError> {
    if depth > MAX_JSON_DEPTH {
        return Err(DisclosureError::Depth);
    }
    match value {
        serde_json::Value::Array(values) => {
            for value in values {
                check_depth(value, depth + 1)?;
            }
        }
        serde_json::Value::Object(values) => {
            for value in values.values() {
                check_depth(value, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}
type JsonFields = Vec<(Vec<String>, Range<usize>)>;

fn json_fields(bytes: &[u8], selections: &[&Pointer]) -> Result<JsonFields, DisclosureError> {
    // Bound depth before PEG parsing.
    check_depth(&serde_json::from_slice::<serde_json::Value>(bytes)?, 0)?;
    let text = std::str::from_utf8(bytes)?;
    let mut parsed = JsonParser::parse(Rule::document, text)?;
    let root = parsed.next().ok_or(DisclosureError::Json)?;
    let span = root.as_span();
    let mut pending = selections
        .iter()
        .map(|selector| selector.0.as_slice())
        .collect::<HashSet<_>>();
    let mut fields = Vec::new();
    visit(
        root,
        span.start()..span.end(),
        &mut Vec::new(),
        &mut pending,
        &mut fields,
    )?;
    if !pending.is_empty() {
        return Err(DisclosureError::Selector);
    }
    Ok(fields)
}

fn visit(
    pair: Pair<'_, Rule>,
    span: Range<usize>,
    path: &mut Vec<String>,
    pending: &mut HashSet<&[String]>,
    fields: &mut JsonFields,
) -> Result<(), DisclosureError> {
    if pending.remove(path.as_slice()) {
        fields.push((path.clone(), span));
    }
    match pair.as_rule() {
        Rule::object => {
            let mut keys = HashSet::new();
            for member in pair.into_inner() {
                let span = member.as_span();
                let mut parts = member.into_inner();
                let key = parts.next().ok_or(DisclosureError::Json)?;
                let key = serde_json::from_str::<String>(key.as_str())?;
                if !keys.insert(key.clone()) {
                    return Err(DisclosureError::Ambiguous);
                }
                let value = parts.next().ok_or(DisclosureError::Json)?;
                path.push(key);
                visit(value, span.start()..span.end(), path, pending, fields)?;
                path.pop();
            }
        }
        Rule::array => {
            for (index, value) in pair.into_inner().enumerate() {
                path.push(index.to_string());
                let span = value.as_span();
                visit(value, span.start()..span.end(), path, pending, fields)?;
                path.pop();
            }
        }
        Rule::string | Rule::number | Rule::boolean | Rule::null => {}
        _ => return Err(DisclosureError::Json),
    }
    Ok(())
}

pub struct Message {
    raw: Vec<u8>,
    start: Range<usize>,
    headers: Vec<(String, Range<usize>)>,
    body: Vec<u8>,
    chunks: Vec<(Range<usize>, Range<usize>)>,
}

fn range_in(raw: &[u8], part: &[u8]) -> Range<usize> {
    // PROOF: httparse returns borrowed slices of this same input buffer.
    let start = part.as_ptr() as usize - raw.as_ptr() as usize;
    start..start + part.len()
}

pub enum Direction<'a> {
    Request,
    Response(&'a http::Method),
}

fn start_line(raw: &[u8], start: usize) -> Result<Range<usize>, DisclosureError> {
    // httparse accepts LF and leading blank lines; disclosure requires a nonempty CRLF line.
    let length = raw
        .get(start..)
        .ok_or(DisclosureError::Http)?
        .iter()
        .position(|byte| matches!(byte, b'\r' | b'\n'))
        .ok_or(DisclosureError::Http)?;
    let end = start + length;
    if length == 0 || raw.get(end..end + 2) != Some(b"\r\n") {
        return Err(DisclosureError::Http);
    }
    Ok(start..end + 2)
}

#[derive(Clone, Copy)]
struct Lines {
    start: usize,
    scan: usize,
}
impl Lines {
    fn new(start: usize) -> Self {
        Self { start, scan: start }
    }
    fn next(&mut self, raw: &[u8]) -> Option<Range<usize>> {
        let tail = raw.get(self.scan..)?;
        let newline = tail.iter().position(|byte| *byte == b'\n');
        self.scan += newline.map_or(tail.len(), |index| index + 1);
        newline.map(|_| {
            let line = self.start..self.scan;
            self.start = self.scan;
            line
        })
    }
    fn end(&mut self, raw: &[u8]) -> Option<usize> {
        while let Some(line) = self.next(raw) {
            if matches!(raw.get(line.clone()), Some(b"\r\n" | b"\n")) {
                return Some(line.end);
            }
        }
        None
    }
}

#[derive(Clone, Copy)]
enum Phase {
    Headers {
        start: usize,
        lines: Lines,
    },
    Fixed {
        start: usize,
        end: usize,
    },
    UntilEof {
        start: usize,
    },
    ChunkSize(Lines),
    Chunk {
        start: usize,
        end: usize,
        after: usize,
    },
    Trailers {
        start: usize,
        lines: Lines,
    },
    Complete(usize),
}
struct Decoder {
    phase: Phase,
    start: Range<usize>,
    headers: Vec<(String, Range<usize>)>,
    body: Vec<u8>,
    chunks: Vec<(Range<usize>, Range<usize>)>,
}
impl Decoder {
    fn new() -> Self {
        Self {
            phase: Phase::Headers {
                start: 0,
                lines: Lines::new(0),
            },
            start: 0..0,
            headers: Vec::new(),
            body: Vec::new(),
            chunks: Vec::new(),
        }
    }
    fn payload(&mut self, raw: &[u8], wire: Range<usize>) -> Result<(), DisclosureError> {
        let payload = raw.get(wire.clone()).ok_or(DisclosureError::Http)?;
        self.chunks
            .push((self.body.len()..self.body.len() + payload.len(), wire));
        self.body.extend_from_slice(payload);
        Ok(())
    }
    fn advance(
        &mut self,
        raw: &[u8],
        direction: &Direction<'_>,
        eof: bool,
    ) -> Result<Option<usize>, DisclosureError> {
        loop {
            self.phase = match self.phase {
                Phase::Headers { start, mut lines } => {
                    let Some(end) = lines.end(raw) else {
                        self.phase = Phase::Headers { start, lines };
                        break;
                    };
                    let input = raw.get(start..end).ok_or(DisclosureError::Http)?;
                    let mut storage = [httparse::EMPTY_HEADER; MAX_HEADERS];
                    let (headers, no_body, forbidden, interim) = match direction {
                        Direction::Response(method) => {
                            let mut parsed = httparse::Response::new(&mut storage);
                            if parsed.parse(input)? != httparse::Status::Complete(input.len()) {
                                return Err(DisclosureError::Http);
                            }
                            let status = parsed.code.ok_or(DisclosureError::Http)?;
                            if status == 101
                                || (**method == http::Method::CONNECT
                                    && (200..300).contains(&status))
                            {
                                return Err(DisclosureError::Http);
                            }
                            (
                                parsed.headers,
                                **method == http::Method::HEAD || matches!(status, 204 | 304),
                                status == 204 || (100..200).contains(&status),
                                (100..200).contains(&status),
                            )
                        }
                        Direction::Request => {
                            let mut parsed = httparse::Request::new(&mut storage);
                            if parsed.parse(input)? != httparse::Status::Complete(input.len()) {
                                return Err(DisclosureError::Http);
                            }
                            (parsed.headers, false, false, false)
                        }
                    };
                    self.start = start_line(raw, start)?;
                    self.headers.clear();
                    let mut length = None;
                    let mut chunked = false;
                    for header in headers {
                        let name = header.name.to_ascii_lowercase();
                        self.headers.push((
                            name.clone(),
                            range_in(raw, header.name.as_bytes()).start
                                ..range_in(raw, header.value).end,
                        ));
                        match name.as_str() {
                            "content-length" => {
                                if forbidden
                                    || length.is_some()
                                    || header.value.is_empty()
                                    || !header.value.iter().all(u8::is_ascii_digit)
                                {
                                    return Err(DisclosureError::Http);
                                }
                                length = Some(std::str::from_utf8(header.value)?.parse::<usize>()?);
                            }
                            "transfer-encoding" => {
                                if forbidden
                                    || chunked
                                    || !header.value.eq_ignore_ascii_case(b"chunked")
                                {
                                    return Err(DisclosureError::Http);
                                }
                                chunked = true;
                            }
                            "content-encoding"
                                if !no_body
                                    && !interim
                                    && !header.value.eq_ignore_ascii_case(b"identity") =>
                            {
                                return Err(DisclosureError::Http);
                            }
                            _ => {}
                        }
                    }
                    if chunked && length.is_some() {
                        return Err(DisclosureError::Http);
                    }
                    if interim {
                        Phase::Headers {
                            start: end,
                            lines: Lines::new(end),
                        }
                    } else if no_body {
                        Phase::Complete(end)
                    } else if chunked {
                        Phase::ChunkSize(Lines::new(end))
                    } else if let Some(length) = length {
                        Phase::Fixed {
                            start: end,
                            end: end.checked_add(length).ok_or(DisclosureError::Http)?,
                        }
                    } else {
                        Phase::UntilEof { start: end }
                    }
                }
                Phase::Fixed { start, end } => {
                    if raw.len() < end {
                        break;
                    }
                    self.payload(raw, start..end)?;
                    Phase::Complete(end)
                }
                Phase::UntilEof { start } => {
                    if !eof {
                        break;
                    }
                    self.payload(raw, start..raw.len())?;
                    Phase::Complete(raw.len())
                }
                Phase::ChunkSize(mut lines) => {
                    let Some(line) = lines.next(raw) else {
                        self.phase = Phase::ChunkSize(lines);
                        break;
                    };
                    let input = raw.get(line.clone()).ok_or(DisclosureError::Http)?;
                    let httparse::Status::Complete((used, count)) =
                        httparse::parse_chunk_size(input)?
                    else {
                        return Err(DisclosureError::Http);
                    };
                    if used != input.len() {
                        return Err(DisclosureError::Http);
                    }
                    let count = usize::try_from(count)?;
                    if count == 0 {
                        Phase::Trailers {
                            start: line.end,
                            lines: Lines::new(line.end),
                        }
                    } else {
                        let end = line.end.checked_add(count).ok_or(DisclosureError::Http)?;
                        Phase::Chunk {
                            start: line.end,
                            end,
                            after: end.checked_add(2).ok_or(DisclosureError::Http)?,
                        }
                    }
                }
                Phase::Chunk { start, end, after } => {
                    if raw.len() < after {
                        break;
                    }
                    if raw.get(end..after) != Some(b"\r\n") {
                        return Err(DisclosureError::Http);
                    }
                    self.payload(raw, start..end)?;
                    Phase::ChunkSize(Lines::new(after))
                }
                Phase::Trailers { start, mut lines } => {
                    let Some(end) = lines.end(raw) else {
                        self.phase = Phase::Trailers { start, lines };
                        break;
                    };
                    let mut storage = [httparse::EMPTY_HEADER; MAX_HEADERS];
                    let input = raw.get(start..end).ok_or(DisclosureError::Http)?;
                    let httparse::Status::Complete((used, _)) =
                        httparse::parse_headers(input, &mut storage)?
                    else {
                        return Err(DisclosureError::Http);
                    };
                    if used != input.len() {
                        return Err(DisclosureError::Http);
                    }
                    Phase::Complete(end)
                }
                Phase::Complete(end) => return Ok(Some(end)),
            };
        }
        if eof {
            Err(DisclosureError::Http)
        } else {
            Ok(None)
        }
    }
    fn finish(self, mut raw: Vec<u8>, end: usize) -> Message {
        raw.truncate(end);
        Message {
            raw,
            start: self.start,
            headers: self.headers,
            body: self.body,
            chunks: self.chunks,
        }
    }
}

fn parse_http(raw: &[u8], direction: Direction<'_>) -> Result<Message, DisclosureError> {
    let mut decoder = Decoder::new();
    let end = decoder
        .advance(raw, &direction, true)?
        .ok_or(DisclosureError::Http)?;
    if end != raw.len() {
        return Err(DisclosureError::Http);
    }
    Ok(decoder.finish(raw.to_vec(), end))
}

pub async fn receive(
    reader: &mut (impl futures::AsyncRead + Unpin),
    method: &http::Method,
    limit: usize,
) -> Result<Message, DisclosureError> {
    use futures::AsyncReadExt;
    let capacity = limit.checked_add(1).ok_or(DisclosureError::Limit)?;
    let mut raw = Vec::new();
    let mut decoder = Decoder::new();
    // Policy: batch reads in a bounded stack buffer.
    const BUFFER_BYTES: usize = 4096;
    let mut buffer = [0; BUFFER_BYTES];
    loop {
        let remaining = buffer.len().min(capacity - raw.len());
        let read = reader
            .read(buffer.get_mut(..remaining).ok_or(DisclosureError::Http)?)
            .await?;
        raw.extend_from_slice(buffer.get(..read).ok_or(DisclosureError::Http)?);
        if let Some(end) = decoder.advance(&raw, &Direction::Response(method), read == 0)? {
            if end > limit {
                return Err(DisclosureError::Limit);
            }
            return Ok(decoder.finish(raw, end));
        }
        if raw.len() > limit {
            return Err(DisclosureError::Limit);
        }
    }
}

pub fn select(
    raw: &[u8],
    direction: Direction<'_>,
    config: &MessageDisclosure,
) -> Result<RangeSet<usize>, DisclosureError> {
    Ok(resolve(raw, direction, config, &MessageDisclosure::default())?.0)
}

pub fn resolve(
    raw: &[u8],
    direction: Direction<'_>,
    reveal: &MessageDisclosure,
    commit: &MessageDisclosure,
) -> Result<(RangeSet<usize>, RangeSet<usize>), DisclosureError> {
    let structured = reveal
        .0
        .iter()
        .chain(&commit.0)
        .any(|s| !matches!(s, Selection::Bytes(_)));
    let message = if structured {
        Some(parse_http(raw, direction)?)
    } else {
        None
    };
    resolve_selections(raw, message.as_ref(), reveal, commit)
}

impl Message {
    pub fn into_body(self) -> Vec<u8> {
        self.body
    }

    pub fn resolve(
        &self,
        reveal: &MessageDisclosure,
        commit: &MessageDisclosure,
    ) -> Result<(RangeSet<usize>, RangeSet<usize>), DisclosureError> {
        resolve_selections(&self.raw, Some(self), reveal, commit)
    }
}

fn resolve_selections(
    raw: &[u8],
    message: Option<&Message>,
    reveal: &MessageDisclosure,
    commit: &MessageDisclosure,
) -> Result<(RangeSet<usize>, RangeSet<usize>), DisclosureError> {
    use tlsn::rangeset::ops::Set;
    let pointers = reveal
        .0
        .iter()
        .chain(&commit.0)
        .filter_map(|s| match s {
            Selection::Json(pointer) => Some(pointer),
            _ => None,
        })
        .collect::<Vec<_>>();
    let fields = if pointers.is_empty() {
        Vec::new()
    } else {
        json_fields(&message.ok_or(DisclosureError::Http)?.body, &pointers)?
    };
    let select = |config: &MessageDisclosure| -> Result<RangeSet<usize>, DisclosureError> {
        let mut ranges = Vec::new();
        for selection in &config.0 {
            if let Selection::Bytes(range) = selection {
                raw.get(range.clone()).ok_or(DisclosureError::Selector)?;
                ranges.push(range.clone());
                continue;
            }
            let message = message.ok_or(DisclosureError::Http)?;
            match selection {
                Selection::Bytes(_) => {}
                Selection::StartLine => ranges.push(message.start.clone()),
                Selection::Header(name) => {
                    let mut matched = message
                        .headers
                        .iter()
                        .filter(|(header, _)| name.as_str().eq_ignore_ascii_case(header))
                        .peekable();
                    matched.peek().ok_or(DisclosureError::Selector)?;
                    ranges.extend(
                        matched
                            .map(|(_, range)| start_line(raw, range.start))
                            .collect::<Result<Vec<_>, _>>()?,
                    );
                }
                Selection::Body => ranges.extend(
                    message
                        .chunks
                        .iter()
                        .map(|(_, wire)| wire.clone())
                        .filter(|r| !r.is_empty()),
                ),
                Selection::Json(pointer) => {
                    let (_, field) = fields
                        .iter()
                        .find(|(path, _)| *path == pointer.0)
                        .ok_or(DisclosureError::Selector)?;
                    for (body, wire) in &message.chunks {
                        let start = body.start.max(field.start);
                        let end = body.end.min(field.end);
                        if start < end {
                            ranges.push(
                                wire.start + start - body.start..wire.start + end - body.start,
                            );
                        }
                    }
                }
            }
        }
        Ok(RangeSet::from(ranges))
    };
    let revealed = select(reveal)?;
    let committed = select(commit)?;
    if !revealed.is_disjoint(&committed) {
        return Err(DisclosureError::Ambiguous);
    }
    Ok((revealed, committed))
}
