use pest::{Parser, iterators::Pair};
use serde::{Deserialize, Serialize};
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
    #[error("transcript commitment count exceeds the session budget")]
    CommitmentLimit,
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
    JsonKey(Pointer),
    JsonValue(Pointer),
}
enum JsonPart {
    Member,
    Key,
    Value,
}
enum Selection {
    Bytes(Range<usize>),
    StartLine,
    Header(http::HeaderName),
    Body,
    Json(Pointer, JsonPart),
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
                    WireSelection::Json(pointer) => Selection::Json(pointer, JsonPart::Member),
                    WireSelection::JsonKey(pointer) => Selection::Json(pointer, JsonPart::Key),
                    WireSelection::JsonValue(pointer) => Selection::Json(pointer, JsonPart::Value),
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

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Disclosure {
    pub reveal: TranscriptSelections,
    pub commit: TranscriptSelections,
}
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
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

fn check_depth(raw: &serde_json::value::RawValue, depth: usize) -> Result<(), DisclosureError> {
    if depth > MAX_JSON_DEPTH {
        return Err(DisclosureError::Depth);
    }
    // RawValue preserves duplicate members and arbitrary-precision literals before PEG parsing.
    let children = match raw.get().as_bytes().first() {
        Some(b'[') => serde_json::from_str::<Vec<&serde_json::value::RawValue>>(raw.get())?,
        Some(b'{') => {
            struct Members;
            impl<'de> serde::de::Visitor<'de> for Members {
                type Value = Vec<&'de serde_json::value::RawValue>;
                fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str("an object")
                }
                fn visit_map<M: serde::de::MapAccess<'de>>(
                    self,
                    mut map: M,
                ) -> Result<Self::Value, M::Error> {
                    let mut values = Vec::new();
                    while let Some((_, value)) =
                        map.next_entry::<serde::de::IgnoredAny, &serde_json::value::RawValue>()?
                    {
                        values.push(value);
                    }
                    Ok(values)
                }
            }
            serde::Deserializer::deserialize_map(
                &mut serde_json::Deserializer::from_str(raw.get()),
                Members,
            )?
        }
        _ => Vec::new(),
    };
    for value in children {
        check_depth(value, depth + 1)?;
    }
    Ok(())
}
enum JsonSpan {
    Value(Range<usize>),
    Member {
        key: Range<usize>,
        value: Range<usize>,
        member: Range<usize>,
    },
}
impl JsonSpan {
    fn range(&self, part: &JsonPart) -> Result<&Range<usize>, DisclosureError> {
        match (self, part) {
            (Self::Value(_), JsonPart::Key) => Err(DisclosureError::Selector),
            (Self::Value(value), JsonPart::Value | JsonPart::Member) => Ok(value),
            (Self::Member { key, .. }, JsonPart::Key) => Ok(key),
            (Self::Member { value, .. }, JsonPart::Value) => Ok(value),
            (Self::Member { member, .. }, JsonPart::Member) => Ok(member),
        }
    }
}
type JsonFields = Vec<(Vec<String>, JsonSpan)>;

fn json_fields(bytes: &[u8], selections: &[&Pointer]) -> Result<JsonFields, DisclosureError> {
    // Bound depth before PEG parsing.
    check_depth(
        serde_json::from_slice::<&serde_json::value::RawValue>(bytes)?,
        0,
    )?;
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
        JsonSpan::Value(span.start()..span.end()),
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
    span: JsonSpan,
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
                let key_span = key.as_span();
                let key = serde_json::from_str::<String>(key.as_str())?;
                if !keys.insert(key.clone()) {
                    return Err(DisclosureError::Ambiguous);
                }
                let value = parts.next().ok_or(DisclosureError::Json)?;
                path.push(key);
                let value_span = value.as_span();
                visit(
                    value,
                    JsonSpan::Member {
                        key: key_span.start()..key_span.end(),
                        value: value_span.start()..value_span.end(),
                        member: span.start()..span.end(),
                    },
                    path,
                    pending,
                    fields,
                )?;
                path.pop();
            }
        }
        Rule::array => {
            for (index, value) in pair.into_inner().enumerate() {
                path.push(index.to_string());
                let span = value.as_span();
                visit(
                    value,
                    JsonSpan::Value(span.start()..span.end()),
                    path,
                    pending,
                    fields,
                )?;
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

fn offset_in(raw: &[u8], part: &[u8]) -> usize {
    // PROOF: httparse returns borrowed slices of this same input buffer.
    part.as_ptr() as usize - raw.as_ptr() as usize
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

enum Body {
    Interim,
    Forbidden,
    Absent,
    Present,
}
enum Framing {
    Unspecified,
    Fixed(usize),
    Chunked,
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
                    let (headers, body) = match direction {
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
                            let body = match status {
                                100..200 => Body::Interim,
                                204 => Body::Forbidden,
                                304 => Body::Absent,
                                _ if **method == http::Method::HEAD => Body::Absent,
                                _ => Body::Present,
                            };
                            (parsed.headers, body)
                        }
                        Direction::Request => {
                            let mut parsed = httparse::Request::new(&mut storage);
                            if parsed.parse(input)? != httparse::Status::Complete(input.len()) {
                                return Err(DisclosureError::Http);
                            }
                            (parsed.headers, Body::Present)
                        }
                    };
                    self.start = start_line(raw, start)?;
                    self.headers.clear();
                    let mut framing = Framing::Unspecified;
                    for header in headers {
                        let name = header.name.to_ascii_lowercase();
                        self.headers.push((
                            name.clone(),
                            start_line(raw, offset_in(raw, header.name.as_bytes()))?,
                        ));
                        match name.as_str() {
                            "content-length" => {
                                if matches!(body, Body::Interim | Body::Forbidden)
                                    || !matches!(framing, Framing::Unspecified)
                                    || header.value.is_empty()
                                    || !header.value.iter().all(u8::is_ascii_digit)
                                {
                                    return Err(DisclosureError::Http);
                                }
                                framing =
                                    Framing::Fixed(std::str::from_utf8(header.value)?.parse()?);
                            }
                            "transfer-encoding" => {
                                if matches!(body, Body::Interim | Body::Forbidden)
                                    || !matches!(framing, Framing::Unspecified)
                                    || !header.value.eq_ignore_ascii_case(b"chunked")
                                {
                                    return Err(DisclosureError::Http);
                                }
                                framing = Framing::Chunked;
                            }
                            "content-encoding"
                                if matches!(body, Body::Present)
                                    && !header.value.eq_ignore_ascii_case(b"identity") =>
                            {
                                return Err(DisclosureError::Http);
                            }
                            _ => {}
                        }
                    }
                    match (body, framing) {
                        (Body::Interim, _) => Phase::Headers {
                            start: end,
                            lines: Lines::new(end),
                        },
                        (Body::Absent | Body::Forbidden, _) => Phase::Complete(end),
                        (Body::Present, Framing::Chunked) => Phase::ChunkSize(Lines::new(end)),
                        (Body::Present, Framing::Fixed(length)) => Phase::Fixed {
                            start: end,
                            end: end.checked_add(length).ok_or(DisclosureError::Http)?,
                        },
                        (Body::Present, Framing::Unspecified) => match direction {
                            Direction::Request => Phase::Complete(end),
                            Direction::Response(_) => Phase::UntilEof { start: end },
                        },
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

#[derive(Serialize, Deserialize)]
pub struct SelectionResolution {
    selector: serde_json::Value,
    ranges: Vec<Range<usize>>,
}
#[derive(Serialize, Deserialize)]
pub struct SelectionMap {
    reveal: Vec<SelectionResolution>,
    commit: Vec<SelectionResolution>,
}
#[derive(Serialize, Deserialize)]
pub struct SelectionAudit {
    pub(super) sent: SelectionMap,
    pub(super) received: SelectionMap,
}
impl SelectionAudit {
    pub fn entries(
        &self,
    ) -> impl Iterator<Item = (&str, &str, &serde_json::Value, &[Range<usize>])> {
        [("sent", &self.sent), ("received", &self.received)]
            .into_iter()
            .flat_map(|(direction, selections)| {
                [
                    ("reveal", &selections.reveal),
                    ("commit", &selections.commit),
                ]
                .into_iter()
                .flat_map(move |(action, entries)| {
                    entries.iter().map(move |entry| {
                        (direction, action, &entry.selector, entry.ranges.as_slice())
                    })
                })
            })
    }
}
impl Selection {
    fn description(&self) -> serde_json::Value {
        use serde_json::json;
        match self {
            Self::Bytes(range) => json!({"bytes": [range.start, range.end]}),
            Self::StartLine => json!("start_line"),
            Self::Header(name) => json!({"header": name.as_str()}),
            Self::Body => json!("body"),
            Self::Json(pointer, part) => {
                let pointer = pointer
                    .0
                    .iter()
                    .map(|s| format!("/{}", s.replace('~', "~0").replace('/', "~1")))
                    .collect::<String>();
                let key = match part {
                    JsonPart::Member => "json",
                    JsonPart::Key => "json_key",
                    JsonPart::Value => "json_value",
                };
                json!({key: pointer})
            }
        }
    }
}
pub struct ResolvedDisclosure {
    revealed: RangeSet<usize>,
    committed: Vec<RangeSet<usize>>,
    selections: SelectionMap,
}
impl ResolvedDisclosure {
    pub fn into_parts(self) -> (RangeSet<usize>, Vec<RangeSet<usize>>, SelectionMap) {
        (self.revealed, self.committed, self.selections)
    }

    pub fn commitments(&self) -> &[RangeSet<usize>] {
        &self.committed
    }
}

pub fn select(
    raw: &[u8],
    direction: Direction<'_>,
    config: &MessageDisclosure,
) -> Result<RangeSet<usize>, DisclosureError> {
    Ok(resolve(raw, direction, config, &MessageDisclosure::default())?.revealed)
}

pub fn resolve(
    raw: &[u8],
    direction: Direction<'_>,
    reveal: &MessageDisclosure,
    commit: &MessageDisclosure,
) -> Result<ResolvedDisclosure, DisclosureError> {
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
    ) -> Result<ResolvedDisclosure, DisclosureError> {
        resolve_selections(&self.raw, Some(self), reveal, commit)
    }
}

fn resolve_selections(
    raw: &[u8],
    message: Option<&Message>,
    reveal: &MessageDisclosure,
    commit: &MessageDisclosure,
) -> Result<ResolvedDisclosure, DisclosureError> {
    use tlsn::rangeset::ops::Set;
    let pointers = reveal
        .0
        .iter()
        .chain(&commit.0)
        .filter_map(|s| match s {
            Selection::Json(pointer, _) => Some(pointer),
            _ => None,
        })
        .collect::<Vec<_>>();
    let fields = if pointers.is_empty() {
        Vec::new()
    } else {
        json_fields(&message.ok_or(DisclosureError::Http)?.body, &pointers)?
    };
    let select = |config: &MessageDisclosure| -> Result<_, DisclosureError> {
        let mut selections = Vec::new();
        for selection in &config.0 {
            let mut ranges = Vec::new();
            if let Selection::Bytes(range) = selection {
                raw.get(range.clone()).ok_or(DisclosureError::Selector)?;
                ranges.push(range.clone());
            } else {
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
                        ranges.extend(matched.map(|(_, range)| range.clone()));
                    }
                    Selection::Body => ranges.extend(
                        message
                            .chunks
                            .iter()
                            .map(|(_, wire)| wire.clone())
                            .filter(|r| !r.is_empty()),
                    ),
                    Selection::Json(pointer, part) => {
                        let (_, field) = fields
                            .iter()
                            .find(|(path, _)| *path == pointer.0)
                            .ok_or(DisclosureError::Selector)?;
                        let field = field.range(part)?;
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
            selections.push(SelectionResolution {
                selector: selection.description(),
                ranges,
            });
        }
        Ok(selections)
    };
    let reveal = select(reveal)?;
    let commit = select(commit)?;
    let revealed = reveal
        .iter()
        .flat_map(|s| &s.ranges)
        .collect::<RangeSet<_>>();
    let mut occupied = revealed.clone();
    let mut committed = Vec::new();
    for selection in &commit {
        let ranges = RangeSet::from(selection.ranges.clone());
        if committed.contains(&ranges) {
            continue;
        }
        if ranges.is_empty() {
            return Err(DisclosureError::Selector);
        }
        if !ranges.is_disjoint(&occupied) {
            return Err(DisclosureError::Ambiguous);
        }
        if committed.len() == super::MAX_COMMITMENTS {
            return Err(DisclosureError::CommitmentLimit);
        }
        occupied.union_mut(&ranges);
        committed.push(ranges);
    }
    Ok(ResolvedDisclosure {
        revealed,
        committed,
        selections: SelectionMap { reveal, commit },
    })
}
