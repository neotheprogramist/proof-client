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
#[derive(Deserialize)]
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
fn json_fields(
    bytes: &[u8],
    selections: &[&Pointer],
) -> Result<Vec<Range<usize>>, DisclosureError> {
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
    fields: &mut Vec<Range<usize>>,
) -> Result<(), DisclosureError> {
    if pending.remove(path.as_slice()) {
        fields.push(span);
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

struct Message {
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
    Ok(start..end)
}

fn parse_http(raw: &[u8], direction: Direction<'_>) -> Result<Message, DisclosureError> {
    let (start, offset, headers, no_body, framing_forbidden) = match direction {
        Direction::Response(method) => {
            let mut start = 0;
            loop {
                let line = start_line(raw, start)?;
                let mut storage = [httparse::EMPTY_HEADER; MAX_HEADERS];
                let mut parsed = httparse::Response::new(&mut storage);
                let offset = start
                    + complete(parsed.parse(raw.get(start..).ok_or(DisclosureError::Http)?)?)?;
                let status = parsed.code.ok_or(DisclosureError::Http)?;
                if status == 101
                    || (*method == http::Method::CONNECT && (200..300).contains(&status))
                {
                    return Err(DisclosureError::Http);
                }
                if (100..200).contains(&status) {
                    if parsed.headers.iter().any(|header| {
                        header.name.eq_ignore_ascii_case("content-length")
                            || header.name.eq_ignore_ascii_case("transfer-encoding")
                    }) {
                        return Err(DisclosureError::Http);
                    }
                    start = offset;
                    continue;
                }
                break (
                    line,
                    offset,
                    parsed.headers.to_vec(),
                    *method == http::Method::HEAD || matches!(status, 204 | 304),
                    status == 204,
                );
            }
        }
        Direction::Request => {
            let mut storage = [httparse::EMPTY_HEADER; MAX_HEADERS];
            let mut parsed = httparse::Request::new(&mut storage);
            let offset = complete(parsed.parse(raw)?)?;
            (
                start_line(raw, 0)?,
                offset,
                parsed.headers.to_vec(),
                false,
                false,
            )
        }
    };
    let mut ranges = Vec::new();
    let mut length = None;
    let mut chunked = false;
    for header in headers.iter() {
        let name = header.name.to_ascii_lowercase();
        let start = range_in(raw, header.name.as_bytes()).start;
        let end = range_in(raw, header.value).end;
        ranges.push((name.clone(), start..end));
        match name.as_str() {
            "content-length" => {
                if framing_forbidden
                    || length.is_some()
                    || header.value.is_empty()
                    || !header.value.iter().all(u8::is_ascii_digit)
                {
                    return Err(DisclosureError::Http);
                }
                length = Some(std::str::from_utf8(header.value)?.parse::<usize>()?);
            }
            "transfer-encoding" => {
                if framing_forbidden || chunked || !header.value.eq_ignore_ascii_case(b"chunked") {
                    return Err(DisclosureError::Http);
                }
                chunked = true;
            }
            "content-encoding" if !no_body && !header.value.eq_ignore_ascii_case(b"identity") => {
                return Err(DisclosureError::Http);
            }
            _ => {}
        }
    }
    if chunked && length.is_some() {
        return Err(DisclosureError::Http);
    }
    let mut body = Vec::new();
    let mut chunks = Vec::new();
    if no_body {
        if offset != raw.len() {
            return Err(DisclosureError::Http);
        }
    } else if chunked {
        let mut position = offset;
        loop {
            let remaining = raw.get(position..).ok_or(DisclosureError::Http)?;
            let (prefix, count) = complete(httparse::parse_chunk_size(remaining)?)?;
            let count = usize::try_from(count)?;
            position = position.checked_add(prefix).ok_or(DisclosureError::Http)?;
            if count == 0 {
                let mut trailers = [httparse::EMPTY_HEADER; MAX_HEADERS];
                let remaining = raw.get(position..).ok_or(DisclosureError::Http)?;
                let (used, _) = complete(httparse::parse_headers(remaining, &mut trailers)?)?;
                if position + used != raw.len() {
                    return Err(DisclosureError::Http);
                }
                break;
            }
            let end = position.checked_add(count).ok_or(DisclosureError::Http)?;
            let payload = raw.get(position..end).ok_or(DisclosureError::Http)?;
            let after = end.checked_add(2).ok_or(DisclosureError::Http)?;
            if raw.get(end..after) != Some(b"\r\n") {
                return Err(DisclosureError::Http);
            }
            chunks.push((body.len()..body.len() + count, position..end));
            body.extend_from_slice(payload);
            position = after;
        }
    } else {
        let payload = raw.get(offset..).ok_or(DisclosureError::Http)?;
        if length.is_some_and(|length| length != payload.len()) {
            return Err(DisclosureError::Http);
        }
        body.extend_from_slice(payload);
        chunks.push((0..payload.len(), offset..raw.len()));
    }
    Ok(Message {
        start,
        headers: ranges,
        body,
        chunks,
    })
}

pub fn select(
    raw: &[u8],
    direction: Direction<'_>,
    config: &MessageDisclosure,
) -> Result<RangeSet<usize>, DisclosureError> {
    let config = &config.0;
    let mut ranges = Vec::new();
    for selection in config {
        if let Selection::Bytes(range) = selection {
            if raw.get(range.clone()).is_none() {
                return Err(DisclosureError::Selector);
            }
            ranges.push(range.clone());
        }
    }
    if config
        .iter()
        .any(|selection| !matches!(selection, Selection::Bytes(_)))
    {
        let message = parse_http(raw, direction)?;
        let pointers = config
            .iter()
            .filter_map(|selection| match selection {
                Selection::Json(pointer) => Some(pointer),
                _ => None,
            })
            .collect::<Vec<_>>();
        let fields = if pointers.is_empty() {
            Vec::new()
        } else {
            json_fields(&message.body, &pointers)?
        };
        for selection in config {
            match selection {
                Selection::Bytes(_) | Selection::Json(_) => {}
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
                        .filter(|range| !range.is_empty()),
                ),
            }
        }
        for field in fields {
            for (body, wire) in &message.chunks {
                let start = body.start.max(field.start);
                let end = body.end.min(field.end);
                if start < end {
                    ranges.push(wire.start + start - body.start..wire.start + end - body.start);
                }
            }
        }
    }
    Ok(RangeSet::from(ranges))
}

fn complete<T>(status: httparse::Status<T>) -> Result<T, DisclosureError> {
    match status {
        httparse::Status::Complete(value) => Ok(value),
        httparse::Status::Partial => Err(DisclosureError::Http),
    }
}
