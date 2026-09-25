#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test observations are direct"
)]
use http::Method;
use proof_client_core::tls::disclosure::{Direction, Disclosure, DisclosureError, select};
use proptest::prelude::*;
use serde_json::json;

fn config() -> Disclosure {
    Disclosure::parse(br#"{"sent":[],"received":[{"json":"/products/0/AvailableBalance"},{"json":"/products/0/currency"}]}"#).unwrap()
}
const RESPONSE_COOKIE: &str = "session=demo-response";

fn content(body: &[u8]) -> Vec<u8> {
    let mut raw = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nSet-Cookie: {RESPONSE_COOKIE}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    raw.extend_from_slice(body);
    raw
}
fn selected(raw: &[u8]) -> Vec<u8> {
    let ranges = select(raw, Direction::Response(&Method::GET), &config().received).unwrap();
    assert!(ranges.iter().all(|range| !range.is_empty()));
    ranges.iter().flat_map(|r| raw[r].to_vec()).collect()
}
proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]
    #[test]
    fn selects_original_decimal_and_string_across_chunk_boundaries(amount in 0u64..1_000_000_000, chunk in 1usize..80) {
        let body = format!(r#"{{"products":[{{"name":"Zażółć \\"","AvailableBalance":{amount}.1200,"currency":"PLN","account":"demo-account-01"}}]}}"#).replace("\\\\\"", "\\\"");
        let body = body.as_bytes();
        let normal = content(body);
        let expected = format!(r#""AvailableBalance":{amount}.1200"currency":"PLN""#).into_bytes();
        for pointers in [
            vec!["/products/0/AvailableBalance", "/products/0/currency"],
            vec!["/products/0/currency", "/products/0/AvailableBalance"],
            vec!["/products/0/AvailableBalance", "/products/0/currency", "/products/0/AvailableBalance"],
        ] {
            let selections = pointers.into_iter().map(|pointer| json!({"json":pointer})).collect::<Vec<_>>();
            let policy = Disclosure::parse(&serde_json::to_vec(&json!({"sent":[],"received":selections})).unwrap()).unwrap();
            let visible = select(&normal, Direction::Response(&Method::GET), &policy.received).unwrap()
                .iter().flat_map(|range| normal[range].to_vec()).collect::<Vec<_>>();
            prop_assert_eq!(visible, expected.clone());
        }
        for chunk in [1, chunk] {
        let mut raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        for bytes in body.chunks(chunk) { raw.extend_from_slice(format!("{:x}\r\n", bytes.len()).as_bytes()); raw.extend_from_slice(bytes); raw.extend_from_slice(b"\r\n"); }
        raw.extend_from_slice(b"0\r\n\r\n");
        prop_assert_eq!(selected(&raw), expected.clone());
        }
    }
}
#[test]
fn ambiguous_and_invalid_inputs_fail_without_secret_diagnostics() {
    for body in [
        r#"{"products":[{"AvailableBalance":1,"AvailableBalance":2,"currency":"PLN"}]}"#,
        r#"{"products":[{"AvailableBalance":1,"\u0041vailableBalance":2,"currency":"PLN"}]}"#,
        r#"{"products":[{"AvailableBalance":1.,"currency":"PLN"}]}"#,
        r#"{"products":[{"AvailableBalance":1,"currency":"PLN"}],"hidden":{"x":1,"\u0078":2}}"#,
    ] {
        let raw = content(body.as_bytes());
        let error =
            select(&raw, Direction::Response(&Method::GET), &config().received).unwrap_err();
        assert_eq!(format!("{error:?}"), error.to_string());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{error:?}").contains(RESPONSE_COOKIE));
    }
    for response in [
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n{}".as_slice(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 2\r\n\r\n{}",
    ] {
        assert!(
            select(
                response,
                Direction::Response(&Method::GET),
                &config().received
            )
            .is_err()
        );
    }
    for variant in [json!({"unquotedPadded":[".x",32]}), json!({"unknown":".x"})] {
        assert!(
            Disclosure::parse(
                &serde_json::to_vec(&json!({"sent":[],"received":[variant]})).unwrap()
            )
            .is_err()
        );
    }
}

#[test]
fn nesting_limit_accepts_its_boundary_and_rejects_the_next_level() {
    for (open, close, selector, expected) in [
        ("[", "]", "/0", b"1".as_slice()),
        ("{\"x\":", "}", "/x", br#""x":1"#.as_slice()),
    ] {
        for depth in [64, 65] {
            let body = format!("{}1{}", open.repeat(depth), close.repeat(depth));
            let config = Disclosure::parse(
                &serde_json::to_vec(&json!({
                    "sent": [], "received": [{"json": selector.repeat(depth)}]
                }))
                .unwrap(),
            )
            .unwrap();
            let raw = content(body.as_bytes());
            let result = select(&raw, Direction::Response(&Method::GET), &config.received);
            if depth == 64 {
                let disclosed: Vec<_> = result
                    .unwrap()
                    .iter()
                    .flat_map(|r| raw[r].to_vec())
                    .collect();
                assert_eq!(disclosed, expected);
            } else {
                assert_eq!(
                    result.unwrap_err().to_string(),
                    "JSON nesting exceeds the parser limit"
                );
            }
        }
    }
}

#[test]
fn literal_keys_cannot_alias_structural_selectors() {
    for body in [
        r#"{"products[0].AvailableBalance":777,"products[0].currency":"PLN"}"#,
        r#"{"products/0/AvailableBalance":777,"products/0/currency":"PLN"}"#,
    ] {
        assert!(
            select(
                &content(body.as_bytes()),
                Direction::Response(&Method::GET),
                &config().received
            )
            .is_err()
        );
    }
    let body = br#"{"products[0].AvailableBalance":777,"products":[{"AvailableBalance":1.2300,"currency":"PLN"}],"x.y":1e999}"#;
    assert_eq!(
        selected(&content(body)),
        br#""AvailableBalance":1.2300"currency":"PLN""#
    );
    let policy = Disclosure::parse(br#"{"sent":[],"received":[{"json":"/x.y"}]}"#).unwrap();
    let raw = content(body);
    let ranges = select(&raw, Direction::Response(&Method::GET), &policy.received).unwrap();
    assert_eq!(
        ranges
            .iter()
            .flat_map(|r| raw[r].to_vec())
            .collect::<Vec<_>>(),
        br#""x.y":1e999"#
    );
}

#[test]
fn deeply_nested_input_is_rejected_before_recursive_peg_parsing() {
    // Historical stack overflow at this size, within the TLS transcript admission bound.
    let body = format!("{}0{}", "[".repeat(32_700), "]".repeat(32_700));
    assert!(
        select(
            &content(body.as_bytes()),
            Direction::Response(&Method::GET),
            &config().received
        )
        .is_err()
    );
}

#[test]
fn interim_responses_never_disclose_final_headers_or_invent_a_body() {
    let policy = Disclosure::parse(br#"{"sent":[],"received":["body"]}"#).unwrap();
    let body = b"public payload";
    for status in (100..200).filter(|status| *status != 101) {
        let mut raw = format!(
            "HTTP/1.1 {status} Interim\r\nLink: </assets/app.css>; rel=preload; as=style\r\n\r\n"
        )
        .into_bytes();
        raw.extend(content(body));
        let ranges = select(&raw, Direction::Response(&Method::GET), &policy.received).unwrap();
        assert_eq!(
            ranges
                .iter()
                .flat_map(|range| raw[range].to_vec())
                .collect::<Vec<_>>(),
            body
        );
    }
    for (method, status, metadata) in [
        (
            Method::HEAD,
            200,
            "Content-Length: 900\r\nContent-Encoding: gzip\r\n",
        ),
        (Method::HEAD, 200, "Transfer-Encoding: chunked\r\n"),
        (Method::GET, 304, "Content-Length: 900\r\n"),
        (Method::GET, 204, ""),
    ] {
        let raw =
            format!("HTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 {status} Final\r\n{metadata}\r\n");
        assert!(
            select(
                raw.as_bytes(),
                Direction::Response(&method),
                &policy.received
            )
            .unwrap()
            .is_empty()
        );
        let extra = format!("{raw}unexpected body");
        assert!(
            select(
                extra.as_bytes(),
                Direction::Response(&method),
                &policy.received
            )
            .is_err()
        );
    }
    for header in ["Content-Length: 0", "Transfer-Encoding: chunked"] {
        let mut raw = format!("HTTP/1.1 103 Early Hints\r\n{header}\r\n\r\n").into_bytes();
        raw.extend(content(body));
        assert!(select(&raw, Direction::Response(&Method::GET), &policy.received).is_err());
    }
    for (method, raw) in [
        (Method::GET, "HTTP/1.1 101 Switching Protocols\r\n\r\n"),
        (Method::CONNECT, "HTTP/1.1 200 Connected\r\n\r\n"),
        (Method::GET, "HTTP/1.1 103 Early Hints\r\n\r\n"),
    ] {
        assert!(
            select(
                raw.as_bytes(),
                Direction::Response(&method),
                &policy.received
            )
            .is_err()
        );
    }
    let policy =
        Disclosure::parse(br#"{"sent":[],"received":["start_line",{"header":"content-length"}]}"#)
            .unwrap();
    let raw = b"HTTP/1.1 103 Early Hints\r\nLink: </assets/app.css>; rel=preload; as=style\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    let ranges = select(raw, Direction::Response(&Method::GET), &policy.received).unwrap();
    assert_eq!(
        ranges
            .iter()
            .flat_map(|range| raw[range].to_vec())
            .collect::<Vec<_>>(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n"
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]
    #[test]
    fn body_selection_reveals_only_payload_for_any_body(body in proptest::collection::vec(any::<u8>(), 0..2048), chunk in 1usize..80) {
        let policy = Disclosure::parse(br#"{"sent":[],"received":["body"]}"#).unwrap();
        let mut raw = b"HTTP/1.1 200 OK\r\nSet-Cookie: session=demo-response\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        for bytes in body.chunks(chunk) { raw.extend_from_slice(format!("{:x}\r\n",bytes.len()).as_bytes());raw.extend_from_slice(bytes);raw.extend_from_slice(b"\r\n"); }
        raw.extend_from_slice(b"0\r\nX-Trace-Id: demo-trace-01\r\n\r\n");
        for response in [content(&body), raw] {
            let ranges=select(&response,Direction::Response(&Method::GET),&policy.received).unwrap();
            let visible=ranges.iter().flat_map(|range|response[range].to_vec()).collect::<Vec<_>>();
            prop_assert_eq!(&visible,&body);
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]
    #[test]
    fn explicit_ranges_merge_without_disclosing_gaps(raw in proptest::collection::vec(any::<u8>(), 8..512), intervals in proptest::collection::vec((0usize..512, 0usize..512), 0..64)) {
        let intervals = intervals.into_iter().map(|(a,b)| {
            let (a,b)=(a%raw.len(),b%raw.len()); [a.min(b), a.max(b)+1]
        }).collect::<Vec<_>>();
        for ranges in [vec![[0,2],[4,6]], intervals] {
            let selections=ranges.iter().map(|range|json!({"bytes":range})).collect::<Vec<_>>();
            let policy=Disclosure::parse(&serde_json::to_vec(&json!({"sent":selections,"received":selections})).unwrap()).unwrap();
            let expected=(0..raw.len()).filter(|i| ranges.iter().any(|[a,b]| a<=i && i<b)).collect::<Vec<_>>();
            for (direction, selection) in [(Direction::Request,&policy.sent),(Direction::Response(&Method::GET),&policy.received)] {
                let actual=select(&raw,direction,selection).unwrap();
                prop_assert_eq!(actual.iter().flatten().collect::<Vec<_>>(),expected.clone());
            }
        }
        for range in [[1,0],[raw.len(),raw.len()+1],[0,0]] {
            let value=serde_json::to_vec(&json!({"sent":[{"bytes":range}],"received":[]})).unwrap();
            prop_assert!(Disclosure::parse(&value).and_then(|policy|select(&raw,Direction::Request,&policy.sent)).is_err());
        }
    }
}
#[test]
fn json_pointers_preserve_literal_keys_root_and_array_indices() {
    let raw = content(br#"{"a/b":{"~key":[1e999]},"":{"~1":42.1200},"01":true}"#);
    for (pointer, expected) in [
        ("/a~1b/~0key/0", b"1e999".as_slice()),
        ("//~01", br#""~1":42.1200"#.as_slice()),
        ("/01", br#""01":true"#.as_slice()),
        (
            "",
            br#"{"a/b":{"~key":[1e999]},"":{"~1":42.1200},"01":true}"#.as_slice(),
        ),
    ] {
        let policy = Disclosure::parse(
            &serde_json::to_vec(&json!({"sent":[],"received":[{"json":pointer}]})).unwrap(),
        )
        .unwrap();
        let result = select(&raw, Direction::Response(&Method::GET), &policy.received)
            .unwrap()
            .iter()
            .flat_map(|range| raw[range].to_vec())
            .collect::<Vec<_>>();
        assert_eq!(result, expected);
    }
    for pointer in ["a", "/~", "/~2", "/a~1b/~0key/01", "/a~1b/~0key/-"] {
        let encoded =
            serde_json::to_vec(&json!({"sent":[],"received":[{"json":pointer}]})).unwrap();
        assert!(
            Disclosure::parse(&encoded)
                .and_then(|policy| select(
                    &raw,
                    Direction::Response(&Method::GET),
                    &policy.received
                ))
                .is_err()
        );
    }
}
#[test]
fn framing_enforces_lengths_and_content_encoding() {
    let policy = Disclosure::parse(br#"{"sent":[],"received":["start_line"]}"#).unwrap();
    for encoding in ["identity", "IDENTITY", "gzip", "br"] {
        let raw = format!(
            "HTTP/1.1 200 OK\r\nContent-Encoding: {encoding}\r\nContent-Length: 1\r\n\r\nx"
        );
        let result = select(
            raw.as_bytes(),
            Direction::Response(&Method::GET),
            &policy.received,
        );
        if encoding.eq_ignore_ascii_case("identity") {
            assert!(result.is_ok());
        } else {
            assert!(matches!(result, Err(DisclosureError::Http)));
        }
    }
    for encoding in [
        "gzip",
        "gzip, chunked",
        "chunked\r\nTransfer-Encoding: chunked",
    ] {
        let raw = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: {encoding}\r\n\r\n0\r\n\r\n");
        assert!(
            select(
                raw.as_bytes(),
                Direction::Response(&Method::GET),
                &policy.received
            )
            .is_err()
        );
    }
    for (method, status) in [
        (Method::GET, 200),
        (Method::HEAD, 200),
        (Method::GET, 304),
        (Method::GET, 204),
    ] {
        for length in ["+2", "-0", "", "2,2", "999999999999999999999999999999"] {
            let raw = format!("HTTP/1.1 {status} Response\r\nContent-Length: {length}\r\n\r\n");
            assert!(
                select(
                    raw.as_bytes(),
                    Direction::Response(&method),
                    &policy.received
                )
                .is_err(),
                "{method} {status} {length}"
            );
        }
    }
    for metadata in [
        "Content-Length: 0",
        "Content-Length: 2",
        "Transfer-Encoding: chunked",
    ] {
        let raw = format!("HTTP/1.1 204 No Content\r\n{metadata}\r\n\r\n");
        assert!(
            select(
                raw.as_bytes(),
                Direction::Response(&Method::GET),
                &policy.received
            )
            .is_err()
        );
    }
}

#[test]
fn start_lines_cannot_disclose_headers_or_silently_select_nothing() {
    let policy =
        Disclosure::parse(br#"{"sent":["start_line"],"received":["start_line"]}"#).unwrap();
    for prefix in [
        "",
        "HTTP/1.1 103 Early Hints\r\nLink: </assets/app.css>; rel=preload; as=style\r\n\r\n",
    ] {
        for leading in ["", "\r\n", "\n"] {
            for ending in ["\r\n", "\n"] {
                for response in [false, true] {
                    let line = if response {
                        "HTTP/1.1 200 OK"
                    } else {
                        "GET / HTTP/1.1"
                    };
                    let prefix = if response { prefix } else { "" };
                    let raw = format!(
                        "{prefix}{leading}{line}{ending}X-Request-Id: demo-request-01\r\n\r\n"
                    );
                    let direction = if response {
                        Direction::Response(&Method::GET)
                    } else {
                        Direction::Request
                    };
                    let result = select(raw.as_bytes(), direction, &policy.received);
                    if leading.is_empty() && ending == "\r\n" {
                        let ranges = result.unwrap();
                        assert_eq!(
                            ranges.iter().collect::<Vec<_>>(),
                            vec![prefix.len()..prefix.len() + line.len() + ending.len()]
                        );
                    } else {
                        assert!(result.is_err(), "{raw:?}");
                    }
                }
            }
        }
    }
    for interim in [
        "HTTP/1.1 103 Early Hints\nLink: </assets/app.css>; rel=preload; as=style\r\n\r\n",
        "\r\nHTTP/1.1 103 Early Hints\r\n\r\n",
    ] {
        let raw = format!("{interim}HTTP/1.1 200 OK\r\n\r\n");
        assert!(
            select(
                raw.as_bytes(),
                Direction::Response(&Method::GET),
                &policy.received
            )
            .is_err()
        );
    }
}

struct FragmentedHttp<'a> {
    bytes: &'a [u8],
    chunk: usize,
    eof: bool,
}
impl futures::AsyncRead for FragmentedHttp<'_> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        output: &mut [u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        if self.bytes.is_empty() && !self.eof {
            return std::task::Poll::Pending;
        }
        let size = self.chunk.min(output.len()).min(self.bytes.len());
        output[..size].copy_from_slice(&self.bytes[..size]);
        self.bytes = &self.bytes[size..];
        std::task::Poll::Ready(Ok(size))
    }
}

proptest::proptest! {
    #[test]
    fn framed_responses_finish_without_eof_and_preserve_body(
        body in proptest::collection::vec(proptest::num::u8::ANY, 0..2048),
        fragment in 1usize..128,
        chunk in 1usize..80,
    ) {
        use futures::FutureExt;
        for chunked in [false, true] {
            let mut raw = b"HTTP/1.1 103 Early Hints\r\nLink: </app.css>\r\n\r\nHTTP/1.1 200 OK\r\nConnection: keep-alive\r\n".to_vec();
            if chunked {
                raw.extend_from_slice(b"Transfer-Encoding: chunked\r\n\r\n");
                for part in body.chunks(chunk) {
                    raw.extend_from_slice(format!("{:x}\r\n", part.len()).as_bytes());
                    raw.extend_from_slice(part);
                    raw.extend_from_slice(b"\r\n");
                }
                raw.extend_from_slice(b"0\r\nX-Trailer: value\r\n\r\n");
            } else {
                raw.extend_from_slice(format!("Content-Length: {}\r\n\r\n",body.len()).as_bytes());
                raw.extend_from_slice(&body);
            }
            let mut reader = FragmentedHttp { bytes: &raw, chunk: fragment, eof: false };
            let result = proof_client_core::tls::disclosure::receive(&mut reader,&http::Method::GET,raw.len()).now_or_never().unwrap().unwrap();
            proptest::prop_assert_eq!(result.into_body(), body.clone());
            let mut reader = FragmentedHttp { bytes: &raw, chunk: fragment, eof: true };
            proptest::prop_assert!(proof_client_core::tls::disclosure::receive(&mut reader,&http::Method::GET,raw.len()-1).now_or_never().unwrap().is_err());
        }
    }
}

#[test]
fn bodyless_and_close_delimited_responses_observe_their_boundaries() {
    use futures::FutureExt;
    for (method, raw, body) in [
        (
            http::Method::HEAD,
            b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n".as_slice(),
            b"".as_slice(),
        ),
        (
            http::Method::GET,
            b"HTTP/1.1 204 No Content\r\n\r\n".as_slice(),
            b"".as_slice(),
        ),
        (
            http::Method::GET,
            b"HTTP/1.1 304 Not Modified\r\nContent-Length: 100\r\n\r\n".as_slice(),
            b"".as_slice(),
        ),
        (
            http::Method::GET,
            b"HTTP/1.1 401 Unauthorized\r\n\r\ndenied".as_slice(),
            b"denied".as_slice(),
        ),
    ] {
        for fragment in 1..=raw.len() {
            let mut reader = FragmentedHttp {
                bytes: raw,
                chunk: fragment,
                eof: body.is_empty(),
            };
            if !body.is_empty() {
                assert!(
                    proof_client_core::tls::disclosure::receive(&mut reader, &method, raw.len())
                        .now_or_never()
                        .is_none()
                );
                reader.bytes = raw;
                reader.eof = true;
            }
            let result =
                proof_client_core::tls::disclosure::receive(&mut reader, &method, raw.len())
                    .now_or_never()
                    .unwrap()
                    .unwrap();
            assert_eq!(result.into_body(), body);
        }
    }
    for raw in [
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabc".as_slice(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n".as_slice(),
    ] {
        let mut reader = FragmentedHttp {
            bytes: raw,
            chunk: 2,
            eof: true,
        };
        assert!(
            proof_client_core::tls::disclosure::receive(&mut reader, &http::Method::GET, raw.len())
                .now_or_never()
                .unwrap()
                .is_err()
        );
    }
}

#[test]
fn surplus_after_one_response_is_independent_of_read_boundaries() {
    use futures::FutureExt;
    for (method, response, body) in [
        (
            Method::GET,
            "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA",
            "A",
        ),
        (
            Method::GET,
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nA\r\n0\r\n\r\n",
            "A",
        ),
        (
            Method::HEAD,
            "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n",
            "",
        ),
        (Method::GET, "HTTP/1.1 204 No Content\r\n\r\n", ""),
    ] {
        let raw = format!("{response}HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nsecret");
        for chunk in 1..=raw.len() {
            let mut reader = FragmentedHttp {
                bytes: raw.as_bytes(),
                chunk,
                eof: false,
            };
            let message =
                proof_client_core::tls::disclosure::receive(&mut reader, &method, response.len())
                    .now_or_never()
                    .unwrap()
                    .unwrap();
            let policy =
                Disclosure::parse(br#"{"sent":[],"received":["start_line","body"]}"#).unwrap();
            let (ranges, _) = message
                .resolve(&policy.received, &policy.commit.received)
                .unwrap();
            assert!(ranges.iter().all(|range| range.end <= response.len()));
            assert_eq!(message.into_body(), body.as_bytes());
        }
    }
}
