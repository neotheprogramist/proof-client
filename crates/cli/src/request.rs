use clap::Args;
use http::{HeaderName, HeaderValue, Method};
use proof_client_core::tls::attest::{AttestError, Request};

#[derive(Args)]
pub struct RequestArgs {
    #[arg(long, required_unless_present = "target", conflicts_with = "target")]
    url: Option<String>,
    #[arg(value_name = "URL")]
    target: Option<String>,
    #[arg(short = 'X', long)]
    request: Option<String>,
    #[arg(short = 'H', long, allow_hyphen_values = true)]
    header: Vec<String>,
    #[arg(short = 'b', long, allow_hyphen_values = true)]
    cookie: Vec<String>,
    #[arg(long, allow_hyphen_values = true)]
    data_raw: Vec<String>,
}

impl RequestArgs {
    pub fn parse(self) -> Result<Request, AttestError> {
        let url = self.url.or(self.target).ok_or(AttestError::Url)?;
        let has_data = !self.data_raw.is_empty();
        let body = self
            .data_raw
            .into_iter()
            .fold(Vec::new(), |mut body, part| {
                if !body.is_empty() {
                    body.push(b'&');
                }
                body.extend_from_slice(part.as_bytes());
                body
            });
        let method = match self.request {
            Some(method) => Method::from_bytes(method.as_bytes())?,
            None if has_data => Method::POST,
            None => Method::GET,
        };
        let mut headers = Vec::new();
        let mut overridden = std::collections::HashSet::new();
        for header in self.header {
            let (name, value) = if let Some((name, value)) = header.split_once(':') {
                (name, value.trim_matches([' ', '\t']))
            } else if let Some(name) = header.strip_suffix(';') {
                let name = HeaderName::from_bytes(name.as_bytes())?;
                overridden.insert(name.clone());
                headers.push((name, HeaderValue::from_static("")));
                continue;
            } else {
                return Err(AttestError::Request);
            };
            let name = HeaderName::from_bytes(name.as_bytes())?;
            overridden.insert(name.clone());
            let value = HeaderValue::from_str(value)?;
            if value.is_empty() {
                if matches!(name.as_str(), "host" | "content-length") {
                    return Err(AttestError::Request);
                }
            } else {
                headers.push((name, value));
            }
        }
        if !overridden.contains(&http::header::ACCEPT) {
            headers.push((http::header::ACCEPT, HeaderValue::from_static("*/*")));
        }
        if has_data && !overridden.contains(&http::header::CONTENT_TYPE) {
            headers.push((
                http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/x-www-form-urlencoded"),
            ));
        }
        if has_data && !overridden.contains(&http::header::CONTENT_LENGTH) {
            headers.push((http::header::CONTENT_LENGTH, HeaderValue::from(body.len())));
        }
        if self.cookie.iter().any(|cookie| !cookie.contains('=')) {
            return Err(AttestError::Request);
        }
        if !self.cookie.is_empty() && !overridden.contains(&http::header::COOKIE) {
            headers.push((
                http::header::COOKIE,
                HeaderValue::from_str(&self.cookie.join(";"))?,
            ));
        }
        Request::new(&url, method, headers, body)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "boundary observations"
)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Input {
        #[command(flatten)]
        request: RequestArgs,
    }

    proptest::proptest! {
        #[test]
        fn curl_arguments_preserve_literal_data_and_header_intent(
            first in "[a-zA-Z0-9@=]{0,80}", second in "[a-zA-Z0-9@=]{0,80}",
            value in "[a-zA-Z0-9]{1,40}"
        ) {
            for explicit in [false, true] {
                let mut args = vec!["attest", "https://example.invalid/a?q=1", "-H", "Accept:",
                    "-H", "X-Empty;", "-H", "Content-Type: application/json", "-b", "session=demo",
                    "--data-raw", &first, "--data-raw", &second];
                if explicit { args.extend(["-X", "PATCH"]); }
                let header = format!("X-Value: {value}");
                args.extend(["-H", &header]);
                let request = Input::try_parse_from(args).unwrap().request.parse().unwrap();
                let bytes = request.bytes();
                let mut headers = [httparse::EMPTY_HEADER; 16];
                let mut parsed = httparse::Request::new(&mut headers);
                let httparse::Status::Complete(offset) = parsed.parse(bytes).unwrap() else { unreachable!() };
                proptest::prop_assert_eq!(parsed.method, Some(if explicit {"PATCH"} else {"POST"}));
                proptest::prop_assert_eq!(parsed.path, Some("/a?q=1"));
                let headers = parsed.headers.iter().map(|h|(h.name,h.value)).collect::<Vec<_>>();
                proptest::prop_assert!(!headers.iter().any(|(n,_)| *n=="accept"));
                for pair in [("x-empty", b"".as_slice()), ("x-value",value.as_bytes()),
                    ("content-type",b"application/json".as_slice()), ("cookie",b"session=demo".as_slice()),
                    ("host",b"example.invalid".as_slice())] {
                    proptest::prop_assert!(headers.contains(&pair));
                }
                let expected = if first.is_empty() { second.clone() } else { format!("{first}&{second}") };
                let length = expected.len().to_string();
                proptest::prop_assert!(headers.contains(&("content-length",length.as_bytes())));
                proptest::prop_assert_eq!(&bytes[offset..],expected.as_bytes());
            }
        }
    }

    #[test]
    fn empty_data_parts_follow_curl_concatenation() {
        // Captured with curl 8.7.1; a separator requires an existing nonempty body.
        for (parts, expected) in [
            (vec!["", "x"], "x"),
            (vec!["x", ""], "x&"),
            (vec!["", ""], ""),
            (vec!["x", "", "y"], "x&&y"),
        ] {
            let args = ["attest", "https://example.invalid"]
                .into_iter()
                .chain(parts.iter().flat_map(|part| ["--data-raw", *part]));
            let request = Input::try_parse_from(args)
                .unwrap()
                .request
                .parse()
                .unwrap();
            let bytes = request.bytes();
            let offset = bytes
                .windows(4)
                .position(|part| part == b"\r\n\r\n")
                .unwrap()
                + 4;
            assert_eq!(&bytes[offset..], expected.as_bytes());
            assert!(bytes.starts_with(b"POST / HTTP/1.1\r\n"));
        }
    }

    #[test]
    fn unsupported_and_ambiguous_arguments_fail_without_io() {
        for args in [
            vec!["--url", "https://example.invalid", "https://other.invalid"],
            vec!["https://example.invalid", "--compressed"],
            vec!["https://example.invalid", "-L"],
            vec!["https://example.invalid", "--data", "@file"],
            vec!["https://example.invalid", "-o", "file"],
        ] {
            assert!(Input::try_parse_from(std::iter::once("attest").chain(args)).is_err());
        }
        for args in [
            vec!["-H", "Host:"],
            vec!["-H", "Content-Length:"],
            vec!["-H", "Host: evil.invalid"],
            vec!["-H", "Content-Length: 9"],
            vec!["-H", "Accept-Encoding: gzip"],
            vec!["-H", "X: ok\r\nCookie: private"],
            vec!["-b", "cookie-file"],
            vec!["-H", "not a header"],
            vec!["-X", "CONNECT"],
        ] {
            let input = Input::try_parse_from(
                ["attest", "https://example.invalid"]
                    .into_iter()
                    .chain(args),
            )
            .unwrap();
            assert!(input.request.parse().is_err());
        }
        for args in [
            vec![],
            vec!["--data-raw", ""],
            vec!["-X", "PATCH", "--data-raw", ""],
            vec!["--data-raw", "@literal"],
        ] {
            let has_data = !args.is_empty();
            let explicit = args.first() == Some(&"-X");
            let input = Input::try_parse_from(
                ["attest", "--url", "https://example.invalid"]
                    .into_iter()
                    .chain(args),
            )
            .unwrap();
            let request = input.request.parse().unwrap();
            let text = std::str::from_utf8(request.bytes()).unwrap();
            assert!(text.starts_with(if explicit {
                "PATCH /"
            } else if has_data {
                "POST /"
            } else {
                "GET /"
            }));
            assert_eq!(text.contains("content-length:"), has_data);
            assert!(text.contains("accept: */*\r\n"));
            assert!(!text.contains("\r\ncookie:"));
            assert_eq!(
                text.contains("content-type: application/x-www-form-urlencoded\r\n"),
                has_data
            );
        }
    }
}
