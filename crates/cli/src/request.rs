use clap::Args;
use http::{HeaderName, HeaderValue, Method};
use proof_client_core::tls::attest::{AttestError, Request};

#[derive(Args)]
pub struct RequestArgs {
    /// HTTPS URL to request again; no redirects or retries.
    #[arg(long, required_unless_present = "target", conflicts_with = "target")]
    url: Option<String>,
    /// HTTPS URL (alternative to --url).
    #[arg(value_name = "URL")]
    target: Option<String>,
    /// HTTP method; defaults to POST with data, GET otherwise.
    #[arg(short = 'X', long, overrides_with = "request")]
    request: Option<String>,
    /// Header; Name: suppresses a default, Name; sends an empty value.
    #[arg(short = 'H', long, allow_hyphen_values = true)]
    header: Vec<String>,
    /// Inline cookies; values remain private unless explicitly disclosed.
    #[arg(short = 'b', long, allow_hyphen_values = true)]
    cookie: Vec<String>,
    /// Literal request body; @ is not a filename.
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
