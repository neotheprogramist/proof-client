use url::Url;

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("extension ID must contain exactly 32 lowercase letters a through p")]
    ExtensionId,
    #[error("native caller must be an exact chrome-extension origin")]
    Origin,
    #[error("native caller URL is invalid")]
    Url(#[from] url::ParseError),
}

pub fn parse_origin(value: &str) -> Result<Url, IdentityError> {
    let url = Url::parse(value)?;
    let id = url.host_str().ok_or(IdentityError::Origin)?;
    if id.len() != 32 || !id.bytes().all(|c| (b'a'..=b'p').contains(&c)) {
        return Err(IdentityError::ExtensionId);
    }
    if value != format!("chrome-extension://{id}/") {
        return Err(IdentityError::Origin);
    }
    Ok(url)
}
