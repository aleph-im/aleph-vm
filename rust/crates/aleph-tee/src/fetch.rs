//! HTTP plumbing shared by the AMD KDS and Intel PCS clients: a response
//! body cap, and the on-disk cache both clients use to stay under the
//! vendors' rate limits.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tracing::debug;

/// How long one vendor request may take end to end. The AMD KDS and Intel
/// PCS answer in well under a second; a black-holed or slow-loris endpoint
/// must not hang a verifier, which has no other way to bound the wait.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// The one HTTP client the vendor fetches share: built once, with the
/// request timeout applied, so no call site can forget it.
pub(crate) fn http_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()
            .expect("the vendor HTTP client builds with static settings")
    })
}

/// Read an HTTP response body, rejecting anything larger than `cap`.
/// Streams the body in chunks so an oversized response is rejected without
/// first buffering the whole thing.
pub(crate) async fn read_body_capped(
    what: &str,
    mut response: reqwest::Response,
    cap: usize,
) -> Result<Vec<u8>> {
    // Fast path: reject up front if the server advertises an oversized body.
    if let Some(len) = response.content_length()
        && len > cap as u64
    {
        bail!("{what} response Content-Length {len} exceeds the {cap} byte cap");
    }

    let mut buf = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .with_context(|| format!("failed to read a {what} response chunk"))?
    {
        if buf.len() + chunk.len() > cap {
            bail!("{what} response body exceeds the {cap} byte cap");
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// The cache directory for one vendor's material:
/// `$XDG_CACHE_HOME/aleph-tee/<vendor>` if set, otherwise
/// `$HOME/.cache/aleph-tee/<vendor>`. `None` when neither variable is set,
/// in which case callers skip the cache.
pub(crate) fn cache_dir(vendor: &str) -> Option<PathBuf> {
    let base = std::env::var("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .ok()
        .or_else(|| {
            std::env::var("HOME")
                .ok()
                .map(|home| PathBuf::from(home).join(".cache"))
        })?;
    Some(base.join("aleph-tee").join(vendor))
}

/// Read a cached file, if it exists and is not empty.
pub(crate) fn read_cached(path: &Path) -> Option<Vec<u8>> {
    match std::fs::read(path) {
        Ok(data) if !data.is_empty() => {
            debug!(path = %path.display(), "using cached copy");
            Some(data)
        }
        _ => None,
    }
}

/// Write data to the cache; a failure is logged, never fatal.
///
/// Written to a sibling temporary file and renamed into place, so a
/// concurrent reader sees either the previous copy or the whole new one.
pub(crate) fn write_cache(path: &Path, data: &[u8]) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    let result = std::fs::write(&tmp, data).and_then(|()| std::fs::rename(&tmp, path));
    match result {
        Ok(()) => debug!(path = %path.display(), "cached"),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            debug!(path = %path.display(), error = %e, "failed to write the cache");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_round_trip_and_empty_files_are_misses() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("item");
        assert!(read_cached(&path).is_none());
        write_cache(&path, b"data");
        assert_eq!(read_cached(&path).unwrap(), b"data");
        // The temporary file is gone once the rename lands.
        assert_eq!(
            std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
            1
        );
        std::fs::write(&path, b"").unwrap();
        assert!(read_cached(&path).is_none());
    }

    #[test]
    fn http_client_is_shared() {
        assert!(std::ptr::eq(http_client(), http_client()));
    }
}
