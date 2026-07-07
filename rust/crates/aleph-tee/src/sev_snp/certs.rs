use std::path::PathBuf;

use anyhow::{Context, Result};
use openssl::x509::X509;
use tracing::debug;

/// A complete AMD SEV-SNP certificate chain containing the VCEK, ASK, and ARK
/// certificates in DER format.
#[derive(Debug, Clone)]
pub struct CertChain {
    /// Versioned Chip Endorsement Key certificate (DER-encoded).
    pub vcek_der: Vec<u8>,
    /// AMD SEV Signing Key certificate (DER-encoded).
    pub ask_der: Vec<u8>,
    /// AMD Root Key certificate (DER-encoded).
    pub ark_der: Vec<u8>,
}

/// TCB security version parameters needed to fetch the correct VCEK
/// certificate from AMD's Key Distribution Service (KDS).
#[derive(Debug, Clone, Copy)]
pub struct TcbParams {
    /// Bootloader security patch level.
    pub bl_spl: u8,
    /// TEE security patch level.
    pub tee_spl: u8,
    /// SNP firmware security patch level.
    pub snp_spl: u8,
    /// Microcode security patch level.
    pub ucode_spl: u8,
}

/// Base URL for AMD's Key Distribution Service.
const KDS_BASE_URL: &str = "https://kdsintf.amd.com/vcek/v1";

/// Return the cache directory for AMD KDS certificates.
///
/// Uses `$XDG_CACHE_HOME/aleph-tee/kds` if set,
/// otherwise `$HOME/.cache/aleph-tee/kds`.
fn cache_dir() -> Option<PathBuf> {
    let base = std::env::var("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .ok()
        .or_else(|| {
            std::env::var("HOME")
                .ok()
                .map(|h| PathBuf::from(h).join(".cache"))
        })?;
    Some(base.join("aleph-tee").join("kds"))
}

/// Read a cached certificate file, if it exists.
fn read_cached(path: &std::path::Path) -> Option<Vec<u8>> {
    match std::fs::read(path) {
        Ok(data) if !data.is_empty() => {
            debug!(path = %path.display(), "using cached certificate");
            Some(data)
        }
        _ => None,
    }
}

/// Write certificate data to the cache.
fn write_cache(path: &std::path::Path, data: &[u8]) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    match std::fs::write(path, data) {
        Ok(()) => debug!(path = %path.display(), "cached certificate"),
        Err(e) => debug!(path = %path.display(), error = %e, "failed to cache certificate"),
    }
}

/// Fetch the VCEK (Versioned Chip Endorsement Key) certificate from AMD KDS.
///
/// The `product` parameter identifies the CPU product line (e.g., "Milan", "Genoa", "Turin").
/// The `chip_id` is the 64-byte unique chip identifier from the attestation report.
/// The `tcb` parameters specify the TCB version to request.
///
/// Returns the VCEK certificate in DER format. Results are cached on disk
/// to avoid hitting AMD's rate limiter on repeated requests.
pub async fn fetch_vcek(product: &str, chip_id: &[u8; 64], tcb: &TcbParams) -> Result<Vec<u8>> {
    let chip_id_hex = hex::encode(chip_id);

    // Check cache first
    let cache_path = cache_dir().map(|d| {
        d.join(product).join(format!(
            "vcek_{chip_id_hex}_{}_{}_{}_{}.der",
            tcb.bl_spl, tcb.tee_spl, tcb.snp_spl, tcb.ucode_spl
        ))
    });
    if let Some(ref path) = cache_path
        && let Some(data) = read_cached(path)
    {
        return Ok(data);
    }

    let url = format!(
        "{KDS_BASE_URL}/{product}/{chip_id_hex}?blSPL={}&teeSPL={}&snpSPL={}&ucodeSPL={}",
        tcb.bl_spl, tcb.tee_spl, tcb.snp_spl, tcb.ucode_spl
    );

    let response = reqwest::get(&url)
        .await
        .with_context(|| format!("failed to fetch VCEK from {url}"))?;

    let status = response.status();
    if !status.is_success() {
        anyhow::bail!("AMD KDS returned HTTP {status} for VCEK request: {url}");
    }

    let bytes = response
        .bytes()
        .await
        .context("failed to read VCEK response body")?;

    let data = bytes.to_vec();
    if let Some(ref path) = cache_path {
        write_cache(path, &data);
    }
    Ok(data)
}

/// Fetch the CA certificate chain (ASK + ARK) from AMD KDS.
///
/// The `product` parameter identifies the CPU product line (e.g., "Milan", "Genoa", "Turin").
///
/// Returns a tuple of `(ask_der, ark_der)` -- the ASK and ARK certificates in DER format.
///
/// AMD's KDS returns PEM-encoded certificates at the `cert_chain` endpoint.
/// Results are cached on disk to avoid hitting AMD's rate limiter.
pub async fn fetch_ca_chain(product: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    // Check cache first
    let cache_paths = cache_dir().map(|d| {
        let dir = d.join(product);
        (dir.join("ask.der"), dir.join("ark.der"))
    });
    if let Some((ref ask_path, ref ark_path)) = cache_paths
        && let (Some(ask), Some(ark)) = (read_cached(ask_path), read_cached(ark_path))
    {
        return Ok((ask, ark));
    }

    let url = format!("{KDS_BASE_URL}/{product}/cert_chain");

    let response = reqwest::get(&url)
        .await
        .with_context(|| format!("failed to fetch CA chain from {url}"))?;

    let status = response.status();
    if !status.is_success() {
        anyhow::bail!("AMD KDS returned HTTP {status} for CA chain request: {url}");
    }

    let bytes = response
        .bytes()
        .await
        .context("failed to read CA chain response body")?;

    // AMD KDS returns PEM-encoded certificates. Parse them and convert to DER.
    let (ask_der, ark_der) = if bytes.starts_with(b"-----BEGIN") {
        let certs = X509::stack_from_pem(&bytes)
            .context("failed to parse PEM certificate chain from AMD KDS")?;
        if certs.len() < 2 {
            anyhow::bail!(
                "expected 2 certificates (ASK + ARK) in CA chain, got {}",
                certs.len()
            );
        }
        let ask_der = certs[0].to_der().context("failed to convert ASK to DER")?;
        let ark_der = certs[1].to_der().context("failed to convert ARK to DER")?;
        (ask_der, ark_der)
    } else {
        // Fallback: try splitting as concatenated DER
        split_der_certs(&bytes).context("failed to split CA chain into ASK and ARK certificates")?
    };

    if let Some((ref ask_path, ref ark_path)) = cache_paths {
        write_cache(ask_path, &ask_der);
        write_cache(ark_path, &ark_der);
    }
    Ok((ask_der, ark_der))
}

/// Split a buffer containing two concatenated DER-encoded certificates
/// into separate (first, second) byte vectors.
///
/// DER encoding starts with a tag byte, then a length encoding.
/// We parse the length of the first certificate to find where the second begins.
fn split_der_certs(data: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    if data.len() < 2 {
        anyhow::bail!("certificate data too short");
    }

    let first_len = der_object_length(data).context("failed to parse first certificate length")?;

    if first_len > data.len() {
        anyhow::bail!(
            "first certificate length ({first_len}) exceeds data length ({})",
            data.len()
        );
    }

    let first = data[..first_len].to_vec();
    let second = data[first_len..].to_vec();

    if second.is_empty() {
        anyhow::bail!("CA chain contains only one certificate, expected two (ASK + ARK)");
    }

    Ok((first, second))
}

/// Calculate the total length of a DER-encoded object (tag + length + value).
///
/// This reads the DER tag and length encoding to determine where the object ends.
fn der_object_length(data: &[u8]) -> Result<usize> {
    if data.is_empty() {
        anyhow::bail!("empty DER data");
    }

    // Skip the tag byte
    if data.len() < 2 {
        anyhow::bail!("DER data too short for tag + length");
    }

    let length_byte = data[1];

    if length_byte & 0x80 == 0 {
        // Short form: length is directly in this byte
        let content_len = length_byte as usize;
        Ok(2 + content_len)
    } else {
        // Long form: lower 7 bits tell how many subsequent bytes encode the length
        let num_length_bytes = (length_byte & 0x7F) as usize;
        if num_length_bytes == 0 {
            anyhow::bail!("indefinite DER length not supported");
        }
        if 2 + num_length_bytes > data.len() {
            anyhow::bail!("DER data too short for length encoding");
        }

        let mut content_len: usize = 0;
        for i in 0..num_length_bytes {
            content_len =
                content_len.checked_shl(8).context("DER length overflow")? | data[2 + i] as usize;
        }

        // Total = tag(1) + length_byte(1) + num_length_bytes + content_len
        Ok(2 + num_length_bytes + content_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_der_object_length_short_form() {
        // Tag 0x30 (SEQUENCE), length 0x05, then 5 bytes of content
        let data = [0x30, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05];
        assert_eq!(der_object_length(&data).unwrap(), 7);
    }

    #[test]
    fn test_der_object_length_long_form() {
        // Tag 0x30, length in 2 bytes: 0x82 0x01 0x00 = 256 bytes of content
        let mut data = vec![0x30, 0x82, 0x01, 0x00];
        data.extend(vec![0u8; 256]);
        assert_eq!(der_object_length(&data).unwrap(), 4 + 256);
    }

    #[test]
    fn test_split_der_certs() {
        // Create two fake DER objects
        let cert1 = vec![0x30, 0x03, 0xAA, 0xBB, 0xCC]; // 5 bytes total
        let cert2 = vec![0x30, 0x02, 0xDD, 0xEE]; // 4 bytes total

        let mut combined = cert1.clone();
        combined.extend_from_slice(&cert2);

        let (first, second) = split_der_certs(&combined).unwrap();
        assert_eq!(first, cert1);
        assert_eq!(second, cert2);
    }

    #[test]
    fn test_split_der_certs_too_short() {
        let result = split_der_certs(&[0x30]);
        assert!(result.is_err());
    }

    #[test]
    fn test_tcb_params() {
        let params = TcbParams {
            bl_spl: 3,
            tee_spl: 0,
            snp_spl: 10,
            ucode_spl: 169,
        };
        assert_eq!(params.bl_spl, 3);
        assert_eq!(params.tee_spl, 0);
        assert_eq!(params.snp_spl, 10);
        assert_eq!(params.ucode_spl, 169);
    }
}
