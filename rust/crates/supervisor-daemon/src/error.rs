//! Daemon-level error type.
//!
//! Increments 1 and 2 only need two corners of the wire vocabulary:
//! VM_NOT_FOUND (an unknown vm_id on the read RPCs) and the INTERNAL
//! catch-all (mirroring the Python `translating_errors()` in
//! src/aleph/vm/supervisor/error_mapping.py). The full ErrorCode mapping
//! arrives with the lifecycle RPCs in increment 3.

use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    #[error("invalid boolean for {key}: {value:?} (expected true/false/1/0/yes/no/on/off/t/f/y/n)")]
    InvalidBool { key: String, value: String },

    #[error("invalid value for {key}: {value:?} (expected {expected})")]
    InvalidSetting {
        key: String,
        value: String,
        expected: &'static str,
    },

    #[error("failed to read {path}: {source}")]
    ReadFile {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("Network interface is not specified and no default route interface was found")]
    NoNetworkInterface,

    #[error("Interface {0} does not exist")]
    InterfaceNotFound(String),

    #[error("No IPv4 address found for interface {0}")]
    NoIpv4Address(String),

    #[error("{0}")]
    Lspci(String),

    #[error("GPU probe failed: {0}")]
    GpuProbe(String),

    #[error("Device vendor not compatible")]
    IncompatibleGpuVendor,

    #[error("statvfs({path}) failed: {source}")]
    Statvfs {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("{0}")]
    Internal(String),

    #[error(transparent)]
    Checks(#[from] crate::checks::ChecksError),

    #[error(transparent)]
    Dns(#[from] crate::net::DnsError),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Transport(#[from] tonic::transport::Error),
}
