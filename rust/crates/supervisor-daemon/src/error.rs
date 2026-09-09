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

    #[error("failed to run lspci {arguments}: {source}")]
    LspciSpawn {
        arguments: String,
        #[source]
        source: std::io::Error,
    },

    #[error("lspci {arguments} exited with {status}")]
    LspciStatus {
        arguments: String,
        status: std::process::ExitStatus,
    },

    #[error("unparseable lspci -mmnnn line: {line:?}")]
    LspciLine { line: String },

    #[error("cannot read the PCI resource file {path}: {source}")]
    GpuResourceRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("PCI resource field {field:?} is not a hexadecimal number: {source}")]
    GpuResourceField {
        field: String,
        #[source]
        source: std::num::ParseIntError,
    },

    #[error("PCI resource line {line:?} does not carry a start, an end and a flag word")]
    GpuResourceLine { line: String },

    #[error("cannot read the confidential-computing register of the GPU at {pci_host}: {source}")]
    GpuRegisterRead {
        pci_host: String,
        #[source]
        source: std::io::Error,
    },

    #[error(
        "the GPU at {pci_host} answers 0xffffffff: it is powered down or off the bus, so its \
         confidential-computing mode cannot be read"
    )]
    GpuUnreadable { pci_host: String },

    #[error("PCI resource line {line:?} does not describe an addressable region: {reason}")]
    GpuBarRange { line: String, reason: &'static str },

    #[error("the BARs of the GPU at {pci_host} push the total for this VM past 64 bits")]
    GpuBarTotal { pci_host: String },

    #[error(
        "a {window_mb} MiB 64-bit PCI MMIO window next to {guest_ram_mb} MiB of guest RAM reaches \
         {top_mb} MiB, past the {budget_mb} MiB the guest can address"
    )]
    GpuMmioBudget {
        window_mb: u64,
        guest_ram_mb: u64,
        top_mb: u64,
        budget_mb: u64,
    },

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
