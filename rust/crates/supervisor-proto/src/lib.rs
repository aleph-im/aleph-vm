//! Generated tonic/prost bindings for the aleph.supervisor.v1 contract.
//!
//! The proto file (proto/supervisor.proto at the repository root) is frozen:
//! any contract change lands as a Python-validated proto PR first, then both
//! bindings regenerate from the same file.

/// The `aleph.supervisor.v1` protobuf package.
#[allow(clippy::all, clippy::pedantic)]
pub mod pb {
    tonic::include_proto!("aleph.supervisor.v1");
}

/// Metadata key of the binary ErrorDetail trailer the server attaches to an
/// abort so the client can rebuild the precise SupervisorError subclass.
/// Mirrors aleph.vm.supervisor_interface.wire.ERROR_TRAILER_KEY.
pub const ERROR_TRAILER_KEY: &str = "aleph-supervisor-error-bin";
