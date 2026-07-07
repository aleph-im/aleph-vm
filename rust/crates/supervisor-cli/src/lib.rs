//! alephctl library: clap surface, supervisor client plumbing and command
//! handlers. main.rs is thin glue so integration tests can drive handlers
//! against an in-process fake supervisor.

pub mod cli;
pub mod client;
