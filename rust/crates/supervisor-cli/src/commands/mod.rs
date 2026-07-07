//! Command handlers. Each takes a connected client and a writer so
//! integration tests capture output; main.rs passes stdout.

pub mod host;
pub mod vm;
