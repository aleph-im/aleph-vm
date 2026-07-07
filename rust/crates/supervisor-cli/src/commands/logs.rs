//! `alephctl logs` (GetLogs / StreamLogs) and `alephctl events`
//! (WatchEvents). Streams run until the server closes them; Ctrl-C is
//! plain process termination, no custom handler.

use std::io::Write;

use anyhow::Result;
use supervisor_proto::pb;

use crate::client::{SupervisorClient, status_error};
use crate::output;

pub async fn logs(
    client: &mut SupervisorClient,
    out: &mut impl Write,
    vm_id: &str,
    follow: bool,
    tail: Option<u32>,
    json: bool,
) -> Result<()> {
    if follow {
        let mut stream = client
            .stream_logs(pb::StreamLogsRequest {
                vm_id: vm_id.to_string(),
                include_history: false,
            })
            .await
            .map_err(status_error)?
            .into_inner();
        while let Some(chunk) = stream.message().await.map_err(status_error)? {
            write_log_chunk(out, &chunk, json)?;
        }
    } else {
        let response = client
            .get_logs(pb::GetLogsRequest {
                vm_id: vm_id.to_string(),
                max_lines: tail.unwrap_or(0),
                from_tail: tail.is_some(),
            })
            .await
            .map_err(status_error)?
            .into_inner();
        for chunk in &response.lines {
            write_log_chunk(out, chunk, json)?;
        }
    }
    Ok(())
}

/// NDJSON in --json mode (streams must stay line-oriented), bare line
/// otherwise.
fn write_log_chunk(out: &mut impl Write, chunk: &pb::LogChunk, json: bool) -> Result<()> {
    if json {
        writeln!(out, "{}", serde_json::to_string(chunk)?)?;
    } else {
        writeln!(out, "{}", chunk.line)?;
    }
    Ok(())
}

pub async fn events(client: &mut SupervisorClient, out: &mut impl Write, json: bool) -> Result<()> {
    let mut stream = client
        .watch_events(pb::WatchEventsRequest {})
        .await
        .map_err(status_error)?
        .into_inner();
    while let Some(event) = stream.message().await.map_err(status_error)? {
        if json {
            writeln!(out, "{}", serde_json::to_string(&event)?)?;
        } else {
            writeln!(
                out,
                "{} {} -> {}",
                event.vm_id,
                output::vm_status_name(event.old_status),
                output::vm_status_name(event.new_status)
            )?;
        }
    }
    Ok(())
}
