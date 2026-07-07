//! `alephctl ports list [vm_id]`.

use std::io::Write;

use anyhow::Result;
use supervisor_proto::pb;

use crate::client::{SupervisorClient, status_error};
use crate::output;

pub async fn list(
    client: &mut SupervisorClient,
    out: &mut impl Write,
    vm_id: Option<String>,
    json: bool,
) -> Result<()> {
    let response = client
        .list_port_forwards(pb::ListPortForwardsRequest {
            vm_id: vm_id.unwrap_or_default(),
        })
        .await
        .map_err(status_error)?
        .into_inner();
    if json {
        return output::write_json(out, &response);
    }
    let rows: Vec<Vec<String>> = response
        .forwards
        .iter()
        .map(|forward| {
            vec![
                forward.vm_id.clone(),
                forward.host_port.to_string(),
                forward.vm_port.to_string(),
                output::protocol_name(forward.protocol),
            ]
        })
        .collect();
    output::write_table(out, &["VM ID", "HOST PORT", "VM PORT", "PROTOCOL"], &rows)?;
    Ok(())
}
