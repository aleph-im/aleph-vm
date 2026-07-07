//! `alephctl health` and `alephctl host-info`.

use std::io::Write;

use anyhow::Result;
use supervisor_proto::pb;

use crate::client::{SupervisorClient, status_error};
use crate::output;

pub async fn health(client: &mut SupervisorClient, out: &mut impl Write, json: bool) -> Result<()> {
    let response = client
        .health(pb::HealthRequest {})
        .await
        .map_err(status_error)?
        .into_inner();
    if json {
        return output::write_json(out, &response);
    }
    writeln!(
        out,
        "status: {}",
        output::health_status_name(response.status)
    )?;
    writeln!(out, "vms: {}", response.vm_count)?;
    Ok(())
}

pub async fn host_info(
    client: &mut SupervisorClient,
    out: &mut impl Write,
    json: bool,
) -> Result<()> {
    let info = client
        .get_host_info(pb::GetHostInfoRequest {})
        .await
        .map_err(status_error)?
        .into_inner();
    if json {
        return output::write_json(out, &info);
    }
    writeln!(out, "hostname: {}", info.hostname)?;
    writeln!(out, "kernel: {}", info.kernel_version)?;
    writeln!(
        out,
        "cpu: {} x {} ({}, {})",
        info.cpu_count, info.cpu_model, info.cpu_architecture, info.cpu_vendor
    )?;
    let memory = if info.memory_type.is_empty() {
        format!("{} MiB", info.memory_mib)
    } else {
        format!("{} MiB {}", info.memory_mib, info.memory_type)
    };
    writeln!(out, "memory: {memory}")?;
    let mut tee: Vec<&str> = Vec::new();
    if info.sev_supported {
        tee.push("sev");
    }
    if info.sev_es_supported {
        tee.push("sev-es");
    }
    if info.sev_snp_supported {
        tee.push("sev-snp");
    }
    if info.tdx_supported {
        tee.push("tdx");
    }
    let tee_line = if tee.is_empty() {
        "none".to_string()
    } else {
        tee.join(" ")
    };
    writeln!(out, "tee: {tee_line}")?;
    writeln!(out, "host_ipv4: {}", output::or_dash(&info.host_ipv4))?;
    for node in &info.numa_nodes {
        writeln!(
            out,
            "numa{}: {} cpus, {} MiB",
            node.index, node.cpu_count, node.memory_mib
        )?;
    }
    for gpu in &info.gpus {
        writeln!(
            out,
            "gpu: {} {} ({})",
            gpu.pci_host, gpu.model, gpu.device_id
        )?;
    }
    Ok(())
}
