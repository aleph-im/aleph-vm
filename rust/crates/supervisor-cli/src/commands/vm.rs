//! `alephctl vm ...`: list, get, spec (and, from Task 7, lifecycle verbs).

use std::io::Write;

use anyhow::Result;
use supervisor_proto::pb;

use crate::client::{SupervisorClient, status_error};
use crate::output;

pub async fn list(client: &mut SupervisorClient, out: &mut impl Write, json: bool) -> Result<()> {
    let response = client
        .list_vms(pb::ListVmsRequest {})
        .await
        .map_err(status_error)?
        .into_inner();
    if json {
        return output::write_json(out, &response);
    }
    let rows: Vec<Vec<String>> = response
        .vms
        .iter()
        .map(|vm| {
            vec![
                vm.vm_id.clone(),
                output::vm_status_name(vm.status),
                output::backend_name(vm.backend),
                vm.ipv4
                    .as_ref()
                    .map(|ip| ip.address.clone())
                    .filter(|address| !address.is_empty())
                    .unwrap_or_else(|| "-".to_string()),
                if vm.status == pb::VmStatus::Running as i32 {
                    output::format_duration_secs(vm.uptime_secs)
                } else {
                    "-".to_string()
                },
            ]
        })
        .collect();
    output::write_table(
        out,
        &["VM ID", "STATUS", "BACKEND", "IPV4", "UPTIME"],
        &rows,
    )?;
    Ok(())
}

pub async fn get(
    client: &mut SupervisorClient,
    out: &mut impl Write,
    vm_id: &str,
    json: bool,
) -> Result<()> {
    let vm = client
        .get_vm(pb::GetVmRequest {
            vm_id: vm_id.to_string(),
        })
        .await
        .map_err(status_error)?
        .into_inner();
    if json {
        return output::write_json(out, &vm);
    }
    write_vm_info(out, &vm)
}

fn write_vm_info(out: &mut impl Write, vm: &pb::VmInfo) -> Result<()> {
    writeln!(out, "vm_id: {}", vm.vm_id)?;
    writeln!(out, "status: {}", output::vm_status_name(vm.status))?;
    if !vm.status_message.is_empty() {
        writeln!(out, "status_message: {}", vm.status_message)?;
    }
    writeln!(out, "backend: {}", output::backend_name(vm.backend))?;
    if let Some(ipv4) = &vm.ipv4
        && !ipv4.address.is_empty()
    {
        writeln!(
            out,
            "ipv4: {} (gw {})",
            ipv4.address,
            output::or_dash(&ipv4.gateway)
        )?;
    }
    if let Some(ipv6) = &vm.ipv6
        && !ipv6.address.is_empty()
    {
        writeln!(out, "ipv6: {}", ipv6.address)?;
    }
    if let Some(numa) = vm.numa_node {
        writeln!(out, "numa_node: {numa}")?;
    }
    writeln!(
        out,
        "uptime: {}",
        output::format_duration_secs(vm.uptime_secs)
    )?;
    writeln!(
        out,
        "confidential_mode: {}",
        output::confidential_mode_name(vm.confidential_mode)
    )?;
    if vm.awaiting_confidential_init {
        writeln!(out, "awaiting_confidential_init: true")?;
    }
    for gpu in &vm.gpus {
        writeln!(out, "gpu: {} {}", gpu.pci_host, gpu.model)?;
    }
    if !vm.guest_channel_path.is_empty() {
        writeln!(out, "guest_channel: {}", vm.guest_channel_path)?;
    }
    Ok(())
}

pub async fn spec(
    client: &mut SupervisorClient,
    out: &mut impl Write,
    vm_id: &str,
    json: bool,
) -> Result<()> {
    let spec = client
        .get_vm_spec(pb::GetVmSpecRequest {
            vm_id: vm_id.to_string(),
        })
        .await
        .map_err(status_error)?
        .into_inner();
    if json {
        return output::write_json(out, &spec);
    }
    writeln!(out, "vm_id: {}", spec.vm_id)?;
    writeln!(out, "backend: {}", output::backend_name(spec.backend))?;
    writeln!(out, "vcpus: {}", spec.vcpus)?;
    writeln!(out, "memory_mib: {}", spec.memory_mib)?;
    writeln!(out, "persistent: {}", spec.persistent)?;
    writeln!(out, "kernel: {}", output::or_dash(&spec.kernel_path))?;
    for disk in &spec.disks {
        writeln!(
            out,
            "disk: {} ({}, {}, {})",
            disk.path,
            output::disk_format_name(disk.format),
            output::disk_role_name(disk.role),
            if disk.readonly { "ro" } else { "rw" }
        )?;
    }
    if let Some(network) = &spec.network {
        writeln!(out, "internet_access: {}", network.internet_access)?;
    }
    if let Some(tee) = &spec.tee {
        writeln!(out, "tee: {}", output::tee_backend_name(tee.backend))?;
    }
    for gpu in &spec.gpus {
        writeln!(out, "gpu: {}", gpu.pci_host)?;
    }
    if let Some(numa) = spec.numa_node {
        writeln!(out, "numa_node: {numa}")?;
    }
    if !spec.hostname.is_empty() {
        writeln!(out, "hostname: {}", spec.hostname)?;
    }
    Ok(())
}
