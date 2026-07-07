//! Integration tests: command handlers against the in-process fake
//! supervisor from tests/support/fake.rs, output captured in a Vec<u8>.

mod support;

use supervisor_cli::{client, commands};
use supervisor_proto::pb;
use support::fake::{FakeSupervisor, spawn};

/// A RUNNING QEMU VM with an IPv4 assignment and 2m5s uptime.
fn running_vm(id: &str) -> pb::VmInfo {
    pb::VmInfo {
        vm_id: id.to_string(),
        status: pb::VmStatus::Running as i32,
        backend: pb::Backend::Qemu as i32,
        ipv4: Some(pb::IpAssignment {
            address: "172.16.3.2".to_string(),
            network_cidr: "172.16.3.0/24".to_string(),
            gateway: "172.16.3.1".to_string(),
        }),
        uptime_secs: 125,
        ..Default::default()
    }
}

fn fake_host() -> pb::HostInfo {
    pb::HostInfo {
        cpu_count: 8,
        cpu_architecture: "x86_64".to_string(),
        cpu_vendor: "AuthenticAMD".to_string(),
        cpu_model: "AMD EPYC 7543".to_string(),
        memory_mib: 16384,
        hostname: "testhost".to_string(),
        kernel_version: "6.8.0-test".to_string(),
        sev_supported: true,
        sev_es_supported: true,
        numa_nodes: vec![pb::NumaNode {
            index: 0,
            cpu_count: 8,
            memory_mib: 16384,
        }],
        ..Default::default()
    }
}

#[tokio::test]
async fn health_prints_status_and_vm_count() {
    let fake = FakeSupervisor {
        vms: vec![running_vm("vm-1")],
        ..Default::default()
    };
    let (_dir, socket) = spawn(fake).await;
    let mut client = client::connect(&socket).await.unwrap();
    let mut out = Vec::new();
    commands::host::health(&mut client, &mut out, false)
        .await
        .unwrap();
    assert_eq!(String::from_utf8(out).unwrap(), "status: OK\nvms: 1\n");
}

#[tokio::test]
async fn health_json_is_the_raw_response() {
    let fake = FakeSupervisor::default();
    let (_dir, socket) = spawn(fake).await;
    let mut client = client::connect(&socket).await.unwrap();
    let mut out = Vec::new();
    commands::host::health(&mut client, &mut out, true)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&out).expect("valid JSON");
    assert_eq!(value["status"], pb::HealthStatus::Ok as i32);
    assert_eq!(value["vm_count"], 0);
}

#[tokio::test]
async fn host_info_prints_a_key_value_block() {
    let fake = FakeSupervisor {
        host: fake_host(),
        ..Default::default()
    };
    let (_dir, socket) = spawn(fake).await;
    let mut client = client::connect(&socket).await.unwrap();
    let mut out = Vec::new();
    commands::host::host_info(&mut client, &mut out, false)
        .await
        .unwrap();
    let text = String::from_utf8(out).unwrap();
    assert_eq!(
        text,
        "hostname: testhost\n\
         kernel: 6.8.0-test\n\
         cpu: 8 x AMD EPYC 7543 (x86_64, AuthenticAMD)\n\
         memory: 16384 MiB\n\
         tee: sev sev-es\n\
         host_ipv4: -\n\
         numa0: 8 cpus, 16384 MiB\n"
    );
}

fn fake_spec(vm_id: &str) -> pb::VmSpec {
    pb::VmSpec {
        vm_id: vm_id.to_string(),
        backend: pb::Backend::Qemu as i32,
        vcpus: 2,
        memory_mib: 2048,
        persistent: true,
        disks: vec![pb::DiskConfig {
            path: "/data/root.qcow2".to_string(),
            readonly: false,
            format: pb::disk_config::Format::Qcow2 as i32,
            role: pb::disk_config::DiskRole::Rootfs as i32,
        }],
        network: Some(pb::NetworkConfig {
            internet_access: true,
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[tokio::test]
async fn vm_list_renders_an_aligned_table() {
    let fake = FakeSupervisor {
        vms: vec![running_vm("vm-1")],
        ..Default::default()
    };
    let (_dir, socket) = spawn(fake).await;
    let mut client = client::connect(&socket).await.unwrap();
    let mut out = Vec::new();
    commands::vm::list(&mut client, &mut out, false)
        .await
        .unwrap();
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "VM ID  STATUS   BACKEND  IPV4        UPTIME\n\
         vm-1   RUNNING  QEMU     172.16.3.2  2m 5s\n"
    );
}

#[tokio::test]
async fn vm_get_renders_a_key_value_block() {
    let fake = FakeSupervisor {
        vms: vec![running_vm("vm-1")],
        ..Default::default()
    };
    let (_dir, socket) = spawn(fake).await;
    let mut client = client::connect(&socket).await.unwrap();
    let mut out = Vec::new();
    commands::vm::get(&mut client, &mut out, "vm-1", false)
        .await
        .unwrap();
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "vm_id: vm-1\n\
         status: RUNNING\n\
         backend: QEMU\n\
         ipv4: 172.16.3.2 (gw 172.16.3.1)\n\
         uptime: 2m 5s\n\
         confidential_mode: NONE\n"
    );
}

#[tokio::test]
async fn vm_get_unknown_id_maps_the_error_trailer() {
    let fake = FakeSupervisor::default();
    let (_dir, socket) = spawn(fake).await;
    let mut client = client::connect(&socket).await.unwrap();
    let mut out = Vec::new();
    let error = commands::vm::get(&mut client, &mut out, "ghost", false)
        .await
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "NotFound: no VM with id ghost [ERROR_CODE_VM_NOT_FOUND]"
    );
}

#[tokio::test]
async fn vm_spec_renders_disks_and_network() {
    let fake = FakeSupervisor {
        spec: Some(fake_spec("vm-1")),
        ..Default::default()
    };
    let (_dir, socket) = spawn(fake).await;
    let mut client = client::connect(&socket).await.unwrap();
    let mut out = Vec::new();
    commands::vm::spec(&mut client, &mut out, "vm-1", false)
        .await
        .unwrap();
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "vm_id: vm-1\n\
         backend: QEMU\n\
         vcpus: 2\n\
         memory_mib: 2048\n\
         persistent: true\n\
         kernel: -\n\
         disk: /data/root.qcow2 (QCOW2, ROOTFS, rw)\n\
         internet_access: true\n"
    );
}

#[tokio::test]
async fn vm_stop_reports_the_returned_status() {
    let fake = FakeSupervisor {
        vms: vec![running_vm("vm-1")],
        ..Default::default()
    };
    let (_dir, socket) = spawn(fake).await;
    let mut client = client::connect(&socket).await.unwrap();
    let mut out = Vec::new();
    commands::vm::stop(&mut client, &mut out, "vm-1", false)
        .await
        .unwrap();
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "stopped vm-1: now RUNNING\n"
    );
}

#[tokio::test]
async fn vm_delete_aborts_when_not_confirmed() {
    let fake = FakeSupervisor {
        vms: vec![running_vm("vm-1")],
        ..Default::default()
    };
    let deleted = fake.deleted.clone();
    let (_dir, socket) = spawn(fake).await;
    let mut client = client::connect(&socket).await.unwrap();
    let mut out = Vec::new();
    commands::vm::delete(
        &mut client,
        &mut out,
        &mut "n\n".as_bytes(),
        "vm-1",
        false,
        false,
    )
    .await
    .unwrap();
    assert!(String::from_utf8(out).unwrap().ends_with("aborted\n"));
    assert!(deleted.lock().unwrap().is_empty());
}

#[tokio::test]
async fn vm_delete_proceeds_on_y() {
    let fake = FakeSupervisor {
        vms: vec![running_vm("vm-1")],
        ..Default::default()
    };
    let deleted = fake.deleted.clone();
    let (_dir, socket) = spawn(fake).await;
    let mut client = client::connect(&socket).await.unwrap();
    let mut out = Vec::new();
    commands::vm::delete(
        &mut client,
        &mut out,
        &mut "y\n".as_bytes(),
        "vm-1",
        false,
        false,
    )
    .await
    .unwrap();
    assert!(String::from_utf8(out).unwrap().ends_with("deleted vm-1\n"));
    assert_eq!(*deleted.lock().unwrap(), vec!["vm-1".to_string()]);
}

#[tokio::test]
async fn vm_delete_with_yes_skips_the_prompt() {
    let fake = FakeSupervisor {
        vms: vec![running_vm("vm-1")],
        ..Default::default()
    };
    let deleted = fake.deleted.clone();
    let (_dir, socket) = spawn(fake).await;
    let mut client = client::connect(&socket).await.unwrap();
    let mut out = Vec::new();
    commands::vm::delete(
        &mut client,
        &mut out,
        &mut "".as_bytes(),
        "vm-1",
        true,
        false,
    )
    .await
    .unwrap();
    assert_eq!(String::from_utf8(out).unwrap(), "deleted vm-1\n");
    assert_eq!(*deleted.lock().unwrap(), vec!["vm-1".to_string()]);
}
