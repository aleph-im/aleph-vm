//! The generated types must serialize to JSON: alephctl's --json output
//! depends on the serde derives added in build.rs.

use supervisor_proto::pb;

#[test]
fn vm_info_serializes_to_json() {
    let info = pb::VmInfo {
        vm_id: "vm-1".to_string(),
        status: pb::VmStatus::Running as i32,
        numa_node: Some(1),
        ..Default::default()
    };
    let value = serde_json::to_value(&info).unwrap();
    assert_eq!(value["vm_id"], "vm-1");
    assert_eq!(value["status"], 3);
    assert_eq!(value["numa_node"], 1);
}

#[test]
fn nested_messages_and_maps_serialize() {
    let backup = pb::BackupInfo {
        source_sizes: [("rootfs".to_string(), 42u64)].into_iter().collect(),
        ..Default::default()
    };
    let value = serde_json::to_value(&backup).unwrap();
    assert_eq!(value["source_sizes"]["rootfs"], 42);
}
