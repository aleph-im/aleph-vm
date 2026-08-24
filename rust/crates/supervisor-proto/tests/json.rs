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
fn nested_messages_serialize() {
    let info = pb::VmInfo {
        ipv4: Some(pb::IpAssignment {
            address: "172.16.0.2".to_string(),
            ..Default::default()
        }),
        ..Default::default()
    };
    let value = serde_json::to_value(&info).unwrap();
    assert_eq!(value["ipv4"]["address"], "172.16.0.2");
}
