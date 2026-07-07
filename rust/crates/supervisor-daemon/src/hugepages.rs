//! Boot-time hugepage reservation across NUMA nodes (Phase 3 increment C2),
//! ported from the aleph-cvm donor `aleph-compute-node/src/hugepages.rs`.
//!
//! This is OPT-IN, gated on the `ALEPH_VM_NUMA_HUGEPAGES` setting (default
//! OFF). Reserving hugepages writes host-wide `nr_hugepages` sysfs files, a
//! REAL host memory reservation, so it never runs unless an operator turns it
//! on. When enabled, at boot the daemon reserves 2 MiB hugepages per NUMA node
//! (honoring any existing 1 GiB reservation) and records the effective counts
//! back onto the [`NumaTopology`], which the [`crate::numa::NumaAllocator`]
//! then draws its per-VM hugepage pools from.
//!
//! Safety: every node keeps a `headroom` floor of regular RAM
//! (`compute_2m_budget` subtracts it), so the host is never starved; a per-node
//! write failure is logged and SKIPPED (that node falls back to regular pages),
//! never blocking boot or VM creation (the fail-safe direction).
//!
//! There is NO Python oracle (the Python daemon never reserved hugepages); the
//! reference is the aleph-cvm Rust donor. Errors surface as `String` to match
//! the daemon's conventions (the donor used anyhow).

use std::path::Path;

use crate::numa::NumaTopology;

/// Per-node floor of regular RAM (MB) kept out of the 2M hugepage reservation
/// so the host and its non-hugepage workloads are never starved. Generous on
/// purpose: hugepages are an opt-in optimization, not a guarantee.
pub const DEFAULT_HEADROOM_MB: u32 = 8192;

/// Real sysfs root for NUMA hugepage control files.
const SYSFS_NODE_ROOT: &str = "/sys/devices/system/node";

/// Compute how many 2 MiB hugepages to reserve on a NUMA node.
///
/// `node_cap = min(per_node_cap, node_ram - headroom)`; the memory already held
/// by 1 GiB pages is subtracted before dividing into 2 MiB pages. Saturating
/// throughout, so an oversized headroom or 1G reservation yields 0 (never
/// underflows), matching the donor.
pub fn compute_2m_budget(
    node_ram_mb: u64,
    existing_1g_pages: u32,
    headroom_mb: u32,
    per_node_cap_mb: u64,
) -> u32 {
    let node_cap = per_node_cap_mb.min(node_ram_mb.saturating_sub(u64::from(headroom_mb)));
    let reserved_1g_mb = u64::from(existing_1g_pages).saturating_mul(1024);
    let budget_mb = node_cap.saturating_sub(reserved_1g_mb);
    u32::try_from(budget_mb / 2).unwrap_or(u32::MAX)
}

/// Write the desired 2M hugepage count to a NUMA node's sysfs file and read it
/// back (the kernel may grant fewer under fragmentation). `sysfs_base` is the
/// node root (real: `/sys/devices/system/node`; tests point it at a temp tree).
pub fn allocate_2m_pages_on_node(
    sysfs_base: &Path,
    node_id: u32,
    count: u32,
) -> Result<u32, String> {
    let path = sysfs_base
        .join(format!("node{node_id}"))
        .join("hugepages/hugepages-2048kB/nr_hugepages");
    std::fs::write(&path, count.to_string())
        .map_err(|error| format!("failed to write {}: {error}", path.display()))?;
    let actual: u32 = std::fs::read_to_string(&path)
        .map_err(|error| format!("failed to read back {}: {error}", path.display()))?
        .trim()
        .parse()
        .map_err(|error| format!("failed to parse {}: {error}", path.display()))?;
    Ok(actual)
}

/// Reserve 2M hugepages across every NUMA node from the real sysfs, updating
/// `topology.nodes[i].total_2m_hugepages` with the effective count. See
/// [`reserve_2m_hugepages_in`] for the behaviour; this is the production entry
/// point (real sysfs root, [`DEFAULT_HEADROOM_MB`]).
pub fn reserve_2m_hugepages(topology: &mut NumaTopology) {
    reserve_2m_hugepages_in(
        topology,
        DEFAULT_HEADROOM_MB,
        None,
        Path::new(SYSFS_NODE_ROOT),
    );
}

/// Reserve 2M hugepages across all NUMA nodes under `sysfs_base`, honoring
/// `headroom_mb` and an optional `global_limit_mb` (total MB of hugepages
/// across all nodes; `None` uses total RAM, with the per-node headroom applied
/// inside [`compute_2m_budget`]). Fail-safe: a node whose write fails is logged
/// and left at whatever its sysfs already had (regular pages there), never
/// aborting the reservation for the other nodes.
pub fn reserve_2m_hugepages_in(
    topology: &mut NumaTopology,
    headroom_mb: u32,
    global_limit_mb: Option<u64>,
    sysfs_base: &Path,
) {
    let num_nodes = topology.nodes.len() as u64;
    if num_nodes == 0 {
        return;
    }
    let total_ram: u64 = topology
        .nodes
        .iter()
        .map(|node| node.total_ram_mb)
        .fold(0u64, u64::saturating_add);
    // No explicit limit -> total RAM; the per-node headroom is applied inside
    // compute_2m_budget, so subtracting it here too would double-count.
    let effective_limit = global_limit_mb.unwrap_or(total_ram);
    let per_node_cap = effective_limit / num_nodes;

    for node in &mut topology.nodes {
        let desired = compute_2m_budget(
            node.total_ram_mb,
            node.total_1g_hugepages,
            headroom_mb,
            per_node_cap,
        );
        if desired == 0 {
            tracing::info!(node = node.id, "no 2M hugepage budget for this node");
            continue;
        }
        match allocate_2m_pages_on_node(sysfs_base, node.id, desired) {
            Ok(actual) => {
                if actual < desired {
                    tracing::warn!(
                        node = node.id,
                        desired,
                        actual,
                        "reserved fewer 2M hugepages than requested (fragmentation?)"
                    );
                } else {
                    tracing::info!(node = node.id, count = actual, "reserved 2M hugepages");
                }
                node.total_2m_hugepages = actual;
            }
            Err(error) => {
                // Fail-safe: this node keeps whatever it already had (regular
                // pages for VMs placed there); the others still get reserved.
                tracing::warn!(
                    node = node.id,
                    error,
                    "failed to reserve 2M hugepages on this node; falling back to regular pages"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::numa::{NumaNode, NumaTopology};
    use std::collections::BTreeSet;

    #[test]
    fn compute_2m_budget_basic() {
        // 64000 MB RAM, 4x1G pages, 4096 headroom, 60000 per-node cap.
        // node_cap = min(60000, 64000-4096=59904) = 59904
        // reserved_1g = 4096; budget = 55808; pages = 27904.
        assert_eq!(compute_2m_budget(64000, 4, 4096, 60000), 27904);
    }

    #[test]
    fn compute_2m_budget_1g_exceeds_cap_yields_zero() {
        assert_eq!(compute_2m_budget(64000, 100, 4096, 60000), 0);
    }

    #[test]
    fn compute_2m_budget_no_1g_pages() {
        // node_cap = 59904; pages = 29952.
        assert_eq!(compute_2m_budget(64000, 0, 4096, 60000), 29952);
    }

    #[test]
    fn compute_2m_budget_headroom_exceeds_ram_yields_zero() {
        assert_eq!(compute_2m_budget(2048, 0, 4096, 60000), 0);
    }

    #[test]
    fn allocate_2m_pages_writes_and_reads_back() {
        let dir = tempfile::tempdir().unwrap();
        let node = dir.path().join("node0/hugepages/hugepages-2048kB");
        std::fs::create_dir_all(&node).unwrap();
        std::fs::write(node.join("nr_hugepages"), "0\n").unwrap();
        // Writing to a regular file "succeeds" and reads back what we wrote.
        assert_eq!(allocate_2m_pages_on_node(dir.path(), 0, 100).unwrap(), 100);
    }

    fn node(id: u32, ram_mb: u64, hp_1g: u32) -> NumaNode {
        NumaNode {
            id,
            cpus: BTreeSet::from([id * 4, id * 4 + 1, id * 4 + 2, id * 4 + 3]),
            total_2m_hugepages: 0,
            total_1g_hugepages: hp_1g,
            total_ram_mb: ram_mb,
        }
    }

    #[test]
    fn reserve_updates_topology_across_nodes() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();
        for id in 0..2 {
            let hp = base.join(format!("node{id}/hugepages/hugepages-2048kB"));
            std::fs::create_dir_all(&hp).unwrap();
            std::fs::write(hp.join("nr_hugepages"), "0\n").unwrap();
        }
        let mut topo = NumaTopology {
            nodes: vec![node(0, 64000, 2), node(1, 64000, 0)],
        };
        // effective_limit = total_ram = 128000; per_node_cap = 64000.
        // Node 0: cap=min(64000,64000-4096=59904)=59904; reserved_1g=2048;
        //         budget=57856; pages=28928.
        // Node 1: cap=59904; reserved_1g=0; budget=59904; pages=29952.
        reserve_2m_hugepages_in(&mut topo, 4096, None, base);
        assert_eq!(topo.nodes[0].total_2m_hugepages, 28928);
        assert_eq!(topo.nodes[1].total_2m_hugepages, 29952);
    }

    #[test]
    fn reserve_is_fail_safe_when_a_node_write_fails() {
        // Node 0 has a writable sysfs; node 1's file is missing (write fails).
        // The reservation must still populate node 0 and leave node 1 at 0
        // (regular pages there), never panic or abort.
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();
        let hp0 = base.join("node0/hugepages/hugepages-2048kB");
        std::fs::create_dir_all(&hp0).unwrap();
        std::fs::write(hp0.join("nr_hugepages"), "0\n").unwrap();
        // node1 directory intentionally absent -> allocate write errors.

        let mut topo = NumaTopology {
            nodes: vec![node(0, 64000, 0), node(1, 64000, 0)],
        };
        reserve_2m_hugepages_in(&mut topo, 4096, None, base);
        assert!(topo.nodes[0].total_2m_hugepages > 0, "node 0 was reserved");
        assert_eq!(
            topo.nodes[1].total_2m_hugepages, 0,
            "node 1 write failed -> stays regular pages, VM creation not blocked"
        );
    }

    #[test]
    fn reserve_on_empty_topology_is_a_noop() {
        let dir = tempfile::tempdir().unwrap();
        let mut topo = NumaTopology::empty();
        reserve_2m_hugepages_in(&mut topo, 4096, None, dir.path());
        assert!(topo.is_empty());
    }
}
