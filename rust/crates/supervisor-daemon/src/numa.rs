//! NUMA topology detection and pack-first vCPU placement (Phase 3 increment
//! C1), ported from the aleph-cvm donor `aleph-compute-node/src/numa.rs`.
//!
//! This module owns three things:
//!   1. [`NumaTopology`]: the host's NUMA nodes parsed from
//!      `/sys/devices/system/node/*` (CPU sets, per-node RAM, and the
//!      hugepage counts kept for `HostInfo` reporting and the C2 hugepage
//!      pools; C1 does not allocate hugepages).
//!   2. [`NumaAllocator`]: the supervisor-side, in-memory placement ledger.
//!      It packs VMs onto nodes (node 0 first, then node 1, ...) tracking
//!      only per-node vCPU counts. The hugepage allocation pools from the
//!      donor are deferred to C2.
//!   3. systemd drop-in helpers: a chosen node's cpuset is written to
//!      `{unit_dir}/aleph-vm-controller@{hash}.service.d/numa.conf` as
//!      `AllowedCPUs=`, which pins the controller unit's vCPUs. The drop-in
//!      doubles as the reconcile source: on a daemon restart the effective
//!      placement is read back from the file.
//!
//! There is NO Python oracle for NUMA (the Python daemon never pinned CPUs
//! or reported a NUMA topology); the reference is the aleph-cvm Rust donor.
//! Fallible functions return `anyhow::Result` with `.context()` (like the
//! donor); the daemon's typed boundary error (`RpcError`) is applied at the
//! call sites in lifecycle.rs, and `PlacementError` below stays a typed enum
//! because its variants pick the gRPC status. `AllowedCPUs`-drop-in IO and
//! sysfs parsing keep their source cause via the context chain.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::units::CONTROLLER_UNIT_PREFIX;

/// A single NUMA node with its CPU set, RAM and hugepage counts.
///
/// The hugepage fields are parsed and carried for `HostInfo` reporting and
/// the C2 hugepage pools; C1 does not allocate hugepages.
#[derive(Debug, Clone)]
pub struct NumaNode {
    /// NUMA node ID (e.g. 0, 1, ...).
    pub id: u32,
    /// Set of logical CPU IDs belonging to this node.
    pub cpus: BTreeSet<u32>,
    /// Number of 2 MiB hugepages on this node (carried for C2/HostInfo).
    pub total_2m_hugepages: u32,
    /// Number of 1 GiB hugepages on this node (carried for C2/HostInfo).
    pub total_1g_hugepages: u32,
    /// Total RAM on this node in MB. `u64` (matching the proto's
    /// `memory_mib`) so a node with >= ~4 TB of RAM is not silently truncated.
    pub total_ram_mb: u64,
}

/// Detected NUMA topology of the host.
#[derive(Debug, Clone, Default)]
pub struct NumaTopology {
    pub nodes: Vec<NumaNode>,
}

impl NumaTopology {
    /// Detect NUMA topology from the real sysfs.
    pub fn detect() -> Result<Self> {
        Self::from_sysfs(Path::new("/sys/devices/system/node"))
    }

    /// An empty topology: NUMA placement is inert (no pinning, no drop-in,
    /// `numa_node` reported unset). This is the fallback when sysfs
    /// detection is unavailable and the default for hermetic test state.
    pub fn empty() -> Self {
        Self { nodes: Vec::new() }
    }

    /// Detect NUMA topology from an arbitrary sysfs-like directory (for
    /// testing).
    pub fn from_sysfs(base: &Path) -> Result<Self> {
        let mut nodes = Vec::new();

        let mut entries: Vec<_> = std::fs::read_dir(base)
            .with_context(|| format!("failed to read {}", base.display()))?
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.starts_with("node"))
            })
            .collect();

        entries.sort_by_key(|entry| {
            entry
                .file_name()
                .to_str()
                .and_then(|name| name.strip_prefix("node"))
                .and_then(|name| name.parse::<u32>().ok())
                .unwrap_or(u32::MAX)
        });

        for entry in entries {
            // A single node with a missing/unreadable/malformed cpulist or
            // meminfo (or a bad directory name) is SKIPPED with a warning, not
            // fatal to the whole topology: a partially-populated sysfs still
            // yields the good nodes rather than degrading the feature host-wide
            // to empty. The hugepage reads already degrade to zero on failure.
            match Self::parse_node(&entry) {
                Ok(node) => {
                    tracing::info!(
                        node = node.id,
                        cpus = ?node.cpus,
                        total_2m_hugepages = node.total_2m_hugepages,
                        total_1g_hugepages = node.total_1g_hugepages,
                        total_ram_mb = node.total_ram_mb,
                        "detected NUMA node"
                    );
                    nodes.push(node);
                }
                Err(error) => {
                    tracing::warn!(
                        directory = %entry.path().display(),
                        error = format!("{error:#}"),
                        "skipping a NUMA node with unreadable or malformed sysfs"
                    );
                }
            }
        }

        Ok(Self { nodes })
    }

    /// Parse one `node*` directory into a [`NumaNode`]. Returns `Err` (for the
    /// caller to skip that node) when the directory name, cpulist, or meminfo
    /// is missing/unreadable/malformed; the hugepage counts degrade to zero.
    fn parse_node(entry: &std::fs::DirEntry) -> Result<NumaNode> {
        let name = entry.file_name();
        let name = name.to_str().context("non-UTF-8 node directory name")?;
        let id: u32 = name
            .strip_prefix("node")
            .with_context(|| format!("unexpected directory name {name}"))?
            .parse()
            .with_context(|| format!("failed to parse node ID from {name}"))?;

        let node_path = entry.path();

        let cpulist_raw = std::fs::read_to_string(node_path.join("cpulist"))
            .with_context(|| format!("failed to read cpulist for {name}"))?;
        let cpus = parse_cpulist(cpulist_raw.trim())?;

        // 2 MiB hugepages: absent counts as zero (a node may expose no
        // hugepage sysfs at all on a host that never reserved any).
        let hp_2m_path = node_path.join("hugepages/hugepages-2048kB/nr_hugepages");
        let total_2m_hugepages: u32 = std::fs::read_to_string(&hp_2m_path)
            .unwrap_or_else(|_| "0".to_string())
            .trim()
            .parse()
            .unwrap_or(0);

        // 1 GiB hugepages (may not exist if not configured at boot).
        let hp_1g_path = node_path.join("hugepages/hugepages-1048576kB/nr_hugepages");
        let total_1g_hugepages: u32 = std::fs::read_to_string(&hp_1g_path)
            .unwrap_or_else(|_| "0".to_string())
            .trim()
            .parse()
            .unwrap_or(0);

        // Per-node MemTotal from meminfo.
        let meminfo_path = node_path.join("meminfo");
        let meminfo = std::fs::read_to_string(&meminfo_path)
            .with_context(|| format!("failed to read meminfo for {name}"))?;
        let total_ram_mb = parse_memtotal_kb(&meminfo)
            .with_context(|| format!("failed to parse MemTotal for {name}"))?
            / 1024;

        Ok(NumaNode {
            id,
            cpus,
            total_2m_hugepages,
            total_1g_hugepages,
            total_ram_mb,
        })
    }

    /// Number of NUMA nodes.
    pub fn num_nodes(&self) -> usize {
        self.nodes.len()
    }

    /// True when no node was detected: NUMA placement is inert.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// True when placement and pinning are active: the host has MORE than one
    /// NUMA node. Every `CONFIG_NUMA` kernel (the distro default) exposes a
    /// `node0` even on a single-socket box, so a one-node host must be treated
    /// exactly like a non-NUMA host: pinning to the only node is `AllowedCPUs`
    /// = all host CPUs, a no-op, so no drop-in is written, no daemon-reload is
    /// issued, no reservation is made, and `VmInfo.numa_node` stays None. The
    /// topology is STILL reported in `HostInfo.numa_nodes` for a single node
    /// (that is pure reporting). See divergence 73.
    pub fn is_placement_active(&self) -> bool {
        self.nodes.len() > 1
    }

    /// The node with the given ID, if present.
    pub fn node(&self, id: u32) -> Option<&NumaNode> {
        self.nodes.iter().find(|node| node.id == id)
    }
}

/// Placement decision: which NUMA node and what cpuset string to pin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NumaPlacement {
    /// The NUMA node ID where the VM is placed.
    pub node: u32,
    /// Compact cpulist string (e.g. "0-3,8-11") for systemd `AllowedCPUs`.
    pub cpuset: String,
}

/// Whether a placement failed because a requested node does not exist (a
/// client argument error) or because no node had enough free vCPUs (a
/// capacity error). The caller maps these onto the right gRPC status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlacementError {
    /// The requested `numa_node` is not a node of this host.
    UnknownNode(String),
    /// No candidate node has enough free vCPUs.
    Insufficient(String),
}

/// Allocator that packs VMs onto NUMA nodes, trying node 0 first, then node
/// 1, etc. C1 tracks only per-node vCPU counts; the donor's 2M/1G hugepage
/// pools are deferred to C2 (the [`NumaNode`] hugepage fields are kept for
/// reporting and that follow-up).
#[derive(Debug)]
pub struct NumaAllocator {
    topology: NumaTopology,
    /// Per-node count of currently allocated vCPUs, indexed like
    /// `topology.nodes`.
    allocated_vcpus: Vec<u32>,
}

impl NumaAllocator {
    /// Create a new allocator with zero allocations.
    pub fn new(topology: NumaTopology) -> Self {
        let n = topology.nodes.len();
        Self {
            topology,
            allocated_vcpus: vec![0; n],
        }
    }

    /// Number of NUMA nodes in the topology.
    pub fn num_nodes(&self) -> usize {
        self.topology.num_nodes()
    }

    /// The topology this ledger tracks.
    pub fn topology(&self) -> &NumaTopology {
        &self.topology
    }

    /// Allocate `vcpus` on a NUMA node using the pack-first strategy.
    ///
    /// If `hint` is `Some(node_id)`, only that node is tried (the requested
    /// placement is honored); an unknown node is [`PlacementError::UnknownNode`]
    /// and an over-committed one is [`PlacementError::Insufficient`].
    /// Otherwise nodes are tried in order (0, 1, 2, ...) and the first one
    /// with enough free vCPUs is selected.
    pub fn allocate(
        &mut self,
        vcpus: u32,
        hint: Option<u32>,
    ) -> Result<NumaPlacement, PlacementError> {
        let candidates: Vec<usize> = if let Some(node_id) = hint {
            match self
                .topology
                .nodes
                .iter()
                .position(|node| node.id == node_id)
            {
                Some(index) => vec![index],
                None => {
                    return Err(PlacementError::UnknownNode(format!(
                        "requested NUMA node {node_id} does not exist on this host"
                    )));
                }
            }
        } else {
            (0..self.topology.nodes.len()).collect()
        };

        for index in candidates {
            let node = &self.topology.nodes[index];
            let available = (node.cpus.len() as u32).saturating_sub(self.allocated_vcpus[index]);
            if vcpus <= available {
                self.allocated_vcpus[index] += vcpus;
                return Ok(NumaPlacement {
                    node: node.id,
                    cpuset: format_cpuset(&node.cpus),
                });
            }
        }

        Err(PlacementError::Insufficient(format!(
            "no NUMA node has {vcpus} free vCPUs for placement"
        )))
    }

    /// Re-register `vcpus` on a known node without running the placement
    /// policy, for rebuilding the ledger from an adopted VM's effective
    /// placement at boot. Unknown node IDs are ignored (a drop-in cpuset
    /// that no longer maps to any node cannot be counted).
    pub fn register(&mut self, node: u32, vcpus: u32) {
        if let Some(index) = self
            .topology
            .nodes
            .iter()
            .position(|entry| entry.id == node)
        {
            self.allocated_vcpus[index] += vcpus;
        }
    }

    /// Release previously allocated vCPUs on a node (saturating subtract).
    pub fn release(&mut self, node: u32, vcpus: u32) {
        if let Some(index) = self
            .topology
            .nodes
            .iter()
            .position(|entry| entry.id == node)
        {
            self.allocated_vcpus[index] = self.allocated_vcpus[index].saturating_sub(vcpus);
        }
    }

    /// Currently allocated vCPUs on a node (for tests and introspection).
    pub fn allocated_vcpus(&self, node: u32) -> u32 {
        self.topology
            .nodes
            .iter()
            .position(|entry| entry.id == node)
            .map(|index| self.allocated_vcpus[index])
            .unwrap_or(0)
    }

    /// Map an effective `AllowedCPUs` cpuset string back to the node whose
    /// CPU set it exactly matches, for reconcile. `None` when no node's CPU
    /// set equals the parsed cpuset (an unrecognized pin, treated unpinned).
    pub fn node_for_cpuset(&self, cpuset: &str) -> Option<u32> {
        let parsed = parse_cpulist(cpuset).ok()?;
        self.topology
            .nodes
            .iter()
            .find(|node| node.cpus == parsed)
            .map(|node| node.id)
    }
}

/// Format a set of CPU IDs as a compact cpulist string (e.g. "0-3,8-11").
pub fn format_cpuset(cpus: &BTreeSet<u32>) -> String {
    let mut result = String::new();
    let mut iter = cpus.iter().copied();

    let Some(first) = iter.next() else {
        return result;
    };

    let mut range_start = first;
    let mut range_end = first;

    let flush = |result: &mut String, start: u32, end: u32| {
        if !result.is_empty() {
            result.push(',');
        }
        if start == end {
            result.push_str(&start.to_string());
        } else {
            result.push_str(&format!("{start}-{end}"));
        }
    };

    for cpu in iter {
        if cpu == range_end + 1 {
            range_end = cpu;
        } else {
            flush(&mut result, range_start, range_end);
            range_start = cpu;
            range_end = cpu;
        }
    }
    flush(&mut result, range_start, range_end);

    result
}

/// The widest single cpulist range we will materialize. A kernel quirk or a
/// corrupt sysfs value ("0-4294967295") would otherwise expand to billions of
/// entries and OOM at boot; no real host has anywhere near this many CPUs per
/// node, so a wider range is rejected (which, via `from_sysfs`, skips the
/// node) rather than allocated.
const MAX_CPULIST_RANGE: u32 = 4096;

/// Parse a Linux cpulist string (e.g. "0-3,8-11") into a sorted set of CPU
/// IDs.
pub fn parse_cpulist(s: &str) -> Result<BTreeSet<u32>> {
    let mut cpus = BTreeSet::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((lo, hi)) = part.split_once('-') {
            let lo: u32 = lo.trim().parse().context("invalid cpu range start")?;
            let hi: u32 = hi.trim().parse().context("invalid cpu range end")?;
            if hi < lo {
                bail!("cpu range {lo}-{hi} ends before it starts");
            }
            // Bound the range so a bogus cpulist cannot OOM the daemon at boot.
            if hi - lo >= MAX_CPULIST_RANGE {
                bail!(
                    "cpu range {lo}-{hi} spans more than {MAX_CPULIST_RANGE} CPUs; \
                     refusing to materialize it"
                );
            }
            cpus.extend(lo..=hi);
        } else {
            let cpu: u32 = part.parse().context("invalid cpu id")?;
            cpus.insert(cpu);
        }
    }
    Ok(cpus)
}

/// Parse MemTotal in kB from a node's meminfo file.
fn parse_memtotal_kb(meminfo: &str) -> Result<u64> {
    for line in meminfo.lines() {
        if line.contains("MemTotal:") {
            let kb_str = line
                .split_whitespace()
                .rev()
                .nth(1) // second from right, before "kB"
                .context("malformed MemTotal line")?;
            return kb_str.parse().context("failed to parse MemTotal value");
        }
    }
    bail!("MemTotal not found in meminfo")
}

// ── systemd AllowedCPUs drop-in ─────────────────────────────────────────

/// Drop-in file name written under the per-instance `.service.d` directory.
const NUMA_DROPIN_FILE: &str = "numa.conf";

/// The `.service.d` drop-in directory for a VM's controller unit, e.g.
/// `{unit_dir}/aleph-vm-controller@{hash}.service.d`.
pub fn dropin_dir(unit_dir: &Path, vm_hash: &str) -> PathBuf {
    unit_dir.join(format!("{CONTROLLER_UNIT_PREFIX}{vm_hash}.service.d"))
}

/// Write the `AllowedCPUs={cpuset}` drop-in for a VM's controller unit,
/// pinning its vCPUs to the chosen node. Creates the `.service.d` directory
/// if absent. The caller triggers a systemd daemon-reload afterwards so a
/// unit that was already loaded picks the property up.
pub fn write_cpuset_dropin(unit_dir: &Path, vm_hash: &str, cpuset: &str) -> Result<()> {
    let dir = dropin_dir(unit_dir, vm_hash);
    std::fs::create_dir_all(&dir).with_context(|| format!("failed to create {}", dir.display()))?;
    let path = dir.join(NUMA_DROPIN_FILE);
    let body = format!(
        "# Written by the aleph-vm supervisor (NUMA CPU pinning). Do not edit.\n\
         [Service]\n\
         AllowedCPUs={cpuset}\n"
    );
    std::fs::write(&path, body).with_context(|| format!("failed to write {}", path.display()))
}

/// Read the effective `AllowedCPUs=` cpuset from a VM's controller drop-in,
/// if the drop-in exists and carries the property. Used at reconcile to map
/// an adopted VM's pin back to a node.
pub fn read_cpuset_dropin(unit_dir: &Path, vm_hash: &str) -> Option<String> {
    let path = dropin_dir(unit_dir, vm_hash).join(NUMA_DROPIN_FILE);
    let contents = std::fs::read_to_string(path).ok()?;
    for line in contents.lines() {
        let line = line.trim();
        if let Some(value) = line.strip_prefix("AllowedCPUs=") {
            let value = value.trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// Remove the NUMA drop-in directory for a VM's controller unit (idempotent;
/// a missing directory is not an error). Called on delete alongside the
/// other teardown.
pub fn remove_cpuset_dropin(unit_dir: &Path, vm_hash: &str) -> Result<()> {
    let dir = dropin_dir(unit_dir, vm_hash);
    match std::fs::remove_dir_all(&dir) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("failed to remove {}", dir.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Topology parsing ────────────────────────────────────────────────

    /// Build one node directory under `base` with the given fields.
    fn write_node(
        base: &Path,
        id: u32,
        cpulist: &str,
        hp_2m: &str,
        hp_1g: Option<&str>,
        mem_kb: u64,
    ) {
        let node = base.join(format!("node{id}"));
        std::fs::create_dir_all(node.join("hugepages/hugepages-2048kB")).unwrap();
        std::fs::write(node.join("cpulist"), format!("{cpulist}\n")).unwrap();
        std::fs::write(
            node.join("hugepages/hugepages-2048kB/nr_hugepages"),
            format!("{hp_2m}\n"),
        )
        .unwrap();
        if let Some(hp_1g) = hp_1g {
            std::fs::create_dir_all(node.join("hugepages/hugepages-1048576kB")).unwrap();
            std::fs::write(
                node.join("hugepages/hugepages-1048576kB/nr_hugepages"),
                format!("{hp_1g}\n"),
            )
            .unwrap();
        }
        std::fs::write(
            node.join("meminfo"),
            format!(
                "Node {id} MemTotal:       {mem_kb} kB\nNode {id} MemFree:        32000000 kB\n"
            ),
        )
        .unwrap();
    }

    #[test]
    fn parse_cpulist_handles_ranges_singles_and_mixes() {
        assert_eq!(parse_cpulist("0-3").unwrap(), BTreeSet::from([0, 1, 2, 3]));
        assert_eq!(parse_cpulist("5").unwrap(), BTreeSet::from([5]));
        assert_eq!(parse_cpulist("0,2,4").unwrap(), BTreeSet::from([0, 2, 4]));
        assert_eq!(
            parse_cpulist("0-3,8-11").unwrap(),
            BTreeSet::from([0, 1, 2, 3, 8, 9, 10, 11])
        );
        assert!(parse_cpulist("not-a-number").is_err());
    }

    #[test]
    fn format_cpuset_collapses_contiguous_ranges() {
        assert_eq!(format_cpuset(&BTreeSet::from([8, 9, 10, 11])), "8-11");
        assert_eq!(format_cpuset(&BTreeSet::from([0, 2, 4])), "0,2,4");
        assert_eq!(format_cpuset(&BTreeSet::from([0, 1, 2, 8, 9])), "0-2,8-9");
        assert_eq!(format_cpuset(&BTreeSet::new()), "");
    }

    #[test]
    fn from_sysfs_reads_multi_node_topology() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();
        write_node(base, 0, "0-3", "100", Some("2"), 65_536_000);
        write_node(base, 1, "4-7", "200", Some("4"), 65_536_000);

        let topo = NumaTopology::from_sysfs(base).unwrap();
        assert_eq!(topo.num_nodes(), 2);
        assert_eq!(topo.nodes[0].id, 0);
        assert_eq!(topo.nodes[0].cpus, BTreeSet::from([0, 1, 2, 3]));
        assert_eq!(topo.nodes[0].total_2m_hugepages, 100);
        assert_eq!(topo.nodes[0].total_1g_hugepages, 2);
        assert_eq!(topo.nodes[0].total_ram_mb, 64_000);
        assert_eq!(topo.nodes[1].id, 1);
        assert_eq!(topo.nodes[1].cpus, BTreeSet::from([4, 5, 6, 7]));
        assert_eq!(topo.nodes[1].total_1g_hugepages, 4);
    }

    #[test]
    fn from_sysfs_reads_single_node_topology() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();
        write_node(base, 0, "0-15", "0", None, 131_072_000);

        let topo = NumaTopology::from_sysfs(base).unwrap();
        assert_eq!(topo.num_nodes(), 1);
        assert!(!topo.is_empty());
        assert_eq!(topo.nodes[0].cpus.len(), 16);
        // 1G hugepages dir absent -> zero, not an error.
        assert_eq!(topo.nodes[0].total_1g_hugepages, 0);
        assert_eq!(topo.nodes[0].total_ram_mb, 128_000);
    }

    #[test]
    fn from_sysfs_skips_a_bad_node_and_keeps_the_others() {
        // FIX 5: one node with an unreadable/garbage cpulist must not abort
        // the whole topology; the good nodes still come back.
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();
        write_node(base, 0, "0-3", "0", None, 32_000_000);
        write_node(base, 1, "4-7", "0", None, 32_000_000);
        // Corrupt node 1's cpulist with a non-numeric value.
        std::fs::write(base.join("node1/cpulist"), "not-a-cpulist\n").unwrap();
        // And a node whose cpulist file is missing entirely.
        let node2 = base.join("node2");
        std::fs::create_dir_all(&node2).unwrap();
        std::fs::write(
            node2.join("meminfo"),
            "Node 2 MemTotal:       32000000 kB\n",
        )
        .unwrap();

        let topo = NumaTopology::from_sysfs(base).unwrap();
        let ids: Vec<u32> = topo.nodes.iter().map(|node| node.id).collect();
        assert_eq!(
            ids,
            vec![0],
            "the good node survives; the bad ones are skipped"
        );
        assert_eq!(topo.node(0).unwrap().cpus, BTreeSet::from([0, 1, 2, 3]));
    }

    #[test]
    fn parse_cpulist_rejects_an_absurd_range_without_oom() {
        // FIX 6: a kernel-quirk range must be rejected by the guard, never
        // materialized (this test would OOM if the guard were absent).
        assert!(parse_cpulist("0-4294967295").is_err());
        assert!(parse_cpulist("0-5000").is_err());
        // A backwards range is rejected too (would underflow the width check).
        assert!(parse_cpulist("7-3").is_err());
        // A range at the cap boundary is still accepted.
        assert_eq!(parse_cpulist("0-4095").unwrap().len(), 4096);
    }

    #[test]
    fn from_sysfs_sorts_nodes_numerically_across_gaps() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();
        // Non-contiguous node IDs, created out of order.
        write_node(base, 3, "12-15", "0", None, 32_000_000);
        write_node(base, 0, "0-3", "0", None, 32_000_000);
        write_node(base, 10, "40-43", "0", None, 32_000_000);

        let topo = NumaTopology::from_sysfs(base).unwrap();
        let ids: Vec<u32> = topo.nodes.iter().map(|node| node.id).collect();
        assert_eq!(
            ids,
            vec![0, 3, 10],
            "nodes sorted numerically, gaps preserved"
        );
        assert_eq!(
            topo.node(10).unwrap().cpus,
            BTreeSet::from([40, 41, 42, 43])
        );
        assert!(topo.node(7).is_none());
    }

    #[test]
    fn parse_memtotal_kb_extracts_the_value() {
        let meminfo = "Node 0 MemTotal:       131072000 kB\nNode 0 MemFree:        64000000 kB\n";
        assert_eq!(parse_memtotal_kb(meminfo).unwrap(), 131_072_000);
        assert!(parse_memtotal_kb("Node 0 MemFree: 1 kB").is_err());
    }

    // ── Allocator ───────────────────────────────────────────────────────

    fn two_nodes(cpus0: &[u32], cpus1: &[u32]) -> NumaTopology {
        NumaTopology {
            nodes: vec![
                NumaNode {
                    id: 0,
                    cpus: cpus0.iter().copied().collect(),
                    total_2m_hugepages: 0,
                    total_1g_hugepages: 0,
                    total_ram_mb: 64_000,
                },
                NumaNode {
                    id: 1,
                    cpus: cpus1.iter().copied().collect(),
                    total_2m_hugepages: 0,
                    total_1g_hugepages: 0,
                    total_ram_mb: 64_000,
                },
            ],
        }
    }

    #[test]
    fn allocator_packs_node_zero_before_node_one() {
        let mut alloc = NumaAllocator::new(two_nodes(&[0, 1, 2, 3], &[4, 5, 6, 7]));

        // 2 vCPUs fit on node 0 (4 available).
        let placement = alloc.allocate(2, None).unwrap();
        assert_eq!(placement.node, 0);
        assert_eq!(placement.cpuset, "0-3");

        // 4 vCPUs no longer fit on node 0 (2 left), spill to node 1.
        let placement = alloc.allocate(4, None).unwrap();
        assert_eq!(placement.node, 1);
        assert_eq!(placement.cpuset, "4-7");
        assert_eq!(alloc.allocated_vcpus(0), 2);
        assert_eq!(alloc.allocated_vcpus(1), 4);
    }

    #[test]
    fn allocator_honors_a_valid_hint() {
        let mut alloc = NumaAllocator::new(two_nodes(&[0, 1, 2, 3], &[4, 5, 6, 7]));
        // Hint node 1 even though node 0 has room.
        let placement = alloc.allocate(2, Some(1)).unwrap();
        assert_eq!(placement.node, 1);
        assert_eq!(alloc.allocated_vcpus(0), 0);
    }

    #[test]
    fn allocator_rejects_an_unknown_hint() {
        let mut alloc = NumaAllocator::new(two_nodes(&[0, 1], &[2, 3]));
        assert!(matches!(
            alloc.allocate(1, Some(9)),
            Err(PlacementError::UnknownNode(_))
        ));
    }

    #[test]
    fn allocator_rejects_when_capacity_is_exhausted() {
        let mut alloc = NumaAllocator::new(two_nodes(&[0, 1, 2, 3], &[4, 5, 6, 7]));
        alloc.allocate(4, None).unwrap();
        alloc.allocate(4, None).unwrap();
        assert!(matches!(
            alloc.allocate(1, None),
            Err(PlacementError::Insufficient(_))
        ));
        // An over-committed explicit hint is Insufficient, not UnknownNode.
        assert!(matches!(
            alloc.allocate(1, Some(0)),
            Err(PlacementError::Insufficient(_))
        ));
    }

    #[test]
    fn allocator_release_frees_capacity() {
        let mut alloc = NumaAllocator::new(two_nodes(&[0, 1, 2, 3], &[4, 5, 6, 7]));
        alloc.allocate(4, None).unwrap();
        // Node 0 full: the next placement spills to node 1.
        assert_eq!(alloc.allocate(1, None).unwrap().node, 1);
        // Free node 0, and the next placement packs there again.
        alloc.release(0, 4);
        assert_eq!(alloc.allocate(1, None).unwrap().node, 0);
    }

    #[test]
    fn register_and_node_for_cpuset_support_reconcile() {
        let mut alloc = NumaAllocator::new(two_nodes(&[0, 1, 2, 3], &[4, 5, 6, 7]));
        assert_eq!(alloc.node_for_cpuset("4-7"), Some(1));
        assert_eq!(alloc.node_for_cpuset("0-3"), Some(0));
        // A cpuset that is not exactly a node's set does not map.
        assert_eq!(alloc.node_for_cpuset("0-1"), None);
        assert_eq!(alloc.node_for_cpuset("garbage"), None);

        // Re-registering a reconciled placement keeps pack-first correct:
        // node 0 already has 3 of its 4 vCPUs used, so a 2-vCPU VM spills.
        alloc.register(0, 3);
        assert_eq!(alloc.allocated_vcpus(0), 3);
        assert_eq!(alloc.allocate(2, None).unwrap().node, 1);
    }

    // ── Drop-in helpers ─────────────────────────────────────────────────

    #[test]
    fn dropin_roundtrips_the_cpuset() {
        let dir = tempfile::tempdir().unwrap();
        let unit_dir = dir.path();
        let hash = "a".repeat(64);

        assert!(read_cpuset_dropin(unit_dir, &hash).is_none());
        write_cpuset_dropin(unit_dir, &hash, "4-7").unwrap();

        let path = dropin_dir(unit_dir, &hash).join(NUMA_DROPIN_FILE);
        assert!(path.exists());
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("[Service]"));
        assert!(body.contains("AllowedCPUs=4-7"));
        assert_eq!(read_cpuset_dropin(unit_dir, &hash), Some("4-7".to_string()));

        // Removal is idempotent.
        remove_cpuset_dropin(unit_dir, &hash).unwrap();
        assert!(!dropin_dir(unit_dir, &hash).exists());
        remove_cpuset_dropin(unit_dir, &hash).unwrap();
    }
}
