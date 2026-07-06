# Rust port: deliberate divergences from the Python daemon

Every place where the Rust supervisor daemon (rust/crates/supervisor-daemon)
deliberately behaves differently from the Python daemon
(src/aleph/vm/supervisor/daemon.py and the modules it serves from). The Python
daemon remains the parity oracle for everything not listed here; anything else
that differs is a bug in the port. Dispositions: **keep** (intentional,
permanent) or **fix-in-python-later** (the Python side has the bug and should
adopt the Rust behavior).

| # | Divergence | Why | Disposition |
|---|------------|-----|-------------|
| 1 | Socket hardening: the Unix socket is bound under umask 0o077 and chmod 0700 afterwards as a backstop. Python binds with default permissions. | Day-one hardening (design doc section 3): only root, the agent's user, may connect; the socket is never observable with permissive modes. | keep |
| 2 | Identity-checked unlink at shutdown: the daemon records (st_dev, st_ino) of the socket it bound and only unlinks that inode. Python unlinks the path unconditionally and can remove a socket a newer daemon instance re-bound at the same path. | Same bug ported nowhere: fixed on the Rust side. The pre-bind stale-socket unlink stays unconditional, matching Python. | fix-in-python-later |
| 3 | No automatic .env loading. Configuration comes from the process environment; under systemd the unit's EnvironmentFile= provides it, for dev runs the explicit --env-file flag does. | Design doc section 6: implicit dotenv loading makes the effective configuration depend on the working directory. | keep |
| 4 | Empty-string ALEPH_VM_* path variables (SUPERVISOR_GRPC_SOCKET, PERSISTENT_VOLUMES_DIR) fall back to their defaults. Python turns "" into PosixPath('.') and then crashes or measures the current working directory. | An empty variable is an unset variable, not a request to operate on CWD. | keep |
| 5 | GPU inventory ordering is deterministic (lspci order, duplicates removed). Python builds the inventory via a set, so its order is nondeterministic. | The agent treats the inventory as a set; deterministic order costs nothing and makes byte-level comparisons and logs stable. | keep |
| 6 | JSON field whitespace in gpu_inventory_json / available_gpus_json is compact (serde_json default) where Python json.dumps uses ", " and ": " separators. | Semantically identical payloads; consumers parse the JSON, nobody compares raw bytes. | keep |
| 7 | HostInfo proto fields the Python daemon never fills (cpu_architecture, cpu_vendor, cpu_model, frequencies, memory type, NUMA topology, the narrow gpus list, the SEV/TDX flags) stay at proto defaults in Rust too. | The proto promises more than either daemon delivers today; inventing values would diverge from the oracle. | keep |
| 8 | Ported warts kept bug-for-bug: a vfio-bound GPU from a non-whitelisted vendor aborts startup, and one lspci -nnk subprocess runs per PCI device before the class filter. | Parity first: fixing these on one side only would make conformance runs diverge. | fix-in-python-later |
| 9 | Increment staging (not a divergence, recorded so nobody is surprised): until increment 2, Health.vm_count is 0 and available GPUs/disk ignore surviving VMs after an adoption swap; Python's settings.check() startup preconditions (/dev/kvm, hypervisor binaries) arrive with the increments that need them. | Increment 1 runs no VMs; each check lands with the increment that depends on it. | keep |
| 10 | Shutdown: the 5 second grace for in-flight RPCs matches Python's server.stop(grace=5). A second SIGTERM/SIGINT skips the grace, unlinks the socket (identity-checked) and exits immediately; Python has no second-signal path. | Dev convenience on the Rust side; harmless under systemd, which sends one SIGTERM. | keep |
