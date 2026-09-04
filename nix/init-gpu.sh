#!/bin/busybox sh
# /init - runs inside the VM as PID 1 on the confidential-GPU image
#
# Copy of init.sh (the v-program platform init) with one extra stage: between
# the verity mounts and the chroot preparation it loads the NVIDIA open kernel
# modules, verifies the GPU against NVIDIA's reference manifests with the
# in-rootfs nvattest, flips the GPU ready state and records the resulting
# claims for the attest-agent. Everything else (networking, dm-verity, the
# workload volume, the guest firewall, fail-closed supervision) is identical
# to init.sh, so the two files diff cleanly.
#
# Fail-closed: every GPU error powers the VM off. A GPU runtime that could not
# prove its GPU must never present an attested endpoint.
#
# The mounts/networking prologue and the wait_for_rootfs_blkdev/wait_for_dev/
# prepare_chroot helpers live in init-common.sh, shared with init-instance.sh.

# shellcheck disable=SC1091  # /bin/init-common.sh only exists inside the initrd
. /bin/init-common.sh

# Parse boot mode from kernel command line.
roothash=$(/bin/busybox sed -n 's/.*\broothash=\([0-9a-fA-F]*\).*/\1/p' /proc/cmdline)
# Parse the V-PROGRAM workload root hash, if present. `\b` requires a
# non-word character immediately before the match: since "_" and letters are
# both word characters, `\broothash=` above never matches inside
# "workload_roothash=" (no boundary between the "d" of "workload" and the "_"
# that follows, nor between that "_" and "r"), and this `\bworkload_roothash=`
# match is unambiguous on its own. The two tokens never cross-match.
workload_roothash=$(/bin/busybox sed -n 's/.*\bworkload_roothash=\([0-9a-fA-F]*\).*/\1/p' /proc/cmdline)

# Verified data volumes: comma-joined roothashes, lowercase hex only (the
# schema and daemon both pin lowercase). Same \b reasoning as above: no
# other token ends in "verified_volumes". Capture up to the next space (not
# a charset restricted to [0-9a-f,]): a malformed token must reach
# mount_verified_volumes' anchored grep so it is the one gate that decides
# well-formedness, rather than silently truncating to an empty capture here.
# shellcheck disable=SC2034  # verified_volumes is consumed by mount_verified_volumes (init-common.sh), not here
verified_volumes=$(/bin/busybox sed -n 's/.*\bverified_volumes=\([^ ]*\).*/\1/p' /proc/cmdline)

# Wait for the rootfs block device to appear.
wait_for_rootfs_blkdev
if [ -z "$blkdev" ]; then
    echo "init: FATAL: no block device found"
    exec /bin/busybox poweroff -f
fi

/bin/busybox mkdir -p /mnt/root

# Install a minimal guest firewall so only the attested TLS port is reachable
# from outside the VM. Everything the workload binds (e.g. the upstream on
# 127.0.0.1:8080, or anything it accidentally binds on 0.0.0.0) stays
# unreachable, so a client cannot bypass the attest-agent and hit the raw app.
# Loopback stays fully open (the agent proxies to the upstream over lo).
#
# The ruleset is STATELESS on purpose: for a TCP connection to the server the
# inbound packets always carry dport 8443, so `tcp dport 8443 accept` covers the
# whole flow without a conntrack module. Load order matches modules.dep.
#
# The `inet` table family filters BOTH IPv4 and IPv6 with one ruleset, so
# `tcp dport 8443` already covers v6 connections. The icmpv6 accept rule is
# control-plane only (no app data crosses it), but without it the firewall
# would break IPv6 on its own: Router Advertisements refresh the SLAAC-free
# default route's lifetime, Neighbor Solicitation/Advertisement keep
# resolving the gateway (NUD re-probes after ~30s idle), and Packet Too Big
# drives Path MTU Discovery. Dropping any of those silently blackholes v6
# minutes into the VM's life, not at boot. No DHCP rules (udp 68/546): both
# clients run with -q and exit before this firewall exists (see init
# networking above).
setup_firewall() {
    /bin/busybox insmod /lib/modules/nfnetlink.ko 2>&1 || echo "init: warning: insmod nfnetlink.ko failed"
    /bin/busybox insmod /lib/modules/nf_tables.ko 2>&1 || echo "init: warning: insmod nf_tables.ko failed"
    if /bin/nft -f - <<'NFT'
table inet filter {
	chain input {
		type filter hook input priority 0; policy drop;
		iif "lo" accept
		tcp dport 8443 accept
		icmpv6 type { nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert, destination-unreachable, packet-too-big, time-exceeded, parameter-problem } accept
	}
}
NFT
    then
        echo "init: firewall active (drop inbound except tcp/8443, loopback, and ND/PMTU icmpv6)"
    else
        echo "init: FATAL: failed to install guest firewall"
        exec /bin/busybox poweroff -f
    fi
}

# Load dm-verity kernel modules if verity is requested (platform rootfs
# and/or workload volume: either token alone is enough to need dm-verity).
if [ -n "$roothash" ] || [ -n "$workload_roothash" ]; then
    echo "init: loading dm-verity kernel modules"
    /bin/busybox insmod /lib/modules/dm-mod.ko 2>&1 || echo "init: warning: insmod dm-mod.ko failed"
    /bin/busybox insmod /lib/modules/dm-bufio.ko 2>&1 || echo "init: warning: insmod dm-bufio.ko failed"
    /bin/busybox insmod /lib/modules/dm-verity.ko 2>&1 || echo "init: warning: insmod dm-verity.ko failed"
    # Create device-mapper control node (not auto-created without udev).
    /bin/busybox mkdir -p /dev/mapper
    /bin/busybox mknod /dev/mapper/control c 10 236
fi

if [ -n "$roothash" ]; then
    # dm-verity: wait for the platform hash tree device (/dev/vdb).
    if wait_for_dev /dev/vdb; then
        hashdev="/dev/vdb"
    else
        echo "init: FATAL: roothash set but /dev/vdb (hash tree) not found"
        exec /bin/busybox poweroff -f
    fi

    echo "init: setting up dm-verity on ${blkdev} with hash tree ${hashdev}"
    echo "init: roothash=${roothash}"
    if /bin/veritysetup open "$blkdev" verity-root "$hashdev" "$roothash" 2>&1; then
        echo "init: mounting /dev/mapper/verity-root"
        if ! /bin/busybox mount -t ext4 -o ro /dev/mapper/verity-root /mnt/root; then
            echo "init: FATAL: verity mount failed"
            exec /bin/busybox poweroff -f
        fi
    else
        echo "init: FATAL: dm-verity verification failed - rootfs may be tampered"
        exec /bin/busybox poweroff -f
    fi
else
    # No dm-verity: direct mount (backwards compatible)
    echo "init: mounting ${blkdev} (no dm-verity)"
    if ! /bin/busybox mount -o ro "$blkdev" /mnt/root; then
        echo "init: WARNING: read-only mount failed; falling back to a writable mount"
        echo "init: WARNING: the rootfs is NOT integrity-protected on this path"
        if ! /bin/busybox mount "$blkdev" /mnt/root; then
            # Nothing to run: without a rootfs the rest of this script would
            # prepare an empty chroot and start the attest-agent proxying to
            # nothing. Fail closed like every other flavor does.
            echo "init: FATAL: rootfs mount failed"
            exec /bin/busybox poweroff -f
        fi
    fi
fi

# V-PROGRAM workload volume: verity-verify and mount the workload data disk
# (/dev/vdc) against its hash tree (/dev/vdd), distinct devices from the
# platform rootfs (/dev/vda) and its hash tree (/dev/vdb) above. Only present
# when the daemon attached a workload; when workload_roothash is empty this
# whole block is skipped and behavior is unchanged (platform /sbin/init runs
# below, as today).
if [ -n "$workload_roothash" ]; then
    if ! wait_for_dev /dev/vdc; then
        echo "init: FATAL: workload_roothash set but /dev/vdc (workload data) not found"
        exec /bin/busybox poweroff -f
    fi
    if ! wait_for_dev /dev/vdd; then
        echo "init: FATAL: workload_roothash set but /dev/vdd (workload hash tree) not found"
        exec /bin/busybox poweroff -f
    fi

    echo "init: setting up dm-verity on /dev/vdc with hash tree /dev/vdd (workload)"
    echo "init: workload_roothash=${workload_roothash}"
    if /bin/veritysetup open /dev/vdc verity-workload /dev/vdd "$workload_roothash" 2>&1; then
        /bin/busybox mkdir -p /mnt/workload
        echo "init: mounting /dev/mapper/verity-workload"
        if ! /bin/busybox mount -t ext4 -o ro /dev/mapper/verity-workload /mnt/workload; then
            echo "init: FATAL: workload verity mount failed"
            exec /bin/busybox poweroff -f
        fi
    else
        echo "init: FATAL: dm-verity verification failed for the workload volume - it may be tampered"
        exec /bin/busybox poweroff -f
    fi
fi

# Confidential GPU: load the driver, verify the GPU against NVIDIA's
# reference manifests, set the ready state, and record the claims for the
# attest-agent. Every failure powers the VM off: a GPU runtime without a
# verified GPU must never present an attested endpoint.
#
# nvattest and nvidia-smi are dynamically linked and live in the verity
# rootfs (nvattest at its nix store path, nvidia-smi as the raw, unpatched
# driver binary), so they run chrooted into /mnt/root. The raw binary's
# PT_INTERP is the literal /lib64/ld-linux-x86-64.so.2, which gpu-rootfs.nix
# symlinks at the same glibc /opt/nvidia/glibc points at; both paths go on
# LD_LIBRARY_PATH so the driver libraries and that libc resolve.
gpu_present() {
    for pcidev in /sys/bus/pci/devices/*; do
        [ "$(/bin/busybox cat "$pcidev/vendor" 2>/dev/null)" = "0x10de" ] && return 0
    done
    return 1
}

gpu_fatal() {
    echo "init: FATAL: gpu attestation failed: $1"
    exec /bin/busybox poweroff -f
}

# nvattest with NVML, chrooted into the verity rootfs. PATH is set explicitly
# rather than inherited: the applet lookup for /usr/bin/nvattest must not
# depend on whatever the kernel handed PID 1.
gpu_nvattest() {
    /bin/busybox chroot /mnt/root /usr/bin/env \
        PATH=/usr/bin:/bin \
        LD_LIBRARY_PATH=/opt/nvidia/lib:/opt/nvidia/glibc \
        SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt \
        nvattest "$@"
}

gpu_smi() {
    /bin/busybox chroot /mnt/root /usr/bin/env \
        PATH=/usr/bin:/bin \
        LD_LIBRARY_PATH=/opt/nvidia/lib:/opt/nvidia/glibc \
        /opt/nvidia/lib/nvidia-smi "$@"
}

gpu_claims=""
gpu_chroot_prepared=""
if gpu_present; then
    echo "init: NVIDIA GPU present, loading the driver"
    /bin/busybox insmod /lib/modules/nvidia.ko NVreg_EnableGpuFirmware=1 || gpu_fatal "insmod nvidia.ko"
    /bin/busybox insmod /lib/modules/nvidia-uvm.ko || gpu_fatal "insmod nvidia-uvm.ko"
    # shellcheck disable=SC2016  # $1/$2 are awk fields, not shell variables
    nvidia_major=$(/bin/busybox awk '$2 == "nvidia" {print $1}' /proc/devices)
    # shellcheck disable=SC2016  # $1/$2 are awk fields, not shell variables
    uvm_major=$(/bin/busybox awk '$2 == "nvidia-uvm" {print $1}' /proc/devices)
    [ -n "$nvidia_major" ] && [ -n "$uvm_major" ] || gpu_fatal "driver registered no char devices"
    /bin/busybox mknod -m 666 /dev/nvidiactl c "$nvidia_major" 255 || gpu_fatal "mknod nvidiactl"
    /bin/busybox mknod -m 666 /dev/nvidia0 c "$nvidia_major" 0 || gpu_fatal "mknod nvidia0"
    /bin/busybox mknod -m 666 /dev/nvidia-uvm c "$uvm_major" 0 || gpu_fatal "mknod nvidia-uvm"
    /bin/busybox mknod -m 666 /dev/nvidia-uvm-tools c "$uvm_major" 1 || gpu_fatal "mknod nvidia-uvm-tools"

    /bin/busybox mkdir -p /run/aleph
    gpu_claims=/run/aleph/gpu-boot-claims.json
    boot_nonce=$(/bin/busybox head -c 32 /dev/urandom | /bin/busybox hexdump -ve '1/1 "%02x"')
    # Exactly 32 bytes of hex, or stop: a short read from /dev/urandom, or a
    # busybox built without the hexdump applet, would otherwise hand nvattest
    # a truncated or empty nonce and the report would not be bound to this
    # boot at all.
    echo "$boot_nonce" | /bin/busybox grep -qE '^[0-9a-f]{64}$' \
        || gpu_fatal "could not generate a 32-byte boot nonce"
    # nvattest and nvidia-smi need /proc, /sys and /dev inside /mnt/root now,
    # before the workload chroot is prepared. prepare_chroot is idempotent on
    # the mount-point directories but not on the bind mounts, so it runs once
    # here and the later selection skips /mnt/root when it already ran (the
    # flag below).
    prepare_chroot /mnt/root
    gpu_chroot_prepared=1
    if ! gpu_nvattest --format json attest --device gpu --verifier local --nonce "$boot_nonce" \
              --rim-url https://rim.attestation.nvidia.com --ocsp-url https://ocsp.ndis.nvidia.com \
              > /run/aleph/gpu-attest.json 2> /run/aleph/gpu-attest.log; then
        /bin/busybox cat /run/aleph/gpu-attest.log
        gpu_fatal "nvattest exited non-zero"
    fi
    # result_code 0, or power off. The CLI pretty-prints its JSON (nlohmann
    # dump(4)) with the top-level keys in alphabetical order, so every key is
    # on its own line. result_message follows result_code today, hence the
    # trailing comma, but the match does not depend on it: a future build that
    # drops or reorders result_message must not silently stop verifying this.
    /bin/busybox grep -qE '"result_code" *: *0 *,?$' /run/aleph/gpu-attest.json \
        || gpu_fatal "result_code != 0"
    # Extract the claims array for the attest-agent (the EAT is not served).
    # "claims" sorts first, so its value spans from the `    "claims": [` line
    # to the matching `    ],` line; nothing nested can sit at that indent.
    # shellcheck disable=SC2016  # $ is sed's last-line address, not a shell variable
    /bin/busybox sed -n '/^    "claims": \[$/,/^    \],$/p' /run/aleph/gpu-attest.json \
        | /bin/busybox sed -e '1s/^    "claims": //' -e '$s/^    \],$/]/' > "$gpu_claims"
    [ -s "$gpu_claims" ] || gpu_fatal "could not extract claims"
    # Every claim object must carry a measres, and every measres must be
    # "success". The object count is what makes the first half enforceable: a
    # bare "all the measres lines say success" count silently accepts a claim
    # that carries NO measres at all. Each array element is printed as a bare
    # "{" at the array's own indent (8 spaces inside the extracted document);
    # an object that is a key's value is printed on that key's line, and
    # objects nested deeper are indented further, so this counts exactly the
    # claim objects. Comparing against the count also covers "fail",
    # "not-run", "absent" and any value nobody anticipated.
    claims_count=$(/bin/busybox grep -c '^        {$' "$gpu_claims")
    measres_total=$(/bin/busybox grep -c '"measres"' "$gpu_claims")
    measres_ok=$(/bin/busybox grep -cE '"measres" *: *"success"' "$gpu_claims")
    [ "$claims_count" -gt 0 ] || gpu_fatal "no GPU claim in the attestation result"
    [ "$measres_total" = "$claims_count" ] || gpu_fatal "a claim carries no measurement result"
    [ "$measres_ok" = "$claims_count" ] || gpu_fatal "measurement comparison failed"
    /bin/busybox chmod 0600 "$gpu_claims"
    # Ready state: the driver refuses CUDA work until it is set, and only a
    # verified GPU may be marked ready. nvidia-smi is the raw driver userland
    # in the rootfs; the agent is static and cannot drive NVML itself. Both
    # calls' output is kept under /run/aleph and printed on failure, so the
    # console says what nvidia-smi actually reported instead of only the
    # reason string.
    #
    # The readback is two greps and the NEGATIVE one runs FIRST on purpose:
    # "not ready" contains "ready", so a positive-only match accepts exactly
    # the state this check exists to catch. Only stdout is matched (stderr
    # goes to its own file) so a driver warning cannot decide the outcome.
    # The exact wording of `nvidia-smi conf-compute -grs` is to be confirmed
    # on the first Blackwell host; until then both patterns are deliberately
    # broad and every ambiguous reading is fatal.
    if ! gpu_smi conf-compute -srs 1 > /run/aleph/gpu-srs.log 2>&1; then
        /bin/busybox cat /run/aleph/gpu-srs.log
        gpu_fatal "setting the ready state"
    fi
    if ! gpu_smi conf-compute -grs > /run/aleph/gpu-grs.log 2> /run/aleph/gpu-grs.err; then
        /bin/busybox cat /run/aleph/gpu-grs.log /run/aleph/gpu-grs.err
        gpu_fatal "reading back the ready state"
    fi
    if /bin/busybox grep -qiE 'not[ -]?ready|disabled|off' /run/aleph/gpu-grs.log; then
        /bin/busybox cat /run/aleph/gpu-grs.log /run/aleph/gpu-grs.err
        gpu_fatal "ready state did not stick"
    fi
    if ! /bin/busybox grep -qiE '(^|[^a-z])ready([^a-z]|$)' /run/aleph/gpu-grs.log; then
        /bin/busybox cat /run/aleph/gpu-grs.log /run/aleph/gpu-grs.err
        gpu_fatal "ready state unreadable"
    fi
    echo "init: GPU verified and ready"
else
    echo "init: no NVIDIA GPU present; running without GPU attestation"
fi

# Prepare only the chroot that will actually run its /sbin/init: when a
# workload volume is mounted, the workload runs INSTEAD OF the platform
# /sbin/init, so the bind mounts (proc, sys, dev, secrets, DNS) belong in
# /mnt/workload and preparing /mnt/root would be wasted work (and vice versa).
# The GPU block above may already have prepared /mnt/root for nvattest; the
# attest-agent's collector keeps chrooting there for the VM's lifetime, so it
# stays prepared either way, and preparing it twice would stack bind mounts.
if [ -n "$workload_roothash" ]; then
    prepare_chroot /mnt/workload
    mount_verified_volumes /mnt/workload
else
    if [ -z "$gpu_chroot_prepared" ]; then
        prepare_chroot /mnt/root
    fi
    # No-op without volumes; fatal if volumes were declared without a
    # workload (the helper checks).
    mount_verified_volumes /mnt/root
fi

# Install the guest firewall BEFORE starting the workload, so the app can never
# be reached directly even during the window before the agent is up.
setup_firewall

# When a V-PROGRAM workload is mounted, its /sbin/init (the workload
# entrypoint, e.g. fib-service) runs INSTEAD OF the baked platform
# /sbin/init (the busybox httpd fallback used when no workload is present).
if [ -n "$workload_roothash" ]; then
    guest_root=/mnt/workload
else
    guest_root=/mnt/root
fi
if [ ! -x "$guest_root/sbin/init" ]; then
    # dm-verity already proved the volume authentic, so a missing /sbin/init
    # means a malformed image: fail closed like every other error path
    # instead of leaving the attest-agent proxying to a dead upstream.
    echo "init: FATAL: no /sbin/init found in $guest_root"
    exec /bin/busybox poweroff -f
fi

# Start the attestation agent (after rootfs mount). With a verified GPU it
# also serves the GPU attestation route: the boot claims proved at boot, plus
# a collector it re-runs per request for a fresh, nonce-bound SPDM report. The
# collector chroots into /mnt/root, which stays mounted and prepared for the
# VM's lifetime even when the workload runs from /mnt/workload.
if [ -n "$gpu_claims" ]; then
    /bin/aleph-attest-agent --port 8443 --upstream http://127.0.0.1:8080 \
        --gpu-claims "$gpu_claims" \
        --gpu-collector "/bin/busybox chroot /mnt/root /usr/bin/env PATH=/usr/bin:/bin LD_LIBRARY_PATH=/opt/nvidia/lib:/opt/nvidia/glibc nvattest --format json collect-evidence --device gpu --nonce" &
else
    /bin/aleph-attest-agent --port 8443 --upstream http://127.0.0.1:8080 &
fi

# Fail-closed supervision (same as init-compose.sh): wait on the guest's PID
# specifically, not on all children. A bare `wait` would keep the VM, and its
# live attested TLS endpoint, up after the workload died, with the agent
# proxying to a dead upstream; instead a dead workload takes the VM down.
echo "init: starting /sbin/init from $guest_root"
if [ -n "$gpu_claims" ]; then
    # The workload finds libcuda through the /opt/nvidia/lib bind-mount
    # prepare_chroot made in its root; the environment crosses chroot.
    export LD_LIBRARY_PATH=/opt/nvidia/lib
fi
/bin/busybox chroot "$guest_root" /sbin/init &
guest_pid=$!
wait "$guest_pid"
echo "init: /sbin/init exited; powering off"
exec /bin/busybox poweroff -f
