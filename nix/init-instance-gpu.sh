#!/bin/busybox sh
# /init for the SNP confidential-INSTANCE image with a confidential GPU.
#
# The owner verifies the launch measurement over attested TLS, then injects
# the LUKS passphrase (EIP-191 owner-signed, enforced by the attest-agent's
# --owner mode). The init waits INDEFINITELY: a host reboot re-enters this
# wait until the owner re-injects. A wrong passphrase zeroizes the attempt
# and resumes waiting (the agent allows authenticated re-injection).
# No guest firewall in this mode: firewall policy belongs to the user rootfs,
# as on classic instances.
#
# Copy of init-instance.sh plus the GPU stage of init-gpu.sh, run from the
# initramfs root instead of a chroot: an instance has no Aleph rootfs to run
# the verifier from (the owner's disk is still locked at this point), so
# nvattest, its closure, NVML, nvidia-smi and the GSP blob ride in the
# measured initrd (gpu-verifier-tree.nix). The owner's rootfs gets the device
# nodes through prepare_chroot's /dev bind and brings its own CUDA userland at
# the manifest's driver_version; nothing from here is bind-mounted into it.
#
# The GPU stage runs BEFORE the attestation agent starts, so a card that
# cannot be proven powers the VM off before the owner is ever asked for the
# LUKS passphrase.

# shellcheck disable=SC1091  # /bin/init-common.sh only exists inside the initrd
. /bin/init-common.sh

# Parse the luks-mode cmdline (normative template: console=ttyS0 luks=1
# swiotlb=262144 owner=0x<40 hex> gpu_arch=<arch> gpu_count=<n>). This image
# boots ONLY in luks mode: fail closed on anything else rather than half-boot
# an unmeasurable configuration. The GPU tokens are parsed by the agent's
# gpu-policy check off /proc/cmdline, not here.
luks=$(/bin/busybox sed -n 's/.*\bluks=\([^ ]*\).*/\1/p' /proc/cmdline)
owner=$(/bin/busybox sed -n 's/.*\bowner=\(0x[0-9a-fA-F]*\).*/\1/p' /proc/cmdline)
if [ "$luks" != "1" ] || [ -z "$owner" ]; then
    echo "init: FATAL: instance image booted without luks=1 owner=0x... cmdline"
    exec /bin/busybox poweroff -f
fi

echo "init: loading dm-crypt kernel modules"
/bin/busybox insmod /lib/modules/dm-mod.ko 2>&1 || echo "init: warning: insmod dm-mod.ko failed"
/bin/busybox insmod /lib/modules/dm-crypt.ko 2>&1 || echo "init: warning: insmod dm-crypt.ko failed"
/bin/busybox mkdir -p /dev/mapper /run/cryptsetup
/bin/busybox mknod /dev/mapper/control c 10 236 2>/dev/null

wait_for_rootfs_blkdev
if [ -z "$blkdev" ]; then
    echo "init: FATAL: no block device found"
    exec /bin/busybox poweroff -f
fi

# --- Untrusted host-supplied LUKS header defense -----------------------------
# The block device and its LUKS2 header come from the untrusted host (the CRN
# operator). The SEV-SNP launch measurement covers the kernel, initrd, cmdline
# and owner key -- it does NOT cover the disk. So a malicious host can keep the
# genuine keyslot and digest (the owner's real passphrase still validates) while
# downgrading the DATA SEGMENT cipher to the null cipher
# (segments.0.encryption: aes-xts-plain64 -> cipher_null-ecb). The genuine
# passphrase then "unlocks" a PLAINTEXT volume the host pre-filled with its own
# rootfs, under a genuine attestation -- a full guest takeover. The related
# keyslot-null variant (CVE-2025-59054, fixed in cryptsetup 2.8.1) forges a
# keyslot the same way; the data-segment variant is NOT fixed at the cryptsetup
# layer and must be caught here, by the consumer (Trail of Bits, 2025-10-30:
# https://blog.trailofbits.com/2025/10/30/vulnerabilities-in-luks2-disk-encryption-for-confidential-vms/).
#
# Defense: copy the header off the untrusted device into initrd RAM ONCE,
# validate the RAM copy, then luksOpen --header the RAM copy so the on-disk
# header can never be swapped between the check and the open (TOCTOU). The
# rootfs is formatted by examples/instance_confidential_snp/build_luks_rootfs.sh
# with the cryptsetup LUKS2 default -- aes-xts-plain64 for every keyslot area
# AND the data segment -- so the invariant is exact: every "encryption" field
# in the header must read aes-xts-plain64, and there must be at least one crypt
# data segment. Any other cipher (a null-cipher downgrade above all) fails
# closed: a tampered header is never fixed by re-injecting the passphrase, so we
# power off rather than wait. The FATAL line is captured on the guest serial
# (owner-readable), and a STOPPED VM is an unambiguous "the host tampered with
# the disk" signal.
luks_header=/run/cryptsetup/luks_header.img
if ! /bin/cryptsetup luksHeaderBackup "$blkdev" --header-backup-file "$luks_header" 2>&1; then
    echo "init: FATAL: no readable LUKS2 header on ${blkdev} (host-supplied disk rejected)"
    exec /bin/busybox poweroff -f
fi
# stderr is left on the serial console so a parse failure names its cause.
meta=$(/bin/cryptsetup luksDump --dump-json-metadata "$luks_header")
# --dump-json-metadata re-serializes the header through OUR cryptsetup, so the
# JSON escaping is ours, not the attacker's: a field smuggled inside a string
# value comes out as \"encryption\" and cannot match. grep -o emits one line
# per match, so wc -l counts fields regardless of how many share a line, and
# the optional whitespace after ':' tolerates a pretty-printing change.
# Only the cipher string is policed, not key_size or sector_size: a tampered
# key_size or a forged keyslot is rejected at luksOpen anyway, because the
# digest binds the volume key and, without the owner's passphrase, the host
# cannot build a self-consistent keyslot+digest pair. The data-segment cipher
# is the one field the digest does NOT bind, so it is the one we must check.
enc_total=$(printf '%s\n' "$meta" | /bin/busybox grep -o '"encryption":[[:space:]]*"' | /bin/busybox wc -l)
enc_ok=$(printf '%s\n' "$meta" | /bin/busybox grep -o '"encryption":[[:space:]]*"aes-xts-plain64"' | /bin/busybox wc -l)
seg_crypt=$(printf '%s\n' "$meta" | /bin/busybox grep -o '"type":[[:space:]]*"crypt"' | /bin/busybox wc -l)
# Belt and braces: crypt and linear are the only segment types a LUKS2 header
# may carry, so "at least one crypt segment and zero linear ones" == "every
# segment is crypt". A linear segment is a plaintext region (the shape a
# mid-reencryption header takes); current cryptsetup happens to reject
# hand-forged ones earlier, but do not depend on that -- a smuggled plaintext
# segment must fail closed here, not at the layer being attacked.
seg_linear=$(printf '%s\n' "$meta" | /bin/busybox grep -o '"type":[[:space:]]*"linear"' | /bin/busybox wc -l)
if [ "$enc_total" -lt 1 ] || [ "$enc_total" != "$enc_ok" ] || [ "$seg_crypt" -lt 1 ] || [ "$seg_linear" -ne 0 ]; then
    echo "init: FATAL: untrusted LUKS header rejected -- expected aes-xts-plain64 on every"
    echo "init:        keyslot area and data segment, got ${enc_ok}/${enc_total} matching and"
    echo "init:        ${seg_crypt} crypt segment(s). Possible host cipher_null downgrade"
    echo "init:        (Trail of Bits 2025-10-30). Refusing to unlock the rootfs."
    exec /bin/busybox poweroff -f
fi
echo "init: LUKS header validated (${enc_ok}/${enc_total} aes-xts-plain64, ${seg_crypt} crypt segment)"

# Confidential GPU: load the driver, verify the GPU against NVIDIA's
# reference manifests, enforce the measured requirement, set the ready state,
# and record the claims for the attest-agent. Every failure powers the VM
# off, an empty PCI bus included: an instance without a verified GPU must
# never present an attested endpoint.
#
# nvattest and nvidia-smi are dynamically linked and live in this initramfs
# with their nix closure at its store paths, so they run in place, with no
# chroot. The raw nvidia-smi's PT_INTERP is the literal
# /lib64/ld-linux-x86-64.so.2, which gpu-verifier-tree.nix symlinks at the
# same glibc /opt/nvidia/glibc points at; both paths go on LD_LIBRARY_PATH so
# the driver libraries and that libc resolve.
# NVIDIA display-class devices on the bus (PCI class 0x03xxxx). Only those
# count: a card's other functions, or any other NVIDIA device, must not
# inflate the device-node count below.
gpu_count() {
    count=0
    for pcidev in /sys/bus/pci/devices/*; do
        [ "$(/bin/busybox cat "$pcidev/vendor" 2>/dev/null)" = "0x10de" ] || continue
        case "$(/bin/busybox cat "$pcidev/class" 2>/dev/null)" in
            0x03*) count=$((count + 1)) ;;
        esac
    done
    echo "$count"
}

gpu_fatal() {
    echo "init: FATAL: gpu attestation failed: $1"
    exec /bin/busybox poweroff -f
}

# nvattest with NVML. PATH is set explicitly rather than inherited: the applet
# lookup for /usr/bin/nvattest must not depend on whatever the kernel handed
# PID 1.
gpu_nvattest() {
    /usr/bin/env \
        PATH=/usr/bin:/bin \
        LD_LIBRARY_PATH=/opt/nvidia/lib:/opt/nvidia/glibc \
        SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt \
        nvattest "$@"
}

gpu_smi() {
    /usr/bin/env \
        PATH=/usr/bin:/bin \
        LD_LIBRARY_PATH=/opt/nvidia/lib:/opt/nvidia/glibc \
        /opt/nvidia/lib/nvidia-smi "$@"
}

gpu_claims=""
gpu_total=$(gpu_count)
if [ "$gpu_total" -gt 0 ]; then
    echo "init: $gpu_total NVIDIA GPU(s) present, loading the driver"
    # The GSP firmware rides in this initramfs, which IS PID 1's root, and the
    # kernel searches it by default: no firmware_class path override here,
    # unlike the v-program flavor where the blob sits in the verity rootfs.
    /bin/busybox insmod /lib/modules/nvidia.ko NVreg_EnableGpuFirmware=1 || gpu_fatal "insmod nvidia.ko"
    /bin/busybox insmod /lib/modules/nvidia-uvm.ko || gpu_fatal "insmod nvidia-uvm.ko"
    # shellcheck disable=SC2016  # $1/$2 are awk fields, not shell variables
    nvidia_major=$(/bin/busybox awk '$2 == "nvidia" {print $1}' /proc/devices)
    # shellcheck disable=SC2016  # $1/$2 are awk fields, not shell variables
    uvm_major=$(/bin/busybox awk '$2 == "nvidia-uvm" {print $1}' /proc/devices)
    [ -n "$nvidia_major" ] && [ -n "$uvm_major" ] || gpu_fatal "driver registered no char devices"
    /bin/busybox mknod -m 666 /dev/nvidiactl c "$nvidia_major" 255 || gpu_fatal "mknod nvidiactl"
    # One node per card, minors in probe order, which is how the driver
    # numbers them. An instance can own several cards (the message carries a
    # count), and a lone /dev/nvidia0 would hide the rest from the guest.
    i=0
    while [ "$i" -lt "$gpu_total" ]; do
        /bin/busybox mknod -m 666 "/dev/nvidia$i" c "$nvidia_major" "$i" || gpu_fatal "mknod nvidia$i"
        i=$((i + 1))
    done
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
    # CC mode allows one RM init per GPU reset: without persistence mode the
    # adapter tears down when nvattest exits and never comes back.
    if ! gpu_smi -pm 1 > /run/aleph/gpu-pm.log 2>&1; then
        /bin/busybox cat /run/aleph/gpu-pm.log
        gpu_fatal "enabling persistence mode"
    fi
    # Collect the SPDM evidence ONCE: the board identity the policy check
    # enforces must come from the very bytes nvattest verified, and attesting
    # from a file touches no GPU, so the one-RM-init-per-reset rule above
    # still holds. Both files are created 0600 (the umask in the subshells
    # covers the redirections), like the attest result and claims below.
    gpu_evidence_doc=/run/aleph/gpu-evidence-doc.json
    gpu_evidence=/run/aleph/gpu-evidence.json
    if ! (umask 077; gpu_nvattest --format json collect-evidence --device gpu --nonce "$boot_nonce" \
              > "$gpu_evidence_doc" 2> /run/aleph/gpu-evidence.log); then
        /bin/busybox cat /run/aleph/gpu-evidence.log
        gpu_fatal "collecting GPU evidence"
    fi
    # Same anchored top-level match as the attest result below (four spaces at
    # dump(4)): a per-device result_code nested deeper must never satisfy it.
    /bin/busybox grep -qE '^    "result_code" *: *0 *,?$' "$gpu_evidence_doc" \
        || gpu_fatal "evidence collection result_code != 0"
    # collect-evidence prints a WRAPPER object ("evidences", "result_code",
    # "result_message"), but attest's file source parses a bare array, so cut
    # the array out once and hand the same file to both readers. Same shape as
    # the claims cut below: "evidences" sorts first, so its value runs from the
    # `    "evidences": [` line to the next line at that same four-space indent
    # starting with `]`, and nothing nested can sit there.
    # shellcheck disable=SC2016  # $ is sed's last-line address, not a shell variable
    (umask 077; /bin/busybox sed -n '/^    "evidences": \[$/,/^    \]/p' "$gpu_evidence_doc" \
        | /bin/busybox sed -e '1s/^    "evidences": //' -e '$s/^    \].*/]/' > "$gpu_evidence")
    [ -s "$gpu_evidence" ] || gpu_fatal "could not extract the evidence array"
    # The full result carries the detached EAT and the log can echo it on
    # failure; neither is served, so both are created 0600 (the umask in the
    # subshell covers the redirections), same as the extracted claims below.
    # --nonce is not redundant with the file source: nvattest compares the
    # nonce of every entry in the file against it (and would otherwise
    # generate a fresh one that no stored entry can answer), and its verifier
    # then compares that entry nonce against the one inside the signed SPDM
    # report, so the verdict stays bound to this boot.
    # The file reaches nvattest as stdin, reopened through /proc/self/fd/0.
    if ! (umask 077; gpu_nvattest --format json attest --device gpu --verifier local --nonce "$boot_nonce" \
              --gpu-evidence-source file --gpu-evidence-file /proc/self/fd/0 \
              --rim-url https://rim.attestation.nvidia.com --ocsp-url https://ocsp.ndis.nvidia.com \
              < "$gpu_evidence" > /run/aleph/gpu-attest.json 2> /run/aleph/gpu-attest.log); then
        /bin/busybox cat /run/aleph/gpu-attest.log
        gpu_fatal "nvattest exited non-zero"
    fi
    # result_code 0, or power off. The CLI pretty-prints its JSON (nlohmann
    # dump(4)) with the top-level keys in alphabetical order, so every key is
    # on its own line. result_message follows result_code today, hence the
    # trailing comma, but the match does not depend on it: a future build that
    # drops or reorders result_message must not silently stop verifying this.
    # The pattern is anchored to the TOP-LEVEL indent (four spaces at dump(4)):
    # a per-device "result_code": 0 nested deeper in the document must never
    # satisfy the check for an overall result that failed.
    /bin/busybox grep -qE '^    "result_code" *: *0 *,?$' /run/aleph/gpu-attest.json \
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
    # The measured requirement (arch, count, optional models) against the
    # policy table in this initramfs, the claims and the evidence nvattest
    # verified; board identity comes from that evidence's signed SPDM opaque
    # data, never from PCI config space or nvidia-smi. Runs BEFORE the ready
    # state, so an unwanted card is never handed to the guest.
    # --observed-count is the PCI scan the /dev/nvidiaN nodes were made from:
    # the agent demands it equal gpu_count, so the bus cannot hold a card
    # nothing verified while the guest gets a node for it.
    if ! /bin/aleph-attest-agent gpu-policy --cmdline /proc/cmdline \
            --gpu-json /etc/aleph/gpu.json \
            --claims "$gpu_claims" --evidence "$gpu_evidence" \
            --nonce "$boot_nonce" --observed-count "$gpu_total" \
            > /run/aleph/gpu-policy.log 2>&1; then
        /bin/busybox cat /run/aleph/gpu-policy.log
        gpu_fatal "GPU requirement not met"
    fi
    /bin/busybox cat /run/aleph/gpu-policy.log
    # CC mode readback, before the ready state: so a card the driver does
    # not report as being in confidential-compute mode is never marked
    # ready. nvattest already bound the card to NVIDIA's reference
    # manifests; --get-cc-feature is the driver's own CC status report, the
    # second, independent lock on the same door. The status is system-wide
    # (one "CC status" line however many cards), so the rule is on lines, not
    # cards: at least one, and every one of them "on". A wording the pattern
    # does not know fails closed.
    if ! gpu_smi conf-compute --get-cc-feature > /run/aleph/gpu-cc.log 2> /run/aleph/gpu-cc.err; then
        /bin/busybox cat /run/aleph/gpu-cc.log /run/aleph/gpu-cc.err
        gpu_fatal "reading back the CC status"
    fi
    if /bin/busybox grep -qiE 'CC status *: *(off|disabled|n/?a)' /run/aleph/gpu-cc.log; then
        /bin/busybox cat /run/aleph/gpu-cc.log /run/aleph/gpu-cc.err
        gpu_fatal "GPU is not in confidential-compute mode"
    fi
    # grep -c exits 1 on a zero count; the count is still printed.
    cc_lines=$(/bin/busybox grep -ciE 'CC status *:' /run/aleph/gpu-cc.log) || true
    cc_on=$(/bin/busybox grep -ciE 'CC status *: *on($|[^a-z0-9])' /run/aleph/gpu-cc.log) || true
    if [ "${cc_lines:-0}" -lt 1 ] || [ "${cc_on:-0}" -ne "$cc_lines" ]; then
        /bin/busybox cat /run/aleph/gpu-cc.log /run/aleph/gpu-cc.err
        gpu_fatal "CC status unreadable"
    fi
    # Ready state: the driver refuses CUDA work until it is set, and only a
    # verified GPU may be marked ready. nvidia-smi is the raw driver userland
    # in this initramfs; the agent is static and cannot drive NVML itself.
    # Both calls' output is kept under /run/aleph and printed on failure, so
    # the console says what nvidia-smi actually reported instead of only the
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
    # Fatal, not a warning: this image exists to run GPU workloads, its
    # measured cmdline states how many cards it must find, and a client
    # cannot tell an empty bus from a verified card by the launch
    # measurement alone. Booting on would serve an attested endpoint with
    # no GPU behind it.
    gpu_fatal "GPU runtime started without a GPU"
fi

# Start the attestation agent EARLY, in owner-auth mode, so the owner can
# verify and inject the passphrase. 0700 pre-creation matches the agent's
# hardened directory check. The GPU route serves the boot claims proved
# above plus a collector the agent re-runs per request for a fresh,
# nonce-bound SPDM report.
/bin/busybox mkdir -m 0700 -p /tmp/secrets
echo "init: starting attestation agent (owner-auth mode, owner=${owner})"
run_attest_agent --owner "$owner" \
    --gpu-claims "$gpu_claims" \
    --gpu-collector "/usr/bin/env PATH=/usr/bin:/bin LD_LIBRARY_PATH=/opt/nvidia/lib:/opt/nvidia/glibc nvattest --format json collect-evidence --device gpu --nonce"

zeroize_passphrase() {
    size=$(/bin/busybox stat -c%s /tmp/secrets/luks_passphrase 2>/dev/null)
    if [ -n "$size" ]; then
        /bin/busybox dd if=/dev/zero of=/tmp/secrets/luks_passphrase bs=1 count="$size" conv=notrunc 2>/dev/null
    fi
    /bin/busybox rm -f /tmp/secrets/luks_passphrase
}

echo "init: waiting for LUKS passphrase at /tmp/secrets/luks_passphrase (no timeout)"
waited=0
while true; do
    # The agent writes the passphrase atomically (temp file + rename() into
    # place), so this poll never has to worry about landing mid-write; [ -s ]
    # (non-empty, not just present) is defense in depth against a legacy or
    # third-party agent build that writes create+truncate-then-write_all,
    # where a poll landing right after the truncate would otherwise see an
    # empty file and feed cryptsetup zero bytes.
    if [ -s /tmp/secrets/luks_passphrase ]; then
        echo "init: unlocking LUKS volume on ${blkdev}"
        # --header pins the open to the RAM copy we validated above; the on-disk
        # header is never re-read, closing the check-vs-use TOCTOU.
        if /bin/cryptsetup luksOpen --header "$luks_header" "$blkdev" cryptroot < /tmp/secrets/luks_passphrase 2>&1; then
            zeroize_passphrase
            break
        fi
        zeroize_passphrase
        echo "init: cryptsetup luksOpen failed (wrong passphrase or corrupt header); waiting for a new injection"
    fi
    /bin/busybox sleep 1
    waited=$((waited + 1))
    if [ $((waited % 60)) -eq 0 ]; then
        echo "init: still waiting for LUKS passphrase (${waited}s)"
    fi
done

/bin/busybox mkdir -p /mnt/root
echo "init: mounting /dev/mapper/cryptroot"
if ! /bin/busybox mount -t ext4 /dev/mapper/cryptroot /mnt/root; then
    echo "init: FATAL: failed to mount /dev/mapper/cryptroot"
    exec /bin/busybox poweroff -f
fi

# The GPU device nodes reach the guest through the /dev bind; the driver
# userland does not. The owner installs it in their own rootfs at the
# manifest's driver_version, so nothing from /opt/nvidia is bind-mounted in
# (this initramfs ships NVML and nvidia-smi only, for the boot-time verifier).
prepare_chroot /mnt/root
if [ ! -x /mnt/root/sbin/init ]; then
    # A missing /sbin/init means the owner's decrypted rootfs is malformed
    # (the same failure class as a v-program workload with no /sbin/init, which
    # also powers off). Fail closed rather than leaving a RUNNING-but-useless VM
    # that looks healthy: the FATAL line is captured on the guest serial (owner-
    # readable via the logs endpoint), and a STOPPED VM is an unambiguous signal
    # to redeploy a fixed rootfs.
    echo "init: FATAL: no /sbin/init in the unlocked rootfs (malformed user image)"
    exec /bin/busybox poweroff -f
fi

# Fail-closed supervision (same as init.sh / init-compose.sh): wait on the
# guest's PID specifically, not on all children. The attest-agent keeps
# serving re-attestation for the VM's lifetime, so a bare `wait` would keep
# the VM and its live attested endpoint up after the owner's /sbin/init
# died; instead a dead guest takes the VM down. (The initramfs /tmp/secrets
# is invisible to the chroot except through prepare_chroot's bind mount.)
echo "init: starting /sbin/init from rootfs"
/bin/busybox chroot /mnt/root /sbin/init &
guest_pid=$!
wait "$guest_pid"
echo "init: /sbin/init exited; powering off"
exec /bin/busybox poweroff -f
