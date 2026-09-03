#!/bin/bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
HELPER="$REPO_ROOT/packaging/aleph-vm/usr/lib/aleph-vm/configure-dnsmasq-apparmor"
POLICY_SOURCE="$REPO_ROOT/packaging/aleph-vm/usr/share/aleph-vm/apparmor/usr.sbin.dnsmasq"
TMP_ROOT="$(mktemp -d)"
trap 'rm -rf "$TMP_ROOT"' EXIT

APPARMOR_DIR="$TMP_ROOT/etc/apparmor.d"
POLICY="$TMP_ROOT/usr/share/aleph-vm/apparmor/usr.sbin.dnsmasq"
LOCAL="$APPARMOR_DIR/local/usr.sbin.dnsmasq"
PARSER_LOG="$TMP_ROOT/apparmor-parser.log"
FAKE_BIN="$TMP_ROOT/bin"
HOST_AWK="$(command -v awk)"

mkdir -p "$(dirname "$POLICY")" "$APPARMOR_DIR/local" "$FAKE_BIN"
cp "$POLICY_SOURCE" "$POLICY"

cat > "$FAKE_BIN/aa-enabled" <<'EOF'
#!/bin/sh
exit "${AA_ENABLED_EXIT:-0}"
EOF
cat > "$FAKE_BIN/apparmor_parser" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$PARSER_LOG"
exit "${APPARMOR_PARSER_EXIT:-0}"
EOF
cat > "$FAKE_BIN/awk" <<'EOF'
#!/bin/sh
# Match gawk's rejection of `include` as a -v variable name so this fixture
# also catches the packaging failure on hosts where gawk provides /usr/bin/awk.
for argument do
  case "$argument" in
    include=*) exit 2 ;;
  esac
done
exec "$HOST_AWK" "$@"
EOF
chmod +x "$FAKE_BIN/aa-enabled" "$FAKE_BIN/apparmor_parser" "$FAKE_BIN/awk"

run_helper() {
  local aa_enabled_exit="$1"
  local apparmor_parser_exit="$2"
  shift 2

  env \
    PATH="$FAKE_BIN:$PATH" \
    ALEPH_VM_APPARMOR_DIR="$APPARMOR_DIR" \
    ALEPH_VM_DNSMASQ_APPARMOR_POLICY="$POLICY" \
    PARSER_LOG="$PARSER_LOG" \
    HOST_AWK="$HOST_AWK" \
    AA_ENABLED_EXIT="$aa_enabled_exit" \
    APPARMOR_PARSER_EXIT="$apparmor_parser_exit" \
    "$HELPER" "$@"
}

file_mode() {
  local mode

  if mode="$(stat -c '%a' "$1" 2>/dev/null)"; then
    printf '%s\n' "$mode"
  else
    stat -f '%Lp' "$1"
  fi
}

assert_count() {
  expected="$1"
  pattern="$2"
  file="$3"
  actual="$(grep -Fxc "$pattern" "$file" || true)"
  [ "$actual" = "$expected" ] || {
    echo "expected $expected copies of '$pattern' in $file, got $actual" >&2
    exit 1
  }
}

cat > "$LOCAL" <<'EOF'
# Administrator-owned dnsmasq additions
/srv/operator/dnsmasq/** r,
EOF
chmod 0640 "$LOCAL"
cat > "$APPARMOR_DIR/usr.sbin.dnsmasq" <<'EOF'
/usr/sbin/dnsmasq {
  include if exists <local/usr.sbin.dnsmasq>
}
EOF

run_helper 0 0 install
cp "$LOCAL" "$TMP_ROOT/local-after-first-install"
run_helper 0 0 install
cmp "$LOCAL" "$TMP_ROOT/local-after-first-install"

grep -Fqx '/srv/operator/dnsmasq/** r,' "$LOCAL"
[ "$(file_mode "$LOCAL")" = 640 ]
assert_count 1 '# BEGIN aleph-vm managed dnsmasq AppArmor rules' "$LOCAL"
assert_count 1 "include if exists \"$POLICY\"" "$LOCAL"
assert_count 1 '# END aleph-vm managed dnsmasq AppArmor rules' "$LOCAL"
[ "$(wc -l < "$PARSER_LOG" | tr -d ' ')" = 2 ]
grep -Fqx -- "-r -W -T $APPARMOR_DIR/usr.sbin.dnsmasq" "$PARSER_LOG"

run_helper 0 0 remove
grep -Fqx '/srv/operator/dnsmasq/** r,' "$LOCAL"
if grep -Fq 'aleph-vm managed' "$LOCAL" || grep -Fq "$POLICY" "$LOCAL"; then
  echo "managed AppArmor lines remain after removal" >&2
  exit 1
fi
[ "$(wc -l < "$PARSER_LOG" | tr -d ' ')" = 3 ]

# A custom distro profile without the local hook cannot activate our fragment.
# Leave the administrator file untouched, skip reload and emit a clear warning.
cp "$LOCAL" "$TMP_ROOT/local-before-missing-hook"
cat > "$APPARMOR_DIR/usr.sbin.dnsmasq" <<'EOF'
/usr/sbin/dnsmasq {
}
EOF
rm -f "$PARSER_LOG"
missing_hook_stderr="$TMP_ROOT/missing-hook.stderr"
run_helper 0 0 install 2> "$missing_hook_stderr"
cmp "$LOCAL" "$TMP_ROOT/local-before-missing-hook"
[ ! -e "$PARSER_LOG" ]
grep -Fq 'does not include <local/usr.sbin.dnsmasq>' "$missing_hook_stderr"

# Installing without a distro profile prepares the local include for a future
# AppArmor installation but does not attempt a reload.
rm -f "$APPARMOR_DIR/usr.sbin.dnsmasq" "$PARSER_LOG"
run_helper 0 0 install
assert_count 1 "include if exists \"$POLICY\"" "$LOCAL"
[ ! -e "$PARSER_LOG" ]

# Disabled AppArmor also leaves the package install successful and skips reload.
cat > "$APPARMOR_DIR/usr.sbin.dnsmasq" <<'EOF'
/usr/sbin/dnsmasq {
  #include if exists <local/usr.sbin.dnsmasq>
}
EOF
run_helper 1 0 install
[ ! -e "$PARSER_LOG" ]

# A parser failure is reported but follows dh_apparmor's nonfatal behavior.
run_helper 0 1 install 2> "$TMP_ROOT/parser-warning"
grep -Fq 'could not reload the dnsmasq AppArmor profile' "$TMP_ROOT/parser-warning"

grep -Fqx '/var/lib/aleph/vm/dhcp/*.leases rw,' "$POLICY_SOURCE"

echo "dnsmasq AppArmor packaging tests passed"
