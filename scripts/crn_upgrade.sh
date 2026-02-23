#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a

REPO="aleph-im/aleph-vm"
DEB_DIR="/opt"
RC=false

usage() {
    echo "Usage: $0 [--rc] [--version VERSION]"
    echo ""
    echo "Options:"
    echo "  --rc              Include release candidate tags"
    echo "  --version VERSION Install a specific version (e.g. 1.10.0, 1.10.0-rc1)"
    echo "  --help            Show this help"
    exit 0
}

# Parse arguments
VERSION=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --rc) RC=true; shift ;;
        --version) VERSION="$2"; shift 2 ;;
        --help) usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

# Detect OS
detect_os() {
    if [[ ! -f /etc/os-release ]]; then
        echo "Cannot detect OS: /etc/os-release not found" >&2
        exit 1
    fi
    . /etc/os-release
    case "${ID}-${VERSION_ID}" in
        debian-12*)  echo "debian-12" ;;
        ubuntu-22*)  echo "ubuntu-22.04" ;;
        ubuntu-24*)  echo "ubuntu-24.04" ;;
        *)
            echo "Unsupported OS: ${ID} ${VERSION_ID}" >&2
            echo "Supported: Debian 12, Ubuntu 22.04, Ubuntu 24.04" >&2
            exit 1
            ;;
    esac
}

# Fetch latest version from GitHub tags
fetch_latest_version() {
    local filter
    if [[ "$RC" == true ]]; then
        filter='select(.name | test("^[0-9]+\\.[0-9]+\\.[0-9]+(-rc[0-9]+)?$"))'
    else
        filter='select(.name | test("^[0-9]+\\.[0-9]+\\.[0-9]+$"))'
    fi

    local tag
    tag=$(curl -fsSL "https://api.github.com/repos/${REPO}/git/refs/tags" \
        | jq -r ".[].ref | ltrimstr(\"refs/tags/\") | ${filter}" \
        | sort -V \
        | tail -1)

    if [[ -z "$tag" ]]; then
        echo "No matching version found" >&2
        exit 1
    fi
    echo "$tag"
}

# Use sudo only if not root
run() {
    if [[ "$(id -u)" -eq 0 ]]; then
        "$@"
    else
        sudo "$@"
    fi
}

OS=$(detect_os)
CURRENT=$(dpkg-query -W -f '${Version}' aleph-vm 2>/dev/null || echo "not installed")

if [[ -z "$VERSION" ]]; then
    VERSION=$(fetch_latest_version)
fi

if [[ "$CURRENT" == "$VERSION" ]]; then
    echo "aleph-vm ${VERSION} is already installed"
    exit 0
fi

DEB_NAME="aleph-vm.${OS}.deb"
DEB_URL="https://github.com/${REPO}/releases/download/${VERSION}/${DEB_NAME}"
DEB_PATH="${DEB_DIR}/${DEB_NAME}"

echo "OS:      ${OS}"
echo "Current: ${CURRENT}"
echo "Target:  ${VERSION}"
echo "Package: ${DEB_URL}"
echo ""

run rm -f "$DEB_PATH"
run wget -q --show-progress -P "$DEB_DIR" "$DEB_URL"
run apt install -y "$DEB_PATH"

echo ""
echo "aleph-vm upgraded: ${CURRENT} -> ${VERSION}"
