# Developer tasks for running the aleph-vm test suite locally.
#
# Requires `just` (https://github.com/casey/just). Run `just` to list recipes.
#
# Quick start (Debian/Ubuntu):
#   just install-system-deps   # once: apt packages + build headers (sudo)
#   just setup-venv            # create .testvenv, install the project + test deps
#   just test                  # run the suite without root
#
# `install-system-deps` installs the apt python3-* bindings (nftables, dbus,
# systemd, ...) and the dev headers pip compiles dbus-python / systemd-python
# against, mirroring .github/workflows/test-using-pytest.yml. `setup-venv` then
# creates a --system-site-packages virtualenv (so those bindings are visible,
# matching CI's hatch `testing` env) and installs the rest with pip.
#
# A handful of tests still require root + network + qemu/firecracker (network
# interfaces, VM creation, runtime downloads); those only pass in CI under sudo.
# Path to the local test virtualenv.

venv := ".testvenv"

# Writable stand-ins for /var/cache/aleph and /var/lib/aleph (gitignored) so the
# suite runs without root.

roots := justfile_directory() / ".test-roots"
py := venv / "bin" / "python"

# List available recipes.
_default:
    @just --list

# Install the apt packages and build headers the test suite needs (sudo).
install-system-deps:
    sudo apt-get update
    sudo apt-get install -y \
        python3 python3-pip python3-aiohttp python3-msgpack python3-aiodns \
        python3-alembic python3-sqlalchemy python3-setproctitle python3-psutil \
        python3-packaging python3-cpuinfo python3-nftables python3-jsonschema \
        python3-jwcrypto nftables redis acl curl systemd-container squashfs-tools \
        debootstrap libsystemd-dev cmake libdbus-1-dev libglib2.0-dev lshw

# Create .testvenv and install the project + test/lint deps (run install-system-deps first).
setup-venv:
    python3 -m venv --system-site-packages {{ venv }}
    {{ venv }}/bin/pip install --upgrade pip
    {{ venv }}/bin/pip install -e . \
        eth_typing==4.3.1 \
        pytest==8.2.1 pytest-cov==5.0.0 pytest-mock==3.14.0 \
        pytest-asyncio==0.23.7 pytest-aiohttp==1.0.5 \
        mypy==1.8.0 ruff==0.4.6 isort==5.13.2

# Run the suite without root, or a subset: `just test tests/supervisor`.
test *args="tests":
    mkdir -p {{ roots }}/cache {{ roots }}/exec
    ALEPH_VM_CACHE_ROOT={{ roots }}/cache \
    ALEPH_VM_EXECUTION_ROOT={{ roots }}/exec \
        {{ py }} -m pytest {{ args }}

# Artifact paths come from the AVM_ITEST_FC_KERNEL / AVM_ITEST_FC_RUNTIME /
# AVM_ITEST_QEMU_IMAGE env vars; see tests/integration/conftest.py for the
# defaults and the full requirements per backend.

# Supervisor integration tests without root (real Firecracker boots over the gRPC daemon; QEMU/networking tests skip).
itest *args="tests/integration":
    AVM_ITEST=1 {{ py }} -m pytest -v -p no:cacheprovider {{ args }}

# Full supervisor integration tests with sudo (QEMU, TAP networking, port forwards, backups/restores).
itest-root *args="tests/integration":
    sudo --preserve-env=AVM_ITEST_FC_KERNEL,AVM_ITEST_FC_RUNTIME,AVM_ITEST_QEMU_IMAGE \
        env AVM_ITEST=1 {{ py }} -m pytest -v -p no:cacheprovider {{ args }}

# Whole-package type check (the CI mypy gate).
check-typing:
    {{ py }} -m mypy src/aleph/vm/

# Style checks (ruff format + isort), matching CI's linting env.
lint:
    {{ py }} -m ruff format --check .
    {{ py }} -m isort --check-only --profile black .

# Apply formatting in place (ruff format + isort).
format:
    {{ py }} -m ruff format .
    {{ py }} -m isort --profile black .

# Remove the local test virtualenv and writable roots.
clean:
    rm -rf {{ venv }} {{ roots }}
