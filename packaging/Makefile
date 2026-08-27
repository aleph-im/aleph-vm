all: debian-package

debian-package: debian-package-resources debian-package-code debian-package-rust
	sudo dpkg-deb --build aleph-vm target/aleph-vm.deb

# Rust supervisor daemon (design doc 2026-07-04-rust-supervisor-daemon-design.md,
# section 9): built with the toolchain pinned in rust/rust-toolchain.toml
# (rustup picks it up when cargo runs from inside rust/), installed under
# /opt/aleph-vm/bin/ next to the supervisor-launcher dispatch script.
# The deb keeps shipping the full Python tree regardless of the
# ALEPH_VM_SUPERVISOR_IMPL flag (default rust); the Python daemon only runs
# when an operator sets python in /etc/aleph-vm/supervisor.env.
# Depends on debian-package-code because that target wipes and rebuilds
# ./aleph-vm/opt/aleph-vm, where the binaries land.
debian-package-rust: debian-package-code
	cd ../rust && cargo build --release --locked
	mkdir -p ./aleph-vm/opt/aleph-vm/bin
	install -m 0755 ../rust/target/release/aleph-vm-supervisor ./aleph-vm/opt/aleph-vm/bin/aleph-vm-supervisor
	install -m 0755 ./supervisor-launcher ./aleph-vm/opt/aleph-vm/bin/supervisor-launcher
	# Per-VM controller (phase 3 task A3): the Rust controller launches the
	# persistent QEMU process, dispatched from the same ALEPH_VM_SUPERVISOR_IMPL
	# flag via controller-launcher. Inert until an operator flips the flag.
	install -m 0755 ../rust/target/release/aleph-vm-controller ./aleph-vm/opt/aleph-vm/bin/aleph-vm-controller
	install -m 0755 ./controller-launcher ./aleph-vm/opt/aleph-vm/bin/controller-launcher
	# Debug CLI (2026-07-07-alephctl): ships next to the supervisor so
	# operators can poke the gRPC socket on-node without a full agent stack.
	install -m 0755 ../rust/target/release/alephctl ./aleph-vm/opt/aleph-vm/bin/alephctl

debian-package-code:
	rm -fr ./aleph-vm/opt/aleph-vm
	mkdir -p ./aleph-vm/opt/aleph-vm
	cp -r ../src/aleph ./aleph-vm/opt/aleph-vm/

	# Fake data for diagnostic and benchmarks
	mkdir -p ./aleph-vm/opt/aleph-vm/examples/
	cp -r ../examples/example_fastapi ./aleph-vm/opt/aleph-vm/examples/example_fastapi
	cp ../examples/program_message_from_aleph.json ./aleph-vm/opt/aleph-vm/examples/program_message_from_aleph.json
	cp ../examples/instance_message_from_aleph.json ./aleph-vm/opt/aleph-vm/examples/instance_message_from_aleph.json
	cp -r ../examples/data ./aleph-vm/opt/aleph-vm/examples/data
	mkdir -p ./aleph-vm/opt/aleph-vm/examples/volumes
	# Making a venv to build the wheel. to work arround a strange problem while building the wheel
	python3 -m venv build_venv
	build_venv/bin/pip install   --progress-bar off --upgrade pip setuptools wheel
	# Versions below MUST mirror pyproject.toml so the .deb ships what the code is tested against.
	# MERGE GATE: aleph-message is git-pinned to the V-PROGRAM schema ref, swap for a release with pyproject.toml.
	# protobuf is pinned to 5.29.6: 5.29.0 has a compilation issue; 6.x needs grpcio/tools 1.71+.
	# legacy-cgi is packaging-only: it backfills the `cgi` module removed from the Python 3.13+ stdlib.
	build_venv/bin/pip install --no-cache-dir  --progress-bar off --target ./aleph-vm/opt/aleph-vm/ 'aleph-message @ git+https://github.com/aleph-im/aleph-message@4ad261ff25f595a64589d49bf36f514c402e7c5e' 'eth-account~=0.10' 'sentry-sdk==2.8' 'qmp==1.1' 'aleph-superfluid~=0.2.1' 'sqlalchemy[asyncio]>=2' 'aiosqlite==0.19' 'alembic==1.13.1' 'aiohttp-cors~=0.7.0' 'pydantic-settings~=2.6.1' 'pyroute2==0.7.12' 'python-cpuid==0.1.1' 'solathon==1.0.7' 'protobuf==5.29.6' 'grpcio>=1.70,<1.71' 'redis>=4.2' 'legacy-cgi>=1.0'
	build_venv/bin/python3 -m compileall ./aleph-vm/opt/aleph-vm/

debian-package-resources: firecracker-bins vmlinux target/bin/sevctl
	rm -fr ./aleph-vm/opt/firecracker
	mkdir -p ./aleph-vm/opt/firecracker
	cp -pr ./target/vmlinux.bin ./aleph-vm/opt/firecracker/
	cp -pr ./target/firecracker ./aleph-vm/opt/firecracker/
	cp -pr ./target/jailer ./aleph-vm/opt/firecracker/
	cp -pr ./target/bin/sevctl ./aleph-vm/opt/sevctl

firecracker-bins: target-dir build-dir
	mkdir -p ./build/firecracker-release
	# Download latest release
	curl -fsSL https://github.com/firecracker-microvm/firecracker/releases/download/v1.15.1/firecracker-v1.15.1-x86_64.tgz | tar -xz --no-same-owner --directory ./build/firecracker-release
	# Copy binaries:
	cp ./build/firecracker-release/release-v*/firecracker-v*[!.debug] ./target/firecracker
	cp ./build/firecracker-release/release-v*/jailer-v*[!.debug] ./target/jailer
	chmod +x ./target/firecracker
	chmod +x ./target/jailer

vmlinux:
	curl -fsSL -o ./target/vmlinux.bin https://ipfs.aleph.cloud/ipfs/QmQvQnZg9rB2fhmuminFSYgtGGzEhfbiTMobppUXVfGBmD

target/bin/sevctl:
	cargo install --locked --git https://github.com/virtee/sevctl.git --rev v0.6.0 --target x86_64-unknown-linux-gnu --root ./target
	./target/bin/sevctl -V

version:
	python3 ./version_from_git.py --inplace deb aleph-vm/DEBIAN/control
	python3 ./version_from_git.py --inplace __version__ ../src/aleph/vm/version.py

build-dir:
	mkdir -p target

target-dir:
	mkdir -p target

clean:
	rm -fr ./target/*
	rm -fr ./build/*
	rm -fr ./aleph-vm/opt/aleph-vm/
	rm -fr ./aleph-vm/opt/firecracker/
	rm -fr ./aleph-vm/opt/aleph-vm/
	rm -fr ./sevctl/target/

all-podman-debian-12: version
	cd .. && podman build -t localhost/aleph-vm-packaging-debian-12:latest -f ./packaging/debian-12.dockerfile .
	mkdir -p ./target
	podman run --rm -ti \
		-w /opt/packaging \
		-v ./target:/opt/packaging/target \
		localhost/aleph-vm-packaging-debian-12:latest \
		make
	file target/aleph-vm.deb
	mv target/aleph-vm.deb target/aleph-vm.debian-12.deb

all-podman-ubuntu-2204: version
	# Ensure the sevctl submodule is checked out first.
	git submodule init
	cd .. && podman build -t localhost/aleph-vm-packaging-ubuntu-2204:latest -f ./packaging/ubuntu-22.04.dockerfile .
	mkdir -p ./target
	podman run --rm -ti \
		-w /opt/packaging \
		-v ./target:/opt/packaging/target \
		localhost/aleph-vm-packaging-ubuntu-2204:latest \
		make
	file target/aleph-vm.deb
	mv target/aleph-vm.deb target/aleph-vm.ubuntu-22.04.deb

all-podman-debian-13: version
	cd .. && podman build -t localhost/aleph-vm-packaging-debian-13:latest -f ./packaging/debian-13.dockerfile .
	mkdir -p ./target
	podman run --rm -ti \
		-w /opt/packaging \
		-v ./target:/opt/packaging/target \
		localhost/aleph-vm-packaging-debian-13:latest \
		make
	file target/aleph-vm.deb
	mv target/aleph-vm.deb target/aleph-vm.debian-13.deb

all-podman-ubuntu-2404: version
	cd .. && podman build -t localhost/aleph-vm-packaging-ubuntu-2404:latest -f ./packaging/ubuntu-24.04.dockerfile .
	mkdir -p ./target
	podman run --rm -ti \
		-w /opt/packaging \
		-v ./target:/opt/packaging/target \
		localhost/aleph-vm-packaging-ubuntu-2404:latest \
		make
	file target/aleph-vm.deb
	mv target/aleph-vm.deb target/aleph-vm.ubuntu-24.04.deb

# extract Python requirements from Debian 12 container
requirements-debian-12: all-podman-debian-12
	podman run --rm -ti \
		-v ./target/aleph-vm.debian-12.deb:/opt/packaging/target/aleph-vm.deb:ro \
		-v ./extract_requirements.sh:/opt/extract_requirements.sh:ro \
		-v ./requirements-debian-12.txt:/mnt/requirements-debian-12.txt \
		debian:bookworm \
		bash -c "/opt/extract_requirements.sh /mnt/requirements-debian-12.txt"

# extract Python requirements from Debian 13 container
requirements-debian-13: all-podman-debian-13
	podman run --rm -ti \
		-v ./target/aleph-vm.debian-13.deb:/opt/packaging/target/aleph-vm.deb:ro \
		-v ./extract_requirements.sh:/opt/extract_requirements.sh:ro \
		-v ./requirements-debian-13.txt:/mnt/requirements-debian-13.txt \
		debian:trixie \
		bash -c "/opt/extract_requirements.sh /mnt/requirements-debian-13.txt"

# extract Python requirements from Ubuntu 22.04 container
requirements-ubuntu-22.04: all-podman-ubuntu-2204
	podman run --rm -ti \
		-v ./target/aleph-vm.ubuntu-22.04.deb:/opt/packaging/target/aleph-vm.deb:ro \
		-v ./extract_requirements.sh:/opt/extract_requirements.sh:ro \
		-v ./requirements-ubuntu-22.04.txt:/mnt/requirements-ubuntu-22.04.txt \
		ubuntu:jammy \
		bash -c "/opt/extract_requirements.sh /mnt/requirements-ubuntu-22.04.txt"

# extract Python requirements from Ubuntu 24.04 container
requirements-ubuntu-24.04: all-podman-ubuntu-2404
	podman run --rm -ti \
		-v ./target/aleph-vm.ubuntu-24.04.deb:/opt/packaging/target/aleph-vm.deb:ro \
		-v ./extract_requirements.sh:/opt/extract_requirements.sh:ro \
		-v ./requirements-ubuntu-24.04.txt:/mnt/requirements-ubuntu-24.04.txt \
		ubuntu:noble \
		bash -c "/opt/extract_requirements.sh /mnt/requirements-ubuntu-24.04.txt"

# run on host in order to sign with GPG
repository-bookworm:
	cd ./repositories/bookworm && reprepro -Vb . includedeb bookworm ../../target/aleph-vm.debian-12.deb && cd ..

# run on host in order to sign with GPG
repository-jammy:
	cd ./repositories/jammy && reprepro -Vb . includedeb jammy ../../target/aleph-vm.ubuntu-22.04.deb && cd ..

# run on host in order to sign with GPG
repository-trixie:
	cd ./repositories/trixie && reprepro -Vb . includedeb trixie ../../target/aleph-vm.debian-13.deb && cd ..

# run on host in order to sign with GPG
repository-noble:
	cd ./repositories/noble && reprepro -Vb . includedeb noble ../../target/aleph-vm.ubuntu-24.04.deb && cd ..

repositories: repository-bookworm repository-trixie repository-jammy repository-noble

all-podman: all-podman-debian-12 all-podman-debian-13 all-podman-ubuntu-2204 all-podman-ubuntu-2404 repositories

