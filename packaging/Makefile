all: debian-package

debian-package: debian-package-resources debian-package-code
	sudo dpkg-deb --build aleph-vm target/aleph-vm.deb

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
	# Fixing this protobuf dependency version to avoid getting CI errors as version 5.29.0 have this compilation issue
	build_venv/bin/pip install --no-cache-dir  --progress-bar off --target ./aleph-vm/opt/aleph-vm/ 'aleph-message~=1.0.1' 'eth-account==0.10' 'sentry-sdk==1.31.0' 'qmp==1.1.0' 'aleph-superfluid~=0.2.1' 'sqlalchemy[asyncio]>=2.0' 'aiosqlite==0.19.0' 'alembic==1.13.1' 'aiohttp_cors==0.7.0' 'pydantic-settings==2.6.1' 'pyroute2==0.7.12' 'python-cpuid==0.1.0' 'solathon==1.0.2' 'protobuf==5.28.3'
	build_venv/bin/python3 -m compileall ./aleph-vm/opt/aleph-vm/

debian-package-resources: firecracker-bins vmlinux target/bin/sevctl
	rm -fr ./aleph-vm/opt/firecracker
	mkdir -p ./aleph-vm/opt/firecracker
	cp -pr ./target/vmlinux.bin ./aleph-vm/opt/firecracker/
	cp -pr ./target/firecracker ./aleph-vm/opt/firecracker/
	cp -pr ./target/jailer ./aleph-vm/opt/firecracker/
	# Disable Kubo installation for now
	# cp -pr ./target/kubo/kubo ./aleph-vm/opt/kubo
	cp -pr ./target/bin/sevctl ./aleph-vm/opt/sevctl

firecracker-bins: target-dir build-dir
	mkdir -p ./build/firecracker-release
	# Download latest release
	curl -fsSL https://github.com/firecracker-microvm/firecracker/releases/download/v1.7.0/firecracker-v1.7.0-x86_64.tgz | tar -xz --no-same-owner --directory ./build/firecracker-release
	# Copy binaries:
	cp ./build/firecracker-release/release-v*/firecracker-v*[!.debug] ./target/firecracker
	cp ./build/firecracker-release/release-v*/jailer-v*[!.debug] ./target/jailer
	chmod +x ./target/firecracker
	chmod +x ./target/jailer

vmlinux:
	#curl -fsSL -o ./target/vmlinux.bin https://s3.amazonaws.com/spec.ccfc.min/img/quickstart_guide/x86_64/kernels/vmlinux.bin
	curl -fsSL -o ./target/vmlinux.bin https://ipfs.aleph.cloud/ipfs/bafybeiaj2lf6g573jiulzacvkyw4zzav7dwbo5qbeiohoduopwxs2c6vvy
	#cp ../kernels/vmlinux.bin ./target/vmlinux.bin

download-ipfs-kubo: target-dir build-dir
	mkdir -p ./target/kubo
	curl -fsSL https://github.com/ipfs/kubo/releases/download/v0.33.2/kubo_v0.33.2_linux-amd64.tar.gz | tar -xz --directory ./target/kubo

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
	rm -fr ./aleph-vm/opt/kubo/
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
repository-noble:
	cd ./repositories/noble && reprepro -Vb . includedeb noble ../../target/aleph-vm.ubuntu-24.04.deb && cd ..

repositories: repository-bookworm repository-jammy repository-noble

all-podman: all-podman-debian-12 all-podman-ubuntu-2204 all-podman-ubuntu-2404 repositories

