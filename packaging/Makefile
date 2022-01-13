all: debian-package

debian-package: debian-package-resources debian-package-code
	sudo dpkg-deb --build aleph-vm target/aleph-vm.deb

debian-package-code:
	rm -fr ./aleph-vm/opt/aleph-vm
	mkdir -p ./aleph-vm/opt/aleph-vm
	cp -r ../vm_supervisor ./aleph-vm/opt/aleph-vm/
	cp -r ../guest_api ./aleph-vm/opt/aleph-vm/
	cp -r ../firecracker ./aleph-vm/opt/aleph-vm/

	# Fake data for diagnostic and benchmarks
	mkdir -p ./aleph-vm/opt/aleph-vm/examples/
	cp -r ../examples/example_fastapi ./aleph-vm/opt/aleph-vm/examples/example_fastapi
	cp ../examples/message_from_aleph.json ./aleph-vm/opt/aleph-vm/examples/message_from_aleph.json
	cp -r ../examples/data ./aleph-vm/opt/aleph-vm/examples/data
	mkdir -p ./aleph-vm/opt/aleph-vm/examples/volumes
	cp ../examples/volumes/volume-venv.squashfs ./aleph-vm/opt/aleph-vm/examples/volumes/volume-venv.squashfs
	mkdir -p ./aleph-vm/opt/aleph-vm/runtimes/aleph-debian-11-python/
	cp ../runtimes/aleph-debian-11-python/rootfs.squashfs ./aleph-vm/opt/aleph-vm/runtimes/aleph-debian-11-python/rootfs.squashfs

	pip3 install --target ./aleph-vm/opt/aleph-vm/ 'aleph-message>=0.1.18'

debian-package-resources: firecracker-bins vmlinux
	rm -fr ./aleph-vm/opt/firecracker
	mkdir -p ./aleph-vm/opt/firecracker
	cp -pr ./target/vmlinux.bin ./aleph-vm/opt/firecracker/
	cp -pr ./target/firecracker ./aleph-vm/opt/firecracker/
	cp -pr ./target/jailer ./aleph-vm/opt/firecracker/

firecracker-bins: target-dir build-dir
	mkdir -p ./build/firecracker-release
	# Download latest release
	curl -fsSL https://github.com/firecracker-microvm/firecracker/releases/download/v0.25.2/firecracker-v0.25.2-x86_64.tgz | tar -xz --directory ./build/firecracker-release
	# Copy binaries:
	cp ./build/firecracker-release/release-v*/firecracker-v* ./target/firecracker
	cp ./build/firecracker-release/release-v*/jailer-v* ./target/jailer
	chmod +x ./target/firecracker
	chmod +x ./target/jailer

vmlinux:
	#curl -fsSL -o ./target/vmlinux.bin https://s3.amazonaws.com/spec.ccfc.min/img/quickstart_guide/x86_64/kernels/vmlinux.bin
	curl -fsSL -o ./target/vmlinux.bin https://github.com/aleph-im/aleph-vm/releases/download/0.1.0/vmlinux.bin
	#cp ../kernels/vmlinux.bin ./target/vmlinux.bin

build-dir:
	mkdir -p target

target-dir:
	mkdir -p target

clean:
	rm -fr ./target/*
	rm -fr ./build/*

all-podman-debian-11:
	cd .. && podman build -t localhost/aleph-vm-packaging:latest -f ./packaging/debian-11.dockerfile .
	mkdir -p ./target
	podman run --rm -ti \
		-w /opt/packaging \
		-v ./target:/opt/packaging/target \
		localhost/aleph-vm-packaging:latest \
		make
	file target/aleph-vm.deb
	mv target/aleph-vm.deb target/aleph-vm.debian-11.deb

all-podman-ubuntu-2004:
	cd .. && podman build -t localhost/aleph-vm-packaging:latest -f ./packaging/ubuntu-20.04.dockerfile .
	mkdir -p ./target
	podman run --rm -ti \
		-w /opt/packaging \
		-v ./target:/opt/packaging/target \
		localhost/aleph-vm-packaging:latest \
		make
	file target/aleph-vm.deb
	mv target/aleph-vm.deb target/aleph-vm.ubuntu-20.04.deb

# run on host in order to sign with GPG
repository-bullseye:
	cd ./repositories/bullseye && reprepro -Vb . includedeb bullseye ../../target/aleph-vm.debian-11.deb && cd ..

# run on host in order to sign with GPG
repository-focal:
	cd ./repositories/focal && reprepro -Vb . includedeb focal ../../target/aleph-vm.ubuntu-20.04.deb && cd ..

repositories: repository-bullseye repository-focal

all-podman: all-podman-debian-11 all-podman-ubuntu-2004 repositories
