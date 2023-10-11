# Testing your VMs locally

You can test your VM locally without uploading each version on the Aleph network.

To do this, you'll want to use the `--fake-data-program` or `-f` argument of the VM Supervisor.

## 0. Build the required squashfs volumes

Build or download the required squashfs volumes:

```shell
cd ./runtimes/aleph-debian-11-python/
sudo bash ./create_disk_image.sh

cd ../..
```
> ℹ️ This does not work in a container since debootstrap requires mounting volumes.

This will create a local runtime root filesystem in `./runtimes/aleph-debian-11-python/rootfs.squashfs`.

```shell
cd ./examples/volumes/
bash ./build_squashfs.sh

cd ../..
```
This will create a local example read-only volume named `./example/volumes/volume-venv.squashfs`.

## 1. In a Docker container

Run the developer image, mounting the two generated volumes:
```shell
docker run -ti --rm \
  -v "$(pwd)/runtimes/aleph-debian-11-python/rootfs.squashfs:/opt/aleph-vm/runtimes/aleph-debian-11-python/rootfs.squashfs:ro" \
  -v "$(pwd)/examples/volumes/volume-venv.squashfs:/opt/aleph-vm/examples/volumes/volume-venv.squashfs:ro" \
  --device /dev/kvm \
  -p 4020:4020 \
  docker.io/alephim/vm-supervisor-dev
```

Or launch this command using:
```shell
bash ./docker/run_vm_supervisor.sh
```


Within the container, run the supervisor with fake data:
```shell
python3 -m orchestrator --print-settings --very-verbose --system-logs --fake-data-program ./examples/example_fastapi
```

> ℹ️ The command is in your .bash_history, press key up to skip typing it. 

## 2. On your system

### 2.a. Install the system requirements

See [../vm_supervisor/README.md](../src/aleph/vm/orchestrator/README.md) to install the system requirements.

### 2.b. Run the supervisor with fake data:

```shell
python3 -m orchestrator --print-settings --very-verbose --system-logs --fake-data-program ./examples/example_fastapi
```

