Run with

```shell
nixos-generate -f vm -c config.nix --run
```

Then inside the VM:

```shell
git clone https://github.com/aleph-im/aleph-vm.git

git checkout hoh-nixos-vm
```

Download Firecracker, Jailer and a Linux kernel:
```shell
bash ./packaging/nixos/setup.sh
```

## Cleanup

Remove all state using:
```shell
rm nixos.qcow2
```