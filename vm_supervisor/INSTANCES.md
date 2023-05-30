
# Instance Messages

Support of Instance message in the aleph-message repository was added in this PR:
https://github.com/aleph-im/aleph-message/pull/48

## Changes added

### Aleph message repository

I added a new type of message called `InstanceMessage`, with the changes that we designed for VM instances.
The content of this message is a new type called `InstanceContent`, that replaces the field `runtime` by `rootfs` that
instead be an Immutable volume becomes a Persistent volume and adds a new field inside called `parent`, that will be the
item hash of the base filesystem of the VM. We will create a .ext4 file with the size of the volume and **"attach"** to it
the base filesystem.

Note that this filesystem should be in **.ext4** format, cannot be an **squashfs**
file, because we will map it as a block device inside the machine.

Also, I added a union type for Instance messages and Program message called `ExecutableMessage` and also a new one called
`ExecutableContent` as union of Instance and program content types.

### Aleph VM repository

I have created a function called `create_devmapper` in _**vm_supervisor/storage.py**_. This method can create a
dev-mapper device base on the parent reference. I followed 
[this](https://community.aleph.im/t/deploying-mutable-vm-instances-on-aleph/56/2) implementation.

In the _**firecracker/microvm.py**_ file I added the `mount_rootfs` method to mount the block device in the case that we
use jailer and also assign correct permissions. And when the VM goes down, I clear all these configurations in the
`teardown` process. As link a block device in a chroot doesn't work I had to do a workaround that consists of copy all
the "dm-*" block devices in the chroot and mount the entire `/dev/mapper` folder in the chroot to make it work. I didn't
found a better solution to it.

Also, I added support to run a writable root filesystem in Firecracker. I have bypassed all the parts that we pass and
use the **_"code"_** properties, like the encoding or the entrypoint.

A new instance message example has been added in **_examples/instance_message_from_aleph.json_**.

### Current status

Now the Dev-mapper device works well, Firecracker loads it in write state, but we need to fix 2 things:
- Route the requests from the CRN to the Firecracker VM on any port, not only using the 8080.
- ~~- Use the entire hard disk inside VM, because now only detects the size of the rootfs.~~(Done)
