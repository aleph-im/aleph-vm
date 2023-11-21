# Qemu support

## Requirements
Commands : qemu, cloud-ds, qemu-img

These are installable via 
`apt install cloud-image-utils qemu-utils qemu-system-x86`

At this moment this branch depends on branch `olethanh-qemu-message-format`  of aleph-message which add the new temporary format.

The easiest way is to check it out locally and install it in your venv using `pip install -e .`

## To test launching a VM instance

Launch aleph.vm.orchestrator with the following environment variables


```environ
ALEPH_VM_FAKE_INSTANCE_BASE=/home/olivier/Projects/qemu-quickstart/jammy-server-cloudimg-amd64.img
ALEPH_VM_FAKE_INSTANCE_MESSAGE=/home/olivier/Projects/aleph/aleph-vm/examples/qemu_message_from_aleph.json
ALEPH_VM_USE_FAKE_INSTANCE_BASE=1
```

Where `ALEPH_VM_FAKE_INSTANCE_BASE` is the path to the base disk image. You can get the Ubuntu one via:
`wget https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img`

You can use any base VM image supporting cloud-init. cloud-init support is mandatory because it is used to set up the network.  


To only launch the VM instance, use the parameter:
`--run-fake-instance`

You can then try to connect via ssh to it's ip. Wait a minute or so for it to set up properly with the network

Or launching the whole supervisor server (no params), then launch the VM via http

```http request
### Start fake VM
GET http://localhost:4020/vm/decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadeca/
Accept: application/json

```
caveat This will return a 502 status code since we can't execute code in an instance vm, but it will still start the VM.

You can then stop the VM using

```http request
### Stop the VM
POST http://localhost:4020/control/machine/decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadeca/stop
Accept: application/json
```
(you might need to comment @require_jwk_authentication)



# TODO
- [x] Launch
- [x] Message format
- [x] Network
- [x] Cloud init
- [x] Download ressource
- [ ] snapshot
- [ ] Multi volume
- [ ] fix logs
- [ ] Testing
- [x] Support raw format for base image
