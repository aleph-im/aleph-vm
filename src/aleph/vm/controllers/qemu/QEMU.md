# Qemu support

## Requirements
Commands : qemu, cloud-ds, qemu-img

These are installable via 
`apt install cloud-image-utils qemu-utils qemu-system-x86`

At this moment this branch depends on branch `olethanh-qemu-message-format`  of aleph-message which add the new temporary format.  https://github.com/olethanh/aleph-message/tree/olethanh-qemu-message-format

The easiest way is to check the branch locally and install it in your venv using `pip install -e .`

## To test launching a VM instance

Launch aleph.vm.orchestrator with the following environment variables


```environ
ALEPH_VM_FAKE_INSTANCE_BASE=/home/olivier/Projects/qemu-quickstart/jammy-server-cloudimg-amd64.img
ALEPH_VM_FAKE_INSTANCE_MESSAGE=/home/olivier/Projects/aleph/aleph-vm/examples/qemu_message_from_aleph.json
ALEPH_VM_USE_FAKE_INSTANCE_BASE=1
# set test as the allocation password
ALEPH_VM_ALLOCATION_TOKEN_HASH=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08

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
POST http://localhost:4020/control/allocations
Content-Type: application/json
X-Auth-Signature: test
Accept: application/json

{"persistent_vms": [], "instances": ["decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadeca"]}
```

After a minutes or two you should be able to SSH into the VM. Check in the log for the VM ip. 
If you used an Ubuntu image the username should be ubuntu

You can then stop the VM using
```http request
### Stop the VM
POST http://localhost:4020/control/machine/decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadeca/stop
Accept: application/json
```
(you will need to comment @require_jwk_authentication)

# Connecting to the VM via your own ssh key
In local development, if you want to connect via ssh to the VM and you don't have your
 key already included in you base image or inside the aleph message, you can configure it in the following way.

First set your key in the environment variable ALEPH_VM_DEVELOPER_SSH_KEYS in the json format. You can add it directly in the `.env` file
```env
ALEPH_VM_DEVELOPER_SSH_KEYS=["ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDj95BHGUx0/z2G/tTrEi8o49i70xvjcEUdSs3j4A33jE7pAphrfRVbuFMgFubcm8n9r5ftd/H8SjjTL4hY9YvWV5ZuMf92GUga3n4wgevvPlBszYZCy/idxFl0vtHYC1CcK9v4tVb9onhDt8FOJkf2m6PmDyvC+6tl6LwoerXTeeiKr5VnTB4KOBkammtFmix3d1X1SZd/cxdwZIHcQ7BNsqBm2w/YzVba6Z4ZnFUelBkQtMQqNs2aV51O1pFFqtZp2mM71D5d8vn9pOtqJ5QmY5IW6NypcyqKJZg5o6QguK5rdXLkc7AWro27BiaHIENl3w0wazp9EDO9zPAGJ6lz olivier@lanius"]
```

Then pass the `--developer-ssh-keys` as an argument when starting the supervisor.

Cloud init support for settings the ssh key in the VM image is required, this is the same mechanism and settings as for firecracker program, of course this is not for production use.

# TODO
- [x] Launch
- [x] Message format
- [x] Network
- [x] Cloud init support
- [x] Download ressource
- [ ] snapshot
- [ ] Multi volume
- [x] fix logs
- [ ] Testing
- [x] Support raw format for base image
- [ ] More testing with different Distro: Fedora, debian, alpine
- [ ] Document for user how to build their own images
- [x] Allow ssh developer key
- [ ] Automated testing in CI
- [ ] Output the whole serial console in logs
- [ ] Test code for websocket logs
