# Tutorial: Creating and hosting a program on Aleph-VM

This is the tutorial for Creating and hosting a program on Aleph-VM, which has been developed and maintained by [Aleph.im](https://www.aleph.im).

## 0. Welcome

Hi, welcome to _Creating and hosting a program on Aleph-VM_. In this tutorial we will take you 
through the fundamentals of running programs on the [Aleph.im](https://aleph.im/) Virtual Machines.
After the tutorial you should have a rough mental picture of how the virtual machines work and 
some good pointers for getting further with running programs of your own.

We expect you to know a little Python and have some experience with Python web frameworks such as
[FastAPI](https://fastapi.tiangolo.com/) or Flask. 
The first chapters of the [FastAPI Tutorial](https://fastapi.tiangolo.com/tutorial/) should cover
enough to get started.

## What we will cover

First we will see how to run the first example from FastAPI's tutorial on Aleph.im, how to
access it and how to update it.

Then we will extend the program to add some Aleph specific functionalities.

## Requirements

To complete this tutorial, you will use the `aleph` command from 
[aleph-client](https://github.com/aleph-im/aleph-client), the `fastapi` framework to create a
simple API and the `uvicorn` server to test your program on your desktop before uploading it on 
Aleph.

First, you need a recent version of Python and [pip](https://pip.pypa.io/en/stable/), 
preferably running on Debian 11 or Ubuntu Linux 20.04 since we have not tested other platforms yet, 
but feel free to use the platform of your choice if you have the skills to adapt our instructions to it.

Some cryptographic functionalities of Aleph use curve secp256k1 and require installing [libsecp256k1](https://github.com/bitcoin-core/secp256k1).
Archiving programs and volumes requires
[Squashfs user space tools](https://github.com/plougher/squashfs-tools).

    sudo apt-get install -y python3-pip libsecp256k1-dev squashfs-tools

You will also need [Uvicorn](https://www.uvicorn.org/) for local testing 
and the [Python Aleph client](https://github.com/aleph-im/aleph-client) for it's command-line tools:

    pip3 install uvicorn[standard] aleph-client fastapi eth_account

## 1. Understanding the VMs

Aleph is a cross-blockchain layer-2 network specifically focused on decentralized applications and
their related infrastructure (storage, computing servers, security).

Aleph-VM is the computing part of the network: It allows the execution of programs stored on the
Aleph network. These programs can interact with the network itself and with the rest of the internet.

In the current stage, these programs can be triggered from outside HTTPS calls. Future ways to
trigger the launch of the programs are planned, such as reacting to specific messages on the
network.

### Virtual Machines

Programs on Aleph run within virtual machines: emulated computer systems with dedicated 
resources that run isolated from each other.

Aleph Virtual Machines (VMs) are based on Linux and 
use [Firecracker](https://firecracker-microvm.github.io/) under the hood. They boot very fast,
so they can be launched on demand and there is no need to keep them running while waiting for new 
requests.

Each program runs on its own dedicated Linux system, with the host providing additional
functionalities related to Aleph.

### Runtime

The base of each VM is a Linux 
[root filesystem](https://en.wikipedia.org/wiki/Root_directory) named __runtime__ and configured
to run programs on the Aleph platform. 

Aleph provides a supported runtime to launch programs written in Python or binaries. 
* Python programs must support the [ASGI interface](https://asgi.readthedocs.io/en/latest/), described in the example below.
* Binaries must listen for HTTP requests on port 8080

The runtime currently supported by Aleph is 
[aleph-debian-11-python](../runtimes/aleph-debian-11-python).

### Volumes

VMs can be extended by specifying additional volumes that will be mounted in the system. 

**Read-only volumes** are useful to separate Python virtual environments, Javascript _node_modules_ 
or static data from the program itself. These volumes can be updated independently from the 
program and the runtime, and maintained by a third party.

**Ephemeral volumes** provide temporary disk storage to a VM during its execution without requiring
more memory.

**Host persistent volumes** are persisted on the VM execution node, but may be garbage collected
by the node without warning.

**Store persistent volumes** (not available yet) are persisted on the Aleph network. New VMs will try to use the latest 
version of this volume, with no guarantee against conflicts.

## 2. Writing a Python program

To create the first program, open your favourite code editor and create a directory named
`my-program`, containing a file named `main.py`.

```
.
└── my-program/
    └── main.py
```

Then write the following code in the file:
```python
from fastapi import FastAPI

app = FastAPI()


@app.get("/")
async def root():
    return {"message": "Hello World"}
```

That's it for your first program.

This code comes from the [FastAPI tutorial](https://fastapi.tiangolo.com/tutorial/first-steps/).
Have a look at it for a better understanding of what it does and how it works.

## 3. Testing locally

Before uploading your program on Aleph, it is best to first test it locally.

Aleph uses the standard [ASGI interface](https://asgi.readthedocs.io/en/latest/introduction.html) to
interface with programs written in Python. ASGI interfaces with many Python frameworks, including
FastAPI but also [Django](https://www.djangoproject.com/) 
or [Quart](https://github.com/pgjones/quart).

Test your progam locally using uvicorn, an ASGI server:

```shell
uvicorn main:app --reload
```

Then open http://127.0.0.1:8000 . The `--reload` option will automatically reload your app
when the code changes.

> ℹ️ If you are running this on a different system than your desktop, specify the IP address of 
> that system using `uvicorn main:app --reload --host 1.2.3.4`, where `1.2.3.4` is the IP address
> of the system.
> Then open your browser on http://1.2.3.4:8000 instead.

> ℹ Installing uvicorn should add the `uvicorn` command to your shell. If it does not, use
> `python3 -m uvicorn` to run it.

## 4. Uploading

After installing [aleph-client](https://github.com/aleph-im/aleph-client), you should have access to the `aleph` command:

```shell
aleph --help
```

Upload your program:

```shell
aleph program ./my-program main:app
```

Press Enter at the following prompt to use the default runtime:
```
Ref of runtime ? [bd79839bf96e595a06da5ac0b6ba51dea6f7e2591bb913deccded04d831d29f4]
```

Press Enter again to skip adding extra volumes to your program:
``` 
Add volume ? [y/N]
```

You should then get a response similar to the following: 
```
Your program has been uploaded on Aleph .

Available on:
  https://aleph.sh/vm/1d3842fc4257c0fd4f9c7d5c55bba16264de8d44f47265a14f8f6eb4d542dda2
  https://du4ef7cck7ap2t44pvoflo5bmjsn5dke6rzglikpr5xljvkc3wra.aleph.sh
Visualise on:
  https://explorer.aleph.im/address/ETH/0x101d8D16372dBf5f1614adaE95Ee5CCE61998Fc9/message/PROGRAM/1d3842fc4257c0fd4f9c7d5c55bba16264de8d44f47265a14f8f6eb4d542dda2
```

You may get the warning `Message failed to publish on IPFS and/or P2P`. 
This is common and usually not an issue.

> ℹ The second URL uses a hostname dedicated to your VM. Aleph identifiers are too long to work
> for URL subdomains, so a base32 encoded version of the identifier is used instead.

> ℹ You can make your own domain point to the VM. See the [ADVANCED](./ADVANCED.md) section.

## 5. Running

You can now run your program by opening one of the URLs above. Each URL is unique for one program.

https://aleph.sh/vm/1d3842fc4257c0fd4f9c7d5c55bba16264de8d44f47265a14f8f6eb4d542dda2

## 6. Uploading updates
 
`"Hello World"` is a nice message, but wouldn't it be nice to have something more friendly, such
as `"Hello Friend"` ? Update the program with the message of your choice.

You could upload the new version as a new program, but this would break the URL above and you
would have to give the updated URL to all your friends. While Aleph messages cannot be edited, 
there is a solution to this issue: you can publish _amend_ messages that reference the original
message to add some changes to it.

The `aleph update` command is similar to `aleph program`, except it requires the hash of the 
program to update.

```shell
aleph update $HASH ./my-program
```

Note that _amend_ messages must be sent from the same Aleph address as the original 
program to work, else they will be ignored.

| ℹ️ Backup your private key, else you may lose the ability to update a program

## Next steps

Check out the [Writing a non-Python program](./SERVER.md) page to run a program written in another language than Python.

Check out the [Advanced usage](./ADVANCED.md) page for more options and capabilities.
