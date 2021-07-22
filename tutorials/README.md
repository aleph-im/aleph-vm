# Tutorial: Creating and hosting a program on Aleph-VM

This is the tutorial for Creating and hosting a program on Aleph-VM, which has been developed and maintained by Aleph.im.

## Welcome

Hi, welcome to _Creating and hosting a program on Aleph-VM_. In this tutorial we will take you 
through the fundamentals of running programs on the [Aleph.im](https://aleph.im/) Virtual Machines.
After the tutorial you should have a rough mental picture of how the virtual machines work and 
some good pointers for getting further with running programs of your own.

We expect you to know a little Python and have some experience with 
the [FastAPI framework](https://fastapi.tiangolo.com/). 
The first chapters of the [FastAPI Tutorial](https://fastapi.tiangolo.com/tutorial/) should cover
enough to get started.

You will need a recent version of Python and [pip](https://pip.pypa.io/en/stable/), 
preferably running on Debian or Ubuntu Linux since we have not tested other platforms yet, 
but feel free to use the platform of your choice if you have the skills to adapt our instructions to it.

## What we will cover

First we will see how to run the first example from FastAPI's tutorial on Aleph.im, how to
access it and how to update it.

Then we will extend the program to add some Aleph specific functionalities.

## Understanding the VMs

Aleph is a cross-blockchain layer-2 network specifically focused on decentralized applications and
their related infrastructure (storage, computing servers, security).

Aleph-VM is the computing part of the network: It allows the execution of programs stored on the
Aleph network. These programs can interact with the network itself and with the rest of the internet.

In the current stage, these programs can only be triggered from outside HTTP calls. Future ways to
trigger the launch of the programs are planned, such as reacting to specific messages on the
network.

## 1. Writing

To create the first program, open your favourite code editor and create a directory named
`my-program`, containing a file named `main.py`.

Then write the following code in file:
```python
from fastapi import FastAPI

app = FastAPI()


@app.get("/")
async def root():
    return {"message": "Hello World"}
```

That's it for your first program.

## 2. Testing locally

Before uploading your program on Aleph, it is best to first test it locally.

Do test your progam using uvicorn:

```shell
pip install uvicorn[standard]
uvicorn main:app --reload
```

Then open http://127.0.0.1:8000 .

## 3. Uploading

Install [aleph-client](https://github.com/aleph-im/aleph-client).

```shell
sudo apt-get install -y squashfs-tools libsecp256k1-dev
pip install aleph-client
```

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

## 4. Running

You can now run your program by opening one of the URLs above. Each URL is unique for one program.


https://aleph.sh/vm/1d3842fc4257c0fd4f9c7d5c55bba16264de8d44f47265a14f8f6eb4d542dda2

## 5. Uploading updates
 
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

Check out the [Advanced usage](./ADVANCED.md) page for more options and capabilities.
