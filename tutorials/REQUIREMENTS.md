# Tutorial: Adding Python libraries to an Aleph VM

## 0.a Setup your environment (Debian/Ubuntu Linux)
```shell
sudo apt install python3-pip python3-venv squashfs-tools
```

```shell
pip3 install aleph-client
```

## 0.b Quick install (macOS using Vagrant)

For starting to run aleph-vm on mac you have to initialize a VM.

### Install VirtualBox
You will need VirtualBox, a free and open-source hosted hypervisor (or virtual machine manager) for the next step.

You can download and install it <a href="https://www.virtualbox.org/wiki/Downloads">here </a>.

### Install Vagrant
Vagrant is an open-source software product for building and maintaining portable virtual software development environments based on VirtualBox.

Run following command for installing it (before make sure [homebrew](brew.sh) is installed on your mac).

```shell
brew install vagrant
```

Once Vagrant is installed, go to your working repository and initialize vagrant

```shell
vagrant init boxomatic/debian-11
```

A `Vagrantfile` (in Ruby) will be created, you can consult it if you wish.

Now in order to instantiate a new virtual machine, run the following command:

```shell
vagrant up
```

If this does not work, check out you System Preferences > Security and Privacy and allow the "System software from developer" in the bottom of the window.

Once the command is down, your virtual machine will be booted and ready!

### Set Vagrantfile configuration

Open the vagrantfile and add following `config.vm.box`

```shell
config.vm.network "forwarded_port", guest:8000, host:8000
```

### 1. Install the packages in a directory

```shell
pip install -t /opt/packages -r requirements.txt
```

```shell
mksquashfs /opt/packages packages.squashfs
```


## 2. Upload the packages

### 2.a. Without IPFS (small size)

```shell
aleph upload packages.squashfs
```

### 2.b. With IPFS
```shell
/opt/go-ipfs/ipfs daemon
```

```shell
ipfs add packages.squashfs
```
| added QmWWX6BaaRkRSr2iNdwH5e29ACPg2nCHHXTRTfuBmVm3Ga venv.squashfs

```shell
aleph pin QmWWX6BaaRkRSr2iNdwH5e29ACPg2nCHHXTRTfuBmVm3Ga
```

## 3. Create your program

```shell
aleph program ./my-program main:app
```

Press Enter at the following prompt to use the default runtime:
```
Ref of runtime ? [bd79839bf96e595a06da5ac0b6ba51dea6f7e2591bb913deccded04d831d29f4]
```

Press `Y` to add extra volumes to your program:
``` 
Add volume ? [y/N] Y
Description: Python Packages
Mount: /opt/packages
Ref: 61f43ab261060ff94838dc94313a70cdb939a5fc6c99924b96d55dcc2c108d03
Use latest version ? [Y/n] 
```

Finally, press Enter to skip adding more volumes.
```shell
Add volume ? [y/N]
```
