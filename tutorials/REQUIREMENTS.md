# Tutorial: Adding Python libraries to an Aleph VM

## 0. Setup your environment
```shell
sudo apt install python3-pip python3-venv squashfs-tools
```

```shell
pip3 install aleph-client
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
ipfs add venv.squashfs
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
