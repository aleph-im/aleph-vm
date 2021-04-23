# VM Connector

Service to schedule the execution of Aleph VM functions 
for the [Aleph.im](https://aleph.im/) project and assist 
[VM Supervisors](../vm_supervisor) with operations related 
to the Aleph network.

## 1. Supported platforms

We support running the VM Connector in a Docker container, on 
[platforms supported by Docker](https://docs.docker.com/engine/install/#supported-platforms).

## 2. Installation

### 2.a. Install Docker

On a Debian/Ubuntu system:
```shell
apt update
apt install -y docker.io
```

### 2.b. Build the Docker image 

Clone this reposotiry on the host machine and enter it:
```shell
git clone https://github.com/aleph-im/aleph-vm.git
cd aleph-vm/
````

Build the image:
```shell
docker build -t aleph-connector -f docker/vm_connector.dockerfile .
```

## 3. Running

### Run the Docker image
```shell
docker run -ti --rm -p 8000:8000/tcp aleph-connector
```

http://localhost:8000/

## 4. Configuration

The VM Supervisor can be configured using  environment variables:

`ALEPH_SERVER` should point to your Aleph Node. 
Defaults to https://api2.aleph.im

`IPFS_SERVER` should point to your IPFS Gateway, defaults to https://ipfs.aleph.im/ipfs
