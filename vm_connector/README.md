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

### 2.b. Pull the Docker image 

```shell
docker pull alephim/vm-connector:alpha
```

## 3. Running

Run the Docker image
```shell
docker run -d -p 4021:4021/tcp --restart=always --name vm-connector alephim/vm-connector:alpha
```

## 4. Configuration

The VM Supervisor can be configured using environment variables:

`API_SERVER` should point to your Aleph Node. 
Defaults to https://official.aleph.cloud

`IPFS_SERVER` should point to your IPFS Gateway, defaults to https://ipfs.aleph.im/ipfs
