# Aleph VM JS Example

A simple example program written in JS that can run in an Aleph VM.

## About

This example is a simple HTTP server listening on port 8080. 
It does not depend on third-party libraries.

Test it on http://localhost:8080.

## Publish the program

### Locally

```shell
make publish
```

### Using Podman

```shell
make podman-prepare
make podman-publish
```

### Using Docker

```shell
make docker-prepare
make docker-publish
```
