#!/bin/sh
docker image ls
docker run --rm -p 8080:8080 amozpay/hello_node