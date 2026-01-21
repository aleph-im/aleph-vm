FROM node:16-bullseye

RUN apt-get update && apt-get -y upgrade && apt-get install -y \
     libsecp256k1-dev \
     squashfs-tools \
     python3-pip \
     git \
     && rm -rf /var/lib/apt/lists/*

RUN pip install aleph-client

WORKDIR /usr/src/example_http_js
COPY . .

RUN npm i
