# Fishnet

Fishnet stands for **Financial time Series Hosting NETwork**.

It is a Compute-over-Data (CoD) system that uses the distributed Aleph.im network as a substrate for computation.
It is a decentralized, peer-to-peer, and serverless system that allows users to run statistical computations on their
timeseries data without having to upload it to a centralized server.

This python module contains a common data model, built on the
[Aleph Active Record SDK (AARS)](https://github.com/aleph-im/active-record-sdk), that is being used by the Fishnet API
and executor VMs. The data model is used to store and query:
- Timeseries & Datasets
- Algorithms
- Permissions
- Executions
- Results

## Roadmap

- [x] Basic message model
- [x] API for communicating with Fishnet system
  - [x] Basic CRUD operations
  - [x] Permission management
  - [ ] Timeslice distribution across executor nodes
  - [ ] Signature verification of requests
  - [ ] Local VM caching
- [x] Executor VM
  - [x] Listens for Aleph "Execution" messages and executes them
  - [x] Uploads results to Aleph
  - [x] Pandas support
  - [ ] Distributed execution & aggregation
  - [ ] Different execution environments (e.g. PyTorch, Tensorflow)
  - [ ] GPU support
