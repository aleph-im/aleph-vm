# aleph-vm supervisor protocol

This directory holds `supervisor.proto`, the single source of truth for
the contract between **network-agent** (Aleph orchestration) and
**supervisor** (infra-only VM management) inside aleph-vm.

Design reference:
`docs/plans/2026-05-28-aleph-vm-architecture-backport-design.md` (mirror
of the same file in the aleph-cvm repo).

## Regenerating Python bindings

```bash
python scripts/generate_proto.py
```

This (re)writes `src/aleph/vm/supervisor/_pb/`:

- `supervisor_pb2.py`: message classes
- `supervisor_pb2_grpc.py`: `SupervisorStub`, `SupervisorServicer`,
  `add_SupervisorServicer_to_server`
- `supervisor_pb2.pyi`: type stubs for mypy

**Generated files are checked in.** Reviewers can read them directly;
new contributors don't need to run protoc to navigate the code. CI runs
the script on every PR and fails if the generated files drift from
`supervisor.proto`.

## Why a closed error enum?

gRPC's status codes (`grpc.StatusCode`) are too coarse to map back to
the aleph-vm HTTP API faithfully. Today's views catch
backend-internal exception types directly (`FileTooLargeError`,
`MicroVMFailedInitError`, ...; see Annex A.6 of the design doc). The
`ErrorCode` enum + `ErrorDetail` message let the supervisor surface
those distinctions across the wire without exporting Python types.

Server side: backend exception → `ErrorDetail` packed into status
trailers, status code chosen from a small mapping table.

Client (agent) side: `grpc.AioRpcError` → read `ErrorDetail` from
trailers → translate to the HTTP shape the view used to derive from
the exception class.

## Versioning

Package: `aleph.supervisor.v1`. Breaking changes bump to `v2`. Field
additions are non-breaking as long as field numbers are stable.
