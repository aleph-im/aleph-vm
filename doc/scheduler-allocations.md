# Scheduler allocations (v2)

2.1 adds a second allocation interface between the scheduler and a CRN. The
legacy `POST /control/allocations` answered only once every VM in the push
was created, which made a large push slow and a partly failing one opaque.
The v2 endpoints answer immediately with a per-VM verdict and converge in
the background.

Both endpoints are scheduler-only and authenticated the same way as the
legacy one: an `Aleph-EIP191-V1` signature from an address in
`AUTHORIZED_ALLOCATION_SIGNERS` (local override), else the settings
aggregate, else `DEFAULT_ALLOCATION_SIGNERS`. The signed payload's `iat`
must be within `ALLOCATION_SIGNATURE_MAX_AGE_SECONDS` (300) of the node's
clock. A plan body may be up to 8 MiB; a larger one gets 413, not 401, so a
scheduler whose plan outgrew the cap is not sent looking at its key.

## A node runs one mode, not both

A node is governed either by v1 pushes or by v2 plans, not both. The two
interfaces hold different ideas of what the node was last told to run, so
pushing to one while the other is in use makes the node converge on
whichever spoke last. Point a given CRN at one of them and leave it there.

## `POST /v2/control/allocations`

The body carries the plan: one entry per VM, each with the VM hash and,
normally, the signed Aleph message for it. Embedding the message is what
lets the node size the VM without fetching anything.

The answer is `202 Accepted` and sorts every hash in the push into a bucket:

| Field | Meaning |
|-------|---------|
| `plan_id` | The plan this answer is about |
| `accepted` | Admitted; the node will create or start it |
| `pending` | Admitted in principle, but the push carried no message to size it by, so the node will fetch it first |
| `unchanged` | Already running here, nothing to do |
| `removing` | Running here, dropped by this plan, teardown started |
| `rejected` | Refused, as a map of hash to `{code, message}`. An entry whose hash the node could not read is keyed by its position in the push instead, as `vms[<i>]` |
| `retained` | Listed for teardown but not removable by an allocation, as a map of hash to reason |
| `status_url` | `/v2/about/executions/list` |

`rejected` codes are short machine strings with a human `message` beside
them, for example `invalid_message` for an entry whose embedded message does
not verify, `node_mismatch` for a message pinned to another node, and the
capacity refusals. A `rejected` key is normally the VM hash, but an entry
the node could not read a hash out of at all is answered under its index in
the pushed list, as `vms[3]`: it names no VM here, and echoing back whatever
string the push sent would be unbounded text off the request.

`retained` reasons name why an allocation may not stop the VM:
`non_persistent`, `payment_stream`, `payment_credit`, `gpu` or
`confidential`. A V-PROGRAM is never retained: the scheduler is its single
source of truth, so a plan that drops one stops it even though it is
credit-paid and confidential.

Four rules matter when reading that answer:

- **A refused hash is never torn down by its own push.** A rejection says
  the node will not run the VM, not that the VM should be destroyed. A hash
  the push listed in any form, including one whose message would not verify,
  is protected from the teardown pass that follows. Only a hash the plan
  never named at all is treated as taken away.
- **A crash loop backs off.** A guest that dies shortly after it reached
  RUNNING is rebuilt, but each death after the first waits longer, from
  `ALLOCATION_RETRY_BASE_INTERVAL` up to `ALLOCATION_RETRY_MAX_INTERVAL`.
  The VM is reported failed with its attempt count and the time the next
  rebuild is due, rather than being rebuilt at boot speed for as long as the
  plan lists it. The record is dropped once the VM has stayed up longer than
  the longest wait the backoff can impose.
- **A stopped VM restarts only on a push.** A VM stopped through the
  operator API, or by the guest shutting itself down, stays stopped. The
  convergence loop does not start it on a supervisor event or on its
  backstop pass. The next plan naming the VM starts it, on the pass that
  push arrives on and whatever backoff an earlier failure left, and each
  push buys exactly one start, so a guest that shuts itself down again is
  not looped on.
- **One create at a time per VM.** Every start path takes a per-hash lock
  around the whole read, record, download and create sequence, so two pushes
  landing at once cannot both build the same VM and have the second's
  failure delete the first's work.

The plan is held in memory only. After an agent restart the node has no
plan, and a node with no plan deletes nothing: acting on a stale plan would
tear down VMs that were migrated elsewhere during the downtime. The
scheduler's next push re-establishes the desired state.

## `POST /v2/control/capacity/check`

The same body, judged the same way, with no side effects: nothing is
recorded and nothing is held, so a scheduler can ask several CRNs before
committing to one. Every entry is treated as a candidate, and nothing
running on the node is read as dropped. The answer is
`{"results": {...}, "capacity": {...}}`. Each hash under `results` comes
back `{"accepted": true}` or
`{"accepted": false, "code": ..., "message": ...}`, under the same keys the
allocation answer uses: the VM hash, or `vms[<i>]` for an entry whose hash
the node could not read. An entry with no embedded message answers
`message_required`: there is nothing to size, and a check does not go and
fetch it. `capacity` is the node's headroom as things stand, independent of
this check's own candidates: `instance_memory_mib`, `program_memory_mib`,
`vcpus`, `disk_mib`, and `gpus` (a list of free card device IDs, or `null`
when the node could not read its GPU inventory).

A pass on this endpoint is advisory. The real allocation judges again and
can still refuse.

## `GET /v2/about/executions/list`

Two disjoint fields per entry. `state` is the supervisor's status, verbatim
(`defined`, `booting`, `running`, `stopping`, `stopped`, `failed`), and
`allocation` is what the agent is doing about the VM in the phases the
supervisor cannot see yet. A VM the plan lists that the supervisor has never
heard of appears with `state: null` and an allocation block, so "working on
it" is distinguishable from "never heard of it".

```json
"allocation": {
  "state": "planned | resolving | downloading | failed",
  "attempts": 2,
  "error": {"code": "...", "message": "..."},
  "next_retry_at": "2026-09-09T12:34:56+00:00"
}
```

`allocation` is `null` once the agent has nothing to add to the supervisor's
word. `attempts` is 0 and `error` and `next_retry_at` are `null` while
nothing has failed.

`error.code` comes from a closed set, and `error.message` is the one sentence
that belongs to that code. This endpoint is unauthenticated and readable from
any origin, so nothing an exception wrote is published here: the full reason a
start failed is in the node's log, which is the operator's to read.

| `error.code` | `error.message` | What it means |
|--------------|-----------------|---------------|
| `insufficient_capacity` | This node has no room for this VM | The node's own admission refused the VM, or the hypervisor reported insufficient resources. Place it elsewhere |
| `download_failed` | A resource this VM needs could not be downloaded | A runtime, code or data resource could not be fetched, or exceeded the node's archive size cap |
| `message_unavailable` | This VM's message could not be read from the network | The node had to fetch the message and the API did not have it, or the connector was down. Usually transient |
| `unsupported` | This node cannot run this VM | The VM asks for something this node does not offer: an unsupported backend, a TEE it cannot launch, or a content type it cannot run. No later attempt does better |
| `startup_failed` | The VM was created but did not reach the running state | Setup or guest init failed after the VM was defined |
| `supervisor_error` | The hypervisor refused to run this VM | The supervisor daemon refused for a reason with no more specific code. The daemon's own code is in the log |
| `vm_failed` | The VM was rebuilt after the hypervisor reported it failed | The guest died after it had been running. This is the crash-loop case, so `attempts` and `next_retry_at` say where the backoff stands |
| `internal` | Unhandled error | The node failed in a way it does not recognise. A bug on the node, not a statement about the VM |

The set is closed and coarser than the node's internal error codes on
purpose: it carries what a scheduler decides on (place the VM elsewhere,
wait, or stop asking), not what an operator debugs with. Treat an unknown
code as `internal` rather than failing to parse, so the node can add one
without breaking a consumer.

A VM the owner stopped carries no allocation block, since the supervisor
already reports it stopped and the agent has nothing to add. A start the
node was asked to make and could not is the node's news, so that one keeps
its failure and attempt count.

## Settings

| Setting | Default | What it does |
|---------|---------|--------------|
| `ALLOCATION_RECONCILE_INTERVAL` | `60` | Seconds between backstop convergence passes. The loop is normally woken by a push or a supervisor event; this only bounds how long a missed wake-up delays a retry |
| `ALLOCATION_RETRY_BASE_INTERVAL` | `30` | First retry delay after a failed create, in seconds. Doubles per attempt |
| `ALLOCATION_RETRY_MAX_INTERVAL` | `900` | Cap on the retry backoff, in seconds |
| `ALLOCATION_DOWNLOAD_CONCURRENCY` | `3` | How many VMs the loop may create at once. The expensive phase is the resource download; the create itself is serialized by the supervisor |
| `ALLOCATION_SIGNATURE_MAX_AGE_SECONDS` | `300` | Age window for the signed payload's `iat` against the node's clock |
| `AUTHORIZED_ALLOCATION_SIGNERS` | empty | Local override of the addresses allowed to sign scheduler requests. When set it is used verbatim and both the aggregate and the built-in default are ignored |
| `DEFAULT_ALLOCATION_SIGNERS` | the foundation scheduler | Fallback used only when there is no local override and the settings aggregate carries none |

All take the `ALEPH_VM_` prefix in `/etc/aleph-vm/supervisor.env`.
Raising `ALLOCATION_DOWNLOAD_CONCURRENCY` makes a large plan converge faster
at the cost of more concurrent bandwidth and disk writes.
