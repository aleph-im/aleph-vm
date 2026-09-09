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
| `rejected` | Refused, as a map of hash to `{code, message}` |
| `retained` | Listed for teardown but not removable by an allocation, as a map of hash to reason |
| `status_url` | `/v2/about/executions/list` |

`rejected` codes are short machine strings with a human `message` beside
them, for example `invalid_message` for an entry whose embedded message does
not verify, `node_mismatch` for a message pinned to another node, and the
capacity refusals. `retained` reasons name why an allocation may not stop
the VM: `non_persistent`, `payment_stream`, `payment_credit`, `gpu`,
`confidential`, or `operator_policy`.

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
running on the node is read as dropped. Each hash comes back
`{"accepted": true}` or `{"accepted": false, "code": ..., "message": ...}`.
An entry with no embedded message answers `message_required`: there is
nothing to size, and a check does not go and fetch it.

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
nothing has failed. The `error.code` vocabulary is still settling for 2.1:
treat it as an opaque string for now and show `error.message` to humans.

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
