# Payment enforcement

> Verified against: 39ec840a (2026-08-19)

## What this covers

Who enforces that a running VM is paid for, and where. Three components have a
say — pyaleph, the scheduler, and the CRN itself — and they cover different
payment tiers by different mechanisms. Also records why the CRN's own checks are
largely duplicative, and the two-part plan for removing them.

## The question this answers

The CRN runs its own payment enforcement in two places. If it duplicates checks
already made upstream, the CRN's copy is code we can delete.

| Where | What it does |
| --- | --- |
| `notify_allocation` (`src/aleph/vm/agent/views/__init__.py:820`) | admission check, per payment tier, at allocation time |
| `check_payment` (`src/aleph/vm/agent/tasks.py:360`) | every `PAYMENT_MONITOR_INTERVAL` (60s): stops VMs whose message went terminal, then re-checks balances and streams |

Upstream there are two enforcement points, not one:

- **pyaleph (CCN)** enforces hold-tier and credit balances by *removing the
  instance message* when the owner's balance no longer covers it.
- **the scheduler** (`aleph-vm-scheduler`, `scheduler-rs/src/actors/payg/`)
  validates superfluid streams.

## Finding 1: hold and credit are already enforced, upstream of both

pyaleph auto-removes instance messages once the owner's balance is
insufficient. So a message that is still retrievable and `processed` from
`/api/v0/messages.json` is, by construction, a message whose balance is
sufficient. The scheduler relies on exactly this — `payment_gate.rs:174` passes
hold and credit VMs straight through with no balance lookup, and
`message_watcher.rs:255` documents the credit case as "managed by CCN API, pass
through without validation".

**That enforcement already reaches the CRN, and not via the balance
arithmetic.** `check_payment`'s *first* loop (`tasks.py:373-407`) polls each
running VM's message status and stops it after `STOP_AFTER_CONFIRMATIONS` = 3
consecutive terminal readings, where `_TERMINAL_STATUSES` includes
`MessageStatus.REMOVED` — precisely what pyaleph sets. The balance branches
that follow it (`tasks.py:412` hold, `tasks.py:437` credit) re-derive a
conclusion the CCN has already drawn and published.

So for hold and credit the CRN checks are duplicative and removable. Two
consequences:

- The terminal-status loop is **load-bearing and must stay**. It is the channel
  through which pyaleph's balance decisions reach the node; deleting it along
  with the balance branches would remove hold/credit enforcement outright.
- The existing CRN hold check is in any case only partial, which is a sign it
  was never the real enforcement: `notify_allocation:868` runs it only for
  confidential or GPU instances, and `check_payment:412` narrows further to
  confidential only, so GPU hold instances are checked once at admission and
  never again.

## Finding 2: PAYG is the exception

pyaleph does not check superfluid streams, so the "message still exists implies
it is paid for" invariant does not hold for PAYG. Enforcement is genuinely split
between the scheduler and the CRN, and this is the only tier where removing the
CRN's check removes something real.

The arithmetic on the two sides matches:

| Aspect | CRN `check_payment` | Scheduler `PaymentGate` | Same? |
| --- | --- | --- | --- |
| Grouping | (owner, chain); the CRN only sees its own VMs | (owner, chain, CRN node hash) | yes in effect |
| Price source | `GET {API_SERVER}/api/v0/price/{hash}` | same URL (`vm_pricer.rs:169`) | yes |
| Community ratio | `COMMUNITY_STREAM_RATIO` = 0.2 | same (`payment_gate.rs:20`) | yes |
| Split formula | `with_community*(1-0.2) + without_community`; community gets `with_community*0.2` | identical (`compute_required_flows`) | yes |
| Buffer | `stream + PAYMENT_BUFFER > required` | `crn_stream + buffer >= required` | `>` vs `>=`, differs only at exact equality |
| Rounding | `format_cost()` floors to 18 dp | none (raw `Decimal`) | differs at ~1e-19, far below the 1e-10 buffer |
| Over-quota policy | pop last VM until covered | same (`revalidate_all_streams`) | yes |
| Transient RPC failure | `continue`, stop nothing | `continue`, stop nothing | yes |
| Revalidation period | 60s | `refresh_interval` | yes |

The formula is not the problem. The gaps are in plumbing and coverage.

## Finding 3: the CRN cannot act on the scheduler's PAYG decisions

`src/aleph/vm/agent/views/__init__.py:586-603` — the `/control/allocations` stop
loop only stops a VM absent from the allocation when it is a v-program or plain
hold-tier:

```python
record.is_vprogram
or (
    not record.uses_payment_stream
    and not record.uses_payment_credit
    and not info.gpus
    and info.confidential_mode is ConfidentialMode.NONE
)
```

Stream-paid VMs are excluded, so when `PaymentGate` drops a PAYG VM from the
allocation that decision cannot reach the CRN. This is why the work splits in
two: the channel has to exist before the local check can go.

## Finding 4: 31 of 152 live PAYG instances are invisible to the scheduler

`payment_gate.rs:process_priced_delta` needs an extractable node hash:

```rust
let node_hash = match extract_node_hash(&priced_vm.vm) {
    Some(h) => h,
    None => { log::warn!("PAYG VM {} has no extractable node hash, skipping"); continue; }
};
```

A PAYG instance with no `requirements.node.node_hash` is skipped — neither
validated nor passed through.

Live network data (`api3.aleph.im`, 2026-08-19; 832 INSTANCE messages, all 152
superfluid ones currently `processed`):

| | pre-split | post-split | total |
| --- | ---: | ---: | ---: |
| pinned to a CRN | 21 | 100 | 121 |
| no `node_hash` (scheduler-blind) | 17 | 14 | **31** |

Chains: 106 BASE, 46 AVAX, across 32 CRNs; the busiest three hold 18, 16 and 15.

The 14 scheduler-blind instances created after the community split are recent
(2025-11-10 → 2026-02-13; senders `0x17AD8057…`, `0xA665c108…`, `0x769dC153…`,
`0x7393feC4…`, `0x0b1c95C2…`). For all 31, the CRN is today the only stream
enforcement there is.

## Finding 5: the community-wallet split uses three different clocks

| Code | Clock |
| --- | --- |
| Scheduler `compute_required_flows` | `vm.created_at` — message creation time |
| CRN `check_payment:460ff` | `_dt_from_ns(info.started_at_ns)` — VM boot time on this CRN |
| CRN `notify_allocation:884ff` | `is_after_community_wallet_start()` with no argument — now |

The split began 2025-02-19 (`community_wallet_timestamp` = 1739996239 in the
settings aggregate). For the 21 live pre-split instances pinned to a CRN this
diverges against the owner: their messages predate the split, so the scheduler
asks 100% to the CRN and nothing to the community wallet, while the CRN —
classifying by boot time — demands 80/20 the moment the VM restarts, finds no
community stream, and stops it. 18 of those 21 sit on one CRN
(`8523c04781a1e437…`).

Removing the CRN's PAYG check therefore *fixes* this group rather than
endangering it.

## Plan

**Part 1 — allocate and delete PAYG instances via `/control/allocations`.**
Drop the `uses_payment_stream` exclusion from the stop loop so the scheduler's
PAYG decisions reach the node, and accept PAYG instances in the allocation
payload. Behaviour-preserving while `check_payment` still runs: the scheduler
and the CRN agree on the arithmetic (finding 2), so the scheduler stopping a VM
the CRN would also stop changes nothing observable. Ship and observe first.

**Part 2 — delete the payment checks.** Once part 1 is live:

- remove the hold and credit branches of both `notify_allocation` and
  `check_payment` (finding 1) — keeping the terminal-status loop, which is what
  actually enforces them;
- remove the superfluid branches of both (findings 2, 3).

Two things to settle before part 2 lands, both from the PAYG side:

- **the 31 node_hash-less instances** (finding 4). Either the scheduler learns to
  handle unpinned PAYG, or new PAYG messages require a node pin and the existing
  31 are migrated. Otherwise part 2 silently un-enforces them.
- **the clock disagreement** (finding 5). Message time is the defensible choice:
  it is what the owner signed. Settling on it is worth doing regardless of part 2.

## Reproducing the data

`api3.aleph.im`, `GET /api/v0/messages.json?msgTypes=INSTANCE` paged at 200,
filtered on `content.payment.type == "superfluid"`, each hash's status confirmed
via `GET /api/v0/messages/{hash}`. Split classification compares `content.time`
against `community_wallet_timestamp` from
`GET /api/v0/aggregates/0xFba561a84A537fCaa567bb7A2257e7142701ae2A.json?keys=settings`.
