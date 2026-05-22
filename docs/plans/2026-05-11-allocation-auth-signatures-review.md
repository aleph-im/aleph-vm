# Code Review — Aleph-EIP191-V1 Allocation Auth (PR #945)

Self-review of the new signature-based allocation auth, in the spirit of a
brutally critical reviewer. Issues are ordered by severity, with mitigations.

## Critical

### C1. TOCTOU race on `_last_accepted_iat` — replay protection is broken under concurrency
`_verify_aleph_signature` does:
```python
previous = _last_accepted_iat.get(recovered.lower(), float("-inf"))
if iat <= previous:
    return False
...
_last_accepted_iat[recovered.lower()] = iat
```
Between the `get` and the assignment, the function `await`s `request.read()`. Two concurrent requests with `iat=N` (same captured signed message) both read `previous < N`, both pass the gate, both write — **same-iat replay succeeds**. Worse: two concurrent legitimate calls with `iat=N` and `iat=N+1` can write in any order, leaving `previous = N`, after which `iat=N+1` can be replayed.

This is the whole point of replay protection. Without serialization across the await point, you have none.

**Mitigation:** wrap the check+update in an `asyncio.Lock` (one global, or one per signer). Move the `_last_accepted_iat` update *before* the `await request.read()` if you can prove the body check can't fail after the iat has been "committed" — but that's a data-corruption antipattern; just take the lock.

### C2. Body-size DoS via `await request.read()` inside the verifier
Any caller can send `Authorization: Aleph-EIP191-V1 sig=…,payload=…` plus a multi-GB body. The verifier calls `await request.read()` *unconditionally* on the way to the body-hash check, fully buffering attacker-controlled bytes into memory before any auth decision. The legacy path never read the body. This is a regression in DoS posture introduced by this PR.

**Mitigation:** set aiohttp's `client_max_size` on the app (e.g., 1 MiB for control endpoints), or check `request.content_length` against a cap before calling `read()`, returning False if exceeded. Either way, **bound memory before reading**.

## High

### H1. Scheme comparison is case-sensitive — violates RFC 7235 §2.1
`if scheme != ALEPH_EIP191_V1_SCHEME` rejects `aleph-eip191-v1`, but auth-scheme tokens are case-insensitive. A well-behaved client lowercasing the scheme would silently get 401s, hard to debug, and a maintainer "fixing" this later by lowercasing both sides would need to be careful about the prefix check on line 150 (`startswith(f"{ALEPH_EIP191_V1_SCHEME} ")`).

**Mitigation:** `scheme.casefold() != ALEPH_EIP191_V1_SCHEME.casefold()` in the parser, and use the same comparison in the dispatcher (or extract the scheme first then dispatch).

### H2. Path binding ignores query string
`payload["path"] != request.path` — `request.path` excludes the query. If any of these 8 endpoints ever gains a query param affecting behavior, the signature won't bind to it. Footgun for future maintainers.

**Mitigation:** sign `request.path_qs` (or assert `request.query_string == ""` in the verifier and document that scheduler endpoints MUST NOT accept query params).

### H3. Unknown auth-params silently accepted
`_parse_auth_params` keeps any `key=value` it sees and only validates the *required* set. A client sending `sig=…,payload=…,extra=poison` is accepted. This isn't currently exploitable, but the verifier's contract is "I bind everything in the payload" — it doesn't, it binds what it knows. If anyone later adds a payload field and forgets to update the dispatcher, the missing-field branch saves them; if they add an *auth-param* that the verifier reads but doesn't validate strictly, this could backfire.

**Mitigation:** reject any auth-param outside the allowlist `{"sig", "payload"}`.

### H4. No integration coverage for migration endpoints with the new scheme
The 5 `@requires_allocation_auth` migration endpoints (`migration.py:80,161,232,319,346`) have unit tests in `test_migration.py` that mock `authenticate_api_request` to `True`, and the new dispatcher has a thorough unit-test suite. But there is **no end-to-end test** that fires a real Aleph-EIP191-V1 signed request at any migration endpoint and gets through. Coverage is asymmetric: `update_allocations` has the integration test, the others don't.

**Mitigation:** add at least one integration test per endpoint (or a parametrized one across handlers) that confirms the decorator + dispatcher chain wires correctly.

### H5. `_last_accepted_iat` is per-process; multi-worker deployments are vulnerable
If the supervisor ever runs more than one worker process behind a load balancer, each worker has its own dict and a captured request can be replayed against a sibling worker. The supervisor is currently single-process — but this assumption is not documented anywhere near the code, and a deployment change would silently weaken auth.

**Mitigation:** add a comment at `_last_accepted_iat`'s definition stating "single-process only; multi-worker requires shared state (Redis, etc.)". Better, add a startup assertion if multi-worker is ever enabled.

## Medium

### M1. `logger.debug` on verification failure hides operational signal
Failed verifications go to DEBUG. Operators triaging a misconfigured scheduler need to enable debug logging globally — noisy and slow.

**Mitigation:** `logger.info` (or `logger.warning`) with structured context: signer (if recovered), reason category (stale, body-mismatch, signer-not-authorized, malformed). Don't log the raw signature/payload — leaks request material into log files.

### M2. Deprecation warning logs every legacy request
At any reasonable scheduler TPS this floods logs. Operators who can't migrate immediately get told the same thing thousands of times an hour.

**Mitigation:** rate-limit (once per minute per remote) or log once at supervisor startup if `ALLOCATION_TOKEN_HASH` is set and `AUTHORIZED_ALLOCATION_SIGNERS` is empty.

### M3. Boundary tests missing for the `iat` window ✅ FIXED
Tests cover ±600s rejected (window is 300s). Nothing tests `iat = now - 300` (boundary), `iat = now - 301`, or that the comparison uses `>` (not `>=`). The implementation uses `abs(...) > max_age` so equality is accepted, but no test pins this down.

**Mitigation applied:** added 5 boundary tests in `test_allocation_auth.py` that freeze `allocation_auth.time` via a `SimpleNamespace` stub and exercise `iat = now`, `now ± max_age` (both accepted), and `now ± (max_age + 1)` (both rejected). The `_freeze_time` helper patches only the module-local `time` reference so pytest internals and other modules are unaffected.

### M4. No cross-signer monotonic-iat test ✅ FIXED
Tests verify monotonic-iat for one signer. Nothing verifies that signer B's first request succeeds even if signer A's last iat is greater. The implementation is correct (per-key dict), but a future "optimization" using a single counter would silently break and tests wouldn't catch it.

**Mitigation applied:** added `test_verify_per_signer_iat_floors_are_independent` — A signs `iat=N` (succeeds, A's floor → N), B signs `iat=N-1` (succeeds, B's floor independent), A signs `iat=N-1` (rejected, below A's floor). A regression to a single global counter would fail this test on the second assertion.

### M5. `request.read()` consumes the body for downstream handlers that stream
aiohttp caches the body when `read()` is called, so handlers that subsequently call `request.json()` work fine. But a future handler using `request.content.iter_chunked()` would silently get an empty stream because the body was already buffered upstream. None of the current handlers stream, but the verifier's side effect on `request` is undocumented.

**Mitigation:** comment in `_verify_aleph_signature` warning that calling this is equivalent to `await request.read()` from the handler's perspective.

### M6. `import functools` inside the decorator
Style nit, but it's noise. Move to the top.

## Low / Code smells

### L1. Lazy `from ... import _last_accepted_iat` inside test functions ✅ FIXED
Originally needed during TDD; can move to module-level imports now.

**Mitigation applied:** all `aleph.vm.orchestrator.views.allocation_auth` imports hoisted to the top of `test_allocation_auth.py` (single import block: module reference + symbols `MAX_SIGNED_REQUEST_BODY_BYTES`, `_last_accepted_iat`, `_parse_auth_params`, `_verify_aleph_signature`, `log_allocation_auth_config`). The `reset_iat_cache` fixture dropped its `try/except ImportError` since the symbol is now guaranteed to exist.

### L2. Magic-number-ish `300` in `ALLOCATION_SIGNATURE_MAX_AGE_SECONDS` ⏭ NO ACTION
Documented at the setting, fine, but worth a comment near the verifier itself: "If you tighten this, replay-window shrinks; if you widen it, captured-request usefulness grows."

**Decision:** skipped. The setting name is self-documenting; any reader of the verifier can grep the constant and find its config-level doc. Adding the tradeoff comment near the verifier would be noise (project preference: only comment when WHY is non-obvious, and the tradeoff is implicit in any time-window auth scheme).

### L3. Authorized-signer set rebuilt every request ⏭ NO ACTION
`{a.lower() for a in settings.AUTHORIZED_ALLOCATION_SIGNERS}` runs on every verification.

**Decision:** skipped, per reviewer's "or just leave it — micro-optimization". A cache keyed on the list identity would handle test monkeypatching, but the cost is microseconds for tiny `n` (< 10 signers in practice). Not worth the invalidation complexity.

### L4. Dispatcher returns 4 different "False" branches ⏭ NON-ISSUE
Lints will complain about `PLR0911` if it's not already noqa'd. Fine as-is.

**Status:** moot after the H1 fix simplified the dispatcher. It now has 4 returns total, only 2 of which are direct `False`; PLR0911's default threshold is 6. Confirmed clean via `ruff check`.

### L5. `request.path` matching is exact — a trailing slash mismatch is a 401 ✅ FIXED
If a scheduler signs `/control/allocations/` (trailing slash) and the route is `/control/allocations`, you get 401 with no useful error. Document or normalize.

**Mitigation applied:** added a one-line comment above the `method_path_mismatch` computation:
```python
# Path matching is exact: aiohttp routes `/foo` and `/foo/` distinctly,
# so signers must use the exact path the route will receive.
```
Normalization would mask aiohttp's actual routing behavior (which IS trailing-slash-sensitive), so the right answer is to make the verifier policy explicit at the comparison site rather than try to paper over it.

## Architecture / Future-proofing

### A1. No key-revocation primitive beyond restart
If a key leaks, mitigation is "edit config + restart". For one scheduler key, fine. But there's no expiry per key, no signed revocation list, no audit trail of which key signed which request (the recovered address isn't logged on success). Add at minimum a structured info-log at success: `signed by 0xABC for POST /control/allocations`.

### A2. Wire format is final; versioning is the only escape hatch
`Aleph-EIP191-V1` is the right approach — bumping to V2 is the migration path. Good.

### A3. `_last_accepted_iat` dict grows unboundedly
Per-signer; one entry per ever-seen authorized signer. With < 10 signers, irrelevant. If the design ever scales to hundreds of signers, no eviction. Current scope: non-issue. Document the assumption.

---

## Summary

The cryptographic core is sound (EIP-191 + recover, body-hash binding, monotonic iat, absolute window, per-signer floor). Where this falls short is **the operational and concurrency side**: the TOCTOU race on the iat dict (C1) defeats replay protection under realistic load, and the unconditional body buffering (C2) is a DoS regression vs. the legacy path. Both are fixable in a few lines.

The test suite is thorough on the verifier's logic but thin on the integration boundary (H4) and concurrency (no test exercises C1).

**Priority order to fix before merge:**
1. C1 (concurrency lock around iat check+update) — correctness
2. C2 (cap body size before `read()`) — DoS
3. H1 (case-insensitive scheme)
4. H4 (integration tests for migration endpoints)
5. M1, M2 (logging hygiene)

The rest can land in follow-ups.
