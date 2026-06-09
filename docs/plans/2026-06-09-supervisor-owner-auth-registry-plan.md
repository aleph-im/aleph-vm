# Operator owner-auth → agent registry — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make operator owner-authorization read the message from the agent registry instead of the hypervisor pool, so `execution.message` is read nowhere in `orchestrator/views/operator.py`.

**Architecture:** Mechanical migration of 9 functions in one file. Three shapes: delete one dead function; make three endpoints execution-free (they used the execution only for auth); for five endpoints that genuinely need `execution.vm`, keep the execution lookup but move the *auth message read* ahead of it, sourced from `get_agent_record_or_404(request, vm_hash)`. Established precedent: `operate_stop`/`operate_reboot`/`operate_erase` already do exactly this.

**Tech Stack:** Python 3, aiohttp, pytest / pytest-asyncio, `mocker` (pytest-mock).

**Design doc:** `docs/plans/2026-06-09-supervisor-owner-auth-registry-design.md`

**Branch:** `od/wire-supervisor-owner-auth` (stacked on #970 `od/wire-supervisor-update-watch`).

---

## Environment notes (read before running anything)

- **Every `Bash` command needs `dangerouslyDisableSandbox: true`** (the repo's seccomp profile blocks sandboxed exec with `apply-seccomp ... Permission denied`).
- **This worktree has no local venv.** Run tests with the sibling worktree's venv:
  ```bash
  cd /home/olivier/git/aleph/aleph-vm/.worktrees/wire-supervisor-expiry
  PYTHONPATH=src /home/olivier/git/aleph/aleph-vm/.worktrees/wire-supervisor-read-views/.testvenv/bin/python -m pytest <args>
  ```
- **Style gates (CI):**
  ```bash
  uvx ruff@0.4.6 format --diff src/aleph/vm/orchestrator/views/operator.py tests/supervisor/views/test_operator.py
  uvx isort==5.13.2 --check-only --profile black src/aleph/vm/orchestrator/views/operator.py tests/supervisor/views/test_operator.py
  ```
  `uvx` writes an untracked `uv.lock` — **never `git add` it.**
- **Pre-existing environmental failures:** the full `tests/supervisor` suite has ~50 failed + 4 errors on `/var/cache/aleph`, `/var/lib/aleph`, and pyroute2 netlink — identical to the `origin/dev` baseline. Judge regressions against that baseline, not against zero. Run the targeted test file `tests/supervisor/views/test_operator.py` (which does not hit those paths) for fast iteration.
- **No `Co-Authored-By` trailer in commits.**

## Shared facts (true for every task)

- File under change: `src/aleph/vm/orchestrator/views/operator.py`.
- Test file: `tests/supervisor/views/test_operator.py`.
- The helper already exists (do not add it):
  ```python
  def get_agent_record_or_404(request: web.Request, vm_hash: ItemHash) -> AgentVmRecord:
      """Owner identity now comes from the agent registry, not the execution."""
      record = request.app["vm_registry"].get(vm_hash)
      if record is None:
          raise web.HTTPNotFound(body=f"No virtual machine with ref {vm_hash}")
      return record
  ```
- `AgentVmRecord.message` is an `ExecutableContent` — the same type `is_sender_authorized(sender, message)` and `message.rootfs.size_mib` already consume.
- **Registry-seeding pattern for tests** (from the existing `test_operator_stop`):
  ```python
  vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
  instance_message = await get_message(ref=vm_hash)
  app["vm_registry"].record(
      vm_hash,
      message=instance_message.content,
      original=instance_message.content,
      persistent=True,
  )
  ```
- **Why the new tests are red on current code:** they seed the *registry* and leave `pool.executions` **empty**. Current code calls `get_execution_or_404` first → 404 on the empty pool. After migration, auth reads the registry → the assertion (403, or a past-auth body) holds. That is the red→green signal.
- `is_sender_authorized` is patched in tests as `aleph.vm.orchestrator.views.operator.is_sender_authorized` to avoid the delegation/network path (matches the existing `test_operator_confidential_initialize_not_authorized`).

---

## Task 1: Delete the dead websocket-auth function and the stale TODO

**Files:**
- Modify: `src/aleph/vm/orchestrator/views/operator.py` (delete `authenticate_websocket_for_vm_or_403` def; delete one comment line in `get_execution_or_404`)
- Test: `tests/supervisor/views/test_operator.py`

`authenticate_websocket_for_vm_or_403` (def at ~line 380) has **zero callers** repo-wide (verified: `grep -rn authenticate_websocket_for_vm_or_403 src/ tests/` returns only the definition). It reads `execution.message`. Remove it (YAGNI). Removing it does not orphan any import: `authenticate_websocket_message` is still used by the websocket-logs handler, `is_sender_authorized` is used throughout, and `VmExecution` is still used by `get_execution_or_404`'s annotation.

- [ ] **Step 1: Write the failing guard test**

Add at the end of `tests/supervisor/views/test_operator.py`:

```python
def test_dead_websocket_auth_helper_is_removed():
    """authenticate_websocket_for_vm_or_403 had no callers; it must be gone."""
    from aleph.vm.orchestrator.views import operator

    assert not hasattr(operator, "authenticate_websocket_for_vm_or_403")
```

- [ ] **Step 2: Run it, verify it fails**

Run:
```bash
PYTHONPATH=src /home/olivier/git/aleph/aleph-vm/.worktrees/wire-supervisor-read-views/.testvenv/bin/python -m pytest tests/supervisor/views/test_operator.py::test_dead_websocket_auth_helper_is_removed -v
```
Expected: FAIL (`assert not True` — the function still exists).

- [ ] **Step 3: Delete the function**

Remove the entire `authenticate_websocket_for_vm_or_403` definition (from its `async def authenticate_websocket_for_vm_or_403(...)` line through its final `raise web.HTTPForbidden(body="Unauthorized sender")`, including the two blank lines that precede it down to one separating blank line). The current body to delete:

```python
async def authenticate_websocket_for_vm_or_403(execution: VmExecution, vm_hash: ItemHash, ws: web.WebSocketResponse):
    """Authenticate a websocket connection.

    Web browsers do not allow setting headers in WebSocket requests, so the authentication
    relies on the first message sent by the client.
    """
    try:
        first_message = await ws.receive_json()
    except TypeError as error:
        logging.exception(error)
        await ws.send_json({"status": "failed", "reason": str(error)})
        raise web.HTTPForbidden(body="Invalid auth package")
    credentials = first_message["auth"]

    try:
        authenticated_sender = await authenticate_websocket_message(credentials)

        if await is_sender_authorized(authenticated_sender, execution.message):
            logger.debug(f"Accepted request to access logs by {authenticated_sender} on {vm_hash}")
            return True
    except Exception as error:
        # Error occurred (invalid auth packet or other
        await ws.send_json({"status": "failed", "reason": str(error)})
        raise web.HTTPForbidden(body="Unauthorized sender")

    # Auth was valid but not the correct user
    logger.debug(f"Denied request to access logs by {authenticated_sender} on {vm_hash}")
    await ws.send_json({"status": "failed", "reason": "unauthorized sender"})
    raise web.HTTPForbidden(body="Unauthorized sender")
```

- [ ] **Step 4: Delete the stale TODO comment in `get_execution_or_404`**

In `get_execution_or_404`, remove the line:
```python
    # TODO: Check if this should be execution.message.address or execution.message.content.address?
```
so the function becomes:
```python
def get_execution_or_404(ref: ItemHash, pool: VmPool) -> VmExecution:
    """Return the execution corresponding to the ref or raise an HTTP 404 error."""
    execution = pool.executions.get(ref)
    if execution:
        return execution
    else:
        raise web.HTTPNotFound(body=f"No virtual machine with ref {ref}")
```

- [ ] **Step 5: Run the guard test + a smoke import**

Run:
```bash
PYTHONPATH=src /home/olivier/git/aleph/aleph-vm/.worktrees/wire-supervisor-read-views/.testvenv/bin/python -m pytest tests/supervisor/views/test_operator.py -q
```
Expected: the new test PASSES and no previously-passing operator test regresses (collection succeeds — proves no import broke).

- [ ] **Step 6: Style + commit**

```bash
uvx ruff@0.4.6 format --diff src/aleph/vm/orchestrator/views/operator.py tests/supervisor/views/test_operator.py
uvx isort==5.13.2 --check-only --profile black src/aleph/vm/orchestrator/views/operator.py tests/supervisor/views/test_operator.py
git add src/aleph/vm/orchestrator/views/operator.py tests/supervisor/views/test_operator.py
git commit -m "refactor(owner-auth): delete dead authenticate_websocket_for_vm_or_403 and stale TODO"
```

---

## Task 2: Make the three execution-free endpoints registry-authorized

**Files:**
- Modify: `src/aleph/vm/orchestrator/views/operator.py` (`operate_expire`, `operate_backup_status`, `operate_backup_delete`)
- Test: `tests/supervisor/views/test_operator.py`

These three use the execution **only** for the auth check. Drop `get_execution_or_404` and the now-unused `pool` local; authorize from the registry.

> **`operate_expire` caveat:** its route `/control/machine/{ref}/expire` carries no `{timeout}` segment, but the handler reads `request.match_info["timeout"]` → `KeyError` → always `400` *before* reaching auth. This routing bug is the known out-of-scope residual (design §7). We still migrate its auth read (so `execution.message` leaves the file) but **do not** add an HTTP happy-path test for it — it cannot return 200. We delete the misleading `@pytest.mark.skip()` test that asserted a non-existent `.expire()` call.

### 2a — `operate_backup_status` and `operate_backup_delete`

- [ ] **Step 1: Write failing tests**

Add to `tests/supervisor/views/test_operator.py`:

```python
@pytest.mark.asyncio
async def test_operator_backup_status_authorized_reads_registry(aiohttp_client, mocker, tmp_path):
    """Authorized backup-status reaches the backup logic with an empty pool."""
    settings.ENABLE_QEMU_SUPPORT = True
    settings.setup()

    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    instance_message = await get_message(ref=vm_hash)
    fake_vm_pool = mocker.AsyncMock(executions={})

    mocker.patch(
        "aleph.vm.orchestrator.views.authentication.authenticate_jwk",
        return_value=instance_message.sender,
    )
    mocker.patch(
        "aleph.vm.orchestrator.views.operator.is_sender_authorized",
        return_value=True,
    )
    # get_backup_directory() mkdirs under settings.EXECUTION_ROOT (a /var path);
    # patch the operator-local name to a tmp dir to avoid the environment's
    # /var PermissionError.
    mocker.patch(
        "aleph.vm.orchestrator.views.operator.get_backup_directory",
        return_value=tmp_path,
    )
    app = setup_webapp(pool=fake_vm_pool)
    app["vm_registry"].record(
        vm_hash,
        message=instance_message.content,
        original=instance_message.content,
        persistent=True,
    )
    client: TestClient = await aiohttp_client(app)
    response = await client.get(f"/control/machine/{vm_hash}/backup")
    # Past auth: no backup exists, so the backup logic returns its own 404.
    assert response.status == 404, await response.text()
    assert "No backup found" in await response.text()


@pytest.mark.asyncio
async def test_operator_backup_status_unauthorized_reads_registry(aiohttp_client, mocker):
    """Backup-status authorizes against the registry, not the pool."""
    settings.ENABLE_QEMU_SUPPORT = True
    settings.setup()

    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    instance_message = await get_message(ref=vm_hash)
    fake_vm_pool = mocker.AsyncMock(executions={})

    mocker.patch(
        "aleph.vm.orchestrator.views.authentication.authenticate_jwk",
        return_value="0xstranger",
    )
    mocker.patch(
        "aleph.vm.orchestrator.views.operator.is_sender_authorized",
        return_value=False,
    )
    app = setup_webapp(pool=fake_vm_pool)
    app["vm_registry"].record(
        vm_hash,
        message=instance_message.content,
        original=instance_message.content,
        persistent=True,
    )
    client: TestClient = await aiohttp_client(app)
    response = await client.get(f"/control/machine/{vm_hash}/backup")
    assert response.status == 403, await response.text()


@pytest.mark.asyncio
async def test_operator_backup_delete_authorized_reads_registry(aiohttp_client, mocker, tmp_path):
    """Authorized backup-delete reaches the delete logic with an empty pool."""
    settings.ENABLE_QEMU_SUPPORT = True
    settings.setup()

    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    instance_message = await get_message(ref=vm_hash)
    fake_vm_pool = mocker.AsyncMock(executions={})

    mocker.patch(
        "aleph.vm.orchestrator.views.authentication.authenticate_jwk",
        return_value=instance_message.sender,
    )
    mocker.patch(
        "aleph.vm.orchestrator.views.operator.is_sender_authorized",
        return_value=True,
    )
    mocker.patch(
        "aleph.vm.orchestrator.views.operator.get_backup_directory",
        return_value=tmp_path,
    )
    app = setup_webapp(pool=fake_vm_pool)
    app["vm_registry"].record(
        vm_hash,
        message=instance_message.content,
        original=instance_message.content,
        persistent=True,
    )
    client: TestClient = await aiohttp_client(app)
    response = await client.delete(f"/control/machine/{vm_hash}/backup/{vm_hash}aa")
    # Past auth: no such backup file, so the delete logic returns its own 404.
    assert response.status == 404, await response.text()
    assert "not found" in await response.text()
```

(The `backup_id` `f"{vm_hash}aa"` satisfies `_validate_backup_id`, which requires the id to start with the vm_hash.)

- [ ] **Step 2: Run, verify they fail**

Run:
```bash
PYTHONPATH=src /home/olivier/git/aleph/aleph-vm/.worktrees/wire-supervisor-read-views/.testvenv/bin/python -m pytest tests/supervisor/views/test_operator.py -k "backup_status or backup_delete" -v
```
Expected: the three new tests FAIL — current code hits `get_execution_or_404` on the empty pool and returns `404 "No virtual machine with ref ..."` (the authorized tests expected a different 404 body; the unauthorized test expected 403).

- [ ] **Step 3: Migrate `operate_backup_status`**

Replace its current head:
```python
    with set_vm_for_logging(vm_hash=vm_hash):
        pool: VmPool = request.app["vm_pool"]
        execution = get_execution_or_404(vm_hash, pool=pool)

        if not await is_sender_authorized(authenticated_sender, execution.message):
            return web.Response(status=403, body="Unauthorized sender")
```
with:
```python
    with set_vm_for_logging(vm_hash=vm_hash):
        record = get_agent_record_or_404(request, vm_hash)
        if not await is_sender_authorized(authenticated_sender, record.message):
            return web.Response(status=403, body="Unauthorized sender")
```

- [ ] **Step 4: Migrate `operate_backup_delete`**

Replace its current head:
```python
    with set_vm_for_logging(vm_hash=vm_hash):
        pool: VmPool = request.app["vm_pool"]
        execution = get_execution_or_404(vm_hash, pool=pool)

        if not await is_sender_authorized(authenticated_sender, execution.message):
            return web.Response(status=403, body="Unauthorized sender")
```
with:
```python
    with set_vm_for_logging(vm_hash=vm_hash):
        record = get_agent_record_or_404(request, vm_hash)
        if not await is_sender_authorized(authenticated_sender, record.message):
            return web.Response(status=403, body="Unauthorized sender")
```

- [ ] **Step 5: Run the three tests, verify they pass**

Run:
```bash
PYTHONPATH=src /home/olivier/git/aleph/aleph-vm/.worktrees/wire-supervisor-read-views/.testvenv/bin/python -m pytest tests/supervisor/views/test_operator.py -k "backup_status or backup_delete" -v
```
Expected: PASS.

### 2b — `operate_expire`

- [ ] **Step 6: Delete the obsolete skipped test**

Remove the entire `test_operator_expire` function (the `@pytest.mark.asyncio` / `@pytest.mark.skip()` decorated test that asserts `fake_vm_pool["executions"][vm_hash].expire.call_count == 1`). It tests behavior that never existed and the endpoint is a known-broken route.

- [ ] **Step 7: Migrate `operate_expire`'s auth read**

Replace:
```python
        pool: VmPool = request.app["vm_pool"]
        execution = get_execution_or_404(vm_hash, pool=pool)

        if not await is_sender_authorized(authenticated_sender, execution.message):
            return web.Response(status=403, body="Unauthorized sender")

        logger.info(f"Expiring in {timeout} seconds: {execution.vm_hash}")
```
with:
```python
        record = get_agent_record_or_404(request, vm_hash)
        if not await is_sender_authorized(authenticated_sender, record.message):
            return web.Response(status=403, body="Unauthorized sender")

        logger.info(f"Expiring in {timeout} seconds: {vm_hash}")
```
(`execution.vm_hash` was equal to `vm_hash`; use `vm_hash` directly.)

- [ ] **Step 8: Verify the targeted file still collects and passes**

Run:
```bash
PYTHONPATH=src /home/olivier/git/aleph/aleph-vm/.worktrees/wire-supervisor-read-views/.testvenv/bin/python -m pytest tests/supervisor/views/test_operator.py -q
```
Expected: PASS (the removed skipped test is gone; nothing else regresses).

- [ ] **Step 9: Style + commit**

```bash
uvx ruff@0.4.6 format --diff src/aleph/vm/orchestrator/views/operator.py tests/supervisor/views/test_operator.py
uvx isort==5.13.2 --check-only --profile black src/aleph/vm/orchestrator/views/operator.py tests/supervisor/views/test_operator.py
git add src/aleph/vm/orchestrator/views/operator.py tests/supervisor/views/test_operator.py
git commit -m "refactor(owner-auth): authorize expire/backup-status/backup-delete from the registry"
```

---

## Task 3: Migrate the five auth-only-swap endpoints

**Files:**
- Modify: `src/aleph/vm/orchestrator/views/operator.py` (`operate_confidential_initialize`, `operate_confidential_measurement`, `operate_confidential_inject_secret`, `operate_backup`, `_do_restore`)
- Test: `tests/supervisor/views/test_operator.py`

These keep the `get_execution_or_404` lookup (they need `execution.vm` / `is_running` / `resources`), but the **auth message** moves to the registry and runs **before** the execution lookup. Pattern:

```python
record = get_agent_record_or_404(request, vm_hash)
if not await is_sender_authorized(authenticated_sender, record.message):
    return web.Response(status=403, body="Unauthorized sender")
execution = get_execution_or_404(vm_hash, pool=pool)   # still needed for execution.vm
```

### 3a — Update the four existing `confidential_initialize` tests to seed the registry

After migration these endpoints authorize from `app["vm_registry"]`; the existing tests seed only `pool.executions`, so without a registry record they would now 404 before auth. Add the registry seed to each.

- [ ] **Step 1: Update `test_operator_confidential_initialize_not_authorized`**

This test uses a `FakeVmPool`/`FakeExecution` and patches `is_sender_authorized` → False, expecting 403. Add a registry record so auth is reached. Replace the body from `with mock.patch(... authenticate_jwk ...)` onward so it seeds the registry on the constructed `app`:

```python
@pytest.mark.asyncio
async def test_operator_confidential_initialize_not_authorized(aiohttp_client):
    """Rejects when the sender is not authorized; auth message comes from the registry."""
    settings.ENABLE_QEMU_SUPPORT = True
    settings.ENABLE_CONFIDENTIAL_COMPUTING = True
    settings.setup()

    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    instance_message = await get_message(ref=vm_hash)

    class FakeExecution:
        message = None
        is_running: bool = True
        is_confidential: bool = False

    class FakeVmPool:
        def __init__(self):
            self.executions = {settings.FAKE_INSTANCE_ID: FakeExecution()}

    with mock.patch(
        "aleph.vm.orchestrator.views.authentication.authenticate_jwk",
        return_value="",
    ):
        with mock.patch(
            "aleph.vm.orchestrator.views.operator.is_sender_authorized",
            return_value=False,
        ) as is_sender_authorized_mock:
            app = setup_webapp(pool=FakeVmPool())
            app["vm_registry"].record(
                vm_hash,
                message=instance_message.content,
                original=instance_message.content,
                persistent=True,
            )
            client = await aiohttp_client(app)
            response = await client.post(
                f"/control/machine/{settings.FAKE_INSTANCE_ID}/confidential/initialize",
            )
            assert response.status == 403
            assert await response.text() == "Unauthorized sender"
            is_sender_authorized_mock.assert_called_once()
```

- [ ] **Step 2: Seed the registry in the three remaining confidential tests**

In each of `test_operator_confidential_initialize_already_running`, `test_operator_confidential_initialize_not_confidential`, and `test_operator_confidential_initialize` (the authorized one), add — immediately after `app = setup_webapp(pool=fake_vm_pool)` — the seed:

```python
    app["vm_registry"].record(
        vm_hash,
        message=instance_message.content,
        original=instance_message.content,
        persistent=True,
    )
```

All three already define `vm_hash` and `instance_message = await get_message(ref=vm_hash)` and set the execution's `message=instance_message.content`, so the registry message matches what they expect.

- [ ] **Step 3: Run them, verify they now fail against current code**

Run:
```bash
PYTHONPATH=src /home/olivier/git/aleph/aleph-vm/.worktrees/wire-supervisor-read-views/.testvenv/bin/python -m pytest tests/supervisor/views/test_operator.py -k confidential_initialize -v
```
Expected: the authorized cases still pass (they seed both pool and registry; current code reads the pool and the message matches), but `test_operator_confidential_initialize_not_authorized` is the red signal — after the test edit it seeds the registry; **current** code still authorizes from `execution.message` (which is `None` on `FakeExecution`) → `is_sender_authorized(None)` patched to False → 403, so it may already pass. If all four pass here, that is acceptable: they are migration-safety tests, and Step 5 proves the migration keeps them green. Proceed.

> Note for the implementer: the genuine red→green proof for the ③ endpoints is the empty-pool 403 tests in Steps 6–9 below, not the confidential-init edits (which exist to keep already-covered paths green through the migration).

### 3b — New empty-pool 403 tests (the red→green proof for ③)

- [ ] **Step 4: Add the four 403 tests**

Add to `tests/supervisor/views/test_operator.py`. Each seeds the registry, leaves the pool empty, patches `is_sender_authorized` → False, and expects 403. On current code each returns 404 (empty pool, execution-first) — red.

```python
@pytest.mark.asyncio
async def test_operator_confidential_measurement_unauthorized_reads_registry(aiohttp_client, mocker):
    settings.ENABLE_QEMU_SUPPORT = True
    settings.ENABLE_CONFIDENTIAL_COMPUTING = True
    settings.setup()

    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    instance_message = await get_message(ref=vm_hash)
    fake_vm_pool = mocker.AsyncMock(executions={})

    mocker.patch(
        "aleph.vm.orchestrator.views.authentication.authenticate_jwk",
        return_value="0xstranger",
    )
    mocker.patch(
        "aleph.vm.orchestrator.views.operator.is_sender_authorized",
        return_value=False,
    )
    app = setup_webapp(pool=fake_vm_pool)
    app["vm_registry"].record(
        vm_hash,
        message=instance_message.content,
        original=instance_message.content,
        persistent=True,
    )
    client: TestClient = await aiohttp_client(app)
    response = await client.get(f"/control/machine/{vm_hash}/confidential/measurement")
    assert response.status == 403, await response.text()


@pytest.mark.asyncio
async def test_operator_confidential_inject_secret_unauthorized_reads_registry(aiohttp_client, mocker):
    settings.ENABLE_QEMU_SUPPORT = True
    settings.ENABLE_CONFIDENTIAL_COMPUTING = True
    settings.setup()

    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    instance_message = await get_message(ref=vm_hash)
    fake_vm_pool = mocker.AsyncMock(executions={})

    mocker.patch(
        "aleph.vm.orchestrator.views.authentication.authenticate_jwk",
        return_value="0xstranger",
    )
    mocker.patch(
        "aleph.vm.orchestrator.views.operator.is_sender_authorized",
        return_value=False,
    )
    app = setup_webapp(pool=fake_vm_pool)
    app["vm_registry"].record(
        vm_hash,
        message=instance_message.content,
        original=instance_message.content,
        persistent=True,
    )
    client: TestClient = await aiohttp_client(app)
    # InjectSecretParams (packet_header, secret) is validated before auth, so the
    # body must be schema-valid for the request to reach the registry-auth check.
    response = await client.post(
        f"/control/machine/{vm_hash}/confidential/inject_secret",
        json={"packet_header": "aGVhZGVy", "secret": "c2VjcmV0"},
    )
    assert response.status == 403, await response.text()


@pytest.mark.asyncio
async def test_operator_backup_unauthorized_reads_registry(aiohttp_client, mocker):
    settings.ENABLE_QEMU_SUPPORT = True
    settings.setup()

    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    instance_message = await get_message(ref=vm_hash)
    fake_vm_pool = mocker.AsyncMock(executions={})

    mocker.patch(
        "aleph.vm.orchestrator.views.authentication.authenticate_jwk",
        return_value="0xstranger",
    )
    mocker.patch(
        "aleph.vm.orchestrator.views.operator.is_sender_authorized",
        return_value=False,
    )
    app = setup_webapp(pool=fake_vm_pool)
    app["vm_registry"].record(
        vm_hash,
        message=instance_message.content,
        original=instance_message.content,
        persistent=True,
    )
    client: TestClient = await aiohttp_client(app)
    response = await client.post(f"/control/machine/{vm_hash}/backup")
    assert response.status == 403, await response.text()


@pytest.mark.asyncio
async def test_operator_restore_unauthorized_reads_registry(aiohttp_client, mocker):
    settings.ENABLE_QEMU_SUPPORT = True
    settings.setup()

    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    instance_message = await get_message(ref=vm_hash)
    fake_vm_pool = mocker.AsyncMock(executions={})

    mocker.patch(
        "aleph.vm.orchestrator.views.authentication.authenticate_jwk",
        return_value="0xstranger",
    )
    mocker.patch(
        "aleph.vm.orchestrator.views.operator.is_sender_authorized",
        return_value=False,
    )
    app = setup_webapp(pool=fake_vm_pool)
    app["vm_registry"].record(
        vm_hash,
        message=instance_message.content,
        original=instance_message.content,
        persistent=True,
    )
    client: TestClient = await aiohttp_client(app)
    # operate_restore acquires the per-VM backup lock then delegates to _do_restore,
    # whose first act (after migration) is the registry-auth check — before any body
    # parsing — so an empty JSON body is fine for the 403 path.
    response = await client.post(
        f"/control/machine/{vm_hash}/restore",
        json={},
    )
    assert response.status == 403, await response.text()
```

- [ ] **Step 5: Run, verify the four new tests fail**

Run:
```bash
PYTHONPATH=src /home/olivier/git/aleph/aleph-vm/.worktrees/wire-supervisor-read-views/.testvenv/bin/python -m pytest tests/supervisor/views/test_operator.py -k "measurement_unauthorized or inject_secret_unauthorized or backup_unauthorized or restore_unauthorized" -v
```
Expected: FAIL — current code returns 404 (empty pool) where the tests expect 403.

### 3c — Apply the migration to the five endpoints

- [ ] **Step 6: Migrate `operate_confidential_initialize`**

Replace:
```python
        pool: VmPool = request.app["vm_pool"]
        logger.debug(f"Iterating through running executions... {pool.executions}")
        execution = get_execution_or_404(vm_hash, pool=pool)

        if not await is_sender_authorized(authenticated_sender, execution.message):
            return web.Response(status=403, body="Unauthorized sender")
```
with:
```python
        pool: VmPool = request.app["vm_pool"]
        record = get_agent_record_or_404(request, vm_hash)
        if not await is_sender_authorized(authenticated_sender, record.message):
            return web.Response(status=403, body="Unauthorized sender")

        logger.debug(f"Iterating through running executions... {pool.executions}")
        execution = get_execution_or_404(vm_hash, pool=pool)
```

- [ ] **Step 7: Migrate `operate_confidential_measurement`**

Replace:
```python
        pool: VmPool = request.app["vm_pool"]
        execution = get_execution_or_404(vm_hash, pool=pool)

        if not await is_sender_authorized(authenticated_sender, execution.message):
            return web.Response(status=403, body="Unauthorized sender")
```
with:
```python
        pool: VmPool = request.app["vm_pool"]
        record = get_agent_record_or_404(request, vm_hash)
        if not await is_sender_authorized(authenticated_sender, record.message):
            return web.Response(status=403, body="Unauthorized sender")

        execution = get_execution_or_404(vm_hash, pool=pool)
```

- [ ] **Step 8: Migrate `operate_confidential_inject_secret`**

Replace:
```python
        pool: VmPool = request.app["vm_pool"]
        execution = get_execution_or_404(vm_hash, pool=pool)
        if not await is_sender_authorized(authenticated_sender, execution.message):
            return web.Response(status=403, body="Unauthorized sender")
```
with:
```python
        pool: VmPool = request.app["vm_pool"]
        record = get_agent_record_or_404(request, vm_hash)
        if not await is_sender_authorized(authenticated_sender, record.message):
            return web.Response(status=403, body="Unauthorized sender")

        execution = get_execution_or_404(vm_hash, pool=pool)
```

- [ ] **Step 9: Migrate `operate_backup`**

Replace:
```python
            pool: VmPool = request.app["vm_pool"]
            execution = get_execution_or_404(vm_hash, pool=pool)

            if not await is_sender_authorized(authenticated_sender, execution.message):
                return web.Response(status=403, body="Unauthorized sender")
```
with:
```python
            pool: VmPool = request.app["vm_pool"]
            record = get_agent_record_or_404(request, vm_hash)
            if not await is_sender_authorized(authenticated_sender, record.message):
                return web.Response(status=403, body="Unauthorized sender")

            execution = get_execution_or_404(vm_hash, pool=pool)
```

- [ ] **Step 10: Migrate `_do_restore` (auth read + two rootfs reads)**

Replace:
```python
            pool: VmPool = request.app["vm_pool"]
            execution = get_execution_or_404(vm_hash, pool=pool)

            if not await is_sender_authorized(authenticated_sender, execution.message):
                return web.Response(status=403, body="Unauthorized sender")
```
with:
```python
            pool: VmPool = request.app["vm_pool"]
            record = get_agent_record_or_404(request, vm_hash)
            if not await is_sender_authorized(authenticated_sender, record.message):
                return web.Response(status=403, body="Unauthorized sender")

            execution = get_execution_or_404(vm_hash, pool=pool)
```
Then replace **both** occurrences of:
```python
            max_upload = execution.message.rootfs.size_mib * 1024 * 1024
```
and
```python
            max_size = execution.message.rootfs.size_mib * 1024 * 1024
```
with the registry-sourced reads:
```python
            max_upload = record.message.rootfs.size_mib * 1024 * 1024
```
and
```python
            max_size = record.message.rootfs.size_mib * 1024 * 1024
```

- [ ] **Step 11: Run the ③ tests, verify green**

Run:
```bash
PYTHONPATH=src /home/olivier/git/aleph/aleph-vm/.worktrees/wire-supervisor-read-views/.testvenv/bin/python -m pytest tests/supervisor/views/test_operator.py -k "confidential or backup or restore" -v
```
Expected: the four new 403 tests PASS; the four confidential-init tests still PASS.

- [ ] **Step 12: Style + commit**

```bash
uvx ruff@0.4.6 format --diff src/aleph/vm/orchestrator/views/operator.py tests/supervisor/views/test_operator.py
uvx isort==5.13.2 --check-only --profile black src/aleph/vm/orchestrator/views/operator.py tests/supervisor/views/test_operator.py
git add src/aleph/vm/orchestrator/views/operator.py tests/supervisor/views/test_operator.py
git commit -m "refactor(owner-auth): authorize confidential/backup/restore endpoints from the registry"
```

---

## Task 4: Lock the invariant and verify the whole file

**Files:**
- Test: `tests/supervisor/views/test_operator.py`

- [ ] **Step 1: Write the source-scan guard test**

Add to `tests/supervisor/views/test_operator.py`:

```python
def test_operator_module_does_not_read_execution_message():
    """Owner-auth and content reads must come from the registry, not the pool execution."""
    import inspect

    from aleph.vm.orchestrator.views import operator

    source = inspect.getsource(operator)
    assert "execution.message" not in source, (
        "operator.py must not read `execution.message`; authorize from the agent "
        "registry (get_agent_record_or_404 -> record.message) instead."
    )
```

- [ ] **Step 2: Run it, verify it passes**

Run:
```bash
PYTHONPATH=src /home/olivier/git/aleph/aleph-vm/.worktrees/wire-supervisor-read-views/.testvenv/bin/python -m pytest tests/supervisor/views/test_operator.py::test_operator_module_does_not_read_execution_message -v
```
Expected: PASS (all `execution.message` reads migrated in Tasks 1–3). If it fails, the failure message names the invariant — find the remaining `execution.message` and migrate it per the Task 3 pattern.

- [ ] **Step 3: Run the full operator test file**

Run:
```bash
PYTHONPATH=src /home/olivier/git/aleph/aleph-vm/.worktrees/wire-supervisor-read-views/.testvenv/bin/python -m pytest tests/supervisor/views/test_operator.py -q
```
Expected: all pass (no `/var/cache/aleph`-class failures in this file).

- [ ] **Step 4: Baseline check on the broader supervisor suite**

Run:
```bash
PYTHONPATH=src /home/olivier/git/aleph/aleph-vm/.worktrees/wire-supervisor-read-views/.testvenv/bin/python -m pytest tests/supervisor -q 2>&1 | tail -20
```
Expected: the failing/error set is the pre-existing environmental baseline (~50 failed + 4 errors on `/var/cache/aleph`, `/var/lib/aleph`, pyroute2) and **no new failures** attributable to this change. If unsure whether a failure is new, diff the failing-test names against `origin/dev` for the same file set.

- [ ] **Step 5: Final style gate + commit**

```bash
uvx ruff@0.4.6 format --diff src/aleph/vm/orchestrator/views/operator.py tests/supervisor/views/test_operator.py
uvx isort==5.13.2 --check-only --profile black src/aleph/vm/orchestrator/views/operator.py tests/supervisor/views/test_operator.py
git add tests/supervisor/views/test_operator.py
git commit -m "test(owner-auth): guard that operator.py never reads execution.message"
```

---

## Done criteria

- `execution.message` appears nowhere in `operator.py` (guard test green).
- `authenticate_websocket_for_vm_or_403` deleted; no import or route broke.
- Three endpoints (`operate_expire`, `operate_backup_status`, `operate_backup_delete`) are execution-free for auth; five (`operate_confidential_initialize`, `operate_confidential_measurement`, `operate_confidential_inject_secret`, `operate_backup`, `_do_restore`) authorize from the registry before their (retained) execution lookup.
- `tests/supervisor/views/test_operator.py` passes; broader suite matches the `origin/dev` environmental baseline with no new failures.
- Style gates clean; no `uv.lock` staged; no `Co-Authored-By` trailer.

## Out of scope (residuals after this PR — design §7)

- `execution.vm` / `execution.is_running` direct hypervisor reads in `operator.py` (Phase-1 Supervisor boundary).
- `operate_expire`'s broken route (no `{timeout}` segment) — known dead route, auth migrated but routing unchanged.
- `create_vm_execution` `save()` readback.
