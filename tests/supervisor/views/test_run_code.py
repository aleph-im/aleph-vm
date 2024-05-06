import asyncio

import pytest
from aiohttp import web, ClientResponseError
from aiohttp.test_utils import make_mocked_request
from aleph_message.exceptions import UnknownHashError

from aleph.vm.conf import settings
from aleph.vm.orchestrator.views import run_code_from_path
from aleph.vm.pool import VmPool


@pytest.mark.asyncio
async def test_run_code_from_invalid_path(aiohttp_client):
    """
    Test that the run_code_from_path endpoint raises the right
    error on invalid paths.
    """
    app = web.Application()
    app.router.add_post('/run_code', run_code_from_path)
    client = await aiohttp_client(app)

    # Passing an invalid item hash to the endpoint should raise an UnknownHashError.
    invalid_hash_request: web.Request = make_mocked_request(
        'GET',
        '/vm/invalid-item-hash',
        match_info={
            'ref': 'invalid-item-hash',
            'suffix': '/some/suffix',
        }
    )
    with pytest.raises(UnknownHashError):
        await run_code_from_path(invalid_hash_request)

    # Calling the view from an HTTP client should result in a 404 error.
    with pytest.raises(ClientResponseError):
        resp = await client.get('/vm/invalid-item-hash')
        assert resp.status == 404
        assert resp.reason == 'Not Found'
        resp.raise_for_status()


@pytest.mark.asyncio
async def test_run_code_from_invalid_storage_hash(aiohttp_client):
    """
    Test that the run_code_from_path endpoint raises an UnknownHashError
    when given an invalid storage hash.
    """
    item_hash = 'cafe' * 16
    settings.FAKE_DATA_PROGRAM = settings.BENCHMARK_FAKE_DATA_PROGRAM

    app = web.Application()

    loop = asyncio.get_running_loop()
    pool = VmPool(loop)
    pool.setup()
    app["vm_pool"] = pool

    app.router.add_post('/run_code', run_code_from_path)
    client = await aiohttp_client(app)

    invalid_hash_request: web.Request = make_mocked_request(
        'GET',
        '/vm/' + item_hash,
        match_info={
            'ref': item_hash,
            'suffix': '/some/suffix',
        },
        app=app,
    )
    with pytest.raises(UnknownHashError):
        await run_code_from_path(invalid_hash_request)

    # Calling the view from an HTTP client should result in a 404 error.
    with pytest.raises(ClientResponseError):
        resp = await client.get('/vm/' + item_hash)
        assert resp.status == 404
        assert resp.reason == 'Invalid message reference'
        resp.raise_for_status()
