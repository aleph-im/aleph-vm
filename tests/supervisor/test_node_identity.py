import tempfile
from pathlib import Path

import pytest
from aiohttp import web
from aleph_message.models import MessageType

from aleph.vm.conf import Settings
from aleph.vm.orchestrator.node_identity import (
    NodeIdentity,
    discover_node_hash,
    start_node_hash_discovery,
    stop_node_hash_discovery,
)
from aleph.vm.orchestrator.supervisor import setup_webapp


def test_node_hash_setting():
    s = Settings(NODE_HASH="abc123")
    assert s.NODE_HASH == "abc123"


def test_owner_address_setting():
    s = Settings(OWNER_ADDRESS="0xDeadBeef")
    assert s.OWNER_ADDRESS == "0xDeadBeef"


def test_payment_receiver_defaults_to_owner_address():
    s = Settings(OWNER_ADDRESS="0xDeadBeef")
    assert s.PAYMENT_RECEIVER_ADDRESS == "0xDeadBeef"


def test_payment_receiver_explicit_overrides_owner():
    s = Settings(OWNER_ADDRESS="0xDeadBeef", PAYMENT_RECEIVER_ADDRESS="0xOther")
    assert s.PAYMENT_RECEIVER_ADDRESS == "0xOther"


def test_explicit_hash_takes_priority():
    identity = NodeIdentity(
        node_hash="explicit123",
        owner_address="0xOwner",
        domain_name="example.com",
        cache_dir=Path(tempfile.mkdtemp()),
    )
    identity.resolve()
    assert identity.get_node_hash() == "explicit123"


def test_cached_hash_read_on_resolve():
    cache_dir = Path(tempfile.mkdtemp())
    (cache_dir / "node-hash").write_text("cached456")
    identity = NodeIdentity(
        node_hash=None,
        owner_address="0xOwner",
        domain_name="example.com",
        cache_dir=cache_dir,
    )
    identity.resolve()
    assert identity.get_node_hash() == "cached456"


def test_no_config_returns_none():
    identity = NodeIdentity(
        node_hash=None,
        owner_address="",
        domain_name="example.com",
        cache_dir=Path(tempfile.mkdtemp()),
    )
    identity.resolve()
    assert identity.get_node_hash() is None


def test_cache_written_on_set():
    cache_dir = Path(tempfile.mkdtemp())
    identity = NodeIdentity(
        node_hash=None,
        owner_address="0xOwner",
        domain_name="example.com",
        cache_dir=cache_dir,
    )
    identity.set_discovered_hash("discovered789")
    assert identity.get_node_hash() == "discovered789"
    assert (cache_dir / "node-hash").read_text() == "discovered789"


@pytest.mark.asyncio
async def test_discover_from_api_single_match(aiohttp_server):
    """Auto-discovery finds exactly one matching CRN registration."""

    async def mock_posts(request):
        return web.json_response(
            {
                "posts": [
                    {
                        "item_hash": "abc123nodeHash",
                        "content": {
                            "content": {
                                "action": "create-resource-node",
                                "details": {
                                    "address": "https://my-node.example.com/",
                                    "name": "My Node",
                                },
                            }
                        },
                    }
                ]
            }
        )

    app = web.Application()
    app.router.add_get("/api/v0/posts.json", mock_posts)
    server = await aiohttp_server(app)

    identity = NodeIdentity(
        node_hash=None,
        owner_address="0xOwner",
        domain_name="my-node.example.com",
        cache_dir=Path(tempfile.mkdtemp()),
    )
    identity.resolve()
    assert identity.needs_discovery()

    discovered = await discover_node_hash(identity, api_server=f"http://localhost:{server.port}")
    assert discovered == "abc123nodeHash"


@pytest.mark.asyncio
async def test_discover_from_api_no_match(aiohttp_server):
    """Auto-discovery finds no matching CRN for this domain."""

    async def mock_posts(request):
        return web.json_response(
            {
                "posts": [
                    {
                        "item_hash": "abc123nodeHash",
                        "content": {
                            "content": {
                                "action": "create-resource-node",
                                "details": {
                                    "address": "https://other-node.example.com/",
                                    "name": "Other Node",
                                },
                            }
                        },
                    }
                ]
            }
        )

    app = web.Application()
    app.router.add_get("/api/v0/posts.json", mock_posts)
    server = await aiohttp_server(app)

    identity = NodeIdentity(
        node_hash=None,
        owner_address="0xOwner",
        domain_name="my-node.example.com",
        cache_dir=Path(tempfile.mkdtemp()),
    )
    identity.resolve()

    discovered = await discover_node_hash(identity, api_server=f"http://localhost:{server.port}")
    assert discovered is None


@pytest.mark.asyncio
async def test_discover_from_api_multiple_matches(aiohttp_server):
    """Auto-discovery finds multiple matches — returns None (ambiguous)."""

    async def mock_posts(request):
        return web.json_response(
            {
                "posts": [
                    {
                        "item_hash": "hash1",
                        "content": {
                            "content": {
                                "action": "create-resource-node",
                                "details": {
                                    "address": "https://my-node.example.com",
                                    "name": "Node A",
                                },
                            }
                        },
                    },
                    {
                        "item_hash": "hash2",
                        "content": {
                            "content": {
                                "action": "create-resource-node",
                                "details": {
                                    "address": "https://my-node.example.com/",
                                    "name": "Node B",
                                },
                            }
                        },
                    },
                ]
            }
        )

    app = web.Application()
    app.router.add_get("/api/v0/posts.json", mock_posts)
    server = await aiohttp_server(app)

    identity = NodeIdentity(
        node_hash=None,
        owner_address="0xOwner",
        domain_name="my-node.example.com",
        cache_dir=Path(tempfile.mkdtemp()),
    )
    identity.resolve()

    discovered = await discover_node_hash(identity, api_server=f"http://localhost:{server.port}")
    assert discovered is None


@pytest.mark.asyncio
async def test_discover_filters_non_create_actions(aiohttp_server):
    """Auto-discovery ignores drop-node and other non-create actions."""

    async def mock_posts(request):
        return web.json_response(
            {
                "posts": [
                    {
                        "item_hash": "dropped_hash",
                        "content": {
                            "content": {
                                "action": "drop-resource-node",
                                "details": {
                                    "address": "https://my-node.example.com/",
                                    "name": "My Node",
                                },
                            }
                        },
                    },
                    {
                        "item_hash": "correct_hash",
                        "content": {
                            "content": {
                                "action": "create-resource-node",
                                "details": {
                                    "address": "https://my-node.example.com/",
                                    "name": "My Node",
                                },
                            }
                        },
                    },
                ]
            }
        )

    app = web.Application()
    app.router.add_get("/api/v0/posts.json", mock_posts)
    server = await aiohttp_server(app)

    identity = NodeIdentity(
        node_hash=None,
        owner_address="0xOwner",
        domain_name="my-node.example.com",
        cache_dir=Path(tempfile.mkdtemp()),
    )
    identity.resolve()

    discovered = await discover_node_hash(identity, api_server=f"http://localhost:{server.port}")
    assert discovered == "correct_hash"


@pytest.mark.asyncio
async def test_discover_handles_malformed_api_response(aiohttp_server):
    """Auto-discovery gracefully handles posts with missing or wrong-typed fields."""

    async def mock_posts(request):
        return web.json_response(
            {
                "posts": [
                    {"item_hash": "no_content"},
                    {"item_hash": "bad_nesting", "content": "not_a_dict"},
                    {"item_hash": "missing_details", "content": {"content": {"action": "create-resource-node"}}},
                    {
                        "item_hash": "good_hash",
                        "content": {
                            "content": {
                                "action": "create-resource-node",
                                "details": {
                                    "address": "https://my-node.example.com/",
                                    "name": "Good Node",
                                },
                            }
                        },
                    },
                ]
            }
        )

    app = web.Application()
    app.router.add_get("/api/v0/posts.json", mock_posts)
    server = await aiohttp_server(app)

    identity = NodeIdentity(
        node_hash=None,
        owner_address="0xOwner",
        domain_name="my-node.example.com",
        cache_dir=Path(tempfile.mkdtemp()),
    )
    identity.resolve()

    discovered = await discover_node_hash(identity, api_server=f"http://localhost:{server.port}")
    assert discovered == "good_hash"


@pytest.mark.asyncio
async def test_discovery_task_resolves_from_setting():
    """When NODE_HASH is set, the startup hook resolves immediately."""
    app = web.Application()
    app["node_identity"] = NodeIdentity(
        node_hash="explicit123",
        owner_address="",
        domain_name="example.com",
        cache_dir=Path(tempfile.mkdtemp()),
    )
    await start_node_hash_discovery(app)
    assert app["node_identity"].get_node_hash() == "explicit123"
    await stop_node_hash_discovery(app)


def _make_notify_app(node_hash: str | None) -> web.Application:
    """Create a minimal app with node identity for notify_allocation tests."""
    app = setup_webapp(pool=None)
    app["node_identity"] = NodeIdentity(
        node_hash=node_hash,
        owner_address="",
        domain_name="example.com",
        cache_dir=Path(tempfile.mkdtemp()),
    )
    app["node_identity"].resolve()
    return app


@pytest.mark.asyncio
async def test_notify_rejects_wrong_node_hash(aiohttp_client, mocker):
    """Allocation targeting a different node is rejected with 400."""
    app = _make_notify_app(node_hash="this_node_hash")
    client = await aiohttp_client(app)

    # Mock try_get_message to return a message with a different node_hash
    mock_message = mocker.Mock()
    mock_message.type = MessageType.instance
    mock_message.content.requirements.node.node_hash = "other_node_hash"
    mocker.patch(
        "aleph.vm.orchestrator.views.try_get_message",
        return_value=mock_message,
    )
    mocker.patch(
        "aleph.vm.orchestrator.views.update_aggregate_settings",
    )

    response = await client.post(
        "/control/allocation/notify",
        json={"instance": "a" * 64, "persistent": True},
    )
    assert response.status == 400
    data = await response.json()
    assert "different node" in data.get("reason", data.get("error", "")).lower()


@pytest.mark.asyncio
async def test_notify_rejects_when_hash_unknown(aiohttp_client, mocker):
    """Allocation targeting a specific node is rejected with 503
    when this node hasn't discovered its hash yet."""
    app = _make_notify_app(node_hash=None)
    client = await aiohttp_client(app)

    mock_message = mocker.Mock()
    mock_message.type = MessageType.instance
    mock_message.content.requirements.node.node_hash = "some_node_hash"
    mocker.patch(
        "aleph.vm.orchestrator.views.try_get_message",
        return_value=mock_message,
    )
    mocker.patch(
        "aleph.vm.orchestrator.views.update_aggregate_settings",
    )

    response = await client.post(
        "/control/allocation/notify",
        json={"instance": "a" * 64, "persistent": True},
    )
    assert response.status == 503


@pytest.mark.asyncio
async def test_status_config_includes_node_hash(aiohttp_client):
    app = _make_notify_app(node_hash="my_node_hash_123")
    client = await aiohttp_client(app)

    response = await client.get("/status/config")
    assert response.status == 200
    data = await response.json()
    assert data["node_hash"] == "my_node_hash_123"


@pytest.mark.asyncio
async def test_status_config_node_hash_null_when_unknown(aiohttp_client):
    app = _make_notify_app(node_hash=None)
    client = await aiohttp_client(app)

    response = await client.get("/status/config")
    assert response.status == 200
    data = await response.json()
    assert data["node_hash"] is None
