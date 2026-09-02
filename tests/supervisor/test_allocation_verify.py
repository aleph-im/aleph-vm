"""The scheduler may choose which messages run here, never what they contain.

Two gates together give that: aleph_message's own validators bind content to
item_hash (sha256 of item_content), and the sender signature covers a buffer
that includes item_hash. Neither alone is enough.
"""

import json
from hashlib import sha256

import pytest
from eth_account import Account
from eth_account.messages import encode_defunct

from aleph.vm.agent.allocation.verify import VerificationOutcome, verify_entry


def sign_message(content_dict: dict, account, *, chain="ETH", message_type="INSTANCE") -> dict:
    """A full message envelope signed the way the network does: item_hash is
    sha256(item_content), and the signature covers chain/sender/type/hash."""
    item_content = json.dumps(content_dict)
    item_hash = sha256(item_content.encode()).hexdigest()
    buffer = f"{chain}\n{account.address}\n{message_type}\n{item_hash}".encode()
    signature = account.sign_message(encode_defunct(buffer)).signature.hex()
    return {
        "chain": chain,
        "sender": account.address,
        "type": message_type,
        "item_hash": item_hash,
        "item_type": "inline",
        "item_content": item_content,
        "content": content_dict,
        "signature": signature if signature.startswith("0x") else "0x" + signature,
        "time": 1.0,
        "channel": "TEST",
    }


@pytest.fixture
def account():
    return Account.create()


@pytest.fixture
def instance_content(account):
    return {
        "address": account.address,
        "time": 1.0,
        "allow_amend": False,
        "environment": {"internet": True, "aleph_api": False, "hypervisor": "qemu"},
        "resources": {"vcpus": 2, "memory": 2048, "seconds": 300},
        "volumes": [],
        "rootfs": {
            "parent": {"ref": "d" * 64, "use_latest": False},
            "persistence": "host",
            "size_mib": 10000,
        },
    }


def test_a_correctly_signed_message_is_verified(account, instance_content):
    message = sign_message(instance_content, account)
    entry = {"item_hash": message["item_hash"], "message": message}

    outcome, verified, _ = verify_entry(entry)

    assert outcome is VerificationOutcome.VERIFIED
    assert verified.message.content.resources.vcpus == 2
    assert verified.original is not verified.message


def test_content_tampered_after_signing_is_rejected(account, instance_content):
    """The scheduler cannot hand us different resources than the user signed:
    item_content no longer hashes to item_hash, so the model rejects it."""
    message = sign_message(instance_content, account)
    tampered = json.loads(message["item_content"])
    tampered["resources"]["vcpus"] = 64
    message["item_content"] = json.dumps(tampered)
    message["content"] = tampered
    entry = {"item_hash": message["item_hash"], "message": message}

    outcome, _, reason = verify_entry(entry)

    assert outcome is VerificationOutcome.REJECTED
    assert reason


def test_a_foreign_signature_is_rejected(account, instance_content):
    """Content that hashes correctly but was signed by somebody else."""
    message = sign_message(instance_content, account)
    message["signature"] = sign_message(instance_content, Account.create())["signature"]
    entry = {"item_hash": message["item_hash"], "message": message}

    outcome, _, _ = verify_entry(entry)

    assert outcome is VerificationOutcome.REJECTED


def test_an_item_hash_that_disagrees_with_the_message_is_rejected(account, instance_content):
    """The plan's hash is the identity the agent keys everything by, so a
    message claiming a different hash must never be accepted under it."""
    entry = {"item_hash": "a" * 64, "message": sign_message(instance_content, account)}

    outcome, _, _ = verify_entry(entry)

    assert outcome is VerificationOutcome.REJECTED


def test_an_entry_without_a_message_is_unverifiable():
    outcome, verified, _ = verify_entry({"item_hash": "b" * 64})

    assert outcome is VerificationOutcome.UNVERIFIABLE
    assert verified is None


def test_a_non_evm_chain_is_unverifiable_not_rejected(account, instance_content):
    """We cannot check a Solana signature, but the user is not at fault:
    fall back to fetching the message ourselves."""
    message = sign_message(instance_content, account, chain="SOL")
    entry = {"item_hash": message["item_hash"], "message": message}

    outcome, _, _ = verify_entry(entry)

    assert outcome is VerificationOutcome.UNVERIFIABLE


def test_a_storage_item_type_is_unverifiable(account, instance_content):
    """No inline content means nothing binds the content to the hash here."""
    message = sign_message(instance_content, account)
    message["item_type"] = "storage"
    message.pop("item_content")
    entry = {"item_hash": message["item_hash"], "message": message}

    outcome, _, _ = verify_entry(entry)

    assert outcome is VerificationOutcome.UNVERIFIABLE


def test_an_embedded_amended_message_is_ignored(account, instance_content):
    """The payload carries no amend: what update_message resolves are the
    use_latest refs inside the volumes, and a resolved ref is an unverifiable
    bare hash. Trusting one would let the scheduler choose the rootfs. A
    scheduler that sends the field anyway is answered from the signed message
    alone."""
    message = sign_message(instance_content, account)
    entry = {
        "item_hash": message["item_hash"],
        "message": message,
        "amended_message": sign_message(dict(instance_content, allow_amend=True), Account.create()),
    }

    outcome, verified, _ = verify_entry(entry)

    assert outcome is VerificationOutcome.VERIFIED
    assert verified.message.content.resources.vcpus == 2
    assert verified.original is not verified.message


def test_a_content_field_diverging_from_the_signed_item_content_is_ignored(account, instance_content):
    """The attack the two gates do not stop on their own.

    item_content, item_hash and the signature are all genuinely the user's, and
    only the separate content field is the scheduler's. InstanceMessage has no
    validator binding the two (ProgramMessage and VerifiableProgramMessage do),
    so before content was re-derived this verified and handed the agent 64
    vCPUs the user never signed for.
    """
    message = sign_message(instance_content, account)
    tampered = json.loads(message["item_content"])
    tampered["resources"]["vcpus"] = 64
    message["content"] = tampered
    entry = {"item_hash": message["item_hash"], "message": message}

    outcome, verified, _ = verify_entry(entry)

    assert outcome is VerificationOutcome.VERIFIED
    assert verified.message.content.resources.vcpus == 2


def test_the_original_is_a_copy_so_resolving_refs_cannot_rewrite_it(account, instance_content):
    """update_message mutates in place, so an aliased original would be
    rewritten along with the message it is supposed to preserve."""
    message = sign_message(instance_content, account)

    _, verified, _ = verify_entry({"item_hash": message["item_hash"], "message": message})

    verified.message.content.resources.vcpus = 64

    assert verified.original.content.resources.vcpus == 2


def test_a_message_that_is_not_an_object_is_rejected():
    """Every other malformed shape answers REJECTED; this one used to escape
    with an AttributeError from the raw.get() calls."""
    outcome, verified, reason = verify_entry({"item_hash": "b" * 64, "message": "not-an-object"})

    assert outcome is VerificationOutcome.REJECTED
    assert verified is None
    assert reason
