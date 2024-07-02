import datetime
import json

import eth_account.messages
import pytest
from eth_account.datastructures import SignedMessage
from eth_account.signers.local import LocalAccount
from jwcrypto import jwk
from jwcrypto.jwa import JWA


@pytest.fixture
def patch_datetime_now(monkeypatch):
    """Fixture for patching the datetime.now() and datetime.utcnow() methods
    to return a fixed datetime object.
    This fixture creates a subclass of `datetime.datetime` called `mydatetime`,
    which overrides the `now()` and `utcnow()` class methods to return a fixed
    datetime object specified by `FAKE_TIME`.
    """

    class MockDateTime(datetime.datetime):
        FAKE_TIME = datetime.datetime(2010, 12, 25, 17, 5, 55)

        @classmethod
        def now(cls, tz=None, *args, **kwargs):
            return cls.FAKE_TIME.replace(tzinfo=tz)

        @classmethod
        def utcnow(cls, *args, **kwargs):
            return cls.FAKE_TIME

    monkeypatch.setattr(datetime, "datetime", MockDateTime)
    return MockDateTime


async def generate_signer_and_signed_headers_for_operation(
    patch_datetime_now, operation_payload: dict
) -> tuple[LocalAccount, dict]:
    """Generate a temporary eth_account for testing and sign the operation with it"""
    account = eth_account.Account()
    signer_account = account.create()
    key = jwk.JWK.generate(
        kty="EC",
        crv="P-256",
        # key_ops=["verify"],
    )
    pubkey = {
        "pubkey": json.loads(key.export_public()),
        "alg": "ECDSA",
        "domain": "localhost",
        "address": signer_account.address,
        "expires": (patch_datetime_now.FAKE_TIME + datetime.timedelta(days=1)).isoformat() + "Z",
    }
    pubkey_payload = json.dumps(pubkey).encode("utf-8").hex()
    signable_message = eth_account.messages.encode_defunct(hexstr=pubkey_payload)
    signed_message: SignedMessage = signer_account.sign_message(signable_message)
    pubkey_signature = to_0x_hex(signed_message.signature)
    pubkey_signature_header = json.dumps(
        {
            "payload": pubkey_payload,
            "signature": pubkey_signature,
        }
    )
    payload_as_bytes = json.dumps(operation_payload).encode("utf-8")

    payload_signature = JWA.signing_alg("ES256").sign(key, payload_as_bytes)
    headers = {
        "X-SignedPubKey": pubkey_signature_header,
        "X-SignedOperation": json.dumps(
            {
                "payload": payload_as_bytes.hex(),
                "signature": payload_signature.hex(),
            }
        ),
    }
    return signer_account, headers


def to_0x_hex(b: bytes) -> str:
    """
    Convert the bytes to a 0x-prefixed hex string
    """

    # force this for compat between different hexbytes versions which behave differenty
    # and conflict with other package don't allow us to have the version we want
    return "0x" + bytes.hex(b)
