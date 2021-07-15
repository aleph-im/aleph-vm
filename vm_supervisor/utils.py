import json
from base64 import b32decode, b16encode
from typing import Any

import aiodns


def b32_to_b16(hash: str) -> bytes:
    """Convert base32 encoded bytes to base16 encoded bytes."""
    # Add padding
    hash_b32: str = hash.upper() + "=" * (56 - len(hash))
    hash_bytes: bytes = b32decode(hash_b32.encode())
    return b16encode(hash_bytes).lower()


async def get_ref_from_dns(domain):
    resolver = aiodns.DNSResolver()
    record = await resolver.query(domain, "TXT")
    return record[0].text


def to_json(o: Any):
    if hasattr(o, "to_dict"):  # dataclasses
        return o.to_dict()
    elif hasattr(o, "dict"):  # Pydantic
        return o.dict()
    else:
        return str(o)


def dumps_for_json(o: Any):
    return json.dumps(o, default=to_json)
