import json
from base64 import b32decode, b16encode
from dataclasses import is_dataclass, asdict as dataclass_as_dict
from typing import Any, Optional

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
    if hasattr(o, "to_dict"):  # default method
        return o.to_dict()
    elif hasattr(o, "dict"):  # Pydantic
        return o.dict()
    elif is_dataclass(o):
        return dataclass_as_dict(o)
    else:
        return str(o)


def dumps_for_json(o: Any, indent: Optional[int] = None):
    return json.dumps(o, default=to_json, indent=indent)
