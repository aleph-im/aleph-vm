#!/usr/bin/env python3
"""Produce an `Aleph-EIP191-V1` Authorization header for a scheduler-only endpoint.

The supervisor's allocation endpoints (`/control/allocations`, the migration
routes, `/control/proxy/regenerate`, ...) authenticate an EIP-191 signature over
a JSON payload binding the request's method, path and body hash. This helper
signs that payload so shell callers (CI, manual operator checks) can reach those
endpoints without reimplementing the scheme.

The signed payload embeds `iat`, which the supervisor rejects outside
ALEPH_VM_ALLOCATION_SIGNATURE_MAX_AGE_SECONDS, so sign at request time rather
than baking a header into a script.

Usage:
    printf '%s' "$BODY" | scripts/sign_allocation_request.py \\
        --key 0x<private-key> --method POST --path /control/allocations

Prints the header value on stdout, e.g.
    Aleph-EIP191-V1 sig=<hex>,payload=<hex>

See :mod:`aleph.vm.agent.views.allocation_auth` for the verifier.
"""

import argparse
import json
import sys
import time
from hashlib import sha256

from eth_account import Account
from eth_account.messages import encode_defunct


def build_header(private_key: str, method: str, path: str, body: bytes) -> str:
    payload = {
        "method": method,
        "path": path,
        "body_sha256": sha256(body).hexdigest(),
        "iat": int(time.time()),
    }
    # The signature covers these exact bytes, which travel in the header, so the
    # verifier re-parses whatever we send and any JSON encoding would work. Sort
    # and strip anyway: it keeps the payload compact, and makes the hash used by
    # the supervisor's replay cache depend only on the fields, not on formatting.
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    signed = Account.from_key(private_key).sign_message(encode_defunct(payload_bytes))
    return f"Aleph-EIP191-V1 sig={signed.signature.hex()},payload={payload_bytes.hex()}"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--key", required=True, help="signer private key, hex (0x-prefixed or not)")
    parser.add_argument("--path", required=True, help="request path, matched exactly (no query string allowed)")
    parser.add_argument("--method", default="POST", help="HTTP method (default: POST)")
    parser.add_argument(
        "--body-file",
        default="-",
        help="file holding the request body; '-' reads stdin (default), '' signs an empty body",
    )
    args = parser.parse_args()

    if args.body_file == "":
        body = b""
    elif args.body_file == "-":
        body = sys.stdin.buffer.read()
    else:
        with open(args.body_file, "rb") as handle:
            body = handle.read()

    print(build_header(args.key, args.method, args.path, body))


if __name__ == "__main__":
    main()
