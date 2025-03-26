#!/usr/bin/env python3
"""
Extract the IP address of a DigitalOcean Droplet
from the JSON returned by `doctl compute droplet get $name --output json
"""

import json
import sys

droplet_raw = sys.stdin.read()
try:
    droplet_info = json.loads(droplet_raw)
    if not droplet_info:
        sys.exit("No droplet info")
    if "errors" in droplet_info:
        sys.exit(droplet_raw)
    if "networks" not in droplet_info[0]:
        sys.exit(f"droplet_info[] {droplet_info[0]}")
    elif ("v4" not in droplet_info[0]["networks"]) or not droplet_info[0]["networks"]["v4"]:
        sys.exit("networks {}".format(droplet_info[0]["networks"]))
    else:
        print(droplet_info[0]["networks"]["v4"][0]["ip_address"])  # noqa: T201

except Exception as e:
    if not isinstance(e, SystemExit):
        print(f"Failed to find ipv4: {e}", file=sys.stderr)  # noqa: T201
        print(droplet_raw, file=sys.stderr)  # noqa: T201
    raise
