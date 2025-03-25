#!/usr/bin/env python3
"""
Extract the IP address of a DigitalOcean Droplet
from the JSON returned by `doctl compute droplet get $name --output json
"""

import json
import sys

try:
    droplet_info = json.load(sys.stdin)
    print(droplet_info[0]["networks"]["v4"][0]["ip_address"])
except Exception:
    print(droplet_info)
    raise
