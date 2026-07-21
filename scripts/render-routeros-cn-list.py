#!/usr/bin/env python3
"""Render a validated IPv4 CIDR list as an idempotent RouterOS import."""

import ipaddress
import sys
from pathlib import Path


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: render-routeros-cn-list.py INPUT OUTPUT")
    source, output = map(Path, sys.argv[1:])
    networks = []
    for raw in source.read_text(encoding="ascii").splitlines():
        if raw.strip():
            networks.append(ipaddress.ip_network(raw.strip()))
    collapsed = list(ipaddress.collapse_addresses(networks))
    if len(collapsed) < 1000:
        raise SystemExit(f"China IPv4 validation failed: only {len(collapsed)} networks")
    lines = [
        "/ip firewall address-list",
        'remove [find list="family_cn_ipv4"]',
        *(f'add list=family_cn_ipv4 address={network} comment="family-mihomo-cn"'
          for network in collapsed),
    ]
    output.write_text("\n".join(lines) + "\n", encoding="ascii")
    print(f"Rendered {len(collapsed)} RouterOS networks to {output}")


if __name__ == "__main__":
    main()
