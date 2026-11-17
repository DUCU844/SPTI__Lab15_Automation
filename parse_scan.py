#!/usr/bin/env python3
"""Part 2 - nmap XML parser and enricher.

Reads the XML produced by `nmap -sV --open -oX scan.xml <target>` with
xml.etree.ElementTree (no third-party nmap library) and writes one structured
dict per live host. Hosts that expose SSH are enriched with the type of their
SSH host keys, obtained with `ssh-keyscan` (which only performs the opening of
the SSH handshake: it never authenticates).

Example:
    python3 parse_scan.py --input part2/scan.xml --output part2/hosts.json
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

# Preference order used to pick the "primary" key type when a host offers several.
KEY_PREFERENCE = ["ssh-ed25519", "ecdsa-sha2-nistp521", "ecdsa-sha2-nistp384",
                  "ecdsa-sha2-nistp256", "rsa-sha2-512", "rsa-sha2-256", "ssh-rsa", "ssh-dss"]
LEGACY_KEY_TYPES = {"ssh-dss"}          # DSA: disabled by default since OpenSSH 7.0


def parse_nmap_xml(path: str) -> list[dict]:
    """Return one dict per live host: ip, hostname and its open ports."""
    root = ET.parse(path).getroot()
    hosts = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue
        # Select the address by addrtype: the first <address> may be the MAC.
        address = host.find("address[@addrtype='ipv4']")
        if address is None:
            address = host.find("address[@addrtype='ipv6']")
        if address is None:
            continue
        hostname_el = host.find("hostnames/hostname")
        open_ports = []
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            name = service.get("name") if service is not None else None
            # "version" = product + version as identified by the -sV probes
            version = None
            if service is not None:
                version = " ".join(x for x in (service.get("product"), service.get("version")) if x) or None
            open_ports.append({
                "port": int(port.get("portid")),
                "service": name,
                "version": version,
            })
        hosts.append({
            "ip": address.get("addr"),
            "hostname": hostname_el.get("name") if hostname_el is not None else None,
            "open_ports": sorted(open_ports, key=lambda p: p["port"]),
        })
    return hosts


def ssh_host_key_types(ip: str, port: int = 22, timeout: int = 5) -> tuple[list[str], str | None]:
    """Run ssh-keyscan and return (key types, error).

    ssh-keyscan prints one line per key: "<host> <key-type> <base64-key>".
    Comment lines (starting with '#') carry the banner and go to stderr.
    """
    cmd = ["ssh-keyscan", "-T", str(timeout), "-p", str(port), ip]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout * 3 + 5)
    except subprocess.TimeoutExpired:
        return [], f"ssh-keyscan timed out after {timeout * 3 + 5}s"
    except FileNotFoundError:
        return [], "ssh-keyscan is not installed"
    types = []
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 3 and not line.startswith("#"):
            types.append(fields[1])
    if not types:
        detail = result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "no keys returned"
        return [], f"no host key received (exit {result.returncode}: {detail})"
    return sorted(set(types), key=lambda t: KEY_PREFERENCE.index(t) if t in KEY_PREFERENCE else 99), None


def enrich_with_ssh_keys(hosts: list[dict], timeout: int = 5) -> None:
    for host in hosts:
        ssh_ports = [p["port"] for p in host["open_ports"] if p["port"] == 22 or p["service"] == "ssh"]
        if not ssh_ports:
            continue
        types, error = ssh_host_key_types(host["ip"], ssh_ports[0], timeout)
        host["ssh_host_key_type"] = types[0] if types else None      # primary (strongest) type
        host["ssh_host_key_types"] = types                            # every type the server offers
        host["ssh_legacy_key"] = bool(LEGACY_KEY_TYPES & set(types))
        if error:
            host["ssh_keyscan_error"] = error


def main() -> int:
    parser = argparse.ArgumentParser(description="Parse nmap XML (-oX) and enrich SSH hosts with host-key types")
    parser.add_argument("--input", required=True, help="nmap XML file (from -oX)")
    parser.add_argument("--output", required=True, help="JSON output file")
    parser.add_argument("--keyscan-timeout", type=int, default=5, help="ssh-keyscan timeout in seconds (default 5)")
    args = parser.parse_args()

    try:
        hosts = parse_nmap_xml(args.input)
    except (OSError, ET.ParseError) as exc:
        print(f"error: cannot parse {args.input}: {exc}", file=sys.stderr)
        return 1
    enrich_with_ssh_keys(hosts, args.keyscan_timeout)
    Path(args.output).write_text(json.dumps(hosts, indent=2) + "\n")
    for host in hosts:
        ports = ", ".join(f"{p['port']}/{p['service']}" for p in host["open_ports"])
        print(f"{host['ip']} ({host['hostname'] or 'no hostname'}): {ports}"
              + (f" | ssh host key: {host.get('ssh_host_key_type')}" if "ssh_host_key_type" in host else ""),
              file=sys.stderr)
    print(f"{len(hosts)} live host(s) written to {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
