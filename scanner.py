#!/usr/bin/env python3
"""Part 1 - Concurrent TCP connect() port scanner (asyncio + Semaphore).

Standard library only. A TCP connect scan needs no privileges: the kernel
performs the three-way handshake, so this script must NOT be run with sudo.

Every probe is classified instead of being collapsed into open / not-open:

    open      SYN-ACK came back, the handshake completed
    closed    RST came back (ConnectionRefusedError)
    filtered  silence until the timeout (dropped, filtered or lost)
    error     the probe could not be sent at all (e.g. EMFILE: too many open
              files). The state of that port is UNKNOWN, never "closed".

Examples:
    python3 scanner.py 10.0.2.15
    python3 scanner.py 10.0.2.15 --ports 22,80,443 --rate 50 --timeout 1
    python3 scanner.py 10.0.2.15 --ports 1-1024 --rate 200 --output scan_rate200.json
    python3 scanner.py 10.0.2.15 --scope scope.txt --retry-unknown
"""
from __future__ import annotations

import argparse
import asyncio
import errno
import ipaddress
import json
import random
import re
import resource
import sys
import time
from collections import Counter
from datetime import datetime
from pathlib import Path

UNKNOWN_LIST_LIMIT = 100  # cap for the list of unknown ports written to the JSON


# --------------------------------------------------------------------------- #
# Argument helpers
# --------------------------------------------------------------------------- #
def parse_ports(spec: str) -> list[int]:
    """Accept '22,80,443', '1-1024' or a mix such as '22,80,8000-8100'."""
    ports: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            if "-" in chunk:
                low_s, high_s = chunk.split("-", 1)
                low, high = int(low_s), int(high_s)
            else:
                low = high = int(chunk)
        except ValueError:
            raise argparse.ArgumentTypeError(f"invalid port specification: {chunk!r}")
        if not (1 <= low <= high <= 65535):
            raise argparse.ArgumentTypeError(f"port range out of bounds (1-65535): {chunk!r}")
        ports.update(range(low, high + 1))
    if not ports:
        raise argparse.ArgumentTypeError("empty port specification")
    return sorted(ports)


def ip_address(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise argparse.ArgumentTypeError(f"not an IP address: {value!r}")


def positive_int(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return number


def check_scope(target: str, scope_file: str) -> None:
    """Refuse to scan anything that scope.txt does not authorize.

    scope.txt must contain the authorized IPv4 address and a line
    'Window: <ISO start> to <ISO end>'. Exits with code 2 when the target is
    not listed or the current time is outside the window.
    """
    text = Path(scope_file).read_text()
    allowed = set(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text))
    if target not in allowed:
        sys.exit(f"[scope] REFUSED: {target} is not authorized by {scope_file} (allowed: {sorted(allowed)})")
    window = re.search(r"Window:\s*(\S+)\s+to\s+(\S+)", text)
    if window:
        start, end = (datetime.fromisoformat(x) for x in window.groups())
        now = datetime.now()
        if not (start <= now <= end):
            sys.exit(f"[scope] REFUSED: now={now:%Y-%m-%dT%H:%M} is outside the authorized window {start} .. {end}")
    print(f"[scope] {target} authorized by {scope_file}", file=sys.stderr)


# --------------------------------------------------------------------------- #
# Scanning
# --------------------------------------------------------------------------- #
async def probe(host: str, port: int, timeout: float) -> str:
    """Probe one TCP port and return its classified outcome."""
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
    except ConnectionRefusedError:
        return "closed"                      # a RST came back
    except (asyncio.TimeoutError, TimeoutError):
        return "filtered"                    # silence: dropped, filtered or lost
    except OSError as exc:                   # e.g. EMFILE: we could not even ask
        return f"error:{errno.errorcode.get(exc.errno, exc.errno)}"
    # When the target is this very host and the port is in the ephemeral range,
    # the kernel can pick the destination port as the source port: the socket
    # then connects to ITSELF (TCP simultaneous open) although nothing listens
    # there. Local address == remote address means "no listener", not "open".
    self_connected = writer.get_extra_info("sockname")[:2] == writer.get_extra_info("peername")[:2]
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass
    return "closed" if self_connected else "open"


async def scan(host: str, ports: list[int], rate: int, timeout: float, jitter: float = 0.0) -> dict[int, str]:
    """Probe every port with at most `rate` probes in flight (asyncio.Semaphore).

    Ports are probed in random order (a sequential sweep is a trivial IDS
    signature) and an optional random delay spreads the probes in time.
    """
    semaphore = asyncio.Semaphore(rate)

    async def limited(port: int) -> tuple[int, str]:
        async with semaphore:
            if jitter > 0:
                await asyncio.sleep(random.uniform(0, jitter))
            return port, await probe(host, port, timeout)

    order = random.sample(ports, len(ports))
    return dict(await asyncio.gather(*(limited(p) for p in order)))


def build_report(target: str, results: dict[int, str], elapsed: float, args: argparse.Namespace,
                 retried: int = 0) -> dict:
    outcomes = Counter(state.split(":")[0] for state in results.values())
    errors = Counter(state.split(":", 1)[1] for state in results.values() if state.startswith("error:"))
    unknown = sorted(p for p, state in results.items() if state.startswith("error:"))
    report = {
        "target": target,
        "scan_time_seconds": round(elapsed, 3),
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "open_ports": sorted(p for p, state in results.items() if state == "open"),
        # --- extra context so that an incomplete scan cannot look complete ---
        "ports_scanned": len(results),
        "rate": args.rate,
        "timeout": args.timeout,
        "outcomes": {k: outcomes.get(k, 0) for k in ("open", "closed", "filtered", "error")},
        "errors": dict(errors),
        "filtered_ports": sorted(p for p, state in results.items() if state == "filtered")[:UNKNOWN_LIST_LIMIT],
        "unknown_ports": unknown[:UNKNOWN_LIST_LIMIT],
        "unknown_ports_truncated": len(unknown) > UNKNOWN_LIST_LIMIT,
        "unknown_retried": retried,
        "complete": not unknown,
    }
    return report


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Concurrent TCP connect port scanner (asyncio). Scan only hosts you are authorized to scan.")
    parser.add_argument("target", type=ip_address, help="IP address to scan")
    parser.add_argument("--ports", type=parse_ports, default=parse_ports("1-1024"),
                        help="port range, e.g. 1-1024 or 22,80,443 (default: 1-1024)")
    parser.add_argument("--rate", type=positive_int, default=200,
                        help="max concurrent connections (default: 200)")
    parser.add_argument("--timeout", type=float, default=0.5,
                        help="per-port timeout in seconds (default: 0.5)")
    parser.add_argument("--output", default=None, help="JSON output file (default: stdout)")
    parser.add_argument("--jitter", type=float, default=0.0,
                        help="max random delay in seconds before each probe (default: 0, no jitter)")
    parser.add_argument("--retry-unknown", action="store_true",
                        help="re-scan at low concurrency (rate 50) every port whose probe failed with an "
                             "OS error or timed out")
    parser.add_argument("--scope", default=None,
                        help="scope file; refuse to scan unless the target and the current time are authorized")
    args = parser.parse_args()

    if args.scope:
        check_scope(args.target, args.scope)

    # Every probe in flight is an open socket, i.e. a file descriptor.
    fd_limit = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
    if min(args.rate, len(args.ports)) > fd_limit - 16:
        print(f"[warning] --rate {args.rate} exceeds the soft limit of open files (ulimit -n = {fd_limit}): "
              f"probes beyond it will fail with EMFILE and their ports will be reported as unknown",
              file=sys.stderr)

    started = time.perf_counter()
    results = asyncio.run(scan(args.target, args.ports, args.rate, args.timeout, args.jitter))
    retried = 0
    if args.retry_unknown:
        unknown = [p for p, state in results.items() if state.startswith("error:") or state == "filtered"]
        if unknown:
            retried = len(unknown)
            print(f"[retry] {retried} probes failed or timed out; re-scanning them at rate 50", file=sys.stderr)
            results.update(asyncio.run(scan(args.target, unknown, min(50, args.rate), args.timeout, args.jitter)))
    elapsed = time.perf_counter() - started

    report = build_report(args.target, results, elapsed, args, retried)
    payload = json.dumps(report, indent=2)
    if args.output:
        Path(args.output).write_text(payload + "\n")
        print(f"[done] {len(report['open_ports'])} open ports on {args.target} in {elapsed:.2f}s "
              f"-> {args.output}", file=sys.stderr)
    else:
        print(payload)

    # Fail loudly: an error count > 0 means the result set is incomplete.
    if not report["complete"]:
        print(f"[WARNING] {report['outcomes']['error']} probes could not be sent {report['errors']}: "
              f"those ports are UNKNOWN, not closed. Re-scan at a lower --rate or use --retry-unknown.",
              file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
