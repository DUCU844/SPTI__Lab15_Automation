#!/usr/bin/env python3
"""Part 1 A/B - sequential vs ThreadPoolExecutor vs asyncio scanners.

The three implementations below are the "naive" ones from the lab statement:
they collapse every failure (refused, timeout, OS error) into "not open".
That is exactly what lets us measure false negatives: for every run we compare
the ports found against the analyst's answer key (--expect).

Usage:
    python3 part1/benchmark.py 10.0.2.15 --expect 22,80,311,444,808
    python3 part1/benchmark.py 10.0.2.15 --expect 22,80,311,444,808 --ports 1-65535 --skip-sequential
"""
from __future__ import annotations

import argparse
import asyncio
import json
import socket
import statistics
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


# ------------------------------ A. sequential ------------------------------ #
def scan_port(host: str, port: int, timeout: float = 1.0) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            s.connect((host, port))
            return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False


def scan_sequential(host: str, ports: list[int], timeout: float) -> list[int]:
    return [p for p in ports if scan_port(host, p, timeout)]


# --------------------------- A. ThreadPoolExecutor -------------------------- #
def scan_port_thread(args: tuple[str, int, float]) -> int | None:
    host, port, timeout = args
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            return port
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None          # "I could not ask" silently becomes "the answer is no"


def scan_threaded(host: str, ports: list[int], timeout: float, max_workers: int) -> list[int]:
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = executor.map(scan_port_thread, [(host, p, timeout) for p in ports])
        return sorted(p for p in results if p is not None)


# ------------------------- B. asyncio + Semaphore --------------------------- #
async def scan_port_async(host: str, port: int, timeout: float) -> int | None:
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return port
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None


async def scan_async(host: str, ports: list[int], timeout: float, max_concurrent: int) -> list[int]:
    semaphore = asyncio.Semaphore(max_concurrent)

    async def limited(port: int) -> int | None:
        async with semaphore:
            return await scan_port_async(host, port, timeout)

    results = await asyncio.gather(*[limited(p) for p in ports])
    return sorted(p for p in results if p is not None)


# -------------------------------- harness ---------------------------------- #
def parse_ports(spec: str) -> list[int]:
    ports: set[int] = set()
    for chunk in spec.split(","):
        if "-" in chunk:
            low, high = chunk.split("-", 1)
            ports.update(range(int(low), int(high) + 1))
        elif chunk.strip():
            ports.add(int(chunk))
    return sorted(ports)


def measure(label: str, concurrency, fn, repeats: int, expected: set[int]) -> dict:
    times, found_sets = [], []
    for _ in range(repeats):
        start = time.perf_counter()
        found = fn()
        times.append(time.perf_counter() - start)
        found_sets.append(set(found))
        time.sleep(0.5)                       # let sockets in TIME_WAIT settle between runs
    worst = min(found_sets, key=lambda s: len(s & expected))
    row = {
        "version": label,
        "concurrency": concurrency,
        "runs": repeats,
        "median_seconds": round(statistics.median(times), 3),
        "min_seconds": round(min(times), 3),
        "max_seconds": round(max(times), 3),
        "found_min": min(len(s & expected) for s in found_sets),
        "found_max": max(len(s & expected) for s in found_sets),
        "expected": len(expected),
        "missed_worst_run": sorted(expected - worst),
        "unexpected": sorted(set().union(*found_sets) - expected),
    }
    print(f"  {label:<12} conc={str(concurrency):<5} median={row['median_seconds']:>7.3f}s "
          f"found={row['found_min']}-{row['found_max']}/{row['expected']} missed={row['missed_worst_run']}",
          file=sys.stderr)
    return row


def to_markdown(rows: list[dict], host: str, nports: int) -> str:
    lines = [
        f"| Version | Concurrency | Median time (s) | Min-max (s) | Known open ports found | Missed (worst run) |",
        f"|---|---:|---:|---:|---:|---|",
    ]
    for r in rows:
        found = f"{r['found_min']}/{r['expected']}" if r["found_min"] == r["found_max"] \
            else f"{r['found_min']}-{r['found_max']}/{r['expected']}"
        missed = ", ".join(map(str, r["missed_worst_run"])) or "none"
        lines.append(f"| {r['version']} | {r['concurrency']} | {r['median_seconds']:.3f} | "
                     f"{r['min_seconds']:.3f}-{r['max_seconds']:.3f} | {found} | {missed} |")
    return f"Target {host}, {nports} ports, {rows[0]['runs'] if rows else 0} runs per row.\n\n" + "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description="Benchmark sequential / threaded / asyncio scanners")
    ap.add_argument("target")
    ap.add_argument("--ports", default="1-1024")
    ap.add_argument("--expect", required=True, help="answer key: comma-separated open ports")
    ap.add_argument("--levels", default="50,200,500,2000", help="concurrency levels to test")
    ap.add_argument("--timeout", type=float, default=0.5)
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--skip-sequential", action="store_true")
    ap.add_argument("--json", default=None, help="write raw rows to this JSON file")
    ap.add_argument("--markdown", default=None, help="write the table to this Markdown file")
    args = ap.parse_args()

    ports = parse_ports(args.ports)
    expected = set(parse_ports(args.expect))
    levels = [int(x) for x in args.levels.split(",")]
    host = args.target
    rows = []

    print(f"Benchmark against {host}, ports {args.ports} ({len(ports)} ports), answer key {sorted(expected)}",
          file=sys.stderr)
    if not args.skip_sequential:
        rows.append(measure("sequential", 1, lambda: scan_sequential(host, ports, 1.0), args.repeats, expected))
    for n in levels:
        rows.append(measure("threads", n, lambda n=n: scan_threaded(host, ports, args.timeout, n),
                            args.repeats, expected))
    for n in levels:
        rows.append(measure("asyncio", n, lambda n=n: asyncio.run(scan_async(host, ports, args.timeout, n)),
                            args.repeats, expected))

    table = to_markdown(rows, host, len(ports))
    print()
    print(table)
    if args.json:
        Path(args.json).write_text(json.dumps(rows, indent=2) + "\n")
    if args.markdown:
        Path(args.markdown).write_text(table)
    return 0


if __name__ == "__main__":
    sys.exit(main())
