#!/usr/bin/env python3
"""Part 3 C/D - access.log analysis, FIRST ITERATION (v1), kept for traceability.

Uses the log pattern, the attack regex and the 3-sigma detector exactly as given
in the theory section. findings_score.md documents what it missed and why; the
fixed analyzer is ../../log_analysis.py.
"""
from __future__ import annotations

import argparse
import json
import re
import statistics
from collections import Counter
from pathlib import Path
from urllib.parse import unquote

LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[.+?\] "(?P<method>\w+) (?P<path>\S+) \S+" '
    r'(?P<status>\d+) (?P<size>\S+)'
)
FAMILIES = {
    "sql_injection": re.compile(r"union.*select|insert.*into|drop\s+table", re.IGNORECASE),
    "path_traversal": re.compile(r"\.\./|\.\.\\"),
    "xss": re.compile(r"<script", re.IGNORECASE),
    "command_injection": re.compile(r"cmd=|exec=|shell=", re.IGNORECASE),
}
HOUR = re.compile(r"\[(\d{2}/\w+/\d{4}):(\d{2}):")


def analyze(log_path: str, sigma: float = 3.0) -> dict:
    ip_counts, status_counts, hourly = Counter(), Counter(), Counter()
    suspicious: dict[str, dict] = {}
    total = unparsed = 0
    for line in Path(log_path).open():
        total += 1
        if h := HOUR.search(line):
            hourly[h.group(2)] += 1
        m = LOG_PATTERN.match(line)
        if not m:
            unparsed += 1
            continue
        ip, status, path = m.group("ip"), m.group("status"), m.group("path")
        ip_counts[ip] += 1
        status_counts[status] += 1
        decoded = unquote(path)
        families = [name for name, rx in FAMILIES.items() if rx.search(decoded)]
        if families:
            entry = suspicious.setdefault(path, {"path": path, "decoded": decoded, "families": families,
                                                 "count": 0, "ips": Counter(), "statuses": Counter()})
            entry["count"] += 1
            entry["ips"][ip] += 1
            entry["statuses"][status] += 1

    counts = list(hourly.values())
    anomalies = []
    mean = stdev = None
    if len(counts) >= 2:
        mean, stdev = statistics.mean(counts), statistics.stdev(counts)
        if stdev > 0:
            for hour, count in sorted(hourly.items()):
                z = (count - mean) / stdev
                if z > sigma:
                    anomalies.append({"hour": hour, "count": count, "z": round(z, 2), "method": "3-sigma"})
    return {
        "total_lines": total,
        "unparsed_lines": unparsed,
        "top_ips": ip_counts.most_common(5),
        "status_distribution": dict(sorted(status_counts.items())),
        "suspicious_paths": sorted(({**e, "ips": dict(e["ips"]), "statuses": dict(e["statuses"])}
                                    for e in suspicious.values()), key=lambda e: -e["count"]),
        "suspicious_total": sum(e["count"] for e in suspicious.values()),
        "hourly": dict(sorted(hourly.items())),
        "sigma_threshold": sigma,
        "mean": round(mean, 1) if mean is not None else None,
        "stdev": round(stdev, 1) if stdev is not None else None,
        "anomalies": anomalies,
    }


def to_markdown(r: dict) -> str:
    out = ["## 4. Suspicious web requests (access.log)", "",
           f"{r['suspicious_total']} requests matched an attack pattern "
           f"({len(r['suspicious_paths'])} distinct paths).", "",
           "| Family | Requests | Source IPs | Path (as logged) |", "|---|---:|---|---|"]
    out += [f"| {', '.join(e['families'])} | {e['count']} | {', '.join(e['ips'])} | `{e['path']}` |"
            for e in r["suspicious_paths"]]
    out += ["", "## 5. Top 5 IPs by request volume", "", "| IP | Requests |", "|---|---:|"]
    out += [f"| {ip} | {n} |" for ip, n in r["top_ips"]]
    out += ["", "## 6. HTTP status code distribution", "", "| Status | Requests |", "|---|---:|"]
    out += [f"| {s} | {n} |" for s, n in r["status_distribution"].items()]
    out += ["", "## 7. Traffic anomalies (3-sigma on hourly request counts)", "",
            f"Baseline: mean={r['mean']} requests/hour, stdev={r['stdev']}.", "", "```"]
    out += [f"[ANOMALY] {a['hour']}:00 — {a['count']} requests (z≈{a['z']:.1f}σ, threshold={r['sigma_threshold']:.1f}σ)"
            for a in r["anomalies"]] or ["no anomalous hours"]
    out += ["```", ""]
    return "\n".join(out)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="access.log analysis (v1)")
    ap.add_argument("log", nargs="?", default="access.log")
    ap.add_argument("--sigma", type=float, default=3.0)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    res = analyze(a.log, a.sigma)
    print(json.dumps(res, indent=2) if a.json else to_markdown(res))
