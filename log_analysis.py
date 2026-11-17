#!/usr/bin/env python3
"""Part 3 C/D - web access log analysis and anomaly detection.

Reads an access log (Common/Combined Log Format) and reports:
  * requests matching SQL injection, path traversal, XSS or command injection
    patterns, plus probes for sensitive paths (a pattern match is triage, not a
    verdict: every hit needs a human or a second signal)
  * top 5 IPs by request volume
  * HTTP status code distribution
  * anomalous hours: 3-sigma on hourly counts, and a robust median/MAD detector
    that is not contaminated by the spike it is trying to find

Standard library only.
    python3 log_analysis.py part3/access.log
    python3 log_analysis.py part3/access.log --sigma 3 --json
"""
from __future__ import annotations

import argparse
import json
import re
import statistics
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import unquote

# The request is everything between the method and the trailing " HTTP/x.y", so
# a raw (unencoded) payload that contains spaces no longer breaks the match.
LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<day>\d{2}/\w+/\d{4}):(?P<hour>\d{2}):[^\]]*\] '
    r'"(?P<method>[A-Z]+) (?P<path>.*?) HTTP/[\d.]+" (?P<status>\d{3}) (?P<size>\S+)'
)

# Attack families: the regex from the theory section, extended.
FAMILIES = {
    "sql_injection": re.compile(
        r"union\b.{0,40}\bselect\b|insert\s+into|drop\s+table|\bselect\b.{1,80}\bfrom\b"
        r"|['\"]\s*(?:or|and)\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+"      # ' OR '1'='1
        r"|\b(?:or|and)\s+\d+\s*=\s*\d+"                               # OR 1=1
        r"|\b(?:sleep|benchmark|pg_sleep)\s*\(|waitfor\s+delay|information_schema",
        re.IGNORECASE),
    "path_traversal": re.compile(
        r"\.\.[/\\]"                                                   # ../  ..\
        r"|(?:^|[=/\s])/?etc/(?:passwd|shadow)\b|proc/self/environ|win\.ini",
        re.IGNORECASE),
    "xss": re.compile(
        r"<\s*script|<\s*(?:svg|iframe|img|body)\b[^>]*\bon\w+\s*=|\bon(?:error|load|click|mouseover|focus)\s*="
        r"|javascript:",
        re.IGNORECASE),
    "command_injection": re.compile(
        r"\b(?:cmd|exec|shell|command)="
        r"|[;|&`]\s*(?:cat|id|whoami|uname|ls|wget|curl|nc|bash|sh|ping|python\d?)\b"   # ;cat  |id
        r"|\$\([^)]*\)|`[^`]+`",                                                        # $(id)  `id`
        re.IGNORECASE),
    "sensitive_path_probe": re.compile(
        r"^/(?:wp-admin|wp-login\.php|phpmyadmin|\.env|\.git(?:/|$)|server-status|admin/config)",
        re.IGNORECASE),
}


def decode(path: str, rounds: int = 3) -> str:
    """Undo percent-encoding repeatedly (attackers double-encode to evade filters).

    '+' means space only inside the query string. SQL comments used as
    whitespace (UNION/**/SELECT) are replaced by a space.
    """
    base, sep, query = path.partition("?")
    text = base + sep + query.replace("+", " ")
    for _ in range(rounds):
        decoded = unquote(text)
        if decoded == text:
            break
        text = decoded
    return re.sub(r"/\*.*?\*/", " ", text)


def classify(path: str) -> tuple[str, list[str]]:
    decoded = decode(path)
    return decoded, [name for name, rx in FAMILIES.items() if rx.search(decoded)]


def detect_anomalies(hourly: dict[str, int], sigma: float = 3.0, robust_threshold: float = 3.5) -> dict:
    """3-sigma detector plus a robust (median / MAD) detector on hourly counts."""
    counts = list(hourly.values())
    out = {"sigma_threshold": sigma, "robust_threshold": robust_threshold, "mean": None, "stdev": None,
           "median": None, "mad": None, "max_attainable_z": None, "anomalies": [], "robust_anomalies": []}
    n = len(counts)
    if n < 2:
        return out
    mean, stdev = statistics.mean(counts), statistics.stdev(counts)
    median = statistics.median(counts)
    mad = statistics.median(abs(c - median) for c in counts)
    out.update(mean=round(mean, 1), stdev=round(stdev, 1), median=median, mad=mad,
               max_attainable_z=round((n - 1) / n ** 0.5, 2))      # limit for a single outlier among n samples
    for hour, count in sorted(hourly.items()):
        z = (count - mean) / stdev if stdev else 0.0
        robust_z = 0.6745 * (count - median) / mad if mad else 0.0
        if z > sigma:
            out["anomalies"].append({"hour": hour, "count": count, "z": round(z, 2), "method": "3-sigma"})
        if robust_z > robust_threshold:
            out["robust_anomalies"].append({"hour": hour, "count": count, "robust_z": round(robust_z, 1),
                                            "z": round(z, 2), "method": "median/MAD"})
    return out


def analyze(log_path: str, sigma: float = 3.0, robust_threshold: float = 3.5) -> dict:
    ip_counts, status_counts, hourly = Counter(), Counter(), Counter()
    suspicious: dict[str, dict] = {}
    total = unparsed = 0
    days = set()

    for line in Path(log_path).open(errors="replace"):           # streamed line by line
        total += 1
        m = LOG_PATTERN.match(line)
        if not m:
            unparsed += 1                                         # counted and reported, never hidden
            continue
        ip, status, path = m.group("ip"), m.group("status"), m.group("path")
        ip_counts[ip] += 1
        status_counts[status] += 1
        days.add(m.group("day"))
        hourly[m.group("hour")] += 1
        decoded, families = classify(path)
        if families:
            entry = suspicious.setdefault(path, {"path": path, "decoded": decoded, "families": families,
                                                 "count": 0, "ips": Counter(), "statuses": Counter()})
            entry["count"] += 1
            entry["ips"][ip] += 1
            entry["statuses"][status] += 1

    result = {
        "total_lines": total,
        "unparsed_lines": unparsed,
        "days": sorted(days),
        "top_ips": ip_counts.most_common(5),
        "status_distribution": dict(sorted(status_counts.items())),
        "suspicious_paths": sorted(({**e, "ips": dict(e["ips"].most_common()), "statuses": dict(sorted(e["statuses"].items()))}
                                    for e in suspicious.values()), key=lambda e: (-e["count"], e["path"])),
        "suspicious_total": sum(e["count"] for e in suspicious.values()),
        "suspicious_by_family": dict(Counter(f for e in suspicious.values() for f in e["families"]
                                             for _ in range(e["count"])).most_common()),
        "suspicious_by_ip": dict(Counter({ip: sum(e["ips"].get(ip, 0) for e in suspicious.values())
                                          for ip in ip_counts}).most_common(5)),
        "hourly": dict(sorted(hourly.items())),
    }
    result.update(detect_anomalies(result["hourly"], sigma, robust_threshold))
    return result


def anomaly_lines(r: dict) -> list[str]:
    lines = [f"[ANOMALY] {a['hour']}:00 — {a['count']} requests (z≈{a['z']:.1f}σ, threshold={r['sigma_threshold']:.1f}σ)"
             for a in r["anomalies"]]
    flagged = {a["hour"] for a in r["anomalies"]}
    for a in r["robust_anomalies"]:
        if a["hour"] not in flagged:
            lines.append(f"[ANOMALY-ROBUST] {a['hour']}:00 — {a['count']} requests (robust z≈{a['robust_z']:.1f}, "
                         f"threshold={r['robust_threshold']:.1f}; only z≈{a['z']:.1f}σ on the global baseline)")
    return lines or ["no anomalous hours"]


def to_markdown(r: dict) -> str:
    out = ["## 5. Suspicious web requests (access.log)", "",
           f"{r['suspicious_total']} of {r['total_lines'] - r['unparsed_lines']} requests matched an attack pattern "
           f"({len(r['suspicious_paths'])} distinct paths). Paths are percent-decoded (up to 3 rounds) before "
           f"matching. A match is triage, not a verdict.", "",
           "| Family | Requests | Source IPs | Statuses | Path as logged | Decoded |", "|---|---:|---|---|---|---|"]
    for e in r["suspicious_paths"]:
        ips = ", ".join(f"{ip} ({n})" for ip, n in e["ips"].items())
        statuses = ", ".join(f"{s}×{n}" for s, n in e["statuses"].items())
        out.append(f"| {', '.join(e['families'])} | {e['count']} | {ips} | {statuses} | `{e['path']}` | `{e['decoded']}` |")
    out += ["", "Requests per family: " + ", ".join(f"{k}: {v}" for k, v in r["suspicious_by_family"].items()),
            "", "Suspicious requests per source IP: " + ", ".join(f"{k}: {v}" for k, v in r["suspicious_by_ip"].items() if v),
            "", "## 6. Top 5 IPs by request volume", "", "| IP | Requests |", "|---|---:|"]
    out += [f"| {ip} | {n} |" for ip, n in r["top_ips"]]
    out += ["", "## 7. HTTP status code distribution", "", "| Status | Requests |", "|---|---:|"]
    out += [f"| {s} | {n} |" for s, n in r["status_distribution"].items()]
    if r["unparsed_lines"]:
        out += ["", f"WARNING: {r['unparsed_lines']} lines did not match the log format (results are incomplete)."]
    out += ["", "## 8. Traffic anomalies (hourly request counts)", "",
            f"- Global baseline: mean = {r['mean']} requests/hour, stdev = {r['stdev']} "
            f"({len(r['hourly'])} hourly samples; the largest z-score a single outlier can reach with this many "
            f"samples is {r['max_attainable_z']})",
            f"- Robust baseline: median = {r['median']}, MAD = {r['mad']}", "", "```"]
    out += anomaly_lines(r)
    out += ["```", "", "| Hour | Requests |", "|---|---:|"]
    out += [f"| {h}:00 | {n} |" for h, n in r["hourly"].items()]
    out.append("")
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description="Web access log analysis: attack patterns, top IPs, statuses, anomalies")
    ap.add_argument("log", nargs="?", default="access.log", help="path to the access log (default: access.log)")
    ap.add_argument("--sigma", type=float, default=3.0, help="z-score threshold of the 3-sigma detector (default 3.0)")
    ap.add_argument("--robust-threshold", type=float, default=3.5,
                    help="threshold of the robust median/MAD detector (default 3.5)")
    ap.add_argument("--json", action="store_true", help="print JSON instead of Markdown")
    args = ap.parse_args()
    try:
        result = analyze(args.log, args.sigma, args.robust_threshold)
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2) if args.json else to_markdown(result))
    return 2 if result["unparsed_lines"] else 0


if __name__ == "__main__":
    sys.exit(main())
