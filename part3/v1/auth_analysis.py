#!/usr/bin/env python3
"""Part 3 A - auth.log analysis, FIRST ITERATION (v1), kept for traceability.

This is the analyzer the analyst ran before the engineer scored it. It uses the
pattern from the theory section. findings_score.md documents what it missed and
why; the fixed analyzer is ../../auth_analysis.py.
"""
from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path

AUTH_FAIL = re.compile(
    r"Failed password for (?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)
AUTH_OK = re.compile(r"Accepted \S+ for (?P<user>\S+) from (?P<ip>\S+)")


def analyze(log_path: str, threshold: int = 10) -> dict:
    fails_by_ip, fails_by_user = Counter(), Counter()
    invalid_users, invalid_lines, accepted = set(), 0, 0
    for line in Path(log_path).open():
        if m := AUTH_FAIL.search(line):
            fails_by_ip[m.group("ip")] += 1
            fails_by_user[m.group("user")] += 1
            if m.group("invalid"):
                invalid_lines += 1
                invalid_users.add(m.group("user"))
        elif AUTH_OK.search(line):
            accepted += 1
    failed = sum(fails_by_ip.values())
    return {
        "threshold": threshold,
        "failed_total": failed,
        "successful_total": accepted,
        "failed_to_successful_ratio": round(failed / accepted, 2) if accepted else None,
        "bruteforce_ips": [{"ip": ip, "failures": n} for ip, n in fails_by_ip.most_common() if n > threshold],
        "targeted_users": [{"user": u, "failures": n, "invalid": u in invalid_users}
                           for u, n in fails_by_user.most_common()],
        "invalid_user_failures": invalid_lines,
    }


def to_markdown(r: dict) -> str:
    out = ["## 1. SSH brute-force sources (auth.log)", "",
           f"IPs with more than {r['threshold']} failed logins, sorted by attempts:", "",
           "| IP | Failed attempts |", "|---|---:|"]
    out += [f"| {x['ip']} | {x['failures']} |" for x in r["bruteforce_ips"]]
    out += ["", "## 2. Targeted user accounts", "", "| User | Failed attempts | Account exists? |", "|---|---:|---|"]
    out += [f"| `{x['user']}` | {x['failures']} | {'no (invalid user)' if x['invalid'] else 'yes'} |"
            for x in r["targeted_users"]]
    out += ["", f"Failed logins for nonexistent accounts (`invalid user`): {r['invalid_user_failures']}", "",
            "## 3. Failed vs successful logins", "",
            f"- Failed: {r['failed_total']}", f"- Successful: {r['successful_total']}",
            f"- Ratio failed:successful = {r['failed_to_successful_ratio']}:1", ""]
    return "\n".join(out)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="auth.log analysis (v1)")
    ap.add_argument("log", nargs="?", default="auth.log")
    ap.add_argument("--threshold", type=int, default=10)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    res = analyze(a.log, a.threshold)
    print(json.dumps(res, indent=2) if a.json else to_markdown(res))
