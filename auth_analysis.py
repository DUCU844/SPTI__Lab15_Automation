#!/usr/bin/env python3
"""Part 3 A - SSH authentication log analysis (brute-force detection).

Reads an sshd auth log and reports:
  1. IPs with more than --threshold failed logins, sorted by attempts, with the
     number of distinct user names each one tried (wordlist vs targeted attack)
  2. the user accounts being targeted ("invalid user" is optional in the pattern)
  3. the ratio of failed to successful logins
  4. successful logins from an address that previously produced failures
     (the highest-value finding: the guessing may have worked)

Standard library only.
    python3 auth_analysis.py part3/auth.log
    python3 auth_analysis.py part3/auth.log --threshold 10 --json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

# "invalid user " is optional. The user name is matched greedily up to the LAST
# " from <ip> port <n>" of the line, so names containing spaces (or even the
# word "from") are captured whole instead of silently dropping the line.
AUTH_FAIL = re.compile(
    r"Failed password for (?P<invalid>invalid user )?(?P<user>.+) "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+"
)
AUTH_OK = re.compile(
    r"Accepted (?P<method>\S+) for (?P<user>.+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+"
)


def analyze(log_path: str, threshold: int = 10) -> dict:
    fails_by_ip: Counter = Counter()
    fails_by_user: Counter = Counter()
    users_by_ip: dict[str, set] = defaultdict(set)
    invalid_users: set = set()
    invalid_lines = accepted = unparsed_failed = 0
    success_after_failures = []

    for line in Path(log_path).open(errors="replace"):          # streamed line by line
        if m := AUTH_FAIL.search(line):
            ip, user = m.group("ip"), m.group("user")
            fails_by_ip[ip] += 1
            fails_by_user[user] += 1
            users_by_ip[ip].add(user)
            if m.group("invalid"):
                invalid_lines += 1
                invalid_users.add(user)
        elif "Failed password" in line:
            unparsed_failed += 1                                # never drop a line silently
        elif m := AUTH_OK.search(line):
            accepted += 1
            prior = fails_by_ip.get(m.group("ip"), 0)           # the log is chronological
            if prior:
                success_after_failures.append({"ip": m.group("ip"), "user": m.group("user"),
                                               "method": m.group("method"), "prior_failures": prior})

    failed = sum(fails_by_ip.values())
    bruteforce = []
    for ip, n in fails_by_ip.most_common():
        if n > threshold:
            distinct = len(users_by_ip[ip])
            style = f"targeted (only `{next(iter(users_by_ip[ip]))}`)" if distinct == 1 \
                else f"wordlist ({distinct} user names)"
            bruteforce.append({"ip": ip, "failures": n, "distinct_users": distinct, "style": style})
    return {
        "threshold": threshold,
        "failed_total": failed,
        "successful_total": accepted,
        "failed_to_successful_ratio": round(failed / accepted, 2) if accepted else None,
        "bruteforce_ips": bruteforce,
        "targeted_users": [{"user": u, "failures": n, "invalid": u in invalid_users}
                           for u, n in fails_by_user.most_common()],
        "invalid_user_failures": invalid_lines,
        "success_after_failures": success_after_failures,
        "unparsed_failed_lines": unparsed_failed,
    }


def to_markdown(r: dict) -> str:
    out = ["## 1. SSH brute-force sources (auth.log)", "",
           f"IPs with more than {r['threshold']} failed logins, sorted by attempts:", "",
           "| IP | Failed attempts | Distinct user names | Attack style |", "|---|---:|---:|---|"]
    out += [f"| {x['ip']} | {x['failures']} | {x['distinct_users']} | {x['style']} |" for x in r["bruteforce_ips"]]
    if not r["bruteforce_ips"]:
        out.append("| (none) | | | |")
    out += ["", "## 2. Targeted user accounts", "",
            "| User | Failed attempts | Account exists? |", "|---|---:|---|"]
    out += [f"| `{x['user']}` | {x['failures']} | {'no (`invalid user`)' if x['invalid'] else 'yes'} |"
            for x in r["targeted_users"]]
    out += ["", f"Failed logins for nonexistent accounts (`invalid user` lines): **{r['invalid_user_failures']}**", "",
            "## 3. Failed vs successful logins", "",
            f"- Failed: **{r['failed_total']}**", f"- Successful: **{r['successful_total']}**",
            f"- Ratio failed:successful = **{r['failed_to_successful_ratio']}:1**"]
    if r["unparsed_failed_lines"]:
        out.append(f"- WARNING: {r['unparsed_failed_lines']} `Failed password` lines did not match the pattern "
                   f"(results are incomplete)")
    out += ["", "## 4. Successful logins after failures (possible compromise)", ""]
    if r["success_after_failures"]:
        out += ["| IP | Account | Method | Failures before the success |", "|---|---|---|---:|"]
        out += [f"| {x['ip']} | `{x['user']}` | {x['method']} | {x['prior_failures']} |"
                for x in r["success_after_failures"]]
        out += ["", "A success right after a run of failures from the same address may mean the guessing worked: "
                    "treat the account as compromised until proven otherwise."]
    else:
        out.append("None: no address with failed logins ever logged in successfully.")
    out.append("")
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description="SSH auth log analysis: brute-force sources, targeted users, ratio")
    ap.add_argument("log", nargs="?", default="auth.log", help="path to the auth log (default: auth.log)")
    ap.add_argument("--threshold", type=int, default=10,
                    help="report IPs with MORE than this many failed logins (default: 10)")
    ap.add_argument("--json", action="store_true", help="print JSON instead of Markdown")
    args = ap.parse_args()
    try:
        result = analyze(args.log, args.threshold)
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2) if args.json else to_markdown(result))
    return 2 if result["unparsed_failed_lines"] else 0


if __name__ == "__main__":
    sys.exit(main())
