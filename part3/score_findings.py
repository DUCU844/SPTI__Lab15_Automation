#!/usr/bin/env python3
"""Part 3 (engineer) - score the analyst's findings against planted.json.

For every planted item: was it detected? For every reported item: was it
planted (otherwise it is a false positive)? Prints a Markdown table.

    python3 part3/score_findings.py planted.json part3/analysis.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser(description="Compare the analyst's findings with what the engineer planted")
    ap.add_argument("planted")
    ap.add_argument("analysis", help="JSON written by part3/build_report.py --json")
    ap.add_argument("--label", default="")
    args = ap.parse_args()

    planted = json.loads(Path(args.planted).read_text())
    found = json.loads(Path(args.analysis).read_text())
    pa, pw, fa, fw = planted["auth"], planted["web"], found["auth"], found["web"]
    rows: list[tuple[str, str, bool, str]] = []        # (category, planted item, detected, detail)

    # ---- auth.log --------------------------------------------------------- #
    reported_ips = {x["ip"]: x["failures"] for x in fa["bruteforce_ips"]}
    for ip, info in pa["attacker_ips"].items():
        got = reported_ips.get(ip)
        ok = got == info["failures"]
        detail = f"reported {got} failures" if got is not None else "IP not reported"
        if got is not None and not ok:
            detail += f" (planted {info['failures']}: {info['failures'] - got} lines not counted)"
        rows.append(("auth: attacker IP", f"{ip} with {info['failures']} failures", ok, detail))
    rows.append(("auth: invalid-user lines", f"{pa['invalid_user_lines']} `invalid user` failures",
                 fa["invalid_user_failures"] == pa["invalid_user_lines"],
                 f"reported {fa['invalid_user_failures']}"))
    reported_users = {x["user"] for x in fa["targeted_users"]}
    for user in pa["targeted_usernames"]:
        rows.append(("auth: targeted user", f"`{user}`", user in reported_users,
                     "listed" if user in reported_users else "not listed"))
    comp = pa["successful_login_after_failures"]
    hits = [x for x in fa.get("success_after_failures", []) if x["ip"] == comp["ip"] and x["user"] == comp["user"]]
    rows.append(("auth: compromise", f"`{comp['user']}` accepted from {comp['ip']} after failures", bool(hits),
                 f"reported ({hits[0]['prior_failures']} prior failures)" if hits else "not reported"))

    # ---- access.log ------------------------------------------------------- #
    suspicious = {e["path"]: e for e in fw["suspicious_paths"]}
    for family, paths in pw["attack_paths"].items():
        for path in paths:
            entry = suspicious.get(path)
            ok = bool(entry) and family in entry["families"] \
                and entry["count"] == pw["attack_path_occurrences"][path]
            if not entry:
                detail = "not flagged"
            elif family not in entry["families"]:
                detail = f"flagged, but as {entry['families']}"
            else:
                detail = f"flagged {entry['count']}/{pw['attack_path_occurrences'][path]} requests"
            rows.append((f"web: {family}", f"`{path}`", ok, detail))
    for path in pw["probe_paths"]:
        entry = suspicious.get(path)
        rows.append(("web: probe", f"`{path}`", bool(entry), "flagged" if entry else "not flagged"))
    hours = {a["hour"]: a for a in fw["anomalies"]}
    robust = {a["hour"]: a for a in fw.get("robust_anomalies", [])}
    for name, hour, count in (("spike", pw["spike_hour"], pw["spike_requests"]),
                              ("secondary burst", pw["secondary_burst"]["hour"], pw["secondary_burst"]["requests"])):
        if hour in hours:
            ok, detail = True, f"3-sigma, z={hours[hour]['z']}"
        elif hour in robust:
            ok, detail = True, f"median/MAD, robust z={robust[hour]['robust_z']} (3-sigma z={robust[hour]['z']})"
        else:
            ok, detail = False, "not flagged"
        rows.append((f"web: {name}", f"{hour}:00 with {count} requests", ok, detail))

    # ---- false positives: reported but never planted ----------------------- #
    planted_paths = {p for paths in pw["attack_paths"].values() for p in paths} | set(pw["probe_paths"])
    false_pos = []
    for ip, n in reported_ips.items():
        if ip not in pa["attacker_ips"]:
            false_pos.append(("auth: brute-force IP", f"{ip} ({n} failures)",
                              "benign noise planted by the engineer" if ip in pa["benign_noise_failures"] else "unknown"))
    for x in fa.get("success_after_failures", []):
        if not (x["ip"] == comp["ip"] and x["user"] == comp["user"]):
            false_pos.append(("auth: compromise", f"`{x['user']}` from {x['ip']}", "not planted"))
    for path, e in suspicious.items():
        if path not in planted_paths:
            false_pos.append((f"web: {', '.join(e['families'])}", f"`{path}` ({e['count']} requests)",
                              "benign look-alike planted by the engineer" if path in pw["benign_lookalike_paths"]
                              else "not planted"))
    planted_hours = {pw["spike_hour"], pw["secondary_burst"]["hour"]}
    for hour in sorted(set(hours) | set(robust)):
        if hour not in planted_hours:
            false_pos.append(("web: anomalous hour", f"{hour}:00", "not planted"))

    detected = sum(1 for r in rows if r[2])
    print(f"### Score{': ' + args.label if args.label else ''}\n")
    print(f"**{detected}/{len(rows)} planted items detected, {len(rows) - detected} missed, "
          f"{len(false_pos)} false positive(s).**\n")
    print("| Category | Planted item | Detected | Detail |")
    print("|---|---|:---:|---|")
    for category, item, ok, detail in rows:
        print(f"| {category} | {item} | {'yes' if ok else '**NO**'} | {detail} |")
    print("\nReport items that were NOT planted (false positives):\n")
    if false_pos:
        print("| Category | Reported item | Origin |")
        print("|---|---|---|")
        for category, item, origin in false_pos:
            print(f"| {category} | {item} | {origin} |")
    else:
        print("None.")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
