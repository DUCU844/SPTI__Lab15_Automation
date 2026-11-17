#!/usr/bin/env python3
"""Part 3 E - combine the outputs of auth_analysis.py and log_analysis.py into report.md.

The analyzers are imported as modules (they expose analyze() and to_markdown()),
so the report always reflects exactly what the scripts compute.

    python3 part3/build_report.py --auth part3/auth.log --access part3/access.log \
            --output part3/report.md --json part3/analysis.json
    # first iteration, kept for traceability:
    python3 part3/build_report.py --analyzers part3/v1 --auth part3/auth.log --access part3/access.log \
            --output part3/v1/report_v1.md --json part3/v1/analysis_v1.json
"""
from __future__ import annotations

import argparse
import importlib
import json
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    ap = argparse.ArgumentParser(description="Build the Part 3 report from both log analyzers")
    ap.add_argument("--auth", default="auth.log")
    ap.add_argument("--access", default="access.log")
    ap.add_argument("--output", default="report.md")
    ap.add_argument("--json", default=None, help="also write the raw findings to this JSON file")
    ap.add_argument("--analyzers", default=str(ROOT), help="directory holding auth_analysis.py / log_analysis.py")
    args = ap.parse_args()

    sys.path.insert(0, str(Path(args.analyzers).resolve()))
    auth_analysis = importlib.import_module("auth_analysis")
    log_analysis = importlib.import_module("log_analysis")

    auth = auth_analysis.analyze(args.auth)
    web = log_analysis.analyze(args.access)

    summary = [
        f"- **{len(auth['bruteforce_ips'])}** address(es) exceeded {auth['threshold']} failed SSH logins: "
        + ", ".join(f"{x['ip']} ({x['failures']})" for x in auth["bruteforce_ips"]),
        f"- **{len(auth['targeted_users'])}** user names were guessed; "
        f"{auth['invalid_user_failures']} failures were for accounts that do not exist",
        f"- Failed:successful logins = {auth['failed_total']}:{auth['successful_total']} "
        f"(**{auth['failed_to_successful_ratio']}:1**)",
    ]
    if "success_after_failures" in auth:
        hits = auth["success_after_failures"]
        summary.append("- **Possible compromise**: " + "; ".join(
            f"`{x['user']}` logged in from {x['ip']} after {x['prior_failures']} failures" for x in hits)
            if hits else "- No successful login from an address with previous failures")
    summary += [
        f"- **{web['suspicious_total']}** web requests matched an attack pattern "
        f"({len(web['suspicious_paths'])} distinct paths)",
        "- Anomalous hours: " + (", ".join(
            f"{a['hour']}:00 ({a['count']} requests)" for a in
            {a["hour"]: a for a in web["anomalies"] + web.get("robust_anomalies", [])}.values()) or "none"),
    ]

    report = "\n".join([
        "# Log analysis report (Part 3)",
        "",
        f"- Generated: {datetime.now().isoformat(timespec='seconds')}",
        f"- Inputs: `{args.auth}` ({auth['failed_total'] + auth['successful_total']} login events), "
        f"`{args.access}` ({web['total_lines']} requests)",
        f"- Analyzers: `{Path(args.analyzers).resolve().name}/auth_analysis.py`, "
        f"`{Path(args.analyzers).resolve().name}/log_analysis.py`",
        "",
        "## Summary",
        "",
        *summary,
        "",
        auth_analysis.to_markdown(auth),
        log_analysis.to_markdown(web),
    ])
    Path(args.output).write_text(report)
    if args.json:
        Path(args.json).write_text(json.dumps({"auth": auth, "web": web}, indent=2) + "\n")
    print(f"report written to {args.output}" + (f", findings to {args.json}" if args.json else ""), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
