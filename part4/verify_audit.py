#!/usr/bin/env python3
"""Part 4 ("Together" step, engineer) - check audit.log against what really ran.

Two independent checks:
  1. Static : recon.py spawns processes in exactly one place, run_logged().
  2. Dynamic: recon.py is executed with tiny PATH shims in front of whois, dig,
     curl and nmap. Each shim appends its own argv to a witness file and then
     exec()s the real tool. The witness list (what really ran) must be equal,
     in order, to the RUN lines of audit.log (what the tool says it ran), and
     every RUN line must be followed by an OK/ERROR outcome.

    python3 part4/verify_audit.py 10.0.2.15
    python3 part4/verify_audit.py example.com
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ["whois", "dig", "curl", "nmap"]


def static_check() -> bool:
    source = (ROOT / "recon.py").read_text().splitlines()
    spawn_lines = [(n, line.strip()) for n, line in enumerate(source, 1)
                   if re.search(r"subprocess\.(run|Popen|call|check_output|check_call)\(|os\.(system|popen|exec\w*)\(", line)]
    start = next(n for n, line in enumerate(source, 1) if line.startswith("def run_logged("))
    end = next(n for n, line in enumerate(source, 1) if n > start and line.startswith("def "))
    print("1. Static check: where does recon.py spawn processes?")
    for n, line in spawn_lines:
        print(f"     recon.py:{n}: {line}   (inside run_logged: {start <= n < end})")
    ok = len(spawn_lines) == 1 and start <= spawn_lines[0][0] < end
    print(f"   -> {'PASS' if ok else 'FAIL'}: {len(spawn_lines)} spawn site(s); run_logged() spans lines {start}-{end - 1}\n")
    return ok


def dynamic_check(target: str) -> bool:
    work = Path(tempfile.mkdtemp(prefix="recon_audit_check_"))
    shims, witness, outdir = work / "shims", work / "witness.log", work / "out"
    shims.mkdir()
    for tool in TOOLS:
        real = shutil.which(tool)
        if not real:
            continue
        shim = shims / tool
        shim.write_text(f'#!/bin/sh\nprintf \'%s\\n\' "{tool} $*" >> "{witness}"\nexec "{real}" "$@"\n')
        shim.chmod(shim.stat().st_mode | stat.S_IXUSR)
    env = dict(os.environ, PATH=f"{shims}{os.pathsep}{os.environ['PATH']}")
    cmd = [sys.executable, str(ROOT / "recon.py"), target, "--output", str(outdir)]
    print(f"2. Dynamic check: running {' '.join(cmd[1:])} with witness shims for {', '.join(TOOLS)}")
    proc = subprocess.run(cmd, env=env, capture_output=True, text=True)
    print(f"     recon.py exit code: {proc.returncode}")

    ran = witness.read_text().splitlines() if witness.exists() else []
    audit_lines = (outdir / "audit.log").read_text().splitlines()
    logged = [m.group(1) for line in audit_lines if (m := re.match(r"\S+ RUN\s+(.*)$", line))]
    # shlex.join may quote an argument; the shim records it unquoted
    logged_plain = [re.sub(r"'([^']*)'", r"\1", c) for c in logged]
    outcomes = [m.group(1) for line in audit_lines if (m := re.match(r"\S+ (OK|ERROR)\s", line))]

    print(f"\n     {'#':>2}  {'really executed (witness)':<62} logged in audit.log")
    ok = True
    for i in range(max(len(ran), len(logged_plain))):
        a = ran[i] if i < len(ran) else "(nothing)"
        b = logged_plain[i] if i < len(logged_plain) else "(nothing)"
        same = a == b
        ok &= same
        print(f"     {i + 1:>2}  {a[:60]:<62} {'yes' if same else 'MISMATCH: ' + b}")
    print(f"\n     commands really executed: {len(ran)} | RUN lines in audit.log: {len(logged)} | "
          f"outcome lines (OK/ERROR): {len(outcomes)}")
    ok &= len(ran) == len(logged) == len(outcomes) and len(ran) > 0
    print(f"   -> {'PASS' if ok else 'FAIL'}: every executed command is in audit.log, every audit entry "
          f"corresponds to a command that ran, and each has an outcome\n     (work dir: {work})")
    return ok


def main() -> int:
    ap = argparse.ArgumentParser(description="Verify that recon.py's audit.log matches the commands that really ran")
    ap.add_argument("target", help="IP address or domain (same rules as recon.py: authorized targets only)")
    args = ap.parse_args()
    results = [static_check(), dynamic_check(args.target)]
    print("\nAUDIT VERIFICATION:", "PASS" if all(results) else "FAIL")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
