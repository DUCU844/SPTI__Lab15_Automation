#!/usr/bin/env python3
"""Part 0 (engineer) - synthetic access.log generator, adapted from the lab's Part 3 script.

What the engineer changed (and recorded in planted.json, never shown to the analyst):
  * the hour of the traffic spike (SPIKE_HOUR) and a second, smaller burst (BURST_HOUR)
  * at least one request of each attack family, percent-encoded, plus harder variants:
    double encoding, payloads without the obvious keyword, and one raw payload with spaces
  * two reconnaissance probes (no payload) and one benign look-alike request

Usage: python3 part0/gen_access_log.py [--out access.log] [--planted planted.json]
"""
import argparse
import datetime
import json
import random
from collections import Counter
from pathlib import Path

SEED = 15
SPIKE_HOUR, SPIKE_REQUESTS = 19, 950                 # engineer: hour of the anomalous spike
BURST_HOUR, BURST_REQUESTS = 4, 320                  # engineer: second, smaller burst
ATTACKERS = ["203.0.113.77", "198.51.100.23"]        # same addresses as in auth.log
ips = ["10.0.0.1", "203.0.113.77", "198.51.100.23", "66.249.66.1", "192.168.1.50"]
normal_paths = ["/", "/index.html", "/about", "/contact", "/static/main.css"]
benign_lookalike = ["/search?q=trade%20union%20select%20committee"]   # legitimate search, looks like SQLi

attack_paths = {       # engineer: every attack family, percent-encoded
    "sql_injection": [
        "/?id=1%27%20UNION%20SELECT%201,2,3--",
        "/login?user=admin%27%20OR%20%271%27%3D%271",
        "/item?id=5 UNION SELECT username,password FROM users--",        # raw spaces, not encoded
    ],
    "path_traversal": [
        "/download?file=..%2F..%2F..%2Fetc%2Fpasswd",
        "/static/%252e%252e%252f%252e%252e%252fetc%252fshadow",           # double encoded
    ],
    "xss": [
        "/search?q=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E",
        "/comment?text=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E",         # no <script> tag
    ],
    "command_injection": [
        "/cgi-bin/status.cgi?cmd=cat%20%2Fetc%2Fpasswd",
        "/ping?host=127.0.0.1%3Bcat%20%2Fetc%2Fpasswd",                   # no cmd= parameter
    ],
}
probe_paths = ["/wp-admin/", "/.env"]                # reconnaissance, no payload


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="access.log")
    ap.add_argument("--planted", default="planted.json")
    args = ap.parse_args()

    rng = random.Random(SEED)
    now = datetime.datetime.now()
    attacks = [p for family in attack_paths.values() for p in family] + probe_paths
    paths = normal_paths + benign_lookalike + attacks
    weights = [20] * len(normal_paths) + [2] * len(benign_lookalike) + [1] * len(attacks)
    seen = Counter()
    hourly = {}

    with open(args.out, "w") as f:
        for hour in range(24):
            count = rng.randint(80, 120)
            if hour == SPIKE_HOUR:
                count = SPIKE_REQUESTS
            elif hour == BURST_HOUR:
                count = BURST_REQUESTS
            hourly[f"{hour:02d}"] = count
            lines = []
            for _ in range(count):
                path = rng.choices(paths, weights=weights)[0]
                if path in attacks:
                    ip = rng.choice(ATTACKERS)                       # attacks come from the attackers
                elif hour == SPIKE_HOUR:
                    ip = rng.choices(ips, weights=[10, 70, 5, 10, 5])[0]   # the spike is attacker 1
                elif hour == BURST_HOUR:
                    ip = rng.choices(ips, weights=[10, 5, 70, 10, 5])[0]   # the burst is attacker 2
                else:
                    ip = rng.choices(ips, weights=[30, 5, 5, 10, 3])[0]
                status = 200 if path not in attacks else rng.choice([200, 403, 500])
                ts = now.replace(hour=hour, minute=rng.randint(0, 59), second=rng.randint(0, 59))
                seen[path] += 1
                lines.append((ts, f'{ip} - - [{ts.strftime("%d/%b/%Y:%H:%M:%S")} -0500] '
                                  f'"GET {path} HTTP/1.1" {status} {rng.randint(200, 5000)}\n'))
            for _, line in sorted(lines):
                f.write(line)

    missing = [p for p in attacks if seen[p] == 0]
    if missing:                                       # fail loudly: every planted item must be in the log
        raise SystemExit(f"planted paths missing from the log, change SEED: {missing}")

    planted_path = Path(args.planted)
    planted = json.loads(planted_path.read_text()) if planted_path.exists() else {}
    planted["web"] = {
        "generated": now.isoformat(timespec="seconds"),
        "seed": SEED,
        "spike_hour": f"{SPIKE_HOUR:02d}",
        "spike_requests": SPIKE_REQUESTS,
        "secondary_burst": {"hour": f"{BURST_HOUR:02d}", "requests": BURST_REQUESTS},
        "attack_paths": attack_paths,
        "attack_path_occurrences": {p: seen[p] for p in attacks},
        "probe_paths": probe_paths,
        "benign_lookalike_paths": benign_lookalike,
        "attacker_ips": ATTACKERS,
        "total_requests": sum(hourly.values()),
    }
    planted_path.write_text(json.dumps(planted, indent=2) + "\n")
    print(f"{args.out}: {sum(hourly.values())} requests, spike at {SPIKE_HOUR:02d}:00 ({SPIKE_REQUESTS}), "
          f"burst at {BURST_HOUR:02d}:00 ({BURST_REQUESTS}), {sum(seen[p] for p in attacks)} attack/probe requests; "
          f"planted -> {args.planted}")


if __name__ == "__main__":
    main()
