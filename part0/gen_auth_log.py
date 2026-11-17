#!/usr/bin/env python3
"""Part 0 (engineer) - synthetic auth.log generator, adapted from the lab's Part 3 script.

What the engineer changed (and recorded in planted.json, never shown to the analyst):
  * two attacker IPs with an exact number of failures each
      - ATTACKER_WORDLIST : sprays a wordlist of user names (many do not exist)
      - ATTACKER_TARGETED : hammers a single account (root)
  * "Failed password for invalid user ..." lines for the accounts that do not exist
  * two invented user names that contain a space (sshd logs them verbatim)
  * one successful password login from the wordlist attacker AFTER its failures
  * benign noise, including an internal host that mistypes a password 12 times

Usage: python3 part0/gen_auth_log.py [--out auth.log] [--planted planted.json]
"""
import argparse
import datetime
import json
import random
from pathlib import Path

SEED = 15                                            # engineer: reproducible log
ATTACKER_WORDLIST = ("203.0.113.77", 240)            # engineer: attacker IP 1 and its failure count
ATTACKER_TARGETED = ("198.51.100.23", 85)            # engineer: attacker IP 2 and its failure count
NOISE = {"10.0.0.1": 6, "10.0.0.2": 4, "192.168.1.50": 12}   # benign hosts and their failures
EXISTING_USERS = ["root", "admin", "ubuntu", "daniel"]
INVALID_USERS = ["oracle", "test", "postgres", "guest", "backup admin", "web master"]  # do not exist
COMPROMISED = ("admin", "password")                  # account the wordlist attacker finally gets into
SUCCESSFUL_LOGINS = 20                               # legitimate key-based logins of daniel


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="auth.log")
    ap.add_argument("--planted", default="planted.json")
    args = ap.parse_args()

    rng = random.Random(SEED)
    now = datetime.datetime.now().replace(microsecond=0)
    start = now - datetime.timedelta(hours=24)
    events = []          # (timestamp, message)
    invalid_lines = 0
    space_lines = 0

    def failed(ts, user, ip):
        nonlocal invalid_lines, space_lines
        prefix = ""
        if user in INVALID_USERS:
            prefix = "invalid user "
            invalid_lines += 1
        if " " in user:
            space_lines += 1
        events.append((ts, f"Failed password for {prefix}{user} from {ip} port {rng.randint(1024, 65535)} ssh2"))

    def rand_ts(lo_seconds, hi_seconds):
        return start + datetime.timedelta(seconds=rng.randint(lo_seconds, hi_seconds))

    # Attacker 1: wordlist spraying over the whole day, then a successful login at the end
    ip, count = ATTACKER_WORDLIST
    last = start
    for _ in range(count):
        ts = rand_ts(0, 80000)
        last = max(last, ts)
        failed(ts, rng.choice(EXISTING_USERS + INVALID_USERS), ip)
    events.append((last + datetime.timedelta(seconds=7),
                   f"Accepted {COMPROMISED[1]} for {COMPROMISED[0]} from {ip} port {rng.randint(1024, 65535)} ssh2"))

    # Attacker 2: targeted guessing against root, concentrated in a 2-hour window
    ip, count = ATTACKER_TARGETED
    for _ in range(count):
        failed(rand_ts(30000, 37200), "root", ip)

    # Benign noise
    for ip, count in NOISE.items():
        for _ in range(count):
            failed(rand_ts(0, 86000), "daniel" if ip == "192.168.1.50" else rng.choice(EXISTING_USERS), ip)
    for _ in range(SUCCESSFUL_LOGINS):
        events.append((rand_ts(0, 86000),
                       f"Accepted publickey for daniel from 192.168.1.1 port {rng.randint(1024, 65535)} ssh2"))

    events.sort(key=lambda e: e[0])                   # a real log is chronological
    with open(args.out, "w") as f:
        for ts, message in events:
            f.write(f"{ts.strftime('%b %d %H:%M:%S')} kali sshd[{rng.randint(1000, 9999)}]: {message}\n")

    planted_path = Path(args.planted)
    planted = json.loads(planted_path.read_text()) if planted_path.exists() else {}
    planted["auth"] = {
        "generated": now.isoformat(),
        "seed": SEED,
        "attacker_ips": {
            ATTACKER_WORDLIST[0]: {"failures": ATTACKER_WORDLIST[1], "style": "wordlist (many user names)"},
            ATTACKER_TARGETED[0]: {"failures": ATTACKER_TARGETED[1], "style": "targeted (root only)"},
        },
        "invalid_user_lines": invalid_lines,
        "usernames_with_spaces": [u for u in INVALID_USERS if " " in u],
        "lines_with_space_usernames": space_lines,
        "targeted_usernames": EXISTING_USERS + INVALID_USERS,
        "successful_login_after_failures": {"ip": ATTACKER_WORDLIST[0], "user": COMPROMISED[0],
                                            "method": COMPROMISED[1]},
        "benign_noise_failures": NOISE,
        "total_failed": sum(1 for _, m in events if m.startswith("Failed")),
        "total_accepted": sum(1 for _, m in events if m.startswith("Accepted")),
    }
    planted_path.write_text(json.dumps(planted, indent=2) + "\n")
    print(f"{args.out}: {len(events)} lines ({planted['auth']['total_failed']} failed, "
          f"{planted['auth']['total_accepted']} accepted, {invalid_lines} 'invalid user'); planted -> {args.planted}")


if __name__ == "__main__":
    main()
