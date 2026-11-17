#!/usr/bin/env python3
"""Handoff 3 (analyst) - compare the engineer's scan JSON files with the answer key.

    python3 part1/compare_answer_key.py --key 22,80,311,444,808 scan_rate200.json scan_rate2000.json
"""
import argparse
import json

ap = argparse.ArgumentParser()
ap.add_argument("--key", required=True, help="answer key: comma-separated open ports")
ap.add_argument("files", nargs="+")
args = ap.parse_args()
key = {int(p) for p in args.key.split(",")}

print(f"answer key: {sorted(key)}")
runs_with_miss = 0
print(f"{'file':<34}{'rate':>6}{'time(s)':>9}{'found':>7}  {'missed':<22}{'not in key':<12}{'probe errors'}")
for name in args.files:
    d = json.load(open(name))
    found = set(d["open_ports"])
    missed = sorted(key - found)
    extra = sorted(found - key)
    runs_with_miss += bool(missed)
    print(f"{name:<34}{d.get('rate', '?'):>6}{d['scan_time_seconds']:>9.3f}{len(found & key):>4}/{len(key):<2}  "
          f"{str(missed or 'none'):<22}{str(extra or 'none'):<12}"
          f"{d.get('outcomes', {}).get('error', '?')} {d.get('errors', '')}")
print(f"files with at least one known open port missed: {runs_with_miss}/{len(args.files)}")
