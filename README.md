# Lab 15 — Automation: reconnaissance and log-analysis toolkit

Team: **Gutiérrez – Ducuara**. A two-role lab: a *scanner engineer* builds the scanning and enrichment half, a
*log analyst* builds the log-analysis half, and both merge their work into `recon.py`.

> **Scope and authorization.** Everything scanned in this lab is one address, `10.0.2.15`, the analyst's own
> Kali Linux VM, inside the time window written in [`scope.txt`](scope.txt). `scanner.py --scope scope.txt`
> refuses any other target or any run outside that window. Domain mode of `recon.py` only issues public
> look-ups (`whois`, `dig`, one `curl -I`) and was run against `example.com`, the domain reserved for documentation.

> **Environment note.** The pair worked on a single Kali VM (VirtualBox NAT, `10.0.2.15`), so the scanner ran on
> the same host it was scanning. That shapes several results below: closed ports answer in microseconds, a
> sequential scan is already fast, and two artefacts of scanning oneself showed up and are documented
> (a TCP self-connection false positive, and nmap labelling closed ports as `filtered`).

---

## 1. Requirements

- **Python 3.10+** (developed and run on Python 3.14.7, Kali Linux 2026.2).
- **No Python dependencies beyond the standard library.** There is nothing to `pip install`.
- External command-line tools, all preinstalled on Kali: `nmap` (7.99 used), `ssh-keyscan`, `whois`, `dig`, `curl`, `git`.
- `sudo` is needed **only** to prepare the target in Part 0 (listeners on ports < 1024, `systemctl start ssh`).
  No script in this repository has to be run as root: `scanner.py` is a TCP connect scanner and unprivileged
  `nmap -sV` falls back to a connect scan.

## 2. Repository layout

```
├── scanner.py              # Part 1: concurrent port scanner (asyncio + Semaphore, argparse, JSON)
├── parse_scan.py           # Part 2: nmap XML parser and ssh-keyscan enricher
├── auth_analysis.py        # Part 3: auth log analysis
├── log_analysis.py         # Part 3: web log analysis + anomaly detection
├── recon.py                # Part 4: integrated tool (single file)
├── scope.txt               # Part 0: authorized target and time window
├── planted.json            # Part 0: what the engineer planted in the logs
├── findings_score.md       # Part 3: planted items versus report, misses and fixes
├── scan_rate200.json       # Part 1: scan at --rate 200
├── scan_rate2000.json      # Part 1: scan at --rate 2000
├── sample_output/          # Part 4: one run of recon.py in IP mode (10.0.2.15) ...
│   ├── results.json
│   ├── report.md
│   ├── audit.log
│   ├── raw/                #   raw output of every command, nmap.xml
│   └── domain_mode/        #   ... and one run in domain mode (example.com): same four items
├── README.md
│
├── part0/                  # start_target.sh (SSH + listeners), log generators, analyst's answer key
├── part1/                  # benchmark.py (sequential / threads / asyncio), result tables, full-range scans
├── part2/                  # scan.xml, hosts.json, sshd journal of the target during the scans
├── part3/                  # auth.log, access.log, report.md, build_report.py, score_findings.py, v1/ (first iteration)
├── part4/                  # verify_audit.py and its two outputs
└── evidencias/             # screenshots of every step, taken inside Kali (index in evidencias/README.md)
```

## 3. How to run each script

```bash
# Part 0 - analyst prepares the target (the only step that needs sudo)
sudo bash part0/start_target.sh 311 444 808          # SSH + three http.server listeners, each in an empty dir
touch /tmp/lab15_target/STOP                         # stop them and put SSH back as it was
# Part 0 - engineer plants the logs
python3 part0/gen_auth_log.py   --out part3/auth.log   --planted planted.json
python3 part0/gen_access_log.py --out part3/access.log --planted planted.json

# Part 1 - scanner
python3 scanner.py 10.0.2.15                                              # ports 1-1024, rate 200, JSON on stdout
python3 scanner.py 10.0.2.15 --ports 22,80,443 --rate 50 --timeout 1
python3 scanner.py 10.0.2.15 --scope scope.txt --rate 200  --output scan_rate200.json
python3 scanner.py 10.0.2.15 --scope scope.txt --rate 2000 --output scan_rate2000.json
python3 scanner.py 10.0.2.15 --ports 1-65535 --rate 2000 --retry-unknown --output full.json
python3 part1/benchmark.py 10.0.2.15 --expect 22,80,311,444,808          # sequential vs threads vs asyncio
python3 part1/compare_answer_key.py --key 22,80,311,444,808 scan_rate200.json scan_rate2000.json

# Part 2 - nmap XML -> hosts.json
nmap -sV --open -oX part2/scan.xml 10.0.2.15
python3 parse_scan.py --input part2/scan.xml --output part2/hosts.json

# Part 3 - log analysis
python3 auth_analysis.py part3/auth.log               # add --json for machine-readable output
python3 log_analysis.py  part3/access.log             # add --sigma 3 --robust-threshold 3.5 --json
python3 part3/build_report.py --auth part3/auth.log --access part3/access.log \
        --output part3/report.md --json part3/analysis.json
python3 part3/score_findings.py planted.json part3/analysis.json          # engineer scores the analyst

# Part 4 - integrated tool
python3 recon.py 10.0.2.15 --verbose --output sample_output               # IP mode (auto-detected)
python3 recon.py example.com --verbose --output sample_output/domain_mode # domain mode (auto-detected)
python3 recon.py 10.0.2.15 --from-results sample_output/results.json --output /tmp/r   # rebuild report.md only
python3 part4/verify_audit.py 10.0.2.15                                   # audit.log vs commands that really ran
```

## 4. What each script does, and why it is built that way

### `scanner.py` (Part 1)

A TCP connect scanner on `asyncio`: one coroutine per port, an `asyncio.Semaphore` caps the probes in flight at
`--rate`. Flags: `target`, `--ports` (`1-1024`, `22,80,443` or a mix), `--rate` (200), `--timeout` (0.5),
`--output` (stdout), plus `--jitter`, `--retry-unknown` and `--scope`.

- **asyncio rather than threads.** Probing is pure waiting; a single-threaded event loop holds thousands of
  sockets without a thread per socket. In the 1,024-port benchmark asyncio was also the faster of the two
  concurrent versions at every concurrency level.
- **Outcomes are classified, not collapsed.** Each probe ends as `open` (handshake completed), `closed`
  (`ConnectionRefusedError`, a RST came back), `filtered` (timeout) or `error:<errno>` (the probe could not be
  sent, e.g. `EMFILE`). An error is *unknown*, never *closed*. The JSON carries the counts, the list of unknown
  ports and `"complete": false`, and the exit code is 3: an incomplete scan cannot pass for a complete one.
- **Fail loudly.** A warning is printed when `--rate` exceeds the soft limit of open files (`ulimit -n`).
  `--retry-unknown` re-scans every errored or timed-out port at rate 50.
- **Scope first.** `--scope scope.txt` exits before sending a packet if the target is not in the file or the
  clock is outside the window.
- **Minimal privilege.** `connect()` needs no root; the script never asks for `sudo`.
- **Random port order**, optional `--jitter`: a sequential, perfectly regular sweep is the easiest scan to fingerprint.
- **Self-connection check.** Found while testing: scanning one's own host over the ephemeral range, the kernel
  can choose the destination port as source port and the socket connects *to itself* (TCP simultaneous open).
  The first version reported port 56846 as open (screenshot `05a`). A probe whose local and remote address are
  identical is now classified `closed`.

### `parse_scan.py` (Part 2)

Parses `nmap -oX` with `xml.etree.ElementTree` only. For each `host` that is up it selects the address by
`addrtype` (the first `<address>` can be the MAC), reads `hostnames/hostname`, and for each `ports/port` whose
`state` is `open` takes `service@name` and `product + version`. Hosts with SSH open are enriched with
`ssh-keyscan`: `ssh_host_key_type` (the strongest type offered), `ssh_host_key_types` (all of them) and
`ssh_legacy_key` (DSA). A timeout, a missing binary or an empty answer sets the field to `null` and records
`ssh_keyscan_error` instead of raising. Accepts `--input` and `--output`.

### `auth_analysis.py` (Part 3 A)

Streams the log line by line. Reports IPs with more than `--threshold` (10) failures sorted by attempts, with
the number of distinct user names per IP (a wordlist looks different from a targeted attack); the targeted
accounts, with `invalid user` treated as optional and recorded; the failed:successful ratio; and successful
logins from an address that had failed before. The user name is matched up to the *last* ` from <ip> port <n>`
so that names with spaces are kept; a `Failed password` line that does not match is counted and reported
(exit code 2) instead of being dropped.

### `log_analysis.py` (Part 3 C, D)

Parses Common Log Format; the request path may contain spaces. The path is percent-decoded until it stops
changing (double encoding) before matching five families: SQL injection, path traversal, XSS, command injection
and probes for sensitive paths. Reports the hits grouped by path with source IPs and status codes, top 5 IPs,
status distribution, and anomalous hours with two detectors: 3-sigma on hourly counts (the required output
format `[ANOMALY] 19:00 — 950 requests (z≈4.5σ, threshold=3.0σ)`) and median/MAD, which is not contaminated by
the spike it is looking for. Lines that do not parse are counted and reported.

`part3/build_report.py` imports both analyzers and writes the combined `report.md` (Part 3 E) plus the same
findings as JSON, which is what `part3/score_findings.py` compares with `planted.json`.

### `recon.py` (Part 4)

One file, two modes (auto-detected with `ipaddress`; `--mode` must agree with the target):

| Mode | Stages |
|---|---|
| IP | `nmap -sV --open --top-ports 100 -oX` (parsed as in Part 2), `dig -x`, `whois` (organization, country), and `curl -I` on every HTTP service nmap found |
| Domain | `whois` (registrar, registration date, expiry date, registrant organization), `dig` A / MX / NS / TXT, `curl -I` (Server, X-Powered-By, CSP, HSTS, X-Frame-Options). nmap is never run against a domain |

- **Audit log.** `run_logged(cmd)` is the only place in the file that spawns a process. It writes `RUN <command>`
  before, and `OK`/`ERROR` with exit status, duration and size after, each with an ISO timestamp with
  milliseconds. Stage boundaries, files read and written, start and end are logged too.
- **Independent stages.** `run_stage()` isolates each stage: a failure is logged, stored in `results.json`
  as `{"status": "error", "error": ...}`, shown in the report, and the next stage runs. Inside `dig` each record
  type is isolated as well. The exit code is 1 if any stage failed, so the failure is loud but not fatal.
- **Structured output.** `results.json` holds parsed fields, never raw text; raw outputs go to `raw/`.
- **The report is generated from `results.json` on disk**, not from memory. `--from-results` rebuilds it from a
  file someone else produced (Handoff 6).
- **Input validation.** The target must be an IP or a syntactically valid domain; commands are passed as argument
  lists (no shell), so a target cannot inject options or commands.

#### Shape of `results.json` (agreed before writing code)

One top-level key per tool, plus `meta`:

```jsonc
{
  "meta":  {"tool": "recon.py", "target": "...", "mode": "ip|domain", "started": "...", "finished": "...",
            "stage_status": {"whois": "ok", "dig": "ok", "curl": "ok", "nmap": "ok|skipped"}},
  "whois": {"status": "ok|error", "query": "...",
            // domain mode
            "registrar": "...", "registration_date": "...", "expiry_date": "...", "registrant_organization": "...",
            // IP mode
            "organization": "...", "country": "...", "network_name": "...", "network_range": "...",
            "fields_not_found": []},
  "dig":   {"status": "ok|partial|error", "query": "...",
            "records": {"A": [], "MX": [], "NS": [], "TXT": []},      // IP mode: {"PTR": []}
            "errors": {"MX": "..."}},                                 // only if a query failed
  "curl":  {"status": "ok|partial|error|skipped",
            "responses": [{"url": "...", "status_line": "HTTP/2 200",
                           "headers": {"server": null, "x-powered-by": null, "content-security-policy": null,
                                       "strict-transport-security": null, "x-frame-options": null},
                           "missing_security_headers": ["Content-Security-Policy (CSP)", "..."]}]},
  "nmap":  {"status": "ok|error|skipped", "command": "...", "scope_of_scan": "...", "host_up": true,
            "ip": "...", "hostname": null,
            "open_ports": [{"port": 22, "protocol": "tcp", "service": "ssh", "version": "OpenSSH 10.3p1 Debian 4"}]}
}
```

A failed stage is `{"status": "error", "error": "<what happened>"}`.

---

## 5. Results

### Part 0

- Target: `10.0.2.15`. Answer key (analyst's private note, `part0/answer_key.txt`): **22** (sshd), **80**
  (apache2, already running on the VM), **311, 444, 808** (the three `python3 -m http.server` listeners).
- Planted logs: `auth.log` 368 lines (347 failed, 21 accepted, 137 `invalid user`), `access.log` 3,415 requests.
  What was planted is in `planted.json`.

### Part 1 A/B — sequential vs threads vs asyncio (ports 1-1024, three runs per row)

| Version | Concurrency | Median time (s) | Min–max (s) | Known open ports found |
|---|---:|---:|---:|---:|
| sequential | 1 | 0.081 | 0.071–0.176 | 5/5 |
| threads | 50 | 0.634 | 0.368–0.716 | 5/5 |
| threads | 200 | 0.481 | 0.390–0.724 | 5/5 |
| threads | 500 | 0.427 | 0.423–0.522 | 5/5 |
| threads | 2000 | 0.512 | 0.438–0.623 | 5/5 |
| asyncio | 50 | 0.259 | 0.217–0.506 | 5/5 |
| asyncio | 200 | 0.332 | 0.290–0.516 | 5/5 |
| asyncio | 500 | 0.344 | 0.286–0.507 | 5/5 |
| asyncio | 2000 | 0.297 | 0.250–0.300 | 5/5 |

The sequential scanner is the fastest here. Scanner and target are the same host, every closed port answers
with an immediate RST, and 1,024 probes take 80 ms; threads and the event loop only add start-up and scheduling
cost. Concurrency pays when probes *wait*: with filtered ports the sequential version needs up to
1,024 × 1 s ≈ 17 min while 200 concurrent probes need about 1,024 / 200 × 0.5 s ≈ 3 s. Between the two
concurrent versions, asyncio was faster than threads at every level in this 1,024-port benchmark.

The same benchmark over all 65,535 ports (`part1/benchmark_full_results.md`, two runs per row):

| Version | Concurrency | Median time (s) | Known open ports found |
|---|---:|---:|---:|
| sequential | 1 | 0.661 | 5/5 |
| threads | 50 / 200 / 500 / 2000 | 2.937 / 6.891 / 11.385 / 10.272 | 5/5 |
| asyncio | 50 / 200 / 500 | 3.818 / 4.819 / 5.172 | 5/5 |
| asyncio | **2000** | **1.355** | **0/5** |

The naive asyncio scanner at 2,000 concurrent connections is the fastest concurrent row and it is wrong about
every open port, without a single warning: it catches `OSError` and returns `None`. Over this range the two
concurrent versions trade places (threads are faster at 50, asyncio at 200 and 500), and both are slower than
the sequential loop for the reason given above.

### Part 1 C/D and Handoff 3 — `scan_rate200.json` and `scan_rate2000.json`

`ulimit -n` on the VM is 1024.

| File | Rate | Time (s) | Open ports reported | Missed vs answer key | Probes that could not be sent |
|---|---:|---:|---|---|---|
| `scan_rate200.json` | 200 | 0.096 | 22, 80, 311, 444, 808 | none | 0 |
| `scan_rate2000.json` | 2000 | 0.092 | 22, 80, 311, 444, 808 | none | 6 × `EMFILE` (ports 61, 231, 582, 766, 802, 922: unknown) |

Thirty more runs at `--rate 2000` over 1-1024: every run lost exactly 6 probes to `EMFILE`; in **1 of 30** the
lost port was a known open one (run 02 missed port **22**). With the first version of the scanner, 1 of 8 runs
missed port **444**.

Full range, 1-65535 (`part1/scan_full_*.json`):

| Run | Time (s) | Found | Outcomes |
|---|---:|---:|---|
| `--rate 200` | 4.81 | 5/5 | 5 open, 65,530 closed, 0 errors |
| `--rate 2000` | 1.50 | **0/5** | 0 open, 0 closed, 1,018 `filtered`, 64,517 `EMFILE` errors |
| `--rate 2000 --retry-unknown` | 5.23 | 5/5 | all 65,535 unknown ports re-scanned at rate 50 |

> **Analyst's confirmation (Handoff 3).** Against my answer key (22, 80, 311, 444, 808), `scan_rate200.json`
> missed no port and `scan_rate2000.json` missed no port either, but it left six ports unprobed (61, 231, 582,
> 766, 802, 922); in the 30 repeat runs at rate 2000 one run missed port 22, and the full-range scan at rate 2000
> missed all five.

#### Question (Part 1)

*Mechanism.* Every probe in flight is an open socket, and every socket is a file descriptor. The process may
hold 1,024 descriptors. Asking for 2,000 concurrent probes over 1,024 ports makes the scanner try to hold 1,024
sockets plus its own descriptors, so `socket()` fails with `EMFILE` for the last six. Those six SYNs are never
sent. Over 65,535 ports the same thing happens to 64,517 probes. A second mechanism appeared in the same run:
the 1,018 probes that *were* sent all timed out, because the event loop spent more than the 0.5 s timeout
failing the other 64,517 tasks before it looked at the replies. The answers had arrived; the scanner did not
read them in time. On a real network the path adds its own losses with the same effect: a full SYN backlog
drops new SYNs, firewalls and IDS rate-limit new connections, and the pool of local source ports runs out.

*Why "not detected" is not "closed".* "Closed" is a statement about the target, and its only evidence is a RST
coming back. In all the cases above no RST came back: either the question was never asked (`EMFILE`) or the
reply was not read (timeout). A scanner that turns `OSError` into `False` converts "I could not ask" into "the
answer is no". Our naive asyncio version did exactly that and reported 0 of 5 open ports in 1.4 s; `scanner.py`
on the same run reported 64,517 unknown ports and exit code 3. The false negative is the same, but only one of
the two outputs lets the reader see it.

*What it implies for any tool, nmap included.* A result set is as complete as its error count says it is, so a
report must state what was probed, what was not, and how many probes failed, and unknown ports must be re-scanned
at lower concurrency. Our own nmap run shows the same principle three ways. `nmap -sV --open 10.0.2.15` printed
`Not shown: 995 filtered tcp ports (no-response)` for ports that are in fact closed (it warns that closed ports
may be reported as filtered because of RST rate limiting): the label describes what nmap received, not the state
of the port. The default scan covers the 1,000 most common ports, so a listener elsewhere is not "closed", it is
unprobed. And `recon.py`, which uses `--top-ports 100`, found 22, 80 and 444 but not 311 and 808, which are open;
its report says explicitly that the other ports were not probed.

### Part 2 — `nmap -sV` and `hosts.json`

`nmap -sV --open -oX part2/scan.xml 10.0.2.15` took 12.5 s and found all five ports of the answer key:

| Port | Service | Version (product + version) |
|---:|---|---|
| 22 | ssh | OpenSSH 10.3p1 Debian 4 |
| 80 | http | Apache httpd 2.4.68 |
| 311, 444, 808 | http | SimpleHTTPServer 0.6 (extra info: Python 3.14.7) |

`ssh-keyscan` returned three host keys; `hosts.json` records `"ssh_host_key_type": "ssh-ed25519"` and
`"ssh_host_key_types": ["ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa"]`, no legacy DSA key.

XML hierarchy, as read before writing the parser: `nmaprun > host > status@state`, `address@addr/@addrtype`,
`hostnames > hostname@name`, `ports > port@protocol/@portid > state@state` and `service@name/@product/@version/@extrainfo`.

#### Question (Part 2)

*Why the version string is valuable to an attacker.* It replaces guessing with a look-up. `Apache httpd 2.4.54`
maps to a CPE (`cpe:/a:apache:http_server:2.4.54`), and the vendor's advisory page and the CVE/NVD records list
exactly what that release is exposed to: 2.4.55 fixed CVE-2006-20001 (mod_dav), CVE-2022-36760 (mod_proxy_ajp
request smuggling) and CVE-2022-37436 (mod_proxy response splitting), and 2.4.56 fixed CVE-2023-25690 and
CVE-2023-27522, all of which affect 2.4.54. From the identifiers the attacker gets severity scores and public
exploit code, and can choose one exploit instead of trying many. In our own scan the banners give away the
distribution as well (`Debian`) and, for the listeners, the exact interpreter (`Python 3.14.7`).

*The cost of obtaining it* is visible in our logs. The plain connect scan of 1,024 ports took 0.1 s and left
nothing in the listeners' logs. `-sV` took 12.5 s and each listener logged the probes: `GET /nmaplowercheck…`,
`POST /sdk`, `GET /HNAP1`, `GET /evox/about` (`evidencias/10_…`), and sshd logged every connection as
`Connection closed by 10.0.2.15 … [preauth]` (`part2/target_sshd_journal.log`, 165 lines over the whole lab).

*`Apache httpd 2.4.54` versus no version string.* The difference is in what the attacker knows, not in what the
server is. With the string, the vulnerable/not-vulnerable question is answered offline. Without it, the attacker
has to fingerprint by behaviour (header order, error pages, default files, responses to malformed requests) or
fire exploits blindly, which is slower and much noisier, so the defender gains detection time. Nothing is fixed:
an unpatched 2.4.54 that hides its banner is still exploitable, and a missing version is not evidence of a patch.
The string can also overstate the exposure, because distributions backport fixes without changing the upstream
number (`2.4.68 (Debian)` says nothing about the Debian patch level).

### Part 3 — log analysis

Final report: [`part3/report.md`](part3/report.md). Scoring and fixes: [`findings_score.md`](findings_score.md).

| Finding | Result |
|---|---|
| IPs with > 10 failed logins | 203.0.113.77 (240, wordlist over 10 user names), 198.51.100.23 (85, only `root`), 192.168.1.50 (12, only `daniel`) |
| Targeted accounts | `root` 115, `daniel` 45, `guest` 30, `test` 27, `ubuntu` 26, `web master` 25, `postgres` 25, `admin` 24, `oracle` 17, `backup admin` 13; 137 failures were for nonexistent accounts |
| Failed : successful | 347 : 21 = **16.52 : 1** |
| Success after failures | `admin` logged in with a password from 203.0.113.77 after 240 failures |
| Suspicious web requests | 413 of 3,415 (12 distinct paths): SQL injection 152, path traversal 128, sensitive-path probes 71, command injection 68, XSS 62 |
| Top 5 IPs | 10.0.0.1 (1,241), 203.0.113.77 (967), 198.51.100.23 (578), 66.249.66.1 (471), 192.168.1.50 (158) |
| Status codes | 200: 3,182; 403: 105; 500: 128 |
| Anomalous hours | `[ANOMALY] 19:00 — 950 requests (z≈4.5σ, threshold=3.0σ)`; `[ANOMALY-ROBUST] 04:00 — 320 requests (robust z≈15.0)` |

Engineer's score: first report 14/27 planted items, final report **27/27**, two false positives in both
(a benign host with 12 failures and a legitimate search containing the words "union select").

The theory's one-line pipeline gives the same per-IP counts as the script on this log
(`grep 'Failed password' part3/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn`: 240, 85, 12, 6, 4),
because it counts fields from the end. The same field trick on the real sshd journal of the target printed
`48 reset` as if it were an address, for lines of a different shape (`… Connection reset by peer [preauth]`):
that is the point where a script with a real pattern is safer than a pipeline.

#### Question (Part 3) — answered by the analyst, reviewed by the engineer

*Effect of daily periodicity on a single global baseline.* Hourly counts on a site with a day/night cycle are
not one roughly normal population; they are a mixture of a busy regime and a quiet one. One global mean falls
between the two and the standard deviation mostly measures the distance between regimes, not the noise inside
either. The threshold `mean + 3σ` therefore sits far above night traffic and close to ordinary peak traffic:
an attack at 03:00 that multiplies night traffic by five can stay under it (false negative), while the normal
daily maximum, or a slightly busy noon, crosses it (false positive). The 99.7 % figure does not apply because
the normality assumption does not hold. Our own log shows a second weakness that is independent of periodicity:
the spike contaminates its own baseline. With 24 samples the largest z-score a single outlier can reach is
(n−1)/√n = 4.69; the 950-request hour scored 4.53, raised the mean to 142.3 and the standard deviation to 178.3,
and the 320-request burst at 04:00, three times a normal hour, scored only 1.0σ.

*Modified approach.* Compare like with like and use robust statistics:

1. Keep one baseline **per hour of the week** (hour-of-day × weekday/weekend) built from the same slot of the
   previous N days or weeks, so that 03:00 is compared with other 03:00s. This removes the daily cycle from the baseline.
2. Compute the baseline with the **median and the median absolute deviation** instead of mean and standard
   deviation, score `0.6745·(x − median)/MAD`, and alert above about 3.5. One past incident then cannot inflate
   the baseline, and the current value is not part of its own reference.
3. Exclude hours already flagged from future baselines, require a minimum amount of history per slot, and tune
   the threshold against past data, since request counts are heavy-tailed.

Equivalent alternatives are a rolling window (compare with the last few hours after removing the seasonal
component) or a seasonal model such as STL or Holt-Winters with alerts on the residual. `log_analysis.py`
implements point 2 on the single day available; point 1 needs several days of logs.

*Engineer's review.* Consistent with the scoring: twelve of the thirteen first-round misses were pattern or
analysis gaps, and the one that no pattern could fix was the 04:00 burst, recovered only by the robust baseline.

### Part 4 — `recon.py`

Sample runs: [`sample_output/`](sample_output) (IP mode, `10.0.2.15`) and
[`sample_output/domain_mode/`](sample_output/domain_mode) (domain mode, `example.com`).

| | IP mode — 10.0.2.15 | Domain mode — example.com |
|---|---|---|
| nmap (top 100) | 22 ssh OpenSSH 10.3p1, 80 http Apache httpd 2.4.68, 444 http SimpleHTTPServer 0.6 | not run |
| dig | no PTR record | A: 104.20.23.154, 172.66.147.243; MX: `0 .`; NS: elliott / hera `.ns.cloudflare.com.`; TXT: 2 |
| whois | Internet Assigned Numbers Authority, US (RFC 1918 block) | Registrar RESERVED-Internet Assigned Numbers Authority; created 1995-08-14; expires 2027-08-13 |
| curl -I | `:80` Apache/2.4.68 (Debian), `:444` SimpleHTTP/0.6 Python/3.14.7 | HTTP/2 200, Server: cloudflare |
| Missing security headers | CSP, HSTS, X-Frame-Options on both | CSP, HSTS, X-Frame-Options |
| Exit code | 0 | 0 |

- **Stages fail independently** (`evidencias/30_…`): with a nonexistent domain, `whois` and `curl` fail, `dig`
  completes, the three output files are written and the exit code is 1; with `nmap` removed from `PATH`, the nmap
  stage fails and `dig` and `whois` still run.
- **Audit check by the engineer** (`part4/verify_audit.py`, outputs in `part4/audit_verification_*.txt`):
  the only process-spawning call in `recon.py` is line 82, inside `run_logged()`; running the tool behind
  witness shims for `whois`, `dig`, `curl` and `nmap` shows 5 commands executed / 5 `RUN` lines / 5 outcomes in
  IP mode and 6 / 6 / 6 in domain mode, in the same order. **No gap between the audit log and what ran.**
  One remark was passed to the analyst: a command whose binary is missing is logged as `RUN` followed by
  `ERROR … command not found`, which is accurate but means a `RUN` line records an attempt, not a success; the
  outcome line must always be read with it.

#### Question (Part 4) — answered by the engineer (the analyst authored the final merge), reviewed by the analyst

*Operational differences for an attacker.*

| | Active (`recon.py`, nmap) | Passive (Shodan query) |
|---|---|---|
| Contact with the target | Packets from the attacker's address reach it | None; the only packets were Shodan's own, earlier |
| Freshness | State at this moment | State at Shodan's last crawl, possibly days or weeks old |
| Coverage | Any port, protocol or probe the attacker chooses, including internal hosts once inside | Only what Shodan scans and only internet-facing addresses; `10.0.2.15` does not exist for Shodan |
| Speed and scale | Bounded by rate limits, time, and the risk of crashing fragile devices | One query returns thousands of hosts by banner, product or CVE |
| Attribution and legality | Traceable to a source address; needs authorization | Leaves no trace on the target; limited by API keys, rate limits and terms of use |

*Which is harder to detect, and why.* Passive reconnaissance. The defender's monitoring sees packets, and a
Shodan query sends none to the defender's network: there is no event to correlate with the attacker. All the
defender can see is Shodan's periodic indexing, which is indistinguishable from the internet's background
scanning and happened before the attacker became interested. Active reconnaissance is visible at several
layers, and our lab shows it: sshd on the target logged 165 lines during the scans, 99 of them
`Connection closed/reset by 10.0.2.15 … [preauth]`, and each listener logged nmap's version probes by name. A SYN
scan would have avoided the application logs, but not a firewall, IDS or flow record.

*When each is appropriate.* Passive first: at the start of an engagement, to map the external attack surface
without alerting anyone, when stealth matters, when the rules of engagement do not yet allow touching the
target, and for defenders auditing what the internet already knows about them. 

---

## 6. Who did what

| Role | Member | Wrote |
|---|---|---|
| Scanner engineer | Gutiérrez | `scanner.py`, `part1/benchmark.py`, `parse_scan.py`, the log generators in `part0/`, `planted.json`, `part3/score_findings.py`, `findings_score.md` (scoring), `recon.py` requirements 1, 3, 4 (CLI and the `whois`, `dig`, `curl`, `nmap` stages), `part4/verify_audit.py`; answered the Part 1, Part 2 and Part 4 questions |
| Log analyst | Ducuara | `scope.txt`, `part0/start_target.sh` and the answer key, `auth_analysis.py`, `log_analysis.py`, `part3/build_report.py`, `part3/report.md`, `recon.py` requirements 2, 5, 6 (`run_logged` and the audit log, `results.json`, `report.md`), the final merge of `recon.py`; answered the Part 3 question |
| Both | | Fixes to the analyzers recorded in `findings_score.md`, the `results.json` shape, the two sample runs |

Handoff files that crossed between the two roles:

| # | Direction | What crossed |
|---:|---|---|
| 1 | analyst → engineer | `scope.txt` |
| 2 | engineer → analyst | `part3/auth.log`, `part3/access.log` (and nothing else) |
| 3 | engineer → analyst | `scan_rate200.json`, `scan_rate2000.json`; the analyst returned the comparison with the answer key |
| 4 | analyst → engineer | `part3/report.md` (first `part3/v1/report_v1.md`); the engineer returned the list of misses |
| 5 | analyst → engineer | the function `run_logged(cmd)` |
| 6 | engineer → analyst | `sample_output/results.json` (IP mode against the address in `scope.txt`) |

## 7. Evidence

Screenshots of every step, taken inside the Kali VM, are in [`evidencias/`](evidencias) with an index in
[`evidencias/README.md`](evidencias/README.md).
