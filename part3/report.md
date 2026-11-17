# Log analysis report (Part 3)

- Generated: 2026-11-16T22:13:56
- Inputs: `part3/auth.log` (368 login events), `part3/access.log` (3415 requests)
- Analyzers: `Lab15/auth_analysis.py`, `Lab15/log_analysis.py`

## Summary

- **3** address(es) exceeded 10 failed SSH logins: 203.0.113.77 (240), 198.51.100.23 (85), 192.168.1.50 (12)
- **10** user names were guessed; 137 failures were for accounts that do not exist
- Failed:successful logins = 347:21 (**16.52:1**)
- **Possible compromise**: `admin` logged in from 203.0.113.77 after 240 failures
- **413** web requests matched an attack pattern (12 distinct paths)
- Anomalous hours: 19:00 (950 requests), 04:00 (320 requests)

## 1. SSH brute-force sources (auth.log)

IPs with more than 10 failed logins, sorted by attempts:

| IP | Failed attempts | Distinct user names | Attack style |
|---|---:|---:|---|
| 203.0.113.77 | 240 | 10 | wordlist (10 user names) |
| 198.51.100.23 | 85 | 1 | targeted (only `root`) |
| 192.168.1.50 | 12 | 1 | targeted (only `daniel`) |

## 2. Targeted user accounts

| User | Failed attempts | Account exists? |
|---|---:|---|
| `root` | 115 | yes |
| `daniel` | 45 | yes |
| `guest` | 30 | no (`invalid user`) |
| `test` | 27 | no (`invalid user`) |
| `ubuntu` | 26 | yes |
| `web master` | 25 | no (`invalid user`) |
| `postgres` | 25 | no (`invalid user`) |
| `admin` | 24 | yes |
| `oracle` | 17 | no (`invalid user`) |
| `backup admin` | 13 | no (`invalid user`) |

Failed logins for nonexistent accounts (`invalid user` lines): **137**

## 3. Failed vs successful logins

- Failed: **347**
- Successful: **21**
- Ratio failed:successful = **16.52:1**

## 4. Successful logins after failures (possible compromise)

| IP | Account | Method | Failures before the success |
|---|---|---|---:|
| 203.0.113.77 | `admin` | password | 240 |

A success right after a run of failures from the same address may mean the guessing worked: treat the account as compromised until proven otherwise.

## 5. Suspicious web requests (access.log)

413 of 3415 requests matched an attack pattern (12 distinct paths). Paths are percent-decoded (up to 3 rounds) before matching. A match is triage, not a verdict.

| Family | Requests | Source IPs | Statuses | Path as logged | Decoded |
|---|---:|---|---|---|---|
| sql_injection | 67 | 10.0.0.1 (23), 203.0.113.77 (18), 66.249.66.1 (15), 198.51.100.23 (9), 192.168.1.50 (2) | 200×67 | `/search?q=trade%20union%20select%20committee` | `/search?q=trade union select committee` |
| path_traversal, command_injection | 38 | 198.51.100.23 (19), 203.0.113.77 (19) | 200×12, 403×13, 500×13 | `/ping?host=127.0.0.1%3Bcat%20%2Fetc%2Fpasswd` | `/ping?host=127.0.0.1;cat /etc/passwd` |
| sensitive_path_probe | 36 | 203.0.113.77 (21), 198.51.100.23 (15) | 200×12, 403×9, 500×15 | `/.env` | `/.env` |
| path_traversal | 35 | 198.51.100.23 (18), 203.0.113.77 (17) | 200×14, 403×10, 500×11 | `/static/%252e%252e%252f%252e%252e%252fetc%252fshadow` | `/static/../../etc/shadow` |
| sensitive_path_probe | 35 | 203.0.113.77 (20), 198.51.100.23 (15) | 200×11, 403×16, 500×8 | `/wp-admin/` | `/wp-admin/` |
| sql_injection | 33 | 198.51.100.23 (18), 203.0.113.77 (15) | 200×15, 403×9, 500×9 | `/item?id=5 UNION SELECT username,password FROM users--` | `/item?id=5 UNION SELECT username,password FROM users--` |
| xss | 31 | 198.51.100.23 (19), 203.0.113.77 (12) | 200×12, 403×8, 500×11 | `/comment?text=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E` | `/comment?text=<img src=x onerror=alert(1)>` |
| xss | 31 | 198.51.100.23 (19), 203.0.113.77 (12) | 200×11, 403×8, 500×12 | `/search?q=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E` | `/search?q=<script>alert(document.cookie)</script>` |
| path_traversal, command_injection | 30 | 203.0.113.77 (15), 198.51.100.23 (15) | 200×6, 403×9, 500×15 | `/cgi-bin/status.cgi?cmd=cat%20%2Fetc%2Fpasswd` | `/cgi-bin/status.cgi?cmd=cat /etc/passwd` |
| sql_injection | 30 | 203.0.113.77 (17), 198.51.100.23 (13) | 200×9, 403×11, 500×10 | `/login?user=admin%27%20OR%20%271%27%3D%271` | `/login?user=admin' OR '1'='1` |
| path_traversal | 25 | 198.51.100.23 (15), 203.0.113.77 (10) | 200×7, 403×6, 500×12 | `/download?file=..%2F..%2F..%2Fetc%2Fpasswd` | `/download?file=../../../etc/passwd` |
| sql_injection | 22 | 198.51.100.23 (14), 203.0.113.77 (8) | 200×4, 403×6, 500×12 | `/?id=1%27%20UNION%20SELECT%201,2,3--` | `/?id=1' UNION SELECT 1,2,3--` |

Requests per family: sql_injection: 152, path_traversal: 128, sensitive_path_probe: 71, command_injection: 68, xss: 62

Suspicious requests per source IP: 198.51.100.23: 189, 203.0.113.77: 184, 10.0.0.1: 23, 66.249.66.1: 15, 192.168.1.50: 2

## 6. Top 5 IPs by request volume

| IP | Requests |
|---|---:|
| 10.0.0.1 | 1241 |
| 203.0.113.77 | 967 |
| 198.51.100.23 | 578 |
| 66.249.66.1 | 471 |
| 192.168.1.50 | 158 |

## 7. HTTP status code distribution

| Status | Requests |
|---|---:|
| 200 | 3182 |
| 403 | 105 |
| 500 | 128 |

## 8. Traffic anomalies (hourly request counts)

- Global baseline: mean = 142.3 requests/hour, stdev = 178.3 (24 hourly samples; the largest z-score a single outlier can reach with this many samples is 4.69)
- Robust baseline: median = 97.0, MAD = 10.0

```
[ANOMALY] 19:00 — 950 requests (z≈4.5σ, threshold=3.0σ)
[ANOMALY-ROBUST] 04:00 — 320 requests (robust z≈15.0, threshold=3.5; only z≈1.0σ on the global baseline)
```

| Hour | Requests |
|---|---:|
| 00:00 | 93 |
| 01:00 | 87 |
| 02:00 | 94 |
| 03:00 | 107 |
| 04:00 | 320 |
| 05:00 | 97 |
| 06:00 | 97 |
| 07:00 | 99 |
| 08:00 | 88 |
| 09:00 | 83 |
| 10:00 | 82 |
| 11:00 | 114 |
| 12:00 | 95 |
| 13:00 | 80 |
| 14:00 | 103 |
| 15:00 | 97 |
| 16:00 | 91 |
| 17:00 | 112 |
| 18:00 | 112 |
| 19:00 | 950 |
| 20:00 | 117 |
| 21:00 | 107 |
| 22:00 | 108 |
| 23:00 | 82 |
