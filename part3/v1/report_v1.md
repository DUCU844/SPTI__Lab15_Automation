# Log analysis report (Part 3)

- Generated: 2026-11-16T22:00:05
- Inputs: `part3/auth.log` (330 login events), `part3/access.log` (3415 requests)
- Analyzers: `v1/auth_analysis.py`, `v1/log_analysis.py`

## Summary

- **3** address(es) exceeded 10 failed SSH logins: 203.0.113.77 (202), 198.51.100.23 (85), 192.168.1.50 (12)
- **8** user names were guessed; 99 failures were for accounts that do not exist
- Failed:successful logins = 309:21 (**14.71:1**)
- **175** web requests matched an attack pattern (5 distinct paths)
- Anomalous hours: 19:00 (950 requests)

## 1. SSH brute-force sources (auth.log)

IPs with more than 10 failed logins, sorted by attempts:

| IP | Failed attempts |
|---|---:|
| 203.0.113.77 | 202 |
| 198.51.100.23 | 85 |
| 192.168.1.50 | 12 |

## 2. Targeted user accounts

| User | Failed attempts | Account exists? |
|---|---:|---|
| `root` | 115 | yes |
| `daniel` | 45 | yes |
| `guest` | 30 | no (invalid user) |
| `test` | 27 | no (invalid user) |
| `ubuntu` | 26 | yes |
| `postgres` | 25 | no (invalid user) |
| `admin` | 24 | yes |
| `oracle` | 17 | no (invalid user) |

Failed logins for nonexistent accounts (`invalid user`): 99

## 3. Failed vs successful logins

- Failed: 309
- Successful: 21
- Ratio failed:successful = 14.71:1

## 4. Suspicious web requests (access.log)

175 requests matched an attack pattern (5 distinct paths).

| Family | Requests | Source IPs | Path (as logged) |
|---|---:|---|---|
| sql_injection | 67 | 66.249.66.1, 10.0.0.1, 203.0.113.77, 198.51.100.23, 192.168.1.50 | `/search?q=trade%20union%20select%20committee` |
| xss | 31 | 198.51.100.23, 203.0.113.77 | `/search?q=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E` |
| command_injection | 30 | 203.0.113.77, 198.51.100.23 | `/cgi-bin/status.cgi?cmd=cat%20%2Fetc%2Fpasswd` |
| path_traversal | 25 | 198.51.100.23, 203.0.113.77 | `/download?file=..%2F..%2F..%2Fetc%2Fpasswd` |
| sql_injection | 22 | 203.0.113.77, 198.51.100.23 | `/?id=1%27%20UNION%20SELECT%201,2,3--` |

## 5. Top 5 IPs by request volume

| IP | Requests |
|---|---:|
| 10.0.0.1 | 1241 |
| 203.0.113.77 | 952 |
| 198.51.100.23 | 560 |
| 66.249.66.1 | 471 |
| 192.168.1.50 | 158 |

## 6. HTTP status code distribution

| Status | Requests |
|---|---:|
| 200 | 3167 |
| 403 | 96 |
| 500 | 119 |

## 7. Traffic anomalies (3-sigma on hourly request counts)

Baseline: mean=142.3 requests/hour, stdev=178.3.

```
[ANOMALY] 19:00 — 950 requests (z≈4.5σ, threshold=3.0σ)
```
