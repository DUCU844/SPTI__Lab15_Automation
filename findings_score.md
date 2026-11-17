# findings_score.md — planted items versus report.md (Part 3)

- Scored by the **scanner engineer** (who planted the logs) against `planted.json`.
- Analyst's inputs: only `part3/auth.log` (368 lines) and `part3/access.log` (3,415 lines), received in Handoff 2.
- Scoring tool: `python3 part3/score_findings.py planted.json <analysis.json>` (the JSON is written by
  `part3/build_report.py --json`, i.e. it contains exactly what `report.md` shows).
- Two rounds were scored: the analyst's first report (`part3/v1/report_v1.md`) and the report produced after
  the misses were fixed together (`part3/report.md`).

| Round | Analyzer | Planted items detected | Missed | False positives |
|---|---|---:|---:|---:|
| 1 | `part3/v1/auth_analysis.py`, `part3/v1/log_analysis.py` (patterns from the theory section) | 14 / 27 | 13 | 2 |
| 2 | `auth_analysis.py`, `log_analysis.py` (after the fixes below) | **27 / 27** | **0** | 2 |

---

## Round 1 — first report (v1)

**14/27 planted items detected, 13 missed, 2 false positive(s).**

| Category | Planted item | Detected | Detail |
|---|---|:---:|---|
| auth: attacker IP | 203.0.113.77 with 240 failures | **NO** | reported 202 failures (planted 240: 38 lines not counted) |
| auth: attacker IP | 198.51.100.23 with 85 failures | yes | reported 85 failures |
| auth: invalid-user lines | 137 `invalid user` failures | **NO** | reported 99 |
| auth: targeted user | `root` | yes | listed |
| auth: targeted user | `admin` | yes | listed |
| auth: targeted user | `ubuntu` | yes | listed |
| auth: targeted user | `daniel` | yes | listed |
| auth: targeted user | `oracle` | yes | listed |
| auth: targeted user | `test` | yes | listed |
| auth: targeted user | `postgres` | yes | listed |
| auth: targeted user | `guest` | yes | listed |
| auth: targeted user | `backup admin` | **NO** | not listed |
| auth: targeted user | `web master` | **NO** | not listed |
| auth: compromise | `admin` accepted from 203.0.113.77 after failures | **NO** | not reported |
| web: sql_injection | `/?id=1%27%20UNION%20SELECT%201,2,3--` | yes | flagged 22/22 requests |
| web: sql_injection | `/login?user=admin%27%20OR%20%271%27%3D%271` | **NO** | not flagged |
| web: sql_injection | `/item?id=5 UNION SELECT username,password FROM users--` | **NO** | not flagged |
| web: path_traversal | `/download?file=..%2F..%2F..%2Fetc%2Fpasswd` | yes | flagged 25/25 requests |
| web: path_traversal | `/static/%252e%252e%252f%252e%252e%252fetc%252fshadow` | **NO** | not flagged |
| web: xss | `/search?q=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E` | yes | flagged 31/31 requests |
| web: xss | `/comment?text=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E` | **NO** | not flagged |
| web: command_injection | `/cgi-bin/status.cgi?cmd=cat%20%2Fetc%2Fpasswd` | yes | flagged 30/30 requests |
| web: command_injection | `/ping?host=127.0.0.1%3Bcat%20%2Fetc%2Fpasswd` | **NO** | not flagged |
| web: probe | `/wp-admin/` | **NO** | not flagged |
| web: probe | `/.env` | **NO** | not flagged |
| web: spike | 19:00 with 950 requests | yes | 3-sigma, z=4.53 |
| web: secondary burst | 04:00 with 320 requests | **NO** | not flagged |

Report items that were NOT planted (false positives):

| Category | Reported item | Origin |
|---|---|---|
| auth: brute-force IP | 192.168.1.50 (12 failures) | benign noise planted by the engineer |
| web: sql_injection | `/search?q=trade%20union%20select%20committee` (67 requests) | benign look-alike planted by the engineer |

### List of misses returned to the analyst

1. Attacker `203.0.113.77`: 202 failures reported, 240 planted (38 lines not counted).
2. `invalid user` lines: 99 reported, 137 planted (the same 38 lines).
3. Targeted user `backup admin` not listed.
4. Targeted user `web master` not listed.
5. Successful login of `admin` from `203.0.113.77` after its failures not reported.
6. SQL injection `/login?user=admin%27%20OR%20%271%27%3D%271` not flagged.
7. SQL injection `/item?id=5 UNION SELECT username,password FROM users--` not flagged (33 requests).
8. Path traversal `/static/%252e%252e%252f%252e%252e%252fetc%252fshadow` not flagged.
9. XSS `/comment?text=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E` not flagged.
10. Command injection `/ping?host=127.0.0.1%3Bcat%20%2Fetc%2Fpasswd` not flagged.
11. Probe `/wp-admin/` not flagged.
12. Probe `/.env` not flagged.
13. Secondary traffic burst at 04:00 (320 requests) not flagged.

---

## Together — cause of each miss and the fix (one line per fix)

| # | Miss | Cause | Fix (one line) |
|---:|---|---|---|
| 1–4 | 38 failures of `203.0.113.77`, 38 `invalid user` lines, users `backup admin` and `web master` | **Weak pattern**: `(?P<user>\S+)` stops at a space, so a user name containing a space makes the whole line fail to match and it is silently dropped | `auth_analysis.py`: user is now `(?P<user>.+)` anchored on the last ` from <ip> port <n>`; any `Failed password` line that still does not match is counted in `unparsed_failed_lines` and reported |
| 5 | Successful login after failures | **Missing analysis** (not a pattern problem): v1 only counted `Accepted` lines, it never related them to earlier failures from the same address | `auth_analysis.py`: every `Accepted` line is checked against the failures already seen from that IP (the log is chronological) and listed in section 4 of the report |
| 6 | SQLi `' OR '1'='1` | **Weak pattern**: the SQL rule only knew `union…select`, `insert…into`, `drop table` | `log_analysis.py`: SQL rule extended with boolean tautologies (`' OR 'x'='x`, `OR 1=1`), `select…from`, time-based functions and `information_schema` |
| 7 | SQLi sent raw, with spaces | **Weak pattern (log format)**: `"(?P<path>\S+) \S+"` stops at the first space, so the line did not match `LOG_PATTERN` at all — 33 requests vanished from every count (top IPs and status codes included) | `log_analysis.py`: the request is now `(?P<path>.*?) HTTP/[\d.]+"`; lines that do not match are counted in `unparsed_lines` and reported (33 → 0) |
| 8 | Double-encoded traversal `%252e%252e%252f` | **Weak pattern (decoding)**: a single `unquote()` turns `%252e` into `%2e`, which the rule does not match | `log_analysis.py`: `decode()` applies `unquote()` until the string stops changing (max. 3 rounds); the traversal rule also matches direct references to `/etc/passwd`, `/etc/shadow` |
| 9 | XSS without `<script>` | **Weak pattern**: the XSS rule was only `<script` | `log_analysis.py`: XSS rule extended with event handlers (`onerror=`, `onload=`…), `javascript:` and `<svg`/`<iframe`/`<img … on…=` |
| 10 | Command injection without `cmd=` | **Weak pattern**: the rule only looked at parameter names `cmd=`, `exec=`, `shell=` | `log_analysis.py`: rule extended with shell metacharacters followed by a command (`;cat`, `\|id`, `&&wget`), `$(…)` and backticks |
| 11–12 | Probes `/wp-admin/`, `/.env` | **No rule**: they carry no payload, so no attack-family pattern can match them | `log_analysis.py`: new family `sensitive_path_probe` (`/wp-admin`, `/wp-login.php`, `/phpmyadmin`, `/.env`, `/.git/`, `/server-status`) |
| 13 | Burst of 320 requests at 04:00 | **Limit of the 3-sigma method**: the 950-request spike at 19:00 contaminates the baseline it is judged against (mean 142.3, stdev 178.3), so 320 requests is only z ≈ 1.0σ although it is 3× a normal hour | `log_analysis.py`: added a robust detector (median 97, MAD 10, threshold 3.5) next to 3-sigma; the burst scores robust z ≈ 15.0 and is reported as `[ANOMALY-ROBUST]` |

No miss was caused by an "unencoded payload" rule in isolation: miss 7 is unencoded, but what failed was the log-line
pattern, not the attack pattern (the payload contains `UNION SELECT` in clear text).

---

## Round 2 — report after the fixes

**27/27 planted items detected, 0 missed, 2 false positive(s).**

| Category | Planted item | Detected | Detail |
|---|---|:---:|---|
| auth: attacker IP | 203.0.113.77 with 240 failures | yes | reported 240 failures |
| auth: attacker IP | 198.51.100.23 with 85 failures | yes | reported 85 failures |
| auth: invalid-user lines | 137 `invalid user` failures | yes | reported 137 |
| auth: targeted user | `root` | yes | listed |
| auth: targeted user | `admin` | yes | listed |
| auth: targeted user | `ubuntu` | yes | listed |
| auth: targeted user | `daniel` | yes | listed |
| auth: targeted user | `oracle` | yes | listed |
| auth: targeted user | `test` | yes | listed |
| auth: targeted user | `postgres` | yes | listed |
| auth: targeted user | `guest` | yes | listed |
| auth: targeted user | `backup admin` | yes | listed |
| auth: targeted user | `web master` | yes | listed |
| auth: compromise | `admin` accepted from 203.0.113.77 after failures | yes | reported (240 prior failures) |
| web: sql_injection | `/?id=1%27%20UNION%20SELECT%201,2,3--` | yes | flagged 22/22 requests |
| web: sql_injection | `/login?user=admin%27%20OR%20%271%27%3D%271` | yes | flagged 30/30 requests |
| web: sql_injection | `/item?id=5 UNION SELECT username,password FROM users--` | yes | flagged 33/33 requests |
| web: path_traversal | `/download?file=..%2F..%2F..%2Fetc%2Fpasswd` | yes | flagged 25/25 requests |
| web: path_traversal | `/static/%252e%252e%252f%252e%252e%252fetc%252fshadow` | yes | flagged 35/35 requests |
| web: xss | `/search?q=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E` | yes | flagged 31/31 requests |
| web: xss | `/comment?text=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E` | yes | flagged 31/31 requests |
| web: command_injection | `/cgi-bin/status.cgi?cmd=cat%20%2Fetc%2Fpasswd` | yes | flagged 30/30 requests |
| web: command_injection | `/ping?host=127.0.0.1%3Bcat%20%2Fetc%2Fpasswd` | yes | flagged 38/38 requests |
| web: probe | `/wp-admin/` | yes | flagged |
| web: probe | `/.env` | yes | flagged |
| web: spike | 19:00 with 950 requests | yes | 3-sigma, z=4.53 |
| web: secondary burst | 04:00 with 320 requests | yes | median/MAD, robust z=15.0 (3-sigma z=1.0) |

Report items that were NOT planted (false positives):

| Category | Reported item | Origin |
|---|---|---|
| auth: brute-force IP | 192.168.1.50 (12 failures) | benign noise planted by the engineer |
| web: sql_injection | `/search?q=trade%20union%20select%20committee` (67 requests) | benign look-alike planted by the engineer |

### The two false positives (present in both rounds, kept on purpose)

| Report item | Why it is reported | Why it is not an attack | Decision |
|---|---|---|---|
| `192.168.1.50`, 12 failed logins | The lab's rule is "more than 10 failed attempts" | Internal address, one single existing account (`daniel`), no successful login afterwards: a user mistyping a password | Threshold kept at 10 (it is the stated requirement). The report now shows *distinct user names* and *attack style* per IP so that a reader can separate 12 failures on one real account from 240 failures over 10 names |
| `/search?q=trade%20union%20select%20committee`, 67 requests | Decoded text contains `union … select`, which is the SQL rule | Ordinary search for English words: no quote, no comment marker, status 200 for every client, requested by crawlers and internal hosts | Kept as a hit. A pattern match is triage, not a verdict; removing `union…select` from the rule to silence it would also hide real injections. The report states this explicitly |

### Engineer's review of the analyst's Part 3 answer

The scoring supports the answer in `README.md` (Part 3 question): the only planted item that no pattern change
could recover was the 04:00 burst, and it was missed precisely because a single global mean/standard deviation
is dominated by the largest value in the series. With 24 hourly samples the largest z-score one outlier can reach
is (n−1)/√n = 4.69; the 19:00 spike scored 4.53 and left no room for a second, smaller anomaly.
