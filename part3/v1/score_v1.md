### Score: v1 (first iteration)

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

