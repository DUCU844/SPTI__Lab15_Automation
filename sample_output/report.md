# Reconnaissance report: 10.0.2.15

- Mode: **ip**
- Started: 2026-11-16T22:12:40-05:00
- Finished: 2026-11-16T22:12:52-05:00
- Tool: recon.py (commands and outcomes are recorded in `audit.log`)

## Summary of findings

| Finding | Value |
|---|---|
| Target | `10.0.2.15` |
| Mode | ip |
| Open ports (top 100 TCP) | 22/ssh, 80/http, 444/http |
| Reverse DNS (PTR) | no PTR record |
| Owner organization | Internet Assigned Numbers Authority |
| Country | US |
| Web server at http://10.0.2.15:80/ | HTTP/1.1 200 OK; Server: Apache/2.4.68 (Debian); X-Powered-By: — |
| Missing security headers at http://10.0.2.15:80/ | Content-Security-Policy (CSP), Strict-Transport-Security (HSTS), X-Frame-Options |
| Web server at http://10.0.2.15:444/ | HTTP/1.0 200 OK; Server: SimpleHTTP/0.6 Python/3.14.7; X-Powered-By: — |
| Missing security headers at http://10.0.2.15:444/ | Content-Security-Policy (CSP), Strict-Transport-Security (HSTS), X-Frame-Options |
| Stages with errors | none |

## Open ports

Command: `nmap -sV --open --top-ports 100 -oX sample_output/raw/nmap.xml 10.0.2.15`

Scope: 100 most common TCP ports (--top-ports 100); other ports were NOT probed. A port that is not listed was either closed or **not probed**; it is not proven closed.

| Port | Protocol | Service | Version |
|---:|---|---|---|
| 22 | tcp | ssh | OpenSSH 10.3p1 Debian 4 |
| 80 | tcp | http | Apache httpd 2.4.68 |
| 444 | tcp | http | SimpleHTTPServer 0.6 |

## Reverse DNS and ownership

- PTR: no PTR record
- Organization: Internet Assigned Numbers Authority
- Country: US
- Network: PRIVATE-ADDRESS-ABLK-RFC1918-IANA-RESERVED (10.0.0.0 - 10.255.255.255)
- Note: private (RFC 1918) address: whois describes the reserved block, not the organization that operates this host

## HTTP response headers and missing security headers

### http://10.0.2.15:80/ — `HTTP/1.1 200 OK`

| Header | Value |
|---|---|
| Server | Apache/2.4.68 (Debian) |
| X-Powered-By | — |
| Content-Security-Policy | — |
| Strict-Transport-Security | — |
| X-Frame-Options | — |

**Missing security headers:** Content-Security-Policy (CSP), Strict-Transport-Security (HSTS), X-Frame-Options.
(HSTS is only honoured over HTTPS; this service is plain HTTP, which is itself a finding.)
The `Server` / `X-Powered-By` headers disclose software and version information.

### http://10.0.2.15:444/ — `HTTP/1.0 200 OK`

| Header | Value |
|---|---|
| Server | SimpleHTTP/0.6 Python/3.14.7 |
| X-Powered-By | — |
| Content-Security-Policy | — |
| Strict-Transport-Security | — |
| X-Frame-Options | — |

**Missing security headers:** Content-Security-Policy (CSP), Strict-Transport-Security (HSTS), X-Frame-Options.
(HSTS is only honoured over HTTPS; this service is plain HTTP, which is itself a finding.)
The `Server` / `X-Powered-By` headers disclose software and version information.


## Stage status

| Tool | Status | Error |
|---|---|---|
| whois | ok | — |
| dig | ok | — |
| curl | ok | — |
| nmap | ok | — |
