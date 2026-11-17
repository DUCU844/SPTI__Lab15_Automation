# Reconnaissance report: example.com

- Mode: **domain**
- Started: 2026-11-16T22:13:08-05:00
- Finished: 2026-11-16T22:13:11-05:00
- Tool: recon.py (commands and outcomes are recorded in `audit.log`)

## Summary of findings

| Finding | Value |
|---|---|
| Target | `example.com` |
| Mode | domain |
| Registrar | RESERVED-Internet Assigned Numbers Authority |
| Registered on | 1995-08-14T04:00:00Z |
| Expires on | 2027-08-13T04:00:00Z |
| Registrant organization | Internet Assigned Numbers Authority |
| A records | 104.20.23.154, 172.66.147.243 |
| Name servers | elliott.ns.cloudflare.com., hera.ns.cloudflare.com. |
| Mail servers | 0 . |
| TXT records | 2 |
| Web server at https://example.com/ | HTTP/2 200; Server: cloudflare; X-Powered-By: — |
| Missing security headers at https://example.com/ | Content-Security-Policy (CSP), Strict-Transport-Security (HSTS), X-Frame-Options |
| Stages with errors | none |

## Registration (whois)

| Field | Value |
|---|---|
| Registrar | RESERVED-Internet Assigned Numbers Authority |
| Registration date | 1995-08-14T04:00:00Z |
| Expiry date | 2027-08-13T04:00:00Z |
| Registrant organization | Internet Assigned Numbers Authority |

## DNS records

| Type | Records |
|---|---|
| A | `104.20.23.154`<br>`172.66.147.243` |
| MX | `0 .` |
| NS | `elliott.ns.cloudflare.com.`<br>`hera.ns.cloudflare.com.` |
| TXT | `"_k2n1y4vw3qtb4skdx9e7dxt97qrmmq9"`<br>`"v=spf1 -all"` |

## HTTP response headers and missing security headers

### https://example.com/ — `HTTP/2 200`

| Header | Value |
|---|---|
| Server | cloudflare |
| X-Powered-By | — |
| Content-Security-Policy | — |
| Strict-Transport-Security | — |
| X-Frame-Options | — |

**Missing security headers:** Content-Security-Policy (CSP), Strict-Transport-Security (HSTS), X-Frame-Options.
The `Server` / `X-Powered-By` headers disclose software and version information.


## Stage status

| Tool | Status | Error |
|---|---|---|
| whois | ok | — |
| dig | ok | — |
| curl | ok | — |
| nmap | skipped | nmap is only run in IP mode |
