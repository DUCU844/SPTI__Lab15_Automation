#!/usr/bin/env python3
"""Part 4 - recon.py: multi-stage reconnaissance of a domain or an IP address.

Single file, standard library only. External tools: whois, dig, curl, nmap.

    python3 recon.py 10.0.2.15 --verbose                    # IP mode (auto-detected)
    python3 recon.py example.com --mode domain --output out/ # domain mode
    python3 recon.py 10.0.2.15 --from-results out/results.json --output out/   # rebuild report.md only

Output directory (default ./recon_<target>_<timestamp>/):
    audit.log      every action: command, outcome (success/error) and timestamp
    results.json   all findings in one dict keyed by tool: whois, dig, curl, nmap (+ meta)
    report.md      human-readable report generated FROM results.json
    raw/           raw output of every command, nmap.xml

Exit code: 0 = every stage succeeded, 1 = at least one stage failed (the other
stages still ran and their results were written), 2 = bad arguments.

IMPORTANT: IP mode is ACTIVE reconnaissance (nmap sends packets to the target).
Only run it against hosts you are authorized to scan (see scope.txt).
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import shlex
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

SECURITY_HEADERS = {
    "content-security-policy": "Content-Security-Policy (CSP)",
    "strict-transport-security": "Strict-Transport-Security (HSTS)",
    "x-frame-options": "X-Frame-Options",
}
REPORTED_HEADERS = ["server", "x-powered-by", *SECURITY_HEADERS]
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$", re.I)

OUTDIR = Path(".")
VERBOSE = False


# =========================================================================== #
#  ANALYST HALF (requirement 2): audit log + run_logged()   [Handoff 5]
# =========================================================================== #
class CommandError(RuntimeError):
    """A command could not be run or finished with an error."""


def now() -> str:
    return datetime.now().astimezone().isoformat(timespec="milliseconds")


def audit(event: str, detail: str) -> None:
    """Append one timestamped line to audit.log (flushed immediately)."""
    with open(OUTDIR / "audit.log", "a") as log:
        log.write(f"{now()} {event:<6} {detail}\n")


def progress(message: str) -> None:
    if VERBOSE:
        print(f"[recon] {message}", file=sys.stderr, flush=True)


def run_logged(cmd: list[str], timeout: int = 60) -> str:
    """Run `cmd`, write the command, its outcome and a timestamp to audit.log, return stdout.

    Every stage calls this instead of subprocess.run, which is what makes the
    audit log complete. Raises CommandError on a missing binary, a timeout or a
    non-zero exit status (after logging it): errors are never swallowed here.
    """
    text = shlex.join(cmd)
    audit("RUN", text)
    progress(f"$ {text}")
    start = time.perf_counter()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        audit("ERROR", f"{text} -> command not found")
        raise CommandError(f"{cmd[0]}: command not found")
    except subprocess.TimeoutExpired:
        audit("ERROR", f"{text} -> timeout after {timeout}s")
        raise CommandError(f"{cmd[0]}: timeout after {timeout}s")
    elapsed = time.perf_counter() - start
    if proc.returncode != 0:
        reason = (proc.stderr.strip().splitlines() or proc.stdout.strip().splitlines() or ["no output"])[-1]
        audit("ERROR", f"{text} -> exit {proc.returncode} in {elapsed:.2f}s: {reason[:200]}")
        raise CommandError(f"{cmd[0]} exited with status {proc.returncode}: {reason[:200]}")
    audit("OK", f"{text} -> exit 0 in {elapsed:.2f}s, {len(proc.stdout)} bytes of output")
    return proc.stdout


def save_raw(name: str, text: str) -> None:
    raw = OUTDIR / "raw"
    raw.mkdir(exist_ok=True)
    (raw / name).write_text(text)
    audit("WRITE", f"raw/{name} ({len(text)} bytes)")


def run_stage(name: str, fn, *args) -> dict:
    """Run one stage in isolation: a failure is logged and recorded, never propagated."""
    audit("STAGE", f"{name} start")
    progress(f"stage {name} ...")
    try:
        data = fn(*args)
        data.setdefault("status", "ok")
    except Exception as exc:                 # stage isolation; the error is logged, stored and reported
        data = {"status": "error", "error": f"{type(exc).__name__}: {exc}"}
        print(f"[recon] stage {name} FAILED: {exc}", file=sys.stderr)
    audit("STAGE", f"{name} end status={data['status']}" + (f" error={data['error']}" if "error" in data else ""))
    return data


# =========================================================================== #
#  ENGINEER HALF (requirements 1, 3, 4): CLI and stages
# =========================================================================== #
def first_match(patterns: list[str], text: str) -> str | None:
    for pattern in patterns:
        m = re.search(rf"^\s*{pattern}:[ \t]*(\S.*?)\s*$", text, re.I | re.M)
        if m:
            return m.group(1)
    return None


# ---- domain mode ----------------------------------------------------------- #
def stage_whois_domain(domain: str) -> dict:
    out = run_logged(["whois", domain], timeout=45)
    save_raw("whois.txt", out)
    data = {
        "query": domain,
        "registrar": first_match(["Registrar", "Sponsoring Registrar", "registrar"], out),
        "registration_date": first_match(["Creation Date", "Created On", "Registered on", "created",
                                          "Registration Time", "Domain Registration Date"], out),
        "expiry_date": first_match(["Registry Expiry Date", "Registrar Registration Expiration Date",
                                    "Expiration Date", "Expiry date", "paid-till", "expires"], out),
        "registrant_organization": first_match(["Registrant Organization", "Registrant Organisation",
                                                "Registrant", "organisation", "org"], out),
    }
    data["fields_not_found"] = [k for k, v in data.items() if v is None]
    return data


def stage_dig_domain(domain: str) -> dict:
    records, errors = {}, {}
    for rtype in ("A", "MX", "NS", "TXT"):
        try:                                 # one failing record type does not stop the others
            out = run_logged(["dig", "+short", "+time=5", "+tries=2", domain, rtype], timeout=30)
            save_raw(f"dig_{rtype}.txt", out)
            records[rtype] = [line.strip() for line in out.splitlines() if line.strip()]
        except CommandError as exc:
            errors[rtype] = str(exc)
    data = {"query": domain, "records": records}
    if errors:
        data["errors"] = errors
        data["status"] = "error" if not records else "partial"
    return data


def parse_headers(raw: str) -> tuple[str | None, dict[str, str]]:
    """Return (status line, headers) of the LAST response in `curl -I` output."""
    blocks = [b for b in re.split(r"\r?\n\r?\n", raw.strip()) if b.strip().upper().startswith("HTTP/")]
    if not blocks:
        return None, {}
    lines = blocks[-1].splitlines()
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
    return lines[0].strip(), headers


def fetch_headers(url: str) -> dict:
    out = run_logged(["curl", "-sS", "-I", "-L", "--max-redirs", "3", "--max-time", "15", url], timeout=30)
    status_line, headers = parse_headers(out)
    if status_line is None:
        raise CommandError(f"curl returned no HTTP response for {url}")
    return {
        "url": url,
        "status_line": status_line,
        "headers": {name: headers.get(name) for name in REPORTED_HEADERS},
        "missing_security_headers": [label for name, label in SECURITY_HEADERS.items() if name not in headers],
        "_raw": out,
    }


def stage_curl_domain(domain: str) -> dict:
    last_error = None
    for scheme in ("https", "http"):         # prefer HTTPS, fall back to HTTP
        try:
            response = fetch_headers(f"{scheme}://{domain}/")
            save_raw("curl_headers.txt", response.pop("_raw"))
            return {"responses": [response]}
        except CommandError as exc:
            last_error = exc
    raise CommandError(f"no HTTP(S) response from {domain}: {last_error}")


# ---- IP mode --------------------------------------------------------------- #
def parse_nmap_xml(path: Path) -> list[dict]:
    """Same structure as Part 2 (parse_scan.py): one dict per live host."""
    hosts = []
    for host in ET.parse(path).getroot().findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue
        address = host.find("address[@addrtype='ipv4']")
        if address is None:
            address = host.find("address[@addrtype='ipv6']")
        hostname = host.find("hostnames/hostname")
        ports = []
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            ports.append({
                "port": int(port.get("portid")),
                "protocol": port.get("protocol"),
                "service": service.get("name") if service is not None else None,
                "version": (" ".join(x for x in (service.get("product"), service.get("version")) if x) or None)
                if service is not None else None,
            })
        hosts.append({"ip": address.get("addr") if address is not None else None,
                      "hostname": hostname.get("name") if hostname is not None else None,
                      "open_ports": sorted(ports, key=lambda p: p["port"])})
    return hosts


def stage_nmap(ip: str) -> dict:
    xml_path = OUTDIR / "raw" / "nmap.xml"
    xml_path.parent.mkdir(exist_ok=True)
    # No sudo: unprivileged nmap falls back to a TCP connect scan (-sT), which is all -sV needs.
    cmd = ["nmap", "-sV", "--open", "--top-ports", "100", "-oX", str(xml_path), ip]
    out = run_logged(cmd, timeout=300)
    save_raw("nmap_stdout.txt", out)
    audit("READ", f"raw/nmap.xml ({xml_path.stat().st_size} bytes, parsed with xml.etree.ElementTree)")
    hosts = parse_nmap_xml(xml_path)
    host = hosts[0] if hosts else {"ip": ip, "hostname": None, "open_ports": []}
    return {
        "command": shlex.join(cmd),
        "scope_of_scan": "100 most common TCP ports (--top-ports 100); other ports were NOT probed",
        "host_up": bool(hosts),
        "ip": host["ip"],
        "hostname": host["hostname"],
        "open_ports": host["open_ports"],
    }


def stage_dig_reverse(ip: str) -> dict:
    out = run_logged(["dig", "+short", "+time=5", "+tries=2", "-x", ip], timeout=30)
    save_raw("dig_reverse.txt", out)
    return {"query": f"-x {ip}", "records": {"PTR": [line.strip() for line in out.splitlines() if line.strip()]}}


def stage_whois_ip(ip: str) -> dict:
    out = run_logged(["whois", ip], timeout=45)
    save_raw("whois.txt", out)
    data = {
        "query": ip,
        "organization": first_match(["OrgName", "org-name", "Organization", "owner", "descr", "netname"], out),
        "country": first_match(["Country", "country"], out),
        "network_name": first_match(["NetName", "netname"], out),
        "network_range": first_match(["NetRange", "inetnum", "CIDR"], out),
    }
    if ipaddress.ip_address(ip).is_private:
        data["note"] = ("private (RFC 1918) address: whois describes the reserved block, "
                        "not the organization that operates this host")
    data["fields_not_found"] = [k for k, v in data.items() if v is None]
    return data


def stage_curl_ip(ip: str, nmap_result: dict) -> dict:
    """Fetch headers from every HTTP service nmap identified (nothing else is contacted)."""
    web_ports = [p for p in nmap_result.get("open_ports", []) if (p["service"] or "").startswith("http")]
    if not web_ports:
        return {"status": "skipped", "reason": "nmap found no HTTP service on the scanned ports", "responses": []}
    responses, errors = [], {}
    for port in web_ports:
        scheme = "https" if "https" in port["service"] or port["port"] in (443, 8443) else "http"
        url = f"{scheme}://{ip}:{port['port']}/"
        try:
            response = fetch_headers(url)
            save_raw(f"curl_headers_{port['port']}.txt", response.pop("_raw"))
            responses.append(response)
        except CommandError as exc:
            errors[url] = str(exc)
    data = {"responses": responses}
    if errors:
        data["errors"] = errors
        data["status"] = "error" if not responses else "partial"
    return data


# =========================================================================== #
#  ANALYST HALF (requirements 5 and 6): results.json and report.md
# =========================================================================== #
def write_results(results: dict) -> Path:
    path = OUTDIR / "results.json"
    path.write_text(json.dumps(results, indent=2) + "\n")
    audit("WRITE", f"results.json ({path.stat().st_size} bytes)")
    return path


def md_escape(value) -> str:
    return str(value).replace("|", "\\|") if value not in (None, "", []) else "—"


def generate_report(results: dict) -> str:
    meta = results["meta"]
    whois, dig, curl, nmap = (results.get(k, {}) for k in ("whois", "dig", "curl", "nmap"))
    responses = curl.get("responses", [])
    summary: list[tuple[str, str]] = [("Target", f"`{meta['target']}`"), ("Mode", meta["mode"])]

    if meta["mode"] == "ip":
        ports = nmap.get("open_ports", [])
        summary += [
            ("Open ports (top 100 TCP)", ", ".join(f"{p['port']}/{p['service']}" for p in ports) or
             ("none" if nmap.get("status") == "ok" else "—")),
            ("Reverse DNS (PTR)", ", ".join(dig.get("records", {}).get("PTR", [])) or "no PTR record"),
            ("Owner organization", md_escape(whois.get("organization"))),
            ("Country", md_escape(whois.get("country"))),
        ]
    else:
        records = dig.get("records", {})
        summary += [
            ("Registrar", md_escape(whois.get("registrar"))),
            ("Registered on", md_escape(whois.get("registration_date"))),
            ("Expires on", md_escape(whois.get("expiry_date"))),
            ("Registrant organization", md_escape(whois.get("registrant_organization"))),
            ("A records", ", ".join(records.get("A", [])) or "—"),
            ("Name servers", ", ".join(records.get("NS", [])) or "—"),
            ("Mail servers", ", ".join(records.get("MX", [])) or "—"),
            ("TXT records", str(len(records.get("TXT", [])))),
        ]
    for r in responses:
        summary.append((f"Web server at {r['url']}",
                        f"{r['status_line']}; Server: {md_escape(r['headers'].get('server'))}; "
                        f"X-Powered-By: {md_escape(r['headers'].get('x-powered-by'))}"))
        summary.append((f"Missing security headers at {r['url']}",
                        ", ".join(r["missing_security_headers"]) or "none"))
    failed = {k: v for k, v in results.items() if isinstance(v, dict) and v.get("status") in ("error", "partial")}
    summary.append(("Stages with errors", ", ".join(failed) or "none"))

    out = [f"# Reconnaissance report: {meta['target']}", "",
           f"- Mode: **{meta['mode']}**", f"- Started: {meta['started']}", f"- Finished: {meta['finished']}",
           f"- Tool: recon.py (commands and outcomes are recorded in `audit.log`)", "",
           "## Summary of findings", "", "| Finding | Value |", "|---|---|"]
    out += [f"| {k} | {v} |" for k, v in summary]

    if meta["mode"] == "ip":
        out += ["", "## Open ports", ""]
        if nmap.get("status") == "error":
            out.append(f"nmap stage failed: {nmap.get('error')}")
        else:
            out += [f"Command: `{nmap.get('command')}`", "",
                    f"Scope: {nmap.get('scope_of_scan')}. A port that is not listed was either closed or "
                    f"**not probed**; it is not proven closed.", "",
                    "| Port | Protocol | Service | Version |", "|---:|---|---|---|"]
            out += [f"| {p['port']} | {p['protocol']} | {md_escape(p['service'])} | {md_escape(p['version'])} |"
                    for p in nmap.get("open_ports", [])] or ["| — | — | no open ports found | — |"]
        out += ["", "## Reverse DNS and ownership", "",
                f"- PTR: {', '.join(dig.get('records', {}).get('PTR', [])) or 'no PTR record'}"
                if dig.get("status") != "error" else f"- dig stage failed: {dig.get('error')}"]
        if whois.get("status") == "error":
            out.append(f"- whois stage failed: {whois.get('error')}")
        else:
            out += [f"- Organization: {md_escape(whois.get('organization'))}",
                    f"- Country: {md_escape(whois.get('country'))}",
                    f"- Network: {md_escape(whois.get('network_name'))} ({md_escape(whois.get('network_range'))})"]
            if whois.get("note"):
                out.append(f"- Note: {whois['note']}")
    else:
        out += ["", "## Registration (whois)", ""]
        if whois.get("status") == "error":
            out.append(f"whois stage failed: {whois.get('error')}")
        else:
            out += ["| Field | Value |", "|---|---|",
                    f"| Registrar | {md_escape(whois.get('registrar'))} |",
                    f"| Registration date | {md_escape(whois.get('registration_date'))} |",
                    f"| Expiry date | {md_escape(whois.get('expiry_date'))} |",
                    f"| Registrant organization | {md_escape(whois.get('registrant_organization'))} |"]
        out += ["", "## DNS records", ""]
        if dig.get("status") == "error" and not dig.get("records"):
            out.append(f"dig stage failed: {dig.get('error') or dig.get('errors')}")
        else:
            out += ["| Type | Records |", "|---|---|"]
            for rtype in ("A", "MX", "NS", "TXT"):
                values = dig.get("records", {}).get(rtype)
                if values is None:
                    cell = f"query failed: {dig.get('errors', {}).get(rtype, 'unknown error')}"
                else:
                    cell = "<br>".join(f"`{md_escape(v)}`" for v in values) or "(no records)"
                out.append(f"| {rtype} | {cell} |")

    out += ["", "## HTTP response headers and missing security headers", ""]
    if curl.get("status") == "error" and not responses:
        out.append(f"curl stage failed: {curl.get('error') or curl.get('errors')}")
    elif curl.get("status") == "skipped":
        out.append(f"Not checked: {curl.get('reason')}.")
    for r in responses:
        h = r["headers"]
        out += [f"### {r['url']} — `{r['status_line']}`", "", "| Header | Value |", "|---|---|",
                f"| Server | {md_escape(h.get('server'))} |",
                f"| X-Powered-By | {md_escape(h.get('x-powered-by'))} |",
                f"| Content-Security-Policy | {md_escape(h.get('content-security-policy'))} |",
                f"| Strict-Transport-Security | {md_escape(h.get('strict-transport-security'))} |",
                f"| X-Frame-Options | {md_escape(h.get('x-frame-options'))} |", ""]
        if r["missing_security_headers"]:
            out.append("**Missing security headers:** " + ", ".join(r["missing_security_headers"]) + ".")
            if r["url"].startswith("http://") and any("HSTS" in m for m in r["missing_security_headers"]):
                out.append("(HSTS is only honoured over HTTPS; this service is plain HTTP, which is itself a finding.)")
        else:
            out.append("All three security headers (CSP, HSTS, X-Frame-Options) are present.")
        if h.get("server") or h.get("x-powered-by"):
            out.append("The `Server` / `X-Powered-By` headers disclose software and version information.")
        out.append("")
    for url, err in (curl.get("errors") or {}).items():
        out.append(f"- {url}: {err}")

    out += ["", "## Stage status", "", "| Tool | Status | Error |", "|---|---|---|"]
    for tool in ("whois", "dig", "curl", "nmap"):
        stage = results.get(tool, {})
        out.append(f"| {tool} | {stage.get('status', '—')} | "
                   f"{md_escape(stage.get('error') or stage.get('errors') or stage.get('reason'))} |")
    out.append("")
    return "\n".join(out)


def write_report(results_path: Path) -> Path:
    """The report is built from results.json on disk, not from in-memory state."""
    results = json.loads(results_path.read_text())
    audit("READ", f"{results_path.name} (to generate report.md)")
    path = OUTDIR / "report.md"
    path.write_text(generate_report(results))
    audit("WRITE", f"report.md ({path.stat().st_size} bytes)")
    return path


# =========================================================================== #
#  ENGINEER HALF (requirement 1): CLI
# =========================================================================== #
def detect_mode(target: str) -> str | None:
    try:
        ipaddress.ip_address(target)
        return "ip"
    except ValueError:
        return "domain" if DOMAIN_RE.match(target) else None


def main() -> int:
    global OUTDIR, VERBOSE
    parser = argparse.ArgumentParser(
        description="Multi-stage reconnaissance of a domain (whois, dig, curl -I) or an IP address "
                    "(nmap -sV, dig -x, whois). Scan only targets you are authorized to scan.")
    parser.add_argument("target", help="domain name or IP address")
    parser.add_argument("--mode", choices=["domain", "ip"], default=None, help="auto-detected if omitted")
    parser.add_argument("--output", default=None,
                        help="directory for output files (default: ./recon_<target>_<timestamp>/)")
    parser.add_argument("--verbose", action="store_true", help="print progress to stderr as the tool runs")
    parser.add_argument("--from-results", default=None, metavar="JSON",
                        help="do not run any stage: rebuild report.md from an existing results.json")
    args = parser.parse_args()

    detected = detect_mode(args.target)
    if detected is None:
        parser.error(f"{args.target!r} is neither an IP address nor a valid domain name")
    mode = args.mode or detected
    if mode != detected:
        parser.error(f"--mode {mode} does not match the target {args.target!r} "
                     f"(it looks like {'an IP address' if detected == 'ip' else 'a domain name'})")

    VERBOSE = args.verbose
    started = datetime.now()
    OUTDIR = Path(args.output) if args.output else Path(f"recon_{args.target}_{started:%Y%m%d_%H%M%S}")
    OUTDIR.mkdir(parents=True, exist_ok=True)
    audit("START", f"recon.py target={args.target} mode={mode} output={OUTDIR} argv={shlex.join(sys.argv[1:])}")
    progress(f"target={args.target} mode={mode} output={OUTDIR}/")

    if args.from_results:
        source = Path(args.from_results)
        audit("READ", f"{source} (--from-results: no stage is run)")
        results = json.loads(source.read_text())
        if results.get("meta", {}).get("target") != args.target:
            audit("ERROR", f"{source} is about {results.get('meta', {}).get('target')!r}, not {args.target!r}")
            parser.error(f"{source} does not describe target {args.target!r}")
        results_path = OUTDIR / "results.json"
        if source.resolve() != results_path.resolve():
            write_results(results)
    else:
        results = {"meta": {"tool": "recon.py", "target": args.target, "mode": mode,
                            "started": started.astimezone().isoformat(timespec="seconds")}}
        if mode == "domain":
            results["whois"] = run_stage("whois", stage_whois_domain, args.target)
            results["dig"] = run_stage("dig", stage_dig_domain, args.target)
            results["curl"] = run_stage("curl", stage_curl_domain, args.target)
            results["nmap"] = {"status": "skipped", "reason": "nmap is only run in IP mode"}
            audit("STAGE", "nmap skipped (domain mode)")
        else:
            results["nmap"] = run_stage("nmap", stage_nmap, args.target)
            results["dig"] = run_stage("dig", stage_dig_reverse, args.target)
            results["whois"] = run_stage("whois", stage_whois_ip, args.target)
            results["curl"] = run_stage("curl", stage_curl_ip, args.target, results["nmap"])
        results["meta"]["finished"] = datetime.now().astimezone().isoformat(timespec="seconds")
        results["meta"]["stage_status"] = {k: results[k]["status"] for k in ("whois", "dig", "curl", "nmap")}
        results_path = write_results(results)

    report_path = write_report(results_path)
    failed = [k for k in ("whois", "dig", "curl", "nmap") if results.get(k, {}).get("status") in ("error", "partial")]
    audit("END", f"exit={'1' if failed else '0'} failed_stages={failed or 'none'}")
    progress(f"done: {results_path}, {report_path}, {OUTDIR / 'audit.log'}")
    print(f"{OUTDIR}/")
    if failed:
        print(f"[recon] WARNING: stages with errors: {', '.join(failed)} (results are incomplete)", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
