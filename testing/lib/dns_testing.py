"""
DNS-related test utilities for PAN-OS policy testing.

This module provides utilities for testing DNS security policies in PAN-OS firewalls.
It includes functions for resolving domain names using different DNS protocols
(plain DNS, DNS-over-TLS, DNS-over-HTTPS), classifying the results, and generating
reports in CSV and HTML formats.

Functions:
    _blocked: Normalize connection-reset style errors.
    _classify: Classify DNS resolution results.
    _cls_css: Get CSS class for HTML export based on action.
    resolve_dns_over_tls: Resolve a domain using DNS-over-TLS.
    resolve_dns_over_https: Resolve a domain using DNS-over-HTTPS.
    resolve_plain_dns: Resolve a domain using plain DNS.
    test_dns_security: Test DNS security policies and generate reports.
"""
from __future__ import annotations

import base64
import csv
import datetime as _dt
import os
import ssl
import sys
from typing import Dict, List
import urllib3
# Suppress InsecureRequestWarning for unverified HTTPS requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

import dns.message
import dns.query
import dns.rdatatype
import dns.resolver
import requests
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from lib.rich_output import console
import settings
from lib.auxiliary_functions import parse_metadata_from_csv

# ──────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────
BLOCKED_IP_SENTINEL = "Not resolved"
CSV_DIR = "test-results"

# ──────────────────────────────────────────────────────────────
# Internal helpers
# ──────────────────────────────────────────────────────────────
def _blocked(exc: Exception) -> str:
    """
    Normalize connection-reset style errors.

    This function handles various connection errors that may occur during DNS resolution
    and normalizes them to a consistent format. It specifically detects connection reset
    errors which typically indicate that the DNS request was blocked by a firewall.

    Args:
        exc: Exception that occurred during DNS resolution

    Returns:
        str: A normalized error message or the BLOCKED_IP_SENTINEL constant
    """
    if isinstance(exc, ConnectionResetError):
        return BLOCKED_IP_SENTINEL
    txt = str(exc)
    if any(p in txt for p in ("10054", "forcibly closed", "Connection reset")):
        return BLOCKED_IP_SENTINEL
    return f"Error: {exc}"


# ──────────────────────────────────────────────────────────────
# Result classifier (tweaked for multi-IP + explicit RCODEs)
# ──────────────────────────────────────────────────────────────
def _classify(result: str) -> tuple[str, str]:
    """
    Return (plain, rich) verdict based on the resolver output.
    Handles lists like "1.1.1.1; 1.0.0.1" and explicit RCODE strings.
    """
    if result == BLOCKED_IP_SENTINEL:
        return "Blocked", "[bold yellow]Blocked[/bold yellow]"

    # DNS failure modes surfaced by the resolvers below
    if result.startswith("Error:"):
        return "Unknown", "Unknown"

    if result in ("", "No A records found"):
        return "Unknown", "Unknown"

    # Split any multi-IP string on semicolons
    ips = [ip.strip() for ip in result.split(";")]

    # Sinkhole check works even when multiple IPs are present
    if settings.DNS_SINKHOLE_RESOLVED_ADDRESS in ips:
        return "Sinkholed", "[bold red]Sinkholed[/bold red]"

    return "Allowed", "[bold green]Allowed[/bold green]"



def _cls_css(action: str) -> str:
    """
    Map DNS resolution actions to CSS classes for HTML export.

    This function takes a DNS resolution action (Sinkholed, Allowed, Blocked) and
    returns the corresponding CSS class name to be used in the HTML report.

    Args:
        action: The DNS resolution action (Sinkholed, Allowed, Blocked)

    Returns:
        str: The CSS class name for the given action
    """
    return {
        "Sinkholed": "sinkholed",
        "Allowed":   "allowed",
        "Blocked":   "error",
    }.get(action, "error")


# ──────────────────────────────────────────────────────────────
# Resolution engines
# ──────────────────────────────────────────────────────────────
# ──────────────────────────────────────────────────────────────
# DNS-over-TLS  (multi-IP + RCODE aware)
# ──────────────────────────────────────────────────────────────
def _resolve_dns_over_tls(fqdn: str, dns_server: str, timeout: float = 5.0) -> str:
    try:
        dns_query = dns.message.make_query(fqdn, dns.rdatatype.A)

        ctx = ssl.create_default_context()
        ctx.verify_mode = ssl.CERT_REQUIRED if settings.DOH_DOT_CERT_VERIFY else ssl.CERT_NONE
        ctx.check_hostname = bool(settings.DOH_DOT_CERT_VERIFY)

        dns_response = dns.query.tls(
            dns_query,
            where=dns_server,
            port=853,
            timeout=timeout,
            ssl_context=ctx,
            server_hostname=dns_server if ctx.check_hostname else None,
        )

        if dns_response.rcode() != dns.rcode.NOERROR:
            return f"Error: {dns.rcode.to_text(dns_response.rcode())}"

        ips = [
            rdata.address
            for rr in dns_response.answer
            if rr.rdtype == dns.rdatatype.A
            for rdata in rr
        ]
        return "; ".join(ips) if ips else "No A records found"
    except Exception as exc:
        return _blocked(exc)


# ──────────────────────────────────────────────────────────────
# DNS-over-HTTPS  (multi-IP + Status/RCODE aware)
# ──────────────────────────────────────────────────────────────
def _resolve_dns_over_https(fqdn: str, timeout: float = 5.0) -> str:
    doh_url = settings.DNS_OVER_HTTPS_URL.rstrip("/")
    try:
        verify = (
            os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")), settings.CA_BUNDLE)
            if settings.DOH_DOT_CERT_VERIFY
            else False
        )

        # Wire-format endpoint
        if doh_url.endswith("dns-query"):
            dns_query = dns.message.make_query(fqdn, dns.rdatatype.A)
            enc = base64.urlsafe_b64encode(dns_query.to_wire()).rstrip(b"=").decode()

            http_response = requests.get(
                doh_url,
                params={"dns": enc},
                headers={"Accept": "application/dns-message"},
                timeout=timeout,
                verify=verify,
            )
            if http_response.status_code != 200:
                return f"Error: HTTP {http_response.status_code}"

            dns_response = dns.message.from_wire(http_response.content)
            if dns_response.rcode() != dns.rcode.NOERROR:
                return f"Error: {dns.rcode.to_text(dns_response.rcode())}"

            ips = [
                rdata.address
                for rr in dns_response.answer
                if rr.rdtype == dns.rdatatype.A
                for rdata in rr
            ]
            return "; ".join(ips) if ips else "No A records found"

        # JSON endpoint
        http_response = requests.get(
            doh_url,
            params={"name": fqdn, "type": "A"},
            headers={"Accept": "application/dns-json"},
            timeout=timeout,
            verify=verify,
        )
        if http_response.status_code != 200:
            return f"Error: HTTP {http_response.status_code}"

        json_payload = http_response.json()
        dns_status = json_payload.get("Status", 0)  # 0 == NOERROR
        if dns_status != 0:
            return f"Error: {dns.rcode.to_text(dns_status)}"

        ips = [a.get("data", "") for a in json_payload.get("Answer", []) if a.get("type") == 1]
        return "; ".join(ips) if ips else "No A records found"

    except requests.exceptions.ConnectionError as exc:
        return _blocked(exc)
    except Exception as exc:
        return _blocked(exc)


# ──────────────────────────────────────────────────────────────
# Plain-text DNS  (multi-IP + RCODE aware)
# ──────────────────────────────────────────────────────────────
def _resolve_plain_text_dns(fqdn: str, dns_server: str, timeout: float = 5.0) -> str:
    """
    Resolve an FQDN via plain UDP/TCP DNS.

    Returns:
        - "ip1; ip2; …"  (all A records)
        - "No A records found"
        - "Error: <RCODE|TIMEOUT|…>"
        - BLOCKED_IP_SENTINEL via _blocked()
    """
    try:
        resolver = dns.resolver.Resolver(configure=False)  # avoid /etc/resolv.conf search domains
        resolver.nameservers = [dns_server]
        resolver.timeout = timeout
        resolver.lifetime = timeout
        resolver.search = ()  # no search list

        dns_response = resolver.resolve(
            fqdn,
            rdtype="A",
            raise_on_no_answer=False,
            lifetime=timeout,
        )

        if dns_response.rrset is None:  # No A records but query succeeded
            return "No A records found"

        ips = [r.address for r in dns_response]
        return "; ".join(ips)

    except dns.resolver.NXDOMAIN:
        return "Error: NXDOMAIN"
    except dns.resolver.NoAnswer:
        return "No A records found"
    except dns.resolver.NoNameservers:
        return "Error: NoNameServers"
    except dns.exception.Timeout:
        return "Error: TIMEOUT"
    except Exception as exc:
        return _blocked(exc)


# ──────────────────────────────────────────────────────────────
# Public entry point
# ──────────────────────────────────────────────────────────────
def test_dns_security(panos_device=None) -> None:  # noqa: D401
    """
    Test DNS security policies and generate reports.

    This function is the main entry point for DNS security testing. It prompts the user
    for a DNS server address, reads a list of FQDNs from a CSV file, and tests each FQDN
    using three different DNS resolution methods: plain DNS, DNS-over-TLS, and DNS-over-HTTPS.
    The results are displayed in a table and exported to CSV and HTML files.

    Args:
        panos_device: The PAN-OS device object (not used in this function but kept for
                     consistency with other test functions)

    Returns:
        None
    """
    console.print("[bold green]Testing DNS Security…[/bold green]")

    dns_server = (
        input(f"Enter DNS server address [`{settings.DEFAULT_DNS_SERVER}`]: ")
        or settings.DEFAULT_DNS_SERVER
    )

    fqdns = parse_metadata_from_csv(
        "FQDNs", os.path.join("..", settings.TEST_FQDNS_FILENAME),
        suppress_output=True
    )
    if not fqdns:
        console.print(f"[bold red]No FQDNs in {settings.TEST_FQDNS_FILENAME}[/bold red]")
        input("Press Enter…")
        return

    # Build table
    from rich.table import Table
    table = Table(title=f"DNS results via {dns_server}")
    for col, style in [("Description", "magenta"), ("FQDN", "cyan"),
                       ("DNS-over-TLS", "green"), ("DoT Action", None),
                       ("DNS-over-HTTPS", "green"), ("DoH Action", None),
                       ("Regular DNS", "green"), ("DNS Action", None),
                       ("Policy", "yellow")]:
        table.add_column(col, style or "")

    rows: List[Dict[str, str]] = []

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  BarColumn(), TextColumn("{task.percentage:>3.0f}%")) as prog:
        task = prog.add_task("[cyan]Testing DNS resolutions...", total=len(fqdns))

        for entry in fqdns:
            fqdn = entry.get("FQDN") or entry.get("fqdn")
            if not fqdn:
                prog.update(task, advance=1)
                continue

            desc = entry.get("Description", "n/a")
            pol  = entry.get("DNS Security Policy", "n/a")

            dot  = _resolve_dns_over_tls(fqdn, dns_server)
            doh  = _resolve_dns_over_https(fqdn)
            pla  = _resolve_plain_text_dns(fqdn, dns_server)

            dot_act, dot_rich   = _classify(dot)
            doh_act, doh_rich   = _classify(doh)
            pla_act, pla_rich   = _classify(pla)

            table.add_row(desc, fqdn,
                          dot, dot_rich,
                          doh, doh_rich,
                          pla, pla_rich,
                          pol)
            rows.append(dict(desc=desc, fqdn=fqdn,
                             dot_ip=dot,   dot_action=dot_act,
                             doh_ip=doh,   doh_action=doh_act,
                             pla_ip=pla,   pla_action=pla_act,
                             pol=pol))

            prog.update(task, advance=1)

    console.print(table)

    # ── export
    timestamp = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs(CSV_DIR, exist_ok=True)
    csv_path  = os.path.join(CSV_DIR, f"dns_security_{timestamp}.csv")
    html_path = os.path.join(CSV_DIR, f"dns_security_{timestamp}.html")

    with open(csv_path, "w", newline="", encoding="utf-8") as fp:
        w = csv.writer(fp)
        w.writerow(["Description", "FQDN",
                    "DoT IP", "DoT Action",
                    "DoH IP", "DoH Action",
                    "Plain IP", "Plain Action",
                    "Policy"])
        for r in rows:
            w.writerow([r["desc"], r["fqdn"],
                        r["dot_ip"],  r["dot_action"],
                        r["doh_ip"],  r["doh_action"],
                        r["pla_ip"],  r["pla_action"],
                        r["pol"]])

    with open(html_path, "w", encoding="utf-8") as fp:
        fp.write(f"""<!doctype html><html><head><meta charset='utf-8'>
<title>DNS Security Results</title>
<style>
table{{border-collapse:collapse;width:100%}}
th,td{{border:1px solid #ddd;padding:6px;text-align:left}}
th{{background:#f2f2f2}}
tr:nth-child(even){{background:#f9f9f9}}
.allowed{{background:#e6ffe6}}
.sinkholed{{background:#ffe6e6}}
.error{{background:#fff6e6}}
</style></head><body>
<h1>DNS Security Results</h1><p>Generated {_dt.datetime.now():%Y-%m-%d %H:%M:%S}</p>
<table><tr><th>Description</th><th>FQDN</th>
<th>DoT IP</th><th>DoT Action</th>
<th>DoH IP</th><th>DoH Action</th>
<th>Plain IP</th><th>Plain Action</th>
<th>Policy</th></tr>
""")
        for r in rows:
            cls = _cls_css(r["pla_action"])
            fp.write(f"<tr class='{cls}'>")
            for col in ("desc", "fqdn", "dot_ip", "dot_action",
                        "doh_ip", "doh_action",
                        "pla_ip", "pla_action", "pol"):
                fp.write(f"<td>{r[col]}</td>")
            fp.write("</tr>")
        fp.write("</table></body></html>")
    console.print(f"[bold cyan]CSV:[/bold cyan]  {os.path.abspath(csv_path)}")
    console.print(f"[bold cyan]HTML:[/bold cyan] {os.path.abspath(html_path)}")
    input("Press Enter to continue…")
