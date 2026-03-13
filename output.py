"""
email_verify.output — Output formatters: table (Rich), JSON, CSV
"""

from __future__ import annotations

import csv
import io
import json
import sys
from datetime import datetime
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

RISK_COLORS = {"LOW": "green", "MEDIUM": "yellow", "HIGH": "red"}

# ── JSON ──────────────────────────────────────────────────────────────────────

def as_json(report: dict, indent: int = 2) -> str:
    """Return the full report as a JSON string."""
    return json.dumps(report, indent=indent, default=str)


def print_json(report: dict) -> None:
    sys.stdout.write(as_json(report) + "\n")


# ── CSV row ───────────────────────────────────────────────────────────────────

CSV_FIELDS = [
    "email",
    "timestamp",
    "syntax_valid",
    "domain",
    "resolved_ip",
    "disposable",
    "free_provider",
    "mx_valid",
    "mx_primary",
    "spf",
    "dmarc",
    "geo_country",
    "geo_region",
    "geo_city",
    "geo_zip",
    "geo_lat",
    "geo_lon",
    "geo_timezone",
    "geo_isp",
    "geo_org",
    "geo_asn",
    "mg_is_valid",
    "mg_mailbox_verification",
    "mg_is_disposable",
    "mg_is_role",
    "mg_did_you_mean",
    "mg_risk",
    "mg_reasons",
    "send_ok",
    "send_message_id",
    "risk_score",
    "risk_level",
    "risk_flags",
]


def report_to_csv_row(report: dict) -> dict:
    dom  = report.get("domain", {})
    dns  = report.get("dns", {})
    geo  = report.get("geo", {})
    v    = report.get("validation", {})
    sp   = report.get("send_probe", {})
    risk = report.get("risk", {})
    syn  = report.get("syntax", {})

    mx = dns.get("mx_records", [])
    primary_mx = mx[0][1] if mx else ""

    return {
        "email":                  report.get("email", ""),
        "timestamp":              report.get("timestamp", ""),
        "syntax_valid":           syn.get("valid", ""),
        "domain":                 dom.get("name", ""),
        "resolved_ip":            dom.get("resolved_ip", ""),
        "disposable":             dom.get("disposable", ""),
        "free_provider":          dom.get("free_provider", ""),
        "mx_valid":               dns.get("mx_valid", ""),
        "mx_primary":             primary_mx,
        "spf":                    bool(dns.get("spf")),
        "dmarc":                  bool(dns.get("dmarc")),
        "geo_country":            geo.get("country", ""),
        "geo_region":             geo.get("regionName", ""),
        "geo_city":               geo.get("city", ""),
        "geo_zip":                geo.get("zip", ""),
        "geo_lat":                geo.get("lat", ""),
        "geo_lon":                geo.get("lon", ""),
        "geo_timezone":           geo.get("timezone", ""),
        "geo_isp":                geo.get("isp", ""),
        "geo_org":                geo.get("org", ""),
        "geo_asn":                geo.get("as", ""),
        "mg_is_valid":            v.get("is_valid", ""),
        "mg_mailbox_verification": v.get("mailbox_verification", ""),
        "mg_is_disposable":       v.get("is_disposable_address", ""),
        "mg_is_role":             v.get("is_role_address", ""),
        "mg_did_you_mean":        v.get("did_you_mean", ""),
        "mg_risk":                v.get("risk", ""),
        "mg_reasons":             "|".join(v.get("reason", [])),
        "send_ok":                sp.get("send_ok", ""),
        "send_message_id":        sp.get("message_id", ""),
        "risk_score":             risk.get("score", ""),
        "risk_level":             risk.get("level", ""),
        "risk_flags":             "|".join(risk.get("flags", [])),
    }


def print_csv_header(writer: "csv.DictWriter") -> None:
    writer.writeheader()


def print_csv_row(report: dict, writer: "csv.DictWriter") -> None:
    writer.writerow(report_to_csv_row(report))


def reports_to_csv_string(reports: list[dict]) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=CSV_FIELDS, extrasaction="ignore")
    writer.writeheader()
    for r in reports:
        writer.writerow(report_to_csv_row(r))
    return buf.getvalue()


# ── Rich table (single report) ────────────────────────────────────────────────

def print_table(report: dict, console: Console | None = None) -> None:
    con = console or Console()

    syn  = report.get("syntax", {})
    dom  = report.get("domain", {})
    dns  = report.get("dns", {})
    geo  = report.get("geo", {})
    v    = report.get("validation", {})
    sp   = report.get("send_probe", {})
    risk = report.get("risk", {})

    con.print(f"\n[bold cyan]⬡ Email Intelligence — gb10.studio Validator[/bold cyan]")
    con.print(f"[dim]Analyzing:[/dim] [white]{report.get('email', '')}[/white]\n")

    if not syn.get("valid"):
        con.print(f"[red]✗ {syn.get('message', 'Invalid')}[/red]")
        return

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Key", style="dim", width=28)
    table.add_column("Value", style="white")

    table.add_row("Email",         report.get("email", ""))
    table.add_row("Domain",        dom.get("name", ""))
    table.add_row("Resolved IP",   dom.get("resolved_ip", "unresolved"))
    table.add_row("Disposable",    "[red]YES ⚠[/red]"  if dom.get("disposable")    else "[green]No[/green]")
    table.add_row("Free Provider", "[yellow]Yes[/yellow]" if dom.get("free_provider") else "[green]No[/green]")

    mx = dns.get("mx_records", [])
    if mx:
        for pref, host in mx:
            table.add_row(f"MX [{pref}]", f"[cyan]{host}[/cyan]")
    else:
        table.add_row("MX", "[red]None[/red]")

    table.add_row("SPF",   "[green]✓[/green]" if dns.get("spf")   else "[red]✗ Missing[/red]")
    table.add_row("DMARC", "[green]✓[/green]" if dns.get("dmarc") else "[red]✗ Missing[/red]")

    if geo.get("country"):
        table.add_row("Country",      f"{geo['country']} ({geo.get('countryCode', '')})")
        table.add_row("City/Region",  f"{geo.get('city','—')}, {geo.get('regionName','—')}")
        table.add_row("ZIP",          geo.get("zip", "—"))
        table.add_row("Coordinates",  f"{geo.get('lat')}, {geo.get('lon')}")
        table.add_row("Timezone",     geo.get("timezone", "—"))
        table.add_row("ISP",          geo.get("isp", "—"))
        table.add_row("Organization", geo.get("org", "—"))
        table.add_row("ASN",          geo.get("as", "—"))

    # Mailgun Validation
    if not v.get("configured"):
        table.add_row("Mailgun Validation", "[yellow]⚠ MAILGUN_API_KEY not set[/yellow]")
    elif v.get("error"):
        table.add_row("Validation Error", f"[red]{v['error']}[/red]")
    else:
        valid   = v.get("is_valid")
        table.add_row("Address Valid", "[green]✓ Yes[/green]" if valid else "[red]✗ No[/red]")
        mbv     = v.get("mailbox_verification")
        mbv_map = {
            "true":    "[green]✓ Exists[/green]",
            "false":   "[red]✗ Does not exist[/red]",
            "unknown": "[yellow]? Inconclusive[/yellow]",
        }
        table.add_row("Mailbox Exists",  mbv_map.get(mbv, "—"))
        if v.get("did_you_mean"):
            table.add_row("Did You Mean", f"[yellow]{v['did_you_mean']}[/yellow]")
        table.add_row("Disposable",    "[red]Yes ⚠[/red]"    if v.get("is_disposable_address") else "[green]No[/green]")
        table.add_row("Role Address",  "[yellow]Yes[/yellow]" if v.get("is_role_address")       else "[green]No[/green]")
        mg_risk   = v.get("risk", "—") or "—"
        risk_col  = {"high": "red", "medium": "yellow", "low": "green"}.get(mg_risk, "white")
        table.add_row("Mailgun Risk",  f"[{risk_col}]{mg_risk.upper()}[/{risk_col}]")
        for reason in v.get("reason", []):
            table.add_row("  Reason", f"[dim]{reason}[/dim]")

    # Send probe
    if sp.get("configured"):
        if sp.get("send_ok"):
            table.add_row("Send Probe",  "[green]✓ Queued by Mailgun[/green]")
            table.add_row("Message-ID",  sp.get("message_id", "—"))
        else:
            table.add_row("Send Probe",  f"[red]✗ {sp.get('error','Failed')}[/red]")

    # Risk
    level    = risk.get("level", "—")
    score    = risk.get("score", 0)
    col      = RISK_COLORS.get(level, "white")
    table.add_row("Risk Score", f"[{col}]{score}/100 — {level}[/{col}]")

    con.print(Panel(table, title="[bold cyan]Email Intelligence Report[/bold cyan]", border_style="cyan"))

    if risk.get("flags"):
        con.print("\n[bold yellow]Risk Flags:[/bold yellow]")
        for f in risk["flags"]:
            con.print(f"  [yellow]⚠[/yellow]  {f}")
    else:
        con.print("\n[green]✓ No risk flags.[/green]")

    con.print()
