#!/usr/bin/env python3
"""
email_validator.py — Email Intelligence & SMTP Verification Tool
For gb10.studio signup validation

Usage:
    python3 email_validator.py [email@example.com]
    python3 email_validator.py  (launches interactive TUI)

Dependencies:
    pip install dnspython textual httpx python-dotenv

Secrets (secrets.env in same dir or cwd):
    MAILGUN_API_KEY=key-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    MAILGUN_SMTP_HOST=smtp.mailgun.org
    MAILGUN_SMTP_PORT=587
    MAILGUN_SMTP_USER=postmaster@mg.gb10.studio
    MAILGUN_SMTP_PASSWORD=your-mailgun-smtp-password
    MAILGUN_FROM=verify@gb10.studio
    MAILGUN_DOMAIN=mg.gb10.studio
"""

import asyncio
import os
import re
import smtplib
import socket
import ssl
import sys
import random
import string
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Optional

import dns.resolver
import httpx
from dotenv import load_dotenv

# ──────────────────────────────────────────────
# CREDENTIALS  (loaded lazily from config system)
# ──────────────────────────────────────────────
# core.py reads directly from env vars which are populated by
# email_verify.config.load_config() before full_analysis() is called.
# When running as a standalone script the old secrets.env fallback still works.

def _get_creds():
    """Return current credential snapshot from environment."""
    return dict(
        api_key       = os.getenv("MAILGUN_API_KEY", ""),
        smtp_host     = os.getenv("MAILGUN_SMTP_HOST", "smtp.mailgun.org"),
        smtp_port     = int(os.getenv("MAILGUN_SMTP_PORT", "587")),
        smtp_user     = os.getenv("MAILGUN_SMTP_USER", ""),
        smtp_password = os.getenv("MAILGUN_SMTP_PASSWORD", ""),
        from_address  = os.getenv("MAILGUN_FROM", "verify@gb10.studio"),
        domain        = os.getenv("MAILGUN_DOMAIN", "mg.gb10.studio"),
    )


from textual.app import App, ComposeResult
from textual.containers import Container, Vertical, Horizontal, ScrollableContainer
from textual.widgets import (
    Header, Footer, Input, Button, Label, Static, LoadingIndicator, Rule
)
from textual.reactive import reactive
from textual import work
from textual.worker import Worker, WorkerState
from rich.text import Text
from rich.table import Table
from rich.console import Console
from rich.panel import Panel


# ──────────────────────────────────────────────
# CORE VALIDATION ENGINE
# ──────────────────────────────────────────────

DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com",
    "tempmail.com", "throwaway.email", "yopmail.com", "sharklasers.com",
    "guerrillamailblock.com", "grr.la", "guerrillamail.info",
    "trashmail.com", "dispostable.com", "fakeinbox.com",
    "maildrop.cc", "spamgourmet.com", "spam4.me",
}

FREE_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "live.com", "icloud.com", "aol.com", "protonmail.com",
    "proton.me", "zoho.com", "mail.com",
}

def fake_sender():
    """Generate a plausible-looking fake sender for SMTP probing."""
    names = ["info", "noreply", "verify", "support", "hello", "admin"]
    rand = ''.join(random.choices(string.ascii_lowercase, k=5))
    return f"{random.choice(names)}.{rand}@gb10.studio"

def validate_syntax(email: str) -> tuple[bool, str]:
    pattern = r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$'
    if re.match(pattern, email):
        return True, "Valid syntax"
    return False, "Invalid email syntax"

def get_domain(email: str) -> str:
    return email.split("@")[-1].lower() if "@" in email else ""

async def resolve_dns(domain: str) -> dict:
    result = {
        "mx_records": [],
        "a_records": [],
        "spf": None,
        "dmarc": None,
        "mx_valid": False,
    }
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
    resolver.timeout = 5
    resolver.lifetime = 10

    # MX records
    try:
        mx_answers = resolver.resolve(domain, "MX")
        result["mx_records"] = sorted(
            [(int(r.preference), str(r.exchange).rstrip('.')) for r in mx_answers],
            key=lambda x: x[0]
        )
        result["mx_valid"] = len(result["mx_records"]) > 0
    except Exception as e:
        result["mx_error"] = str(e)

    # A records
    try:
        a_answers = resolver.resolve(domain, "A")
        result["a_records"] = [str(r) for r in a_answers]
    except Exception:
        pass

    # SPF (TXT record containing spf)
    try:
        txt_answers = resolver.resolve(domain, "TXT")
        for rdata in txt_answers:
            txt = "".join([s.decode() for s in rdata.strings])
            if txt.startswith("v=spf1"):
                result["spf"] = txt
    except Exception:
        pass

    # DMARC
    try:
        dmarc_answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rdata in dmarc_answers:
            txt = "".join([s.decode() for s in rdata.strings])
            if "v=DMARC" in txt:
                result["dmarc"] = txt
    except Exception:
        pass

    return result

async def mailgun_validate_address(email: str) -> dict:
    """
    Use the Mailgun Email Validation API (v4) to verify the address.
    Requires MAILGUN_API_KEY — paid Email Validation add-on.
    """
    creds = _get_creds()
    result = {
        "configured": bool(creds["api_key"]),
        "is_valid": None,
        "mailbox_verification": None,
        "is_disposable_address": None,
        "is_role_address": None,
        "did_you_mean": None,
        "risk": None,
        "reason": [],
        "raw": {},
        "error": None,
    }

    if not creds["api_key"]:
        result["error"] = "MAILGUN_API_KEY not set"
        return result

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                "https://api.mailgun.net/v4/address/validate",
                params={"address": email},
                auth=("api", creds["api_key"]),
            )
            data = resp.json()
            result["raw"] = data
            if resp.status_code != 200:
                result["error"] = f"API returned {resp.status_code}: {data.get('message', resp.text)}"
                return result
            result["is_valid"]              = data.get("is_valid")
            result["mailbox_verification"]  = data.get("mailbox_verification")
            result["is_disposable_address"] = data.get("is_disposable_address")
            result["is_role_address"]       = data.get("is_role_address")
            result["did_you_mean"]          = data.get("did_you_mean")
            result["risk"]                  = data.get("risk")
            result["reason"]                = data.get("reason", [])
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"

    return result


async def mailgun_send_probe(email: str) -> dict:
    """Send a probe message via the Mailgun Messages API."""
    creds = _get_creds()
    result = {
        "configured": bool(creds["api_key"] and creds["domain"]),
        "send_ok": False,
        "message_id": None,
        "error": None,
    }

    if not result["configured"]:
        result["error"] = "MAILGUN_API_KEY or MAILGUN_DOMAIN not set"
        return result

    rand_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
    html_body = f"""<html><body style="font-family:monospace;color:#1a1a2e;background:#f4f6fb;padding:32px">
<h2 style="color:#1565c0">⬡ gb10.studio — Email Probe</h2>
<p>Automated deliverability probe for signup validation.</p>
<table style="border-collapse:collapse;font-size:13px">
  <tr><td style="padding:4px 16px 4px 0;color:#546e7a">Probe ID</td><td><code>{rand_id}</code></td></tr>
  <tr><td style="padding:4px 16px 4px 0;color:#546e7a">Timestamp</td><td>{datetime.now().isoformat()}</td></tr>
  <tr><td style="padding:4px 16px 4px 0;color:#546e7a">Recipient</td><td>{email}</td></tr>
</table></body></html>"""

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                f"https://api.mailgun.net/v3/{creds['domain']}/messages",
                auth=("api", creds["api_key"]),
                data={
                    "from":          creds["from_address"],
                    "to":            email,
                    "subject":       "gb10.studio — Email Verification Probe",
                    "text":          f"gb10.studio probe.\nProbe ID: {rand_id}\n{datetime.now().isoformat()}",
                    "html":          html_body,
                    "h:X-Probe-ID":  rand_id,
                },
            )
            data = resp.json()
            if resp.status_code == 200:
                result["send_ok"]    = True
                result["message_id"] = data.get("id", "")
            else:
                result["error"] = f"API {resp.status_code}: {data.get('message', '')}"
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"

    return result


async def geo_lookup(ip: str) -> dict:
    """Free IP geolocation via ip-api.com."""
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            resp = await client.get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query")
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    return data
    except Exception:
        pass
    return {}

async def whois_asn(ip: str) -> dict:
    """Get ASN/org info from ipinfo.io (no key needed for basic)."""
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            resp = await client.get(f"https://ipinfo.io/{ip}/json")
            if resp.status_code == 200:
                return resp.json()
    except Exception:
        pass
    return {}

async def full_analysis(email: str) -> dict:
    """Master analysis pipeline."""
    report = {
        "email": email,
        "timestamp": datetime.now().isoformat(),
        "syntax": {},
        "domain": {},
        "dns": {},
        "geo": {},
        "ipinfo": {},
        "validation": {},   # Mailgun Email Validation API result
        "send_probe": {},   # Mailgun Messages API send result
        "risk": {},
    }

    # Syntax
    ok, msg = validate_syntax(email)
    report["syntax"] = {"valid": ok, "message": msg}
    if not ok:
        return report

    domain = get_domain(email)
    report["domain"] = {
        "name": domain,
        "disposable": domain in DISPOSABLE_DOMAINS,
        "free_provider": domain in FREE_EMAIL_DOMAINS,
    }

    # DNS
    dns_data = await resolve_dns(domain)
    report["dns"] = dns_data

    # Geo for first A record or first MX IP
    target_ip = None
    if dns_data.get("a_records"):
        target_ip = dns_data["a_records"][0]
    elif dns_data.get("mx_records"):
        mx_host = dns_data["mx_records"][0][1]
        try:
            target_ip = socket.gethostbyname(mx_host)
        except Exception:
            pass

    if target_ip:
        geo, ipinfo = await asyncio.gather(
            geo_lookup(target_ip),
            whois_asn(target_ip),
        )
        report["geo"] = geo
        report["ipinfo"] = ipinfo
        report["domain"]["resolved_ip"] = target_ip

    # Run Mailgun validation API + send probe concurrently
    validation_result, send_result = await asyncio.gather(
        mailgun_validate_address(email),
        mailgun_send_probe(email),
    )
    report["validation"] = validation_result
    report["send_probe"] = send_result

    # ── Risk Scoring ─────────────────────────────────────────────────
    risk_score = 0
    risk_flags = []

    if report["domain"]["disposable"]:
        risk_score += 60
        risk_flags.append("Disposable email domain")
    if not dns_data.get("mx_valid"):
        risk_score += 40
        risk_flags.append("No MX records found")
    if not dns_data.get("spf"):
        risk_score += 10
        risk_flags.append("No SPF record")
    if not dns_data.get("dmarc"):
        risk_score += 10
        risk_flags.append("No DMARC record")

    # Mailgun Validation API is the authoritative verdict
    v = report.get("validation", {})
    if v.get("configured"):
        if v.get("is_valid") is False:
            risk_score += 60
            risk_flags.append("Mailgun: address flagged as INVALID")
        if v.get("mailbox_verification") == "false":
            risk_score += 55
            risk_flags.append("Mailgun: mailbox does NOT exist (MX RCPT probe failed)")
        elif v.get("mailbox_verification") == "unknown":
            risk_score += 15
            risk_flags.append("Mailgun: mailbox existence inconclusive (catch-all or greylisting)")
        if v.get("is_disposable_address"):
            if not report["domain"]["disposable"]:   # avoid double-counting
                risk_score += 40
                risk_flags.append("Mailgun: address identified as disposable")
        if v.get("is_role_address"):
            risk_score += 10
            risk_flags.append("Role address (e.g. postmaster@, abuse@, info@)")
        if v.get("did_you_mean"):
            risk_flags.append(f"Did you mean: {v['did_you_mean']}?")
        mg_risk = v.get("risk", "")
        if mg_risk == "high":
            risk_score += 30
            risk_flags.append("Mailgun risk classification: HIGH")
        elif mg_risk == "medium":
            risk_score += 15
            risk_flags.append("Mailgun risk classification: MEDIUM")
        for reason in v.get("reason", []):
            risk_flags.append(f"Mailgun reason: {reason}")
        if v.get("error"):
            risk_flags.append(f"Validation API error: {v['error']}")
    else:
        risk_flags.append("Mailgun validation not configured — add MAILGUN_API_KEY to secrets.env")

    # Send probe — note: a successful send does NOT mean the address is valid
    # (Mailgun queues and attempts async), but a hard API rejection does matter
    sp = report.get("send_probe", {})
    if sp.get("configured") and sp.get("error") and not sp.get("send_ok"):
        risk_score += 10
        risk_flags.append(f"Send probe API error: {sp['error']}")

    risk_level = "LOW" if risk_score < 20 else "MEDIUM" if risk_score < 50 else "HIGH"
    report["risk"] = {
        "score": min(risk_score, 100),
        "level": risk_level,
        "flags": risk_flags,
    }

    return report


# ──────────────────────────────────────────────
# TEXTUAL TUI
# ──────────────────────────────────────────────

RISK_COLORS = {"LOW": "green", "MEDIUM": "yellow", "HIGH": "red"}

class ResultPanel(Static):
    """Renders the analysis result."""

    def render_report(self, report: dict) -> str:
        lines = []

        def row(label, value, color="white"):
            return f"[dim]{label:<28}[/dim] [{color}]{value}[/{color}]"

        lines.append(f"\n[bold cyan]━━ EMAIL INTELLIGENCE REPORT ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold cyan]")
        lines.append(f"[dim]Analyzed:[/dim] [white]{report['email']}[/white]   [dim]{report['timestamp']}[/dim]\n")

        # Syntax
        lines.append("[bold]● SYNTAX[/bold]")
        syn = report.get("syntax", {})
        color = "green" if syn.get("valid") else "red"
        lines.append(row("  Format", syn.get("message", "—"), color))

        if not syn.get("valid"):
            return "\n".join(lines)

        # Domain
        lines.append("\n[bold]● DOMAIN[/bold]")
        dom = report.get("domain", {})
        lines.append(row("  Domain", dom.get("name", "—")))
        lines.append(row("  Resolved IP", dom.get("resolved_ip", "unresolved"), "cyan"))
        lines.append(row("  Disposable", "YES ⚠" if dom.get("disposable") else "No", "red" if dom.get("disposable") else "green"))
        lines.append(row("  Free Provider", "Yes" if dom.get("free_provider") else "No", "yellow" if dom.get("free_provider") else "green"))

        # DNS
        lines.append("\n[bold]● DNS[/bold]")
        dns_d = report.get("dns", {})
        mx = dns_d.get("mx_records", [])
        if mx:
            for pref, host in mx:
                lines.append(row(f"  MX [{pref}]", host, "cyan"))
        else:
            lines.append(row("  MX Records", "NONE FOUND ✗", "red"))

        a_recs = dns_d.get("a_records", [])
        lines.append(row("  A Records", ", ".join(a_recs) if a_recs else "none", "cyan" if a_recs else "dim"))
        lines.append(row("  SPF", "✓ Present" if dns_d.get("spf") else "✗ Missing", "green" if dns_d.get("spf") else "red"))
        lines.append(row("  DMARC", "✓ Present" if dns_d.get("dmarc") else "✗ Missing", "green" if dns_d.get("dmarc") else "red"))

        if dns_d.get("spf"):
            spf_short = dns_d["spf"][:80] + "..." if len(dns_d["spf"]) > 80 else dns_d["spf"]
            lines.append(row("  SPF Value", spf_short, "dim"))

        # Geolocation
        geo = report.get("geo", {})
        ipinfo = report.get("ipinfo", {})
        if geo or ipinfo:
            lines.append("\n[bold]● GEOLOCATION[/bold]")
            if geo.get("country"):
                lines.append(row("  Country", f"{geo.get('country', '—')} ({geo.get('countryCode', '')})", "yellow"))
                lines.append(row("  Region", geo.get("regionName", "—")))
                lines.append(row("  City", geo.get("city", "—")))
                lines.append(row("  ZIP", geo.get("zip", "—")))
                lat, lon = geo.get("lat"), geo.get("lon")
                if lat and lon:
                    lines.append(row("  Coordinates", f"{lat}, {lon}"))
                lines.append(row("  Timezone", geo.get("timezone", "—")))
                lines.append(row("  ISP", geo.get("isp", "—"), "cyan"))
                lines.append(row("  Organization", geo.get("org", "—"), "cyan"))
                lines.append(row("  ASN", geo.get("as", "—"), "dim"))

        # Mailgun Email Validation API
        v = report.get("validation", {})
        lines.append("\n[bold]● MAILGUN EMAIL VALIDATION[/bold]")
        if not v.get("configured"):
            lines.append(row("  Status", "⚠ MAILGUN_API_KEY not set in secrets.env", "yellow"))
        else:
            if v.get("error"):
                lines.append(row("  API Error", v["error"], "red"))
            else:
                valid = v.get("is_valid")
                lines.append(row("  Address Valid", "✓ Yes" if valid else "✗ No", "green" if valid else "red"))
                mbv = v.get("mailbox_verification")
                mbv_color = {"true": "green", "false": "red", "unknown": "yellow"}.get(mbv, "dim")
                mbv_label = {"true": "✓ Exists", "false": "✗ Does not exist", "unknown": "? Inconclusive (catch-all / greylisting)"}.get(mbv, "—")
                lines.append(row("  Mailbox Exists", mbv_label, mbv_color))
                if v.get("did_you_mean"):
                    lines.append(row("  Did You Mean", v["did_you_mean"], "yellow"))
                lines.append(row("  Disposable", "Yes ⚠" if v.get("is_disposable_address") else "No", "red" if v.get("is_disposable_address") else "green"))
                lines.append(row("  Role Address", "Yes" if v.get("is_role_address") else "No", "yellow" if v.get("is_role_address") else "green"))
                mg_risk = v.get("risk", "—")
                risk_col = {"high": "red", "medium": "yellow", "low": "green"}.get(mg_risk, "dim")
                lines.append(row("  Mailgun Risk", mg_risk.upper() if mg_risk else "—", risk_col))
                for reason in v.get("reason", []):
                    lines.append(row("  Reason", reason, "dim"))

        # Send Probe
        sp = report.get("send_probe", {})
        if sp.get("configured"):
            lines.append("\n[bold]● MAILGUN SEND PROBE[/bold]")
            if sp.get("send_ok"):
                lines.append(row("  Queued by Mailgun", "✓ Accepted", "green"))
                lines.append(row("  Message-ID", sp.get("message_id", "—"), "dim"))
            else:
                lines.append(row("  Queued by Mailgun", "✗ Rejected", "red"))
                if sp.get("error"):
                    lines.append(row("  Error", sp["error"], "red"))

        # Risk Assessment
        risk = report.get("risk", {})
        if risk:
            level = risk.get("level", "—")
            score = risk.get("score", 0)
            color = RISK_COLORS.get(level, "white")
            lines.append(f"\n[bold]● RISK ASSESSMENT[/bold]")
            bar_filled = int(score / 5)
            bar = "█" * bar_filled + "░" * (20 - bar_filled)
            lines.append(f"  [{color}]Score: {score}/100  [{bar}]  {level} RISK[/{color}]")
            for flag in risk.get("flags", []):
                lines.append(f"  [yellow]⚠[/yellow]  {flag}")
            if not risk.get("flags"):
                lines.append(f"  [green]✓[/green]  No risk flags detected")

        lines.append(f"\n[bold cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold cyan]\n")
        return "\n".join(lines)

    def display_report(self, report: dict):
        self.update(self.render_report(report))

    def display_error(self, msg: str):
        self.update(f"\n[red bold]  ✗ Error:[/red bold] [red]{msg}[/red]\n")

    def display_loading(self):
        self.update("\n[dim cyan]  ⟳ Running analysis pipeline...[/dim cyan]\n  [dim]DNS • SMTP • GeoIP • ASN lookups in progress[/dim]\n")


class EmailValidatorApp(App):
    CSS = """
    Screen {
        background: #0a0e1a;
    }

    Header {
        background: #0d1224;
        color: #4fc3f7;
        text-style: bold;
        border-bottom: solid #1a2744;
    }

    Footer {
        background: #0d1224;
        color: #546e7a;
        border-top: solid #1a2744;
    }

    #main-container {
        padding: 1 2;
        height: 100%;
    }

    #title-bar {
        height: 3;
        content-align: center middle;
        color: #4fc3f7;
        text-style: bold;
        margin-bottom: 1;
    }

    #subtitle {
        height: 1;
        content-align: center middle;
        color: #37474f;
        margin-bottom: 1;
    }

    #input-row {
        height: 3;
        margin-bottom: 1;
    }

    #email-input {
        width: 1fr;
        background: #0d1224;
        border: solid #1a2744;
        color: #e0f7fa;
        padding: 0 1;
    }

    #email-input:focus {
        border: solid #4fc3f7;
    }

    #verify-btn {
        width: 18;
        background: #1a3a5c;
        color: #4fc3f7;
        border: solid #1e4976;
        margin-left: 1;
    }

    #verify-btn:hover {
        background: #1e4976;
        color: #81d4fa;
    }

    #verify-btn:focus {
        border: solid #4fc3f7;
    }

    #result-scroll {
        height: 1fr;
        border: solid #1a2744;
        background: #080b14;
        padding: 0 1;
    }

    #result-panel {
        color: #cfd8dc;
    }

    #status-bar {
        height: 1;
        color: #37474f;
        margin-top: 1;
    }
    """

    TITLE = "Email Intelligence"
    BINDINGS = [
        ("ctrl+c", "quit", "Quit"),
        ("ctrl+l", "clear", "Clear"),
        ("f5", "analyze", "Analyze"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        with Container(id="main-container"):
            yield Static("⬡  EMAIL INTELLIGENCE & SMTP VERIFICATION", id="title-bar")
            yield Static("gb10.studio signup validator · DNS · SMTP · GeoIP · ASN", id="subtitle")
            with Horizontal(id="input-row"):
                yield Input(placeholder="Enter email address to validate...", id="email-input")
                yield Button("⬡  Analyze", id="verify-btn", variant="primary")
            with ScrollableContainer(id="result-scroll"):
                yield ResultPanel(
                    "\n[dim]  Enter an email address above and press Analyze or hit Enter.[/dim]\n"
                    "  [dim]All lookups run locally. No data is stored or transmitted to third parties.[/dim]\n",
                    id="result-panel"
                )
            yield Static("", id="status-bar")
        yield Footer()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.run_analysis()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "verify-btn":
            self.run_analysis()

    def action_analyze(self) -> None:
        self.run_analysis()

    def action_clear(self) -> None:
        self.query_one("#email-input", Input).value = ""
        self.query_one("#result-panel", ResultPanel).update(
            "\n[dim]  Cleared. Enter a new email address.[/dim]\n"
        )
        self.query_one("#status-bar", Static).update("")

    @work(exclusive=True)
    async def run_analysis(self) -> None:
        email = self.query_one("#email-input", Input).value.strip()
        if not email:
            return

        panel = self.query_one("#result-panel", ResultPanel)
        status = self.query_one("#status-bar", Static)
        panel.display_loading()
        status.update(f"[cyan]Analyzing {email}...[/cyan]")

        try:
            report = await full_analysis(email)
            panel.display_report(report)
            risk = report.get("risk", {})
            level = risk.get("level", "—")
            score = risk.get("score", 0)
            color = RISK_COLORS.get(level, "white")
            status.update(f"[dim]Done.[/dim]  Risk: [{color}]{level} ({score}/100)[/{color}]   [dim]{datetime.now().strftime('%H:%M:%S')}[/dim]")
        except Exception as e:
            panel.display_error(str(e))
            status.update(f"[red]Error: {e}[/red]")

