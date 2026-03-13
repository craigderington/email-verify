"""
email_verify.batch — Async CSV batch processor

Usage:
    email-verify --batch signups.csv
    email-verify --batch signups.csv --output results.csv
    email-verify --batch signups.csv --output results.json --json
    email-verify --batch signups.csv --threshold 30 --concurrency 3
"""

from __future__ import annotations

import asyncio
import csv
import json
import sys
import time
from pathlib import Path
from typing import AsyncIterator, Optional

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.table import Table
from rich.text import Text

from email_verify.output import CSV_FIELDS, report_to_csv_row, RISK_COLORS


# ── CSV reader ────────────────────────────────────────────────────────────────

def read_emails_from_csv(path: Path) -> list[str]:
    """
    Read email addresses from a CSV file.
    Accepts:
      - Single-column files (no header, just addresses)
      - Multi-column files — looks for a column named:
        email, email_address, e-mail, address  (case-insensitive)
      - Plain text files with one address per line
    """
    emails: list[str] = []

    raw = path.read_text(encoding="utf-8-sig")
    lines = [l.strip() for l in raw.splitlines() if l.strip()]

    if not lines:
        return emails

    # Detect if this is actually CSV (contains commas or tabs outside @ addresses)
    has_delimiter = any(
        ("," in line or "\t" in line)
        for line in lines
        if "@" not in line or line.count(",") > 0
    )

    if not has_delimiter:
        # Plain text: one address per line
        for line in lines:
            if "@" in line:
                emails.append(line)
        return emails

    # CSV path — try to detect header with known email column names
    with open(path, newline="", encoding="utf-8-sig") as f:
        try:
            dialect = csv.Sniffer().sniff(raw[:4096], delimiters=",\t|;")
        except csv.Error:
            dialect = csv.excel

        reader = csv.DictReader(f, dialect=dialect)
        headers = {(h or "").strip().lower(): h for h in (reader.fieldnames or [])}
        email_col = next(
            (headers[k] for k in ["email", "email_address", "e-mail", "address", "mail"]
             if k in headers),
            None,
        )

        if email_col:
            for row in reader:
                addr = (row.get(email_col) or "").strip()
                if addr and "@" in addr:
                    emails.append(addr)
            return emails

    # No recognised header — treat first column as email, skip non-address rows
    with open(path, newline="", encoding="utf-8-sig") as f:
        try:
            dialect = csv.Sniffer().sniff(raw[:4096], delimiters=",\t|;")
        except csv.Error:
            dialect = csv.excel
        reader2 = csv.reader(f, dialect=dialect)
        for i, row in enumerate(reader2):
            if not row:
                continue
            addr = row[0].strip()
            if i == 0 and "@" not in addr:
                continue  # skip header row
            if "@" in addr:
                emails.append(addr)

    return emails


# ── Batch runner ──────────────────────────────────────────────────────────────

async def _bounded_analyze(
    sem: asyncio.Semaphore,
    email: str,
    delay_ms: int,
) -> dict:
    from email_verify.core import full_analysis
    async with sem:
        if delay_ms > 0:
            await asyncio.sleep(delay_ms / 1000)
        return await full_analysis(email)


async def run_batch(
    emails: list[str],
    concurrency: int = 5,
    delay_ms: int = 200,
    progress: Optional[Progress] = None,
    task_id=None,
) -> list[dict]:
    sem = asyncio.Semaphore(concurrency)
    tasks = [
        asyncio.create_task(_bounded_analyze(sem, email, delay_ms))
        for email in emails
    ]

    results = []
    for coro in asyncio.as_completed(tasks):
        result = await coro
        results.append(result)
        if progress and task_id is not None:
            progress.advance(task_id)

    # Re-sort to match input order
    order = {e: i for i, e in enumerate(emails)}
    results.sort(key=lambda r: order.get(r.get("email", ""), 9999))
    return results


# ── Summary table ─────────────────────────────────────────────────────────────

def _build_summary(reports: list[dict], threshold: int) -> Table:
    table = Table(
        title="Batch Results Summary",
        show_header=True,
        header_style="bold cyan",
        border_style="cyan",
        show_lines=False,
    )
    table.add_column("Email",        style="white",   no_wrap=True, max_width=36)
    table.add_column("Valid",        justify="center", width=6)
    table.add_column("Mailbox",      justify="center", width=10)
    table.add_column("Disposable",   justify="center", width=11)
    table.add_column("MG Risk",      justify="center", width=9)
    table.add_column("Score",        justify="right",  width=6)
    table.add_column("Level",        justify="center", width=8)
    table.add_column("Flags",        style="dim",      overflow="fold")

    for r in reports:
        dom  = r.get("domain", {})
        v    = r.get("validation", {})
        risk = r.get("risk", {})
        syn  = r.get("syntax", {})

        score = risk.get("score", 0)
        level = risk.get("level", "—")
        col   = RISK_COLORS.get(level, "white")

        valid_str = "[green]✓[/green]" if syn.get("valid") else "[red]✗[/red]"

        mbv = v.get("mailbox_verification", "")
        mbv_str = {
            "true":    "[green]✓[/green]",
            "false":   "[red]✗[/red]",
            "unknown": "[yellow]?[/yellow]",
        }.get(mbv, "[dim]—[/dim]")

        disp_str = "[red]Yes[/red]" if (dom.get("disposable") or v.get("is_disposable_address")) else "[green]No[/green]"

        mg_risk  = v.get("risk", "") or ""
        mg_col   = {"high": "red", "medium": "yellow", "low": "green"}.get(mg_risk, "dim")
        mg_str   = f"[{mg_col}]{mg_risk.upper() or '—'}[/{mg_col}]"

        score_str = f"[{col}]{score}[/{col}]"
        level_str = f"[{col}]{level}[/{col}]"

        flags = risk.get("flags", [])
        flag_str = " · ".join(flags[:2]) + (" …" if len(flags) > 2 else "")

        table.add_row(
            r.get("email", ""),
            valid_str,
            mbv_str,
            disp_str,
            mg_str,
            score_str,
            level_str,
            flag_str,
        )

    return table


def _build_stats(reports: list[dict], threshold: int, elapsed: float) -> str:
    total    = len(reports)
    valid    = sum(1 for r in reports if r.get("syntax", {}).get("valid"))
    flagged  = sum(1 for r in reports if r.get("risk", {}).get("score", 0) >= threshold)
    high     = sum(1 for r in reports if r.get("risk", {}).get("level") == "HIGH")
    medium   = sum(1 for r in reports if r.get("risk", {}).get("level") == "MEDIUM")
    low      = sum(1 for r in reports if r.get("risk", {}).get("level") == "LOW")
    no_mx    = sum(1 for r in reports if not r.get("dns", {}).get("mx_valid"))
    disposable = sum(1 for r in reports if r.get("domain", {}).get("disposable"))

    return (
        f"[bold]Processed:[/bold] {total}  "
        f"[bold]Valid syntax:[/bold] {valid}  "
        f"[bold]Flagged (≥{threshold}):[/bold] [red]{flagged}[/red]  "
        f"[dim]HIGH[/dim] [red]{high}[/red]  "
        f"[dim]MED[/dim] [yellow]{medium}[/yellow]  "
        f"[dim]LOW[/dim] [green]{low}[/green]  "
        f"[dim]No MX:[/dim] {no_mx}  "
        f"[dim]Disposable:[/dim] {disposable}  "
        f"[dim]Elapsed:[/dim] {elapsed:.1f}s"
    )


# ── Entry point ───────────────────────────────────────────────────────────────

def run_batch_command(
    input_path: Path,
    output_path: Optional[Path],
    output_format: str,         # table | json | csv
    concurrency: int,
    delay_ms: int,
    threshold: int,
    console: Optional[Console] = None,
) -> int:
    """
    Run batch validation.  Returns exit code (0 = all clear, 1 = any flagged).
    """
    con = console or Console()

    # Read input
    try:
        emails = read_emails_from_csv(input_path)
    except FileNotFoundError:
        con.print(f"[red]✗ File not found:[/red] {input_path}")
        return 2
    except Exception as e:
        con.print(f"[red]✗ Could not read {input_path}:[/red] {e}")
        return 2

    if not emails:
        con.print(f"[yellow]⚠[/yellow]  No valid email addresses found in [bold]{input_path}[/bold]")
        return 0

    con.print(
        f"\n[bold cyan]⬡ email-verify batch[/bold cyan]  "
        f"[dim]{len(emails)} addresses · concurrency={concurrency} · delay={delay_ms}ms[/dim]\n"
    )

    # Progress bar
    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=con,
        transient=False,
    )

    t0 = time.monotonic()
    with progress:
        task_id = progress.add_task("Validating…", total=len(emails))
        reports = asyncio.run(run_batch(emails, concurrency, delay_ms, progress, task_id))

    elapsed = time.monotonic() - t0

    # Output
    if output_format == "json":
        payload = json.dumps(reports, indent=2, default=str)
        if output_path:
            output_path.write_text(payload)
            con.print(f"[green]✓[/green]  JSON written to [bold]{output_path}[/bold]")
        else:
            sys.stdout.write(payload + "\n")

    elif output_format == "csv":
        from email_verify.output import reports_to_csv_string
        csv_text = reports_to_csv_string(reports)
        if output_path:
            output_path.write_text(csv_text)
            con.print(f"[green]✓[/green]  CSV written to [bold]{output_path}[/bold]")
        else:
            sys.stdout.write(csv_text)

    else:  # table (default)
        con.print(_build_summary(reports, threshold))
        if output_path:
            # Still write CSV alongside the table view
            from email_verify.output import reports_to_csv_string
            out = output_path.with_suffix(".csv") if output_path.suffix == "" else output_path
            out.write_text(reports_to_csv_string(reports))
            con.print(f"[green]✓[/green]  CSV also written to [bold]{out}[/bold]")

    con.print(f"\n{_build_stats(reports, threshold, elapsed)}\n")

    # Exit code
    flagged = sum(1 for r in reports if r.get("risk", {}).get("score", 0) >= threshold)
    return 1 if flagged else 0
