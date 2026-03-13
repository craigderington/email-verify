"""
email_verify.cli — Entry point for the `email-verify` uv tool

Install:
    uv tool install email-verify

Usage:
    email-verify                              # interactive TUI
    email-verify user@example.com            # single address, table output
    email-verify user@example.com --json     # single address, JSON output
    email-verify --batch signups.csv         # batch mode, table summary
    email-verify --batch signups.csv --output results.csv --format csv
    email-verify --init                      # write config + secrets templates
    email-verify --version
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from rich.console import Console

console = Console()


def _print_version() -> None:
    from importlib.metadata import version, PackageNotFoundError
    try:
        v = version("email-verify")
    except PackageNotFoundError:
        v = "dev"
    console.print(f"[bold cyan]email-verify[/bold cyan] [dim]v{v}[/dim]")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="email-verify",
        description="Email Intelligence & Verification Tool\nDNS · Mailgun Validation API · GeoIP · ASN · Risk Scoring",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  email-verify                              interactive TUI
  email-verify user@example.com            single address (table)
  email-verify user@example.com --json     single address (JSON)
  email-verify --batch list.csv            batch from CSV (table summary)
  email-verify --batch list.csv --output results.csv --format csv
  email-verify --batch list.csv --output results.json --format json
  email-verify --init                      write config/secrets templates
""",
    )
    parser.add_argument("email", nargs="?", metavar="EMAIL",
                        help="Email address to validate (omit to launch TUI)")
    parser.add_argument("--batch", "-b", metavar="FILE",
                        help="CSV/text file of addresses to validate in bulk")
    parser.add_argument("--output", "-o", metavar="FILE",
                        help="Write batch results to this file (default: stdout)")
    parser.add_argument("--format", "-f", choices=["table", "json", "csv"],
                        default=None, metavar="FORMAT",
                        help="Output format: table (default) | json | csv")
    parser.add_argument("--json", "-j", action="store_true",
                        help="Print full JSON for a single address")
    parser.add_argument("--concurrency", "-c", type=int, default=None, metavar="N",
                        help="Parallel workers for batch (default from config)")
    parser.add_argument("--delay", type=int, default=None, metavar="MS",
                        help="Delay between batch requests in ms (default from config)")
    parser.add_argument("--threshold", "-t", type=int, default=None, metavar="SCORE",
                        help="Risk score threshold for exit code 1 (default from config)")
    parser.add_argument("--init", action="store_true",
                        help="Write config.toml + secrets.env to ~/.config/email-verify/")
    parser.add_argument("--config", metavar="FILE",
                        help="Path to config.toml")
    parser.add_argument("--secrets", metavar="FILE",
                        help="Path to secrets.env")
    parser.add_argument("--version", "-V", action="store_true",
                        help="Print version and exit")
    return parser


def main() -> None:
    parser = _build_parser()
    args   = parser.parse_args()

    if args.version:
        _print_version()
        sys.exit(0)

    if args.init:
        from email_verify.config import init_config
        init_config()
        sys.exit(0)

    import os
    if args.secrets:
        os.environ["EMAIL_VERIFY_SECRETS"] = args.secrets
    if args.config:
        os.environ["EMAIL_VERIFY_CONFIG"] = args.config

    from email_verify.config import load_config
    cfg = load_config()

    concurrency = args.concurrency or cfg.batch.concurrency
    delay_ms    = args.delay       or cfg.batch.delay_ms
    threshold   = args.threshold   or cfg.output.risk_threshold
    fmt         = args.format      or cfg.output.default_format

    if args.batch:
        from email_verify.batch import run_batch_command
        exit_code = run_batch_command(
            input_path    = Path(args.batch),
            output_path   = Path(args.output) if args.output else None,
            output_format = fmt,
            concurrency   = concurrency,
            delay_ms      = delay_ms,
            threshold     = threshold,
            console       = console,
        )
        sys.exit(exit_code)

    if args.email:
        from email_verify.core import full_analysis
        report = asyncio.run(full_analysis(args.email))

        if args.json or fmt == "json":
            from email_verify.output import print_json
            print_json(report)
        elif fmt == "csv":
            from email_verify.output import reports_to_csv_string
            sys.stdout.write(reports_to_csv_string([report]))
        else:
            from email_verify.output import print_table
            print_table(report, console)

        score = report.get("risk", {}).get("score", 0)
        sys.exit(1 if score >= threshold else 0)

    from email_verify.core import EmailValidatorApp
    app = EmailValidatorApp()
    app.run()
