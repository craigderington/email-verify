"""
email_verify.config — Configuration & secrets resolution

Lookup order (first match wins):

  Secrets:
    1. --secrets FILE  (CLI flag → EMAIL_VERIFY_SECRETS env var set by cli.py)
    2. EMAIL_VERIFY_SECRETS environment variable
    3. ~/.config/email-verify/secrets.env
    4. ./secrets.env  (cwd)

  Config:
    1. EMAIL_VERIFY_CONFIG environment variable
    2. ~/.config/email-verify/config.toml
    3. built-in defaults

Config file format  (~/.config/email-verify/config.toml):
  [mailgun]
  api_key      = "key-..."
  domain       = "mg.yourdomain.com"
  from_address = "verify@yourdomain.com"
  smtp_host    = "smtp.mailgun.org"
  smtp_port    = 587
  smtp_user    = "postmaster@mg.yourdomain.com"
  smtp_password = "..."

  [output]
  default_format = "table"   # table | json | csv
  risk_threshold = 50        # 0-100: exit code 1 if score >= threshold

  [batch]
  concurrency = 5            # parallel workers
  delay_ms    = 200          # ms between requests (rate limiting)
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

# ── Config dir ────────────────────────────────────────────────────────────────

def config_dir() -> Path:
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "email-verify"


def config_file() -> Path:
    return config_dir() / "config.toml"


def default_secrets_file() -> Path:
    return config_dir() / "secrets.env"


# ── TOML loading (stdlib tomllib, Python 3.11+) ───────────────────────────────

def _load_toml(path: Path) -> dict:
    try:
        import tomllib
        with open(path, "rb") as f:
            return tomllib.load(f)
    except FileNotFoundError:
        return {}
    except Exception as e:
        print(f"[email-verify] Warning: could not parse {path}: {e}", file=sys.stderr)
        return {}


# ── Secrets loading ───────────────────────────────────────────────────────────

def load_secrets() -> None:
    """Load .env secrets in priority order."""
    candidates = [
        Path(os.environ["EMAIL_VERIFY_SECRETS"]) if "EMAIL_VERIFY_SECRETS" in os.environ else None,
        default_secrets_file(),
        Path.cwd() / "secrets.env",
    ]
    for p in candidates:
        if p and p.exists():
            load_dotenv(p, override=False)
            return
    # No file found — env vars may already be set directly, that's fine


# ── Dataclasses ───────────────────────────────────────────────────────────────

@dataclass
class MailgunConfig:
    api_key:       str = ""
    domain:        str = ""
    from_address:  str = ""
    smtp_host:     str = "smtp.mailgun.org"
    smtp_port:     int = 587
    smtp_user:     str = ""
    smtp_password: str = ""


@dataclass
class OutputConfig:
    default_format:  str = "table"   # table | json | csv
    risk_threshold:  int = 50        # exit code 1 if score >= this


@dataclass
class BatchConfig:
    concurrency: int = 5
    delay_ms:    int = 200


@dataclass
class AppConfig:
    mailgun: MailgunConfig = field(default_factory=MailgunConfig)
    output:  OutputConfig  = field(default_factory=OutputConfig)
    batch:   BatchConfig   = field(default_factory=BatchConfig)


# ── Builder ───────────────────────────────────────────────────────────────────

def load_config() -> AppConfig:
    """
    Build AppConfig by merging:
      config.toml  →  overridden by  →  environment variables / secrets.env
    """
    load_secrets()

    # Load TOML if present
    _cfg_env = os.environ.get("EMAIL_VERIFY_CONFIG", "").strip()
    toml_path = Path(_cfg_env) if _cfg_env else config_file()
    raw = _load_toml(toml_path) if toml_path.exists() else {}

    mg_toml  = raw.get("mailgun", {})
    out_toml = raw.get("output", {})
    bat_toml = raw.get("batch", {})

    # env vars win over toml
    def ev(key: str, toml_val, default="") -> str:
        return os.environ.get(key) or toml_val or default

    def ei(key: str, toml_val, default: int) -> int:
        try:
            return int(os.environ.get(key, toml_val or default))
        except (TypeError, ValueError):
            return default

    mailgun = MailgunConfig(
        api_key       = ev("MAILGUN_API_KEY",       mg_toml.get("api_key")),
        domain        = ev("MAILGUN_DOMAIN",         mg_toml.get("domain")),
        from_address  = ev("MAILGUN_FROM",           mg_toml.get("from_address")),
        smtp_host     = ev("MAILGUN_SMTP_HOST",      mg_toml.get("smtp_host"), "smtp.mailgun.org"),
        smtp_port     = ei("MAILGUN_SMTP_PORT",      mg_toml.get("smtp_port"), 587),
        smtp_user     = ev("MAILGUN_SMTP_USER",      mg_toml.get("smtp_user")),
        smtp_password = ev("MAILGUN_SMTP_PASSWORD",  mg_toml.get("smtp_password")),
    )

    output = OutputConfig(
        default_format = ev("EMAIL_VERIFY_FORMAT",    out_toml.get("default_format"), "table"),
        risk_threshold = ei("EMAIL_VERIFY_THRESHOLD", out_toml.get("risk_threshold"), 50),
    )

    batch = BatchConfig(
        concurrency = ei("EMAIL_VERIFY_CONCURRENCY", bat_toml.get("concurrency"), 5),
        delay_ms    = ei("EMAIL_VERIFY_DELAY_MS",    bat_toml.get("delay_ms"), 200),
    )

    return AppConfig(mailgun=mailgun, output=output, batch=batch)


# ── Init helper ───────────────────────────────────────────────────────────────

CONFIG_TOML_TEMPLATE = """\
# email-verify configuration
# Full docs: https://github.com/craigderington/email-verify

[mailgun]
# Private API key — Mailgun Dashboard → Account → API Keys
api_key      = ""
domain       = "mg.yourdomain.com"
from_address = "verify@yourdomain.com"

# SMTP relay (optional)
smtp_host     = "smtp.mailgun.org"
smtp_port     = 587
smtp_user     = "postmaster@mg.yourdomain.com"
smtp_password = ""

[output]
# Default output format: table | json | csv
default_format = "table"
# Exit with code 1 when risk score >= this value (useful in CI/scripts)
risk_threshold = 50

[batch]
# Parallel workers when processing a CSV
concurrency = 5
# Milliseconds between requests (be kind to the Mailgun API)
delay_ms = 200
"""

SECRETS_ENV_TEMPLATE = """\
# secrets.env — Mailgun credentials for email-verify
# This file is loaded automatically when placed at:
#   ~/.config/email-verify/secrets.env   ← preferred
#   ./secrets.env                        ← fallback
# NEVER commit this file to version control.

MAILGUN_API_KEY=key-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
MAILGUN_DOMAIN=mg.yourdomain.com
MAILGUN_FROM=verify@yourdomain.com
MAILGUN_SMTP_HOST=smtp.mailgun.org
MAILGUN_SMTP_PORT=587
MAILGUN_SMTP_USER=postmaster@mg.yourdomain.com
MAILGUN_SMTP_PASSWORD=your-mailgun-smtp-password-here
"""


def init_config(dest: Optional[Path] = None) -> None:
    """Write config.toml + secrets.env templates."""
    from rich.console import Console
    con = Console()

    target_dir = dest or config_dir()
    target_dir.mkdir(parents=True, exist_ok=True)

    cfg = target_dir / "config.toml"
    sec = target_dir / "secrets.env"

    for path, content, label in [
        (cfg, CONFIG_TOML_TEMPLATE, "config.toml"),
        (sec, SECRETS_ENV_TEMPLATE, "secrets.env"),
    ]:
        if path.exists():
            con.print(f"[yellow]⚠[/yellow]  [dim]{path}[/dim] already exists — skipping.")
        else:
            path.write_text(content)
            con.print(f"[green]✓[/green]  Wrote [bold]{label}[/bold] → {path}")

    con.print(f"\n[dim]Edit [bold]{sec}[/bold] and fill in your Mailgun API key.[/dim]")
