"""
Tests for email-verify

Run:  uv run pytest tests/ -v
"""

import csv
import io
import json
import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ── Helpers ───────────────────────────────────────────────────────────────────

VALID_EMAIL   = "user@example.com"
INVALID_EMAIL = "notanemail"
DISPOSABLE    = "test@mailinator.com"
ROLE_EMAIL    = "postmaster@example.com"


def _make_report(
    email=VALID_EMAIL,
    syntax_valid=True,
    mx_valid=True,
    disposable=False,
    mailbox_verification="true",
    mg_risk="low",
    is_valid=True,
    risk_score=0,
    risk_level="LOW",
):
    return {
        "email": email,
        "timestamp": "2025-01-01T00:00:00",
        "syntax": {"valid": syntax_valid, "message": "Valid syntax" if syntax_valid else "Invalid"},
        "domain": {"name": email.split("@")[-1] if "@" in email else "", "disposable": disposable,
                   "free_provider": False, "resolved_ip": "1.2.3.4"},
        "dns": {"mx_records": [("10", "mail.example.com")] if mx_valid else [],
                "a_records": ["1.2.3.4"], "spf": "v=spf1 include:mailgun.org ~all",
                "dmarc": "v=DMARC1; p=none", "mx_valid": mx_valid},
        "geo": {"country": "United States", "countryCode": "US", "regionName": "Florida",
                "city": "Orlando", "zip": "32801", "lat": 28.5, "lon": -81.4,
                "timezone": "America/New_York", "isp": "Example ISP", "org": "Example Org",
                "as": "AS12345 Example"},
        "ipinfo": {},
        "validation": {
            "configured": True, "is_valid": is_valid,
            "mailbox_verification": mailbox_verification,
            "is_disposable_address": disposable, "is_role_address": False,
            "did_you_mean": None, "risk": mg_risk, "reason": [], "raw": {}, "error": None,
        },
        "send_probe": {"configured": True, "send_ok": True,
                       "message_id": "<probe-abc123@gb10.studio>", "error": None},
        "risk": {"score": risk_score, "level": risk_level, "flags": []},
    }


# ── Syntax validation ─────────────────────────────────────────────────────────

class TestSyntaxValidation:
    def test_valid_email(self):
        from email_verify.core import validate_syntax
        ok, msg = validate_syntax("user@example.com")
        assert ok is True

    def test_invalid_no_at(self):
        from email_verify.core import validate_syntax
        ok, _ = validate_syntax("notanemail")
        assert ok is False

    def test_invalid_no_tld(self):
        from email_verify.core import validate_syntax
        ok, _ = validate_syntax("user@example")
        assert ok is False

    def test_valid_plus_addressing(self):
        from email_verify.core import validate_syntax
        ok, _ = validate_syntax("user+tag@example.com")
        assert ok is True

    def test_valid_subdomain(self):
        from email_verify.core import validate_syntax
        ok, _ = validate_syntax("user@mail.example.co.uk")
        assert ok is True


# ── Domain helpers ────────────────────────────────────────────────────────────

class TestDomainHelpers:
    def test_get_domain(self):
        from email_verify.core import get_domain
        assert get_domain("user@example.com") == "example.com"

    def test_get_domain_empty(self):
        from email_verify.core import get_domain
        assert get_domain("invalid") == ""

    def test_disposable_detection(self):
        from email_verify.core import DISPOSABLE_DOMAINS
        assert "mailinator.com" in DISPOSABLE_DOMAINS
        assert "guerrillamail.com" in DISPOSABLE_DOMAINS

    def test_free_provider_detection(self):
        from email_verify.core import FREE_EMAIL_DOMAINS
        assert "gmail.com" in FREE_EMAIL_DOMAINS
        assert "protonmail.com" in FREE_EMAIL_DOMAINS


# ── Config ────────────────────────────────────────────────────────────────────

class TestConfig:
    def test_load_config_defaults(self, monkeypatch):
        monkeypatch.delenv("MAILGUN_API_KEY", raising=False)
        monkeypatch.delenv("MAILGUN_DOMAIN", raising=False)
        monkeypatch.setenv("EMAIL_VERIFY_SECRETS", "/nonexistent/path/secrets.env")
        from email_verify.config import load_config
        cfg = load_config()
        assert cfg.mailgun.smtp_host == "smtp.mailgun.org"
        assert cfg.mailgun.smtp_port == 587
        assert cfg.batch.concurrency == 5
        assert cfg.output.default_format == "table"

    def test_env_vars_override_defaults(self, monkeypatch):
        monkeypatch.setenv("MAILGUN_API_KEY", "key-test-123")
        monkeypatch.setenv("MAILGUN_DOMAIN", "mg.test.com")
        monkeypatch.setenv("EMAIL_VERIFY_CONCURRENCY", "10")
        monkeypatch.setenv("EMAIL_VERIFY_SECRETS", "/nonexistent/secrets.env")
        from email_verify import config
        import importlib
        importlib.reload(config)
        cfg = config.load_config()
        assert cfg.mailgun.api_key == "key-test-123"
        assert cfg.mailgun.domain == "mg.test.com"
        assert cfg.batch.concurrency == 10

    def test_config_dir_linux(self, monkeypatch):
        monkeypatch.setenv("XDG_CONFIG_HOME", "/tmp/test-config")
        from email_verify import config
        import importlib
        importlib.reload(config)
        d = config.config_dir()
        assert str(d) == "/tmp/test-config/email-verify"

    def test_init_config_creates_files(self, tmp_path):
        from email_verify.config import init_config
        init_config(dest=tmp_path)
        assert (tmp_path / "config.toml").exists()
        assert (tmp_path / "secrets.env").exists()

    def test_init_config_does_not_overwrite(self, tmp_path):
        from email_verify.config import init_config
        (tmp_path / "config.toml").write_text("existing = true\n")
        init_config(dest=tmp_path)
        assert (tmp_path / "config.toml").read_text() == "existing = true\n"


# ── Output formatters ─────────────────────────────────────────────────────────

class TestOutputFormatters:
    def test_as_json_roundtrip(self):
        from email_verify.output import as_json
        report = _make_report()
        js = as_json(report)
        parsed = json.loads(js)
        assert parsed["email"] == VALID_EMAIL

    def test_csv_row_fields(self):
        from email_verify.output import report_to_csv_row, CSV_FIELDS
        row = report_to_csv_row(_make_report())
        for field in CSV_FIELDS:
            assert field in row

    def test_csv_row_values(self):
        from email_verify.output import report_to_csv_row
        row = report_to_csv_row(_make_report(email="craig@gb10.studio"))
        assert row["email"] == "craig@gb10.studio"
        assert row["geo_city"] == "Orlando"
        assert row["mg_mailbox_verification"] == "true"

    def test_reports_to_csv_string(self):
        from email_verify.output import reports_to_csv_string, CSV_FIELDS
        reports = [_make_report(), _make_report(email="other@example.com")]
        csv_text = reports_to_csv_string(reports)
        reader = csv.DictReader(io.StringIO(csv_text))
        rows = list(reader)
        assert len(rows) == 2
        assert rows[0]["email"] == VALID_EMAIL
        assert set(CSV_FIELDS).issubset(set(reader.fieldnames or []))

    def test_print_json_output(self, capsys):
        from email_verify.output import print_json
        print_json(_make_report())
        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert parsed["email"] == VALID_EMAIL


# ── Batch CSV reader ──────────────────────────────────────────────────────────

class TestBatchCsvReader:
    def test_read_plain_text(self, tmp_path):
        from email_verify.batch import read_emails_from_csv
        f = tmp_path / "emails.txt"
        f.write_text("user@example.com\nother@test.org\n")
        emails = read_emails_from_csv(f)
        assert emails == ["user@example.com", "other@test.org"]

    def test_read_csv_with_email_header(self, tmp_path):
        from email_verify.batch import read_emails_from_csv
        f = tmp_path / "signups.csv"
        f.write_text("name,email,date\nAlice,alice@example.com,2025-01-01\nBob,bob@test.org,2025-01-02\n")
        emails = read_emails_from_csv(f)
        assert "alice@example.com" in emails
        assert "bob@test.org" in emails

    def test_read_csv_single_column_no_header(self, tmp_path):
        from email_verify.batch import read_emails_from_csv
        f = tmp_path / "list.csv"
        f.write_text("user1@example.com\nuser2@example.com\n")
        emails = read_emails_from_csv(f)
        assert len(emails) == 2

    def test_skip_invalid_rows(self, tmp_path):
        from email_verify.batch import read_emails_from_csv
        f = tmp_path / "mixed.txt"
        f.write_text("valid@example.com\nnot-an-email\nother@test.org\n")
        emails = read_emails_from_csv(f)
        assert "valid@example.com" in emails
        assert "other@test.org" in emails
        assert "not-an-email" not in emails

    def test_file_not_found(self):
        from email_verify.batch import read_emails_from_csv
        with pytest.raises(FileNotFoundError):
            read_emails_from_csv(Path("/nonexistent/file.csv"))


# ── Risk scoring ──────────────────────────────────────────────────────────────

class TestRiskScoring:
    @pytest.mark.asyncio
    async def test_disposable_domain_high_risk(self):
        from email_verify.core import full_analysis
        with patch("email_verify.core.resolve_dns") as mock_dns, \
             patch("email_verify.core.mailgun_validate_address") as mock_val, \
             patch("email_verify.core.mailgun_send_probe") as mock_send, \
             patch("email_verify.core.geo_lookup", return_value={}), \
             patch("email_verify.core.whois_asn", return_value={}):

            mock_dns.return_value = {"mx_records": [], "a_records": [], "spf": None,
                                     "dmarc": None, "mx_valid": False}
            mock_val.return_value = {"configured": True, "is_valid": False,
                                     "mailbox_verification": "false",
                                     "is_disposable_address": True, "is_role_address": False,
                                     "did_you_mean": None, "risk": "high", "reason": [], "error": None}
            mock_send.return_value = {"configured": True, "send_ok": False, "message_id": None,
                                      "error": "rejected"}

            report = await full_analysis(DISPOSABLE)
            assert report["risk"]["score"] >= 50
            assert report["risk"]["level"] in ("MEDIUM", "HIGH")

    @pytest.mark.asyncio
    async def test_valid_email_low_risk(self):
        from email_verify.core import full_analysis
        with patch("email_verify.core.resolve_dns") as mock_dns, \
             patch("email_verify.core.mailgun_validate_address") as mock_val, \
             patch("email_verify.core.mailgun_send_probe") as mock_send, \
             patch("email_verify.core.geo_lookup", return_value={}), \
             patch("email_verify.core.whois_asn", return_value={}), \
             patch("socket.gethostbyname", return_value="1.2.3.4"):

            mock_dns.return_value = {
                "mx_records": [(10, "mail.example.com")],
                "a_records": ["1.2.3.4"],
                "spf": "v=spf1 ~all", "dmarc": "v=DMARC1; p=none", "mx_valid": True,
            }
            mock_val.return_value = {
                "configured": True, "is_valid": True,
                "mailbox_verification": "true", "is_disposable_address": False,
                "is_role_address": False, "did_you_mean": None,
                "risk": "low", "reason": [], "error": None,
            }
            mock_send.return_value = {
                "configured": True, "send_ok": True,
                "message_id": "<abc@mg.example.com>", "error": None,
            }

            report = await full_analysis(VALID_EMAIL)
            assert report["risk"]["score"] < 50
            assert report["risk"]["level"] == "LOW"
