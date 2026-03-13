# email-verify

**Email Intelligence & SMTP Verification Tool**

DNS · Mailgun Validation API · GeoIP · ASN · Risk Scoring

---

## Install

```bash
uv tool install email-verify
```

Or from source:

```bash
git clone https://github.com/craigderington/email-verify
cd email-verify
uv tool install .
```

## Setup

Generate a `secrets.env` template in the current directory:

```bash
email-verify --init
```

Edit `secrets.env` and fill in your Mailgun credentials:

```env
MAILGUN_API_KEY=key-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
MAILGUN_DOMAIN=mg.yourdomain.com
MAILGUN_FROM=verify@yourdomain.com
```

> **Note:** The Email Validation API requires the Mailgun **Email Validation** add-on (InboxReady).  
> Your Private API key is found at: Mailgun Dashboard → Account → API Keys.

## Usage

```bash
# Interactive TUI (dark terminal dashboard)
email-verify

# Single address — CLI output
email-verify user@example.com

# Point at a secrets file in a non-standard location
email-verify --secrets /etc/email-verify/secrets.env user@example.com

# Print version
email-verify --version
```

## What it checks

| Layer | Checks |
|---|---|
| **Syntax** | RFC-compliant regex |
| **Domain** | Disposable domain list, free provider detection |
| **DNS** | MX records, A records, SPF, DMARC |
| **Mailgun Validation API** | `is_valid`, `mailbox_verification` (MX RCPT probe via Mailgun infra), `is_disposable_address`, `is_role_address`, `did_you_mean`, risk classification |
| **Send Probe** | Authenticated message dispatch via Mailgun Messages API |
| **GeoIP** | Country, region, city, ZIP, lat/lon, timezone (ip-api.com) |
| **ASN / Org** | ISP, organisation, AS number (ipinfo.io) |
| **Risk Score** | 0–100 composite with labelled flags |

## Risk scoring

| Signal | Points |
|---|---|
| Disposable domain (local list) | +60 |
| No MX records | +40 |
| Mailgun: address invalid | +60 |
| Mailgun: mailbox does not exist | +55 |
| Mailgun: disposable address | +40 |
| Mailgun: HIGH risk classification | +30 |
| Mailgun: MEDIUM risk classification | +15 |
| Mailgun: mailbox inconclusive | +15 |
| Role address | +10 |
| No SPF record | +10 |
| No DMARC record | +10 |

## secrets.env lookup order

1. Path passed via `--secrets FILE`
2. `EMAIL_VERIFY_SECRETS` environment variable
3. `secrets.env` in the same directory as the installed package
4. `secrets.env` in the current working directory

## Development

```bash
git clone https://github.com/craigderington/email-verify
cd email-verify
uv sync
uv run email-verify --version
```

## License

MIT © Craig Derington
