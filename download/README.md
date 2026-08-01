# EXENOM Python CLI — Standalone Edition

A zero-dependency Python 3 script that runs the EXENOM attack-surface scanner in any terminal. No `pip install` needed.

## Quick Start

```bash
# Download
curl -O https://raw.githubusercontent.com/yourusername/exenom/main/download/easm.py

# Run
python3 easm.py scan example.com
```

## All Commands

```bash
# Full scan (all 10 modules)
python3 easm.py scan example.com

# Selected modules
python3 easm.py scan example.com --modules dns,http,vulns,firewall

# Custom ports
python3 easm.py scan example.com --ports 80,443,8080

# Skip subdomain enumeration (faster)
python3 easm.py scan example.com --no-subdomains

# JSON report
python3 easm.py scan example.com --output json > report.json

# Tuning
python3 easm.py scan example.com --timeout 6000 --concurrency 100

# Shorthand (no "scan" keyword)
python3 easm.py example.com
```

## Modules (10)

| Module | Description |
|--------|-------------|
| `dns` | DNS records via DNS-over-HTTPS (Cloudflare 1.1.1.1) |
| `subdomains` | crt.sh + HackerTarget + brute-force |
| `ports` | TCP connect scan with banner grabbing |
| `http` | HTTP/HTTPS probing |
| `tls` | Certificate analysis (issuer, expiry, SAN, self-signed) |
| `tech` | Technology fingerprinting |
| `vulns` | Security headers + 35 exposed paths + .git dump |
| `emailsec` | SPF/DMARC/DKIM/MX validation (via DoH) |
| `firewall` | WAF detection + 330+ encoded bypass payloads per category |
| `cloudenum` | S3/GCP/Azure/GitHub asset discovery |

## Requirements

- Python 3.7+
- Internet connection
- No pip packages required (stdlib only)

## Developer

Built by **Rudresha RK** — Cybersecurity Undergraduate
