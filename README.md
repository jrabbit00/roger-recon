# Roger Recon 🐰

A comprehensive reconnaissance toolkit for bug bounty hunting and penetration testing.

![Test](https://github.com/jrabbit00/roger-recon/actions/workflows/test.yml/badge.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)

## Features

| Feature | Flag | Description |
|---------|------|-------------|
| Subdomain enumeration | (default) | crt.sh + bruteforce (80+ wordlist) |
| Port scanning | `--full-scan` | Multi-threaded common port scan |
| Technology detection | `--detect-tech` | Server, frameworks, CMS identification |
| Vulnerability scanning | `--vuln-scan` | Security headers, HTTP methods, CORS, secrets |
| Screenshots | `--screenshots` | Webpage captures (requires playwright) |

## Installation

```bash
git clone https://github.com/jrabbit00/roger-recon.git
cd roger-recon
```

For screenshots (optional):
```bash
pip install playwright
playwright install chromium
```

## Quick Start

```bash
# Basic subdomain enumeration
python3 subenum.py example.com

# Full scan with all features
python3 subenum.py target.com --full-scan --detect-tech --vuln-scan

# With screenshots
python3 subenum.py target.com --screenshots

# Save results to JSON
python3 subenum.py target.com -o results.json --vuln-scan
```

## Usage

```
usage: subenum.py [-h] [-o OUTPUT] [--full-scan] [--detect-tech] [--vuln-scan]
                  [--screenshots] [--screenshot-dir SCREENSHOT_DIR]
                  domain

positional arguments:
  domain                Target domain (e.g., example.com)

optional arguments:
  -h, --help            show this help message and exit
  -o, --output          Output file (JSON)
  --full-scan           Run full port scan
  --detect-tech         Detect technologies
  --vuln-scan           Run vulnerability scanning
  --screenshots         Take screenshots
  --screenshot-dir      Screenshot output directory (default: screenshots)
```

## Vulnerability Checks

- **Missing security headers**: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, Referrer-Policy, Permissions-Policy
- **Dangerous HTTP methods**: PUT, DELETE, PATCH, TRACE, OPTIONS
- **Hardcoded secrets**: API keys, tokens, passwords, AWS credentials, private keys
- **CORS misconfigurations**: Wildcard origins, credentials + wildcard
- **Error exposure**: SQL errors, stack traces, PHP errors

## Requirements

- Python 3.7+
- No external dependencies for core features
- `playwright` for screenshots (optional)

## Roadmap

- [x] Subdomain enumeration
- [x] Port scanning
- [x] Technology detection
- [x] Vulnerability scanning
- [ ] Screenshots (optional)
- [ ] Web crawling
- [ ] API integrations (Shodan, VirusTotal)
- [ ] GUI

## Legal Warning

This tool is for authorized testing only. Always get permission before scanning targets you don't own. Use responsibly.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Author

Created by Ashlee 🐰