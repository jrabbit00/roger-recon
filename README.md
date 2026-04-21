# Roger Recon 🐰

A comprehensive recon toolkit for bug bounty hunting and penetration testing.

## Installation

```bash
git clone https://github.com/yourusername/roger-recon.git
cd roger-recon
```

For screenshots (optional):
```bash
pip3 install playwright
playwright install chromium
```

## Usage

```bash
# Basic subdomain enumeration
python3 subenum.py example.com

# Full scan
python3 subenum.py example.com --full-scan --detect-tech --vuln-scan

# With screenshots (requires playwright)
python3 subenum.py example.com --screenshots

# Save results
python3 subenum.py example.com -o results.json --vuln-scan
```

## Features

| Feature | Flag | Description |
|---------|------|-------------|
| Subdomain enum | (default) | crt.sh + bruteforce |
| Port scanning | `--full-scan` | Common ports |
| Tech detection | `--detect-tech` | Server, frameworks, CMS |
| Vuln scanning | `--vuln-scan` | Security headers, methods, CORS |
| Screenshots | `--screenshots` | Webpage captures (requires playwright) |

## Vulnerability Checks

- Missing security headers (HSTS, CSP, X-Frame-Options, etc.)
- Dangerous HTTP methods (PUT, DELETE, PATCH, TRACE)
- Hardcoded secrets in source
- CORS misconfigurations
- Error message exposure

## Requirements

- Python 3.7+
- No dependencies for core features
- `playwright` for screenshots

## License

MIT