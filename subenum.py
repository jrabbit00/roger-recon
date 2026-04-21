#!/usr/bin/env python3
"""
Roger Recon - Full-featured Reconnaissance Tool
Subdomain enum + port scan + tech detection + vuln scan + screenshots
"""

import argparse
import json
import socket
import threading
import re
import time
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from html.parser import HTMLParser
from urllib.parse import urlparse

# Playwright availability - will try to import, fallback to None
PLAYWRIGHT_AVAILABLE = False
try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    pass  # Screenshots won't work but tool continues


# Extended subdomain wordlists
STANDARD_SUBDOMAINS = [
    "www", "api", "dev", "test", "staging", "admin", "mail", "ftp",
    "static", "cdn", "blog", "shop", "store", "app", "mobile",
    "webmail", "ns1", "mx", "dns", "ns", "autodiscover", "autoconfig",
    "m", "support", "help", "docs", "wiki", "forum", "chat", "stats",
    "vpn", "ssh", "git", "svn", "jenkins", "ci", "cd", "build",
    "beta", "alpha", "demo", "preprod", "prod", "stage", "backup",
    "proxy", "internal", "private", "corp", "office", "cloud",
    "db", "database", "mysql", "postgres", "redis", "mongo",
    "gateway", "lb", "loadbalancer", "cdn2", "static1", "assets",
    "crm", "erp", "portal", "v2", "v3", "old", "new", "legacy",
    "playground", "sandbox", "lab", "research", "analysis",
    "secure", "login", "dashboard", "control", "manage"
]

# Common ports
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 
                3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 27017]

# Security headers
SECURITY_HEADERS = {
    'Strict-Transport-Security': 'HSTS not set',
    'Content-Security-Policy': 'CSP not set',
    'X-Frame-Options': 'Clickjacking not prevented',
    'X-Content-Type-Options': 'MIME sniffing not prevented',
    'X-XSS-Protection': 'XSS filter not set',
    'Referrer-Policy': 'Referrer policy not set',
    'Permissions-Policy': 'Permissions policy not set'
}

# Vulnerable patterns
VULN_PATTERNS = [
    (r'<input[^>]*type=["\']?password', 'Password field found'),
    (r'api[_-]?key["\']?\s*[:=]', 'Hardcoded API key'),
    (r'secret["\']?\s*[:=]', 'Hardcoded secret'),
    (r'token["\']?\s*[:=]', 'Hardcoded token'),
    (r'AWS_ACCESS_KEY', 'AWS credentials'),
    (r'-----BEGIN.*PRIVATE KEY-----', 'Private key exposed'),
    (r'SQL syntax.*MySQL', 'SQL error exposed'),
    (r'Parse error', 'PHP error'),
    (r'Fatal error', 'PHP fatal error'),
    (r' at line \d+', 'Stack trace'),
]


def check_subdomain(domain, subdomain):
    """Check if a subdomain exists"""
    full_domain = f"{subdomain}.{domain}"
    try:
        socket.gethostbyname(full_domain)
        return full_domain
    except socket.gaierror:
        return None


def bruteforce_subdomains(domain):
    """Bruteforce subdomains"""
    found = []
    print(f"[*] Checking {len(STANDARD_SUBDOMAINS)} subdomains on {domain}...")
    
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(check_subdomain, domain, sub): sub for sub in STANDARD_SUBDOMAINS}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)
                print(f"[+] Found: {result}")
    
    return found


def crt_sh_enum(domain):
    """Get subdomains from crt.sh"""
    found = []
    url = f"https://crt.sh/?q={domain}&output=json"
    
    try:
        print("[*] Fetching from crt.sh...")
        req = Request(url, headers={'User-Agent': 'RogerRecon/1.0'})
        with urlopen(req, timeout=30) as response:
            data = json.loads(response.read().decode())
            
        for entry in data:
            name = entry.get('name_value', '')
            for sub in name.split('\n'):
                sub = sub.strip()
                if sub.endswith(domain) and sub != domain and '*' not in sub and ' ' not in sub:
                    found.append(sub)
                    
    except Exception as e:
        print(f"[!] crt.sh error: {e}")
    
    return list(set(found))


def scan_port(host, port, timeout=2):
    """Scan a single port"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False


def scan_ports(host, ports=None):
    """Scan multiple ports"""
    ports_to_scan = ports if ports else COMMON_PORTS
    open_ports = []
    
    print(f"[*] Scanning {len(ports_to_scan)} ports on {host}...")
    
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(scan_port, host, port): port for port in ports_to_scan}
        for future in as_completed(futures):
            port = futures[future]
            if future.result():
                open_ports.append(port)
                print(f"[+] Port {port} is open")
    
    return open_ports


def detect_tech(url):
    """Detect technologies"""
    tech = []
    try:
        req = Request(url, headers={'User-Agent': 'RogerRecon/1.0'})
        with urlopen(req, timeout=10) as response:
            headers = dict(response.headers)
            server = headers.get('Server', '')
            
            if server:
                tech.append(f"Server: {server}")
            if 'X-Powered-By' in headers:
                tech.append(f"X-Powered-By: {headers['X-Powered-By']}")
            
            try:
                html = response.read().decode('utf-8', errors='ignore')
                
                checks = [
                    ('WordPress', 'wp-content'),
                    ('React', 'react'),
                    ('Vue.js', 'vue'),
                    ('Angular', 'angular'),
                    ('Bootstrap', 'bootstrap'),
                    ('jQuery', 'jquery'),
                    ('Nginx', 'nginx'),
                    ('Apache', 'apache'),
                    ('Django', 'django'),
                    ('Flask', 'flask'),
                    ('Express', 'express'),
                ]
                
                for name, pattern in checks:
                    if pattern in html.lower():
                        tech.append(name)
                        
            except:
                pass
                
    except Exception as e:
        return [f"Error: {e}"]
    
    return tech if tech else ["Unknown"]


def check_security_headers(url):
    """Check for missing security headers"""
    missing = []
    try:
        req = Request(url, headers={'User-Agent': 'RogerRecon/1.0'})
        with urlopen(req, timeout=10) as response:
            headers = dict(response.headers)
            
            for header, description in SECURITY_HEADERS.items():
                if header not in headers:
                    missing.append(f"{header}: {description}")
                    
    except Exception as e:
        return [f"Error: {e}"]
    
    return missing


def check_http_methods(url):
    """Check dangerous HTTP methods"""
    dangerous = []
    methods = ['PUT', 'DELETE', 'PATCH', 'TRACE', 'OPTIONS']
    
    for method in methods:
        try:
            req = Request(url, method=method, headers={'User-Agent': 'RogerRecon/1.0'})
            with urlopen(req, timeout=5) as response:
                if response.status < 400:
                    dangerous.append(f"{method} allowed")
        except HTTPError as e:
            if e.code != 405 and e.code != 501:
                dangerous.append(f"{method} returned {e.code}")
        except:
            pass
    
    return dangerous


def check_vulns(url):
    """Check for vulnerabilities"""
    vulns = []
    try:
        req = Request(url, headers={'User-Agent': 'RogerRecon/1.0'})
        with urlopen(req, timeout=10) as response:
            try:
                html = response.read().decode('utf-8', errors='ignore')
                
                for pattern, description in VULN_PATTERNS:
                    if re.search(pattern, html, re.IGNORECASE):
                        vulns.append(description)
                        
            except:
                pass
                
    except Exception as e:
        return [f"Error: {e}"]
    
    return vulns


def check_cors(url):
    """Check CORS config"""
    issues = []
    try:
        req = Request(url, headers={
            'User-Agent': 'RogerRecon/1.0',
            'Origin': 'https://evil.com'
        })
        with urlopen(req, timeout=10) as response:
            headers = dict(response.headers)
            
            acao = headers.get('Access-Control-Allow-Origin', '')
            acac = headers.get('Access-Control-Allow-Credentials', '')
            
            if acao == '*':
                issues.append("CORS allows all origins")
            elif acao and acao != 'null':
                issues.append(f"CORS allows: {acao}")
            
            if acac == 'true' and acao == '*':
                issues.append("CORS credentials + wildcard")
                    
    except:
        pass
    
    return issues


def take_screenshot(url, output_dir, hostname):
    """Take screenshot of a webpage using playwright"""
    if not PLAYWRIGHT_AVAILABLE:
        return "Playwright not installed"
    
    screenshot_path = os.path.join(output_dir, f"{hostname}.png")
    
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.set_viewport_size({"width": 1280, "height": 720})
            page.goto(url, timeout=30000, wait_until="networkidle")
            page.screenshot(path=screenshot_path)
            browser.close()
            
        print(f"[+] Screenshot saved: {screenshot_path}")
        return screenshot_path
        
    except Exception as e:
        print(f"[!] Screenshot failed for {hostname}: {e}")
        return f"Error: {e}"


def scan_vulnerabilities(host):
    """Run all vuln checks"""
    protocol = "https" if 443 in [443, 8443] else "http"
    url = f"{protocol}://{host}"
    
    results = {
        "host": host,
        "security_headers": [],
        "http_methods": [],
        "vulnerabilities": [],
        "cors": []
    }
    
    print(f"[*] Scanning {host} for vulnerabilities...")
    
    headers = check_security_headers(url)
    if headers:
        results["security_headers"] = headers
        for h in headers[:3]:
            print(f"  [!] Missing: {h}")
    
    methods = check_http_methods(url)
    if methods:
        results["http_methods"] = methods
        for m in methods[:3]:
            print(f"  [!] {m}")
    
    vulns = check_vulns(url)
    if vulns:
        results["vulnerabilities"] = vulns
        for v in vulns[:3]:
            print(f"  [!] {v}")
    
    cors = check_cors(url)
    if cors:
        results["cors"] = cors
        for c in cors[:3]:
            print(f"  [!] CORS: {c}")
    
    return results


def main():
    parser = argparse.ArgumentParser(description="Roger Recon - Full-featured Recon Tool 🐰")
    parser.add_argument("domain", help="Target domain (e.g., example.com)")
    parser.add_argument("-o", "--output", help="Output file (JSON)", default=None)
    parser.add_argument("--full-scan", help="Run full port scan", action="store_true")
    parser.add_argument("--detect-tech", help="Detect technologies", action="store_true")
    parser.add_argument("--vuln-scan", help="Run vulnerability scan", action="store_true")
    parser.add_argument("--screenshots", help="Take screenshots", action="store_true")
    parser.add_argument("--screenshot-dir", help="Screenshot output directory", default="screenshots")
    
    args = parser.parse_args()
    
    domain = args.domain.lower().strip()
    
    if not re.match(r'^[a-z0-9\-\.]+$', domain):
        print("[!] Invalid domain format")
        return
    
    # Check playwright
    if args.screenshots and not PLAYWRIGHT_AVAILABLE:
        print("[!] Playwright not installed. Run: pip install playwright && playwright install chromium")
    
    # Create screenshot dir
    if args.screenshots:
        os.makedirs(args.screenshot_dir, exist_ok=True)
    
    print(f"[*] Starting recon on: {domain}")
    print("=" * 60)
    
    results = {
        "domain": domain,
        "subdomains": [],
        "ports": {},
        "technologies": {},
        "vulnerabilities": {},
        "screenshots": {}
    }
    
    # Subdomain enum
    print("\n[>>] STEP 1: Subdomain Enumeration")
    print("-" * 40)
    ct_subs = crt_sh_enum(domain)
    results["subdomains"].extend(ct_subs)
    
    bf_subs = bruteforce_subdomains(domain)
    results["subdomains"].extend(bf_subs)
    
    results["subdomains"] = sorted(list(set(results["subdomains"])))
    print(f"\n[*] Total subdomains: {len(results['subdomains'])}")
    
    # Port scan
    if args.full_scan:
        print("\n[>>] STEP 2: Port Scanning")
        print("-" * 40)
        results["ports"][domain] = scan_ports(domain, COMMON_PORTS[:15])
    
    # Tech detection
    if args.detect_tech:
        print("\n[>>] STEP 3: Technology Detection")
        print("-" * 40)
        
        for sub in results["subdomains"][:5]:
            try:
                url = f"https://{sub}"
                tech = detect_tech(url)
                results["technologies"][sub] = tech
                print(f"[+] {sub}: {', '.join(tech)}")
            except:
                pass
    
    # Vuln scan
    if args.vuln_scan:
        print("\n[>>] STEP 4: Vulnerability Scanning")
        print("-" * 40)
        
        for sub in results["subdomains"][:10]:
            try:
                vuln_results = scan_vulnerabilities(sub)
                if any([vuln_results["security_headers"], 
                       vuln_results["http_methods"],
                       vuln_results["vulnerabilities"],
                       vuln_results["cors"]]):
                    results["vulnerabilities"][sub] = vuln_results
            except Exception as e:
                print(f"[!] Error: {e}")
    
    # Screenshots
    if args.screenshots and PLAYWRIGHT_AVAILABLE:
        print("\n[>>] STEP 5: Screenshots")
        print("-" * 40)
        
        for sub in results["subdomains"][:10]:
            try:
                url = f"https://{sub}"
                screenshot_path = take_screenshot(url, args.screenshot_dir, sub.replace('.', '_'))
                results["screenshots"][sub] = screenshot_path
            except Exception as e:
                print(f"[!] Screenshot error: {e}")
    
    # Summary
    print("\n" + "=" * 60)
    print("[*] SUMMARY")
    print("-" * 60)
    print(f"Domain: {domain}")
    print(f"Subdomains: {len(results['subdomains'])}")
    print(f"Vulns found: {sum([len(v.get('security_headers', [])) + len(v.get('vulnerabilities', [])) for v in results['vulnerabilities'].values()])}")
    print(f"Screenshots: {len(results['screenshots'])}")
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n[*] Results saved to {args.output}")
    
    return results


if __name__ == "__main__":
    main()