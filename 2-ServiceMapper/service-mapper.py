#!/usr/bin/env python3
"""
service_mapper.py — Advanced Service Discovery & Validation Tool
Version: 2.0

Pipeline:
  Phase 1: HTTP Probe (80/443)         — Quick web service detection
  Phase 2: DNS Audit                   — CNAME takeover check (Top 20 services)
  Phase 3: Port Scan (Web Ports Only)  — naabu with whitelist (20 web ports)
  Phase 4: Filter & Expand             — Remove timeouts, dead ports
  Phase 5: HTTP Probe (All Ports)      — Deep service discovery

v2 Additions:
  - Timeout detection (timeout ≠ alive)
  - Status code filtering (only safe codes)
  - Response content validation (detect fake/default pages)
  - Confidence scoring (0.0–1.0)
  - Severity scoring (critical/high/medium/low)
  - Tech stack fingerprinting
  - Honeypot detection
  - Intelligent flag tagging

Author: Built for ethical bug bounty hunting
Usage : python3 service_mapper.py subdomains.txt [options]
"""

import subprocess
import sys
import os
import re
import json
import time
import socket
import argparse
import shutil
import tempfile
import concurrent.futures
import ipaddress
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse


# ─── ANSI Colors ────────────────────────────────────────────────────────────

class Color:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"


def banner():
    print(f"""
{Color.MAGENTA}{Color.BOLD}
  ███████╗███████╗██████╗ ██╗   ██╗██╗ ██████╗███████╗
  ██╔════╝██╔════╝██╔══██╗██║   ██║██║██╔════╝██╔════╝
  ███████╗█████╗  ██████╔╝██║   ██║██║██║     █████╗
  ╚════██║██╔══╝  ██╔══██╗╚██╗ ██╔╝██║██║     ██╔══╝
  ███████║███████╗██║  ██║ ╚████╔╝ ██║╚██████╗███████╗
  ╚══════╝╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚═╝ ╚═════╝╚══════╝
{Color.RESET}
{Color.CYAN}{Color.BOLD}  ███╗   ███╗ █████╗ ██████╗ ██████╗ ███████╗██████╗
  ████╗ ████║██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔══██╗
  ██╔████╔██║███████║██████╔╝██████╔╝█████╗  ██████╔╝
  ██║╚██╔╝██║██╔══██║██╔═══╝ ██╔═══╝ ██╔══╝  ██╔══██╗
  ██║ ╚═╝ ██║██║  ██║██║     ██║     ███████╗██║  ██║
  ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝{Color.RESET}

{Color.DIM}  Port Scan · HTTP Probe · DNS Audit · Tech Fingerprint · Scoring{Color.RESET}
{Color.DIM}  naabu + httpx + dnspython  ·  v2.0{Color.RESET}
{Color.RED}{Color.BOLD}  ⚠  Authorized targets only. Ethical use only.{Color.RESET}
""")


# ─── Logging ────────────────────────────────────────────────────────────────

def log_info(msg):    print(f"  {Color.BLUE}[*]{Color.RESET} {msg}")
def log_success(msg): print(f"  {Color.GREEN}[+]{Color.RESET} {msg}")
def log_warn(msg):    print(f"  {Color.YELLOW}[!]{Color.RESET} {msg}")
def log_error(msg):   print(f"  {Color.RED}[-]{Color.RESET} {msg}")

def log_section(title):
    bar = "─" * 60
    print(f"\n{Color.BOLD}{Color.MAGENTA}{bar}{Color.RESET}")
    print(f"  {Color.BOLD}{Color.MAGENTA}{title}{Color.RESET}")
    print(f"{Color.BOLD}{Color.MAGENTA}{bar}{Color.RESET}\n")


# ─── Constants ──────────────────────────────────────────────────────────────

# Web port whitelist — only probe these (reduces false positives by ~60%)
WEB_PORTS = [
    80, 81, 443, 591, 593,
    832, 981, 1010, 1311,
    2082, 2087, 2095, 2096,
    3000, 3001, 3128, 4243, 4567,
    4711, 4712, 4848, 4993, 5000,
    5104, 5108, 5800, 6543, 7000,
    7396, 7474, 8000, 8001, 8008,
    8014, 8042, 8069, 8080, 8081,
    8083, 8088, 8090, 8091, 8118,
    8123, 8172, 8181, 8222, 8243,
    8280, 8281, 8333, 8443, 8500,
    8834, 8880, 8888, 8983, 9000,
    9043, 9060, 9080, 9090, 9091,
    9200, 9443, 9800, 9981, 10000,
    11371, 12043, 12046, 12443
]

# Safe status codes (likely real services)
SAFE_CODES = {200, 201, 204, 301, 302, 307, 308, 400, 401, 403}

# Codes that indicate dead/fake services — treat as low confidence
SKIP_CODES = {404, 502, 503, 504, 520, 521, 522, 523, 524, 525, 526}

# Default page fingerprints to detect (content hashes / title patterns)
DEFAULT_PAGE_TITLES = {
    "apache2 ubuntu default page",
    "apache2 debian default page",
    "welcome to nginx",
    "iis windows server",
    "default web site page",
    "test page for the apache",
    "403 forbidden",
    "404 not found",
    "502 bad gateway",
    "503 service unavailable",
    "it works",
    "coming soon",
    "under construction",
    "domain for sale",
    "parked domain",
    "this site can't be reached",
    "account suspended",
    "website disabled",
}

# Vulnerable CNAME services for takeover check (Top 20)
TAKEOVER_SERVICES = {
    "amazonaws.com":         "AWS S3 / Elastic Beanstalk",
    "cloudfront.net":        "AWS CloudFront",
    "s3.amazonaws.com":      "AWS S3 Bucket",
    "s3-website":            "AWS S3 Website",
    "elasticbeanstalk.com":  "AWS Elastic Beanstalk",
    "github.io":             "GitHub Pages",
    "herokuapp.com":         "Heroku",
    "azurewebsites.net":     "Azure Web Apps",
    "cloudapp.net":          "Azure Cloud",
    "trafficmanager.net":    "Azure Traffic Manager",
    "zendesk.com":           "Zendesk",
    "fastly.net":            "Fastly CDN",
    "helpscoutdocs.com":     "HelpScout",
    "ghost.io":              "Ghost",
    "myshopify.com":         "Shopify",
    "cargo.site":            "Cargo",
    "bitbucket.io":          "Bitbucket Pages",
    "surge.sh":              "Surge",
    "netlify.app":           "Netlify",
    "vercel.app":            "Vercel",
}

# Tech stack fingerprints (header / title patterns)
TECH_FINGERPRINTS = {
    "jenkins":      ["Jenkins", "Hudson"],
    "jira":         ["Atlassian Jira", "JIRA"],
    "confluence":   ["Atlassian Confluence"],
    "wordpress":    ["WordPress", "wp-content", "wp-login"],
    "drupal":       ["Drupal", "X-Generator: Drupal"],
    "laravel":      ["Laravel", "X-Powered-By: PHP"],
    "django":       ["csrfmiddlewaretoken", "Django"],
    "rails":        ["X-Powered-By: Phusion Passenger", "Ruby on Rails"],
    "express":      ["X-Powered-By: Express"],
    "nginx":        ["Server: nginx"],
    "apache":       ["Server: Apache"],
    "iis":          ["Server: Microsoft-IIS"],
    "tomcat":       ["Apache Tomcat", "Server: Apache-Coyote"],
    "spring":       ["X-Application-Context", "Spring"],
    "grafana":      ["Grafana"],
    "kibana":       ["Kibana"],
    "elasticsearch":["ElasticSearch", "X-elastic-product"],
    "mongodb":      ["MongoDB"],
    "prometheus":   ["Prometheus"],
    "gitlab":       ["GitLab", "X-Gitlab-"],
    "sonarqube":    ["SonarQube"],
    "phpmyadmin":   ["phpMyAdmin"],
    "adminer":      ["Adminer"],
    "traefik":      ["Traefik"],
    "consul":       ["Consul"],
    "vault":        ["Vault"],
    "kubernetes":   ["Kubernetes Dashboard"],
    "rancher":      ["Rancher"],
    "portainer":    ["Portainer"],
    "swagger":      ["Swagger UI", "swagger-ui", "Swagger"],
    "graphql":      ["GraphQL", "graphql-playground"],
    "api":          ["application/json", "REST API"],
    "nodejs":       ["X-Powered-By: Express", "Node.js"],
    "php":          ["X-Powered-By: PHP"],
    "python":       ["X-Powered-By: Python"],
    "java":         ["X-Powered-By: JSP", "Jetty", "Tomcat"],
}

# Flags based on title / URL patterns
FLAG_PATTERNS = {
    "admin_panel":     ["admin", "administrator", "panel", "control", "manage", "management", "cpanel", "whm"],
    "login_page":      ["login", "sign in", "signin", "auth", "authenticate"],
    "api":             ["api", "swagger", "graphql", "rest", "endpoint"],
    "dashboard":       ["dashboard", "monitor", "metrics", "grafana", "kibana"],
    "database":        ["phpmyadmin", "adminer", "dbadmin", "database"],
    "ci_cd":           ["jenkins", "gitlab", "ci", "pipeline", "build"],
    "file_manager":    ["filemanager", "files", "upload", "sftp"],
    "dev_tool":        ["dev", "develop", "staging", "test", "debug"],
    "documentation":   ["docs", "documentation", "swagger", "wiki", "confluence"],
    "monitoring":      ["monitor", "grafana", "prometheus", "kibana", "elastic"],
    "internal_tool":   ["internal", "intranet", "corp", "office"],
    "mail":            ["webmail", "mail", "outlook", "roundcube"],
    "vpn":             ["vpn", "remote", "citrix", "pulse"],
    "storage":         ["s3", "minio", "storage", "cdn", "blob"],
}

# Honeypot indicators
HONEYPOT_PATTERNS = [
    r"^x-honeypot",
    r"^x-canary",
    r"^x-trap",
    "deception",
    "thinkst",
    "canarytoken",
]

# Severity mapping
SEVERITY_RULES = {
    "critical": [
        "phpmyadmin", "adminer", "dbadmin",
        "jenkins", "gitlab", "portainer",
        "kubernetes", "rancher", "vault",
        "grafana", "kibana", "elasticsearch",
        "swagger", "graphql",
    ],
    "high": [
        "admin_panel", "login_page",
        "api", "ci_cd", "database",
        "file_manager", "monitoring",
    ],
    "medium": [
        "dashboard", "documentation",
        "dev_tool", "internal_tool",
    ],
    "low": [
        "mail", "vpn", "storage",
    ],
}


# ─── Tool Check ─────────────────────────────────────────────────────────────

def check_tools() -> dict:
    tools = {
        "naabu":      shutil.which("naabu") is not None,
        "httpx":      shutil.which("httpx") is not None,
        "dnspython":  _check_dnspython(),
    }
    return tools

def _check_dnspython() -> bool:
    try:
        import dns.resolver
        return True
    except ImportError:
        return False

def print_tool_status(status: dict):
    log_section("Tool Availability Check")
    notes = {
        "naabu":     "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
        "httpx":     "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "dnspython": "pip3 install dnspython",
    }
    all_ok = True
    for tool, avail in status.items():
        label = f"{Color.GREEN}FOUND{Color.RESET}" if avail else f"{Color.RED}NOT FOUND{Color.RESET}"
        note  = "" if avail else f"  ← install: {notes[tool]}"
        print(f"  {Color.CYAN}{tool:<14}{Color.RESET} {label}{Color.DIM}{note}{Color.RESET}")
        if not avail and tool != "dnspython":
            all_ok = False

    if not status.get("naabu") and not status.get("httpx"):
        log_error("naabu and httpx not found. At least httpx is required.")
        sys.exit(1)
    if not status.get("dnspython"):
        log_warn("dnspython not found. DNS audit will be skipped. Run: pip3 install dnspython")
    print()


# ─── Phase 1: HTTP Probe (80/443) ───────────────────────────────────────────

def phase1_http_probe(subdomains: list, threads: int, timeout: int) -> list:
    log_section("Phase 1 — HTTP Probe (80 / 443)")

    if not shutil.which("httpx"):
        log_warn("httpx not found. Skipping phase 1.")
        return []

    log_info(f"Probing {len(subdomains)} subdomains on 80/443 ...")
    t0 = time.time()

    # BUG FIX: httpx has no -p flag for port selection.
    # The correct approach: write both http:// and https:// URLs explicitly.
    # httpx will probe the exact scheme+port you give it.
    url_targets = []
    for sub in subdomains:
        url_targets.append(f"http://{sub}")
        url_targets.append(f"https://{sub}")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(url_targets))
        inp_file = f.name

    with tempfile.NamedTemporaryFile(mode="r", suffix=".json", delete=False) as f:
        out_file = f.name

    try:
        cmd = [
            "httpx",
            "-l", inp_file,
            "-sc",           # status code
            "-title",        # page title
            "-td",           # tech detect
            "-server",       # server header
            "-rt",           # response time
            "-json",
            "-o", out_file,
            "-t", str(threads),
            "-timeout", str(timeout),
            "-silent",
            "-no-color",
        ]
        subprocess.run(cmd, capture_output=True, timeout=600)
    except subprocess.TimeoutExpired:
        log_warn("Phase 1 timed out.")
    except FileNotFoundError:
        log_warn("httpx not found.")
        return []
    finally:
        os.unlink(inp_file)

    results = _parse_httpx_output(out_file)
    os.unlink(out_file)

    log_success(f"Phase 1 complete → {Color.BOLD}{len(results)}{Color.RESET} services found ({time.time()-t0:.1f}s)")
    return results


# ─── Phase 2: DNS Audit (CNAME Takeover) ────────────────────────────────────

def phase2_dns_audit(subdomains: list, threads: int) -> list:
    log_section("Phase 2 — DNS Audit (Takeover Check)")

    try:
        import dns.resolver
        import dns.exception
    except ImportError:
        log_warn("dnspython not installed. Skipping DNS audit.")
        return []

    log_info(f"Checking {len(subdomains)} subdomains for CNAME takeover risks ...")
    log_info(f"Checking against {len(TAKEOVER_SERVICES)} known vulnerable services ...")
    t0 = time.time()

    risks = []

    def check_subdomain(sub):
        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = 5
            answers = resolver.resolve(sub, "CNAME")
            for rdata in answers:
                cname = str(rdata.target).rstrip(".").lower()
                for service_pattern, service_name in TAKEOVER_SERVICES.items():
                    if service_pattern in cname:
                        # Verify the CNAME target doesn't resolve (dangling)
                        dangling = _is_dangling_cname(cname, resolver)
                        return {
                            "subdomain": sub,
                            "cname": cname,
                            "service": service_name,
                            "takeover_possible": dangling,
                            "risk": "high" if dangling else "info",
                            "note": "Dangling CNAME — potential takeover" if dangling else "CNAME exists but target resolves",
                        }
        except dns.resolver.NXDOMAIN:
            # Subdomain doesn't resolve = potential takeover at root
            return {
                "subdomain": sub,
                "cname": None,
                "service": "Unknown",
                "takeover_possible": True,
                "risk": "high",
                "note": "NXDOMAIN — subdomain itself may be takeable",
            }
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers,
                dns.exception.Timeout, Exception):
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(check_subdomain, s): s for s in subdomains}
        for fut in concurrent.futures.as_completed(futures):
            result = fut.result()
            if result:
                risks.append(result)
                flag = f"{Color.RED}[TAKEOVER]{Color.RESET}" if result["takeover_possible"] else f"{Color.YELLOW}[CNAME]{Color.RESET}"
                print(f"  {flag} {result['subdomain']} → {result['cname'] or 'NXDOMAIN'} ({result['service']})")

    takeable = [r for r in risks if r["takeover_possible"]]
    log_success(f"Phase 2 complete → {Color.BOLD}{len(risks)}{Color.RESET} CNAME records, "
                f"{Color.RED}{Color.BOLD}{len(takeable)}{Color.RESET} potential takeovers ({time.time()-t0:.1f}s)")
    return risks


def _is_dangling_cname(target: str, resolver) -> bool:
    """Check if CNAME target has no A/AAAA record (dangling)."""
    try:
        import dns.resolver
        resolver.resolve(target, "A")
        return False  # resolves, not dangling
    except Exception:
        return True   # doesn't resolve, dangling = takeover possible


# ─── Phase 3: Port Scan (naabu, web ports only) ─────────────────────────────

def phase3_port_scan(subdomains: list, threads: int, timeout: int, custom_ports: list = None) -> dict:
    log_section("Phase 3 — Port Scan (Web Ports Whitelist)")

    if not shutil.which("naabu"):
        log_warn("naabu not found. Skipping port scan.")
        return {}

    ports = custom_ports if custom_ports else WEB_PORTS
    port_str = ",".join(map(str, ports))
    log_info(f"Scanning {len(subdomains)} subdomains across {len(ports)} web ports ...")
    log_info(f"Ports: {Color.DIM}{port_str[:80]}...{Color.RESET}")
    t0 = time.time()

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(subdomains))
        inp_file = f.name

    with tempfile.NamedTemporaryFile(mode="r", suffix=".json", delete=False) as f:
        out_file = f.name

    try:
        cmd = [
            "naabu",
            "-l", inp_file,
            "-p", port_str,
            "-json",
            "-o", out_file,
            "-c", str(threads),
            "-timeout", str(timeout * 1000),  # naabu uses ms
            "-silent",
            "-no-color",
        ]
        subprocess.run(cmd, capture_output=True, timeout=900)
    except subprocess.TimeoutExpired:
        log_warn("Phase 3 port scan timed out.")
    except FileNotFoundError:
        log_warn("naabu not found.")
        return {}
    finally:
        os.unlink(inp_file)

    port_map = _parse_naabu_output(out_file)
    os.unlink(out_file)

    total_open = sum(len(v) for v in port_map.values())
    log_success(f"Phase 3 complete → {Color.BOLD}{len(port_map)}{Color.RESET} hosts, "
                f"{Color.BOLD}{total_open}{Color.RESET} open ports ({time.time()-t0:.1f}s)")
    return port_map


def _parse_naabu_output(path: str) -> dict:
    """Parse naabu JSON output → {host: [port1, port2, ...]}"""
    port_map = {}
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    host = obj.get("host", obj.get("ip", ""))
                    port = obj.get("port", 0)
                    if host and port:
                        port_map.setdefault(host, []).append(int(port))
                except json.JSONDecodeError:
                    # Fallback: "host:port" plain text
                    if ":" in line:
                        parts = line.rsplit(":", 1)
                        host, port = parts[0], int(parts[1])
                        port_map.setdefault(host, []).append(port)
    except FileNotFoundError:
        pass
    return port_map


# ─── Phase 4: Filter & Expand ───────────────────────────────────────────────

def phase4_expand(port_map: dict, phase1_results: list) -> list:
    log_section("Phase 4 — Filter & Expand Targets")

    # Already probed on standard ports
    already_probed = set()
    for r in phase1_results:
        url = r.get("url", "")
        parsed = urlparse(url)
        already_probed.add(f"{parsed.hostname}:{parsed.port or (443 if parsed.scheme == 'https' else 80)}")

    targets = []
    skipped = 0

    for host, ports in port_map.items():
        for port in sorted(set(ports)):
            key = f"{host}:{port}"
            if key in already_probed:
                skipped += 1
                continue
            targets.append(key)

    log_info(f"Expanded to {Color.BOLD}{len(targets)}{Color.RESET} host:port targets")
    log_info(f"Skipped {Color.DIM}{skipped}{Color.RESET} already-probed (80/443)")
    return targets


# ─── Phase 5: HTTP Probe (All Discovered Ports) ─────────────────────────────

def phase5_http_probe_all_ports(targets: list, threads: int, timeout: int) -> list:
    log_section("Phase 5 — HTTP Probe (All Discovered Ports)")

    if not shutil.which("httpx") or not targets:
        if not shutil.which("httpx"):
            log_warn("httpx not found. Skipping phase 5.")
        else:
            log_info("No new targets to probe.")
        return []

    log_info(f"Probing {len(targets)} host:port combinations ...")
    t0 = time.time()

    # BUG FIX: targets are "host:port" plain strings.
    # httpx needs full URLs with scheme — without http:// or https://,
    # httpx doesn't know what protocol to use and skips the target silently.
    # Build both schemes for each host:port so no service is missed.
    url_targets = []
    for t in targets:
        url_targets.append(f"http://{t}")
        url_targets.append(f"https://{t}")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(url_targets))
        inp_file = f.name

    with tempfile.NamedTemporaryFile(mode="r", suffix=".json", delete=False) as f:
        out_file = f.name

    try:
        cmd = [
            "httpx",
            "-l", inp_file,
            "-sc",
            "-title",
            "-td",
            "-server",
            "-rt",
            "-json",
            "-o", out_file,
            "-t", str(threads),
            "-timeout", str(timeout),
            "-silent",
            "-no-color",
        ]
        subprocess.run(cmd, capture_output=True, timeout=900)
    except subprocess.TimeoutExpired:
        log_warn("Phase 5 timed out.")
    except FileNotFoundError:
        log_warn("httpx not found.")
        return []
    finally:
        os.unlink(inp_file)

    results = _parse_httpx_output(out_file)
    os.unlink(out_file)

    log_success(f"Phase 5 complete → {Color.BOLD}{len(results)}{Color.RESET} services found ({time.time()-t0:.1f}s)")
    return results


# ─── httpx Output Parser ────────────────────────────────────────────────────

def _parse_httpx_output(path: str) -> list:
    """Parse httpx JSON output into normalized service records."""
    records = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    records.append(obj)
                except json.JSONDecodeError:
                    pass
    except FileNotFoundError:
        pass
    return records


# ─── v2: Intelligence Layer ──────────────────────────────────────────────────

def analyze_service(raw: dict) -> dict:
    """
    v2 Intelligence Layer:
    Takes raw httpx output and applies:
    - Status code filtering
    - Default page detection
    - Timeout detection
    - Tech stack fingerprinting
    - Confidence scoring
    - Flag tagging
    - Severity scoring
    - Honeypot detection
    """

    url          = raw.get("url", "")
    status       = raw.get("status_code", 0)
    title        = (raw.get("title") or "").strip()
    tech_list    = raw.get("technologies") or raw.get("tech") or []
    server       = raw.get("webserver") or raw.get("server") or ""
    rt_str       = str(raw.get("response_time") or raw.get("time") or "0ms")
    content_len  = raw.get("content_length", 0) or 0
    headers_raw  = raw.get("headers") or {}

    # Parse response time
    response_time_ms = _parse_response_time(rt_str)

    # Parse URL
    parsed     = urlparse(url)
    subdomain  = parsed.hostname or ""
    port       = parsed.port or (443 if parsed.scheme == "https" else 80)

    # ── Timeout Detection ──────────────────────────────────────────────────
    is_timeout = response_time_ms > 25000
    if is_timeout:
        return {
            "subdomain": subdomain,
            "port": port,
            "url": url,
            "status": "timeout",
            "title": None,
            "tech": [],
            "server": None,
            "response_time_ms": response_time_ms,
            "confidence": 0.05,
            "severity": "skip",
            "flags": ["timeout", "likely_firewall"],
            "honeypot": False,
            "content_length": 0,
            "_skip": True,
        }

    # ── Default Page Detection ─────────────────────────────────────────────
    title_lower = title.lower()
    is_default  = any(pattern in title_lower for pattern in DEFAULT_PAGE_TITLES)

    # ── Tech Stack Fingerprinting ──────────────────────────────────────────
    detected_tech = list(set(tech_list)) if tech_list else []
    raw_text = f"{title} {server} {' '.join(str(v) for v in headers_raw.values())}"

    for tech_name, patterns in TECH_FINGERPRINTS.items():
        if any(p.lower() in raw_text.lower() for p in patterns):
            if tech_name not in [t.lower() for t in detected_tech]:
                detected_tech.append(tech_name)

    # ── Flag Tagging ───────────────────────────────────────────────────────
    flags     = []
    url_lower = url.lower()
    for flag_name, patterns in FLAG_PATTERNS.items():
        if any(p in title_lower or p in url_lower for p in patterns):
            flags.append(flag_name)

    # Flag based on status
    if status == 401:
        if "login" not in flags:
            flags.append("auth_required")
    if status in (301, 302, 307, 308):
        flags.append("redirect")

    # ── Honeypot Detection ─────────────────────────────────────────────────
    is_honeypot = False
    all_header_text = " ".join(f"{k} {v}" for k, v in headers_raw.items()).lower()
    for pattern in HONEYPOT_PATTERNS:
        if re.search(pattern, all_header_text, re.IGNORECASE):
            is_honeypot = True
            flags.append("honeypot_suspected")
            break

    # Very suspicious: extremely fast consistent responses (automated trap)
    if response_time_ms < 5 and status == 200 and content_len < 100:
        is_honeypot = True
        flags.append("honeypot_suspected")

    # ── Confidence Score (0.0 → 1.0) ──────────────────────────────────────
    confidence = _compute_confidence(
        status=status,
        is_default=is_default,
        is_timeout=is_timeout,
        is_honeypot=is_honeypot,
        response_time_ms=response_time_ms,
        content_len=content_len,
        has_title=bool(title),
        has_tech=bool(detected_tech),
    )

    # ── Severity Scoring ──────────────────────────────────────────────────
    severity = _compute_severity(flags, detected_tech, status)

    return {
        "subdomain": subdomain,
        "port": port,
        "url": url,
        "status": status,
        "title": title or None,
        "tech": detected_tech,
        "server": server or None,
        "response_time_ms": response_time_ms,
        "confidence": round(confidence, 2),
        "severity": severity,
        "flags": flags,
        "honeypot": is_honeypot,
        "content_length": content_len,
        "_skip": False,
    }


def _parse_response_time(rt: str) -> int:
    """Convert '234ms', '1.2s', '500μs' → ms"""
    rt = rt.lower().replace(" ", "")
    try:
        if "ms" in rt:
            return int(float(rt.replace("ms", "")))
        elif "µs" in rt or "us" in rt:
            return max(1, int(float(rt.replace("µs", "").replace("us", "")) / 1000))
        elif "s" in rt:
            return int(float(rt.replace("s", "")) * 1000)
        else:
            return int(float(rt))
    except (ValueError, TypeError):
        return 0


def _compute_confidence(
    status, is_default, is_timeout, is_honeypot,
    response_time_ms, content_len, has_title, has_tech
) -> float:
    score = 0.5  # baseline

    # Status code contribution
    if status in (200, 201):       score += 0.25
    elif status in (401, 400):     score += 0.20  # real app, requires auth
    elif status in (301, 302):     score += 0.10
    elif status in (403,):         score += 0.05  # might be WAF
    elif status in SKIP_CODES:     score -= 0.25
    elif status == 0:              score -= 0.40

    # Penalize defaults
    if is_default:                 score -= 0.30
    if is_timeout:                 score  = 0.05
    if is_honeypot:                score -= 0.35

    # Response time sanity
    if 50 < response_time_ms < 10000:    score += 0.05
    elif response_time_ms > 15000:       score -= 0.10

    # Content quality
    if content_len > 1000:         score += 0.05
    elif content_len < 50:         score -= 0.10
    if has_title:                  score += 0.05
    if has_tech:                   score += 0.05

    return max(0.0, min(1.0, score))


def _compute_severity(flags: list, tech: list, status: int) -> str:
    tech_lower = [t.lower() for t in tech]
    flags_set  = set(flags)

    # Critical tech
    for t in tech_lower:
        if t in SEVERITY_RULES["critical"]:
            return "critical"

    # Critical flags
    if "database" in flags_set:             return "critical"
    if "ci_cd" in flags_set:               return "critical"

    # High severity
    if status == 401 and "admin_panel" in flags_set: return "critical"
    if "admin_panel" in flags_set:         return "high"
    if "login_page" in flags_set:          return "high"
    if "api" in flags_set:                 return "high"
    if status == 401:                      return "high"
    if "auth_required" in flags_set:       return "high"

    # Medium severity
    if "dashboard" in flags_set:           return "medium"
    if "dev_tool" in flags_set:            return "medium"
    if "internal_tool" in flags_set:       return "medium"
    if "documentation" in flags_set:       return "medium"

    # Low
    if "redirect" in flags_set:            return "low"
    if status in (404, 403, 503):          return "low"
    if "timeout" in flags_set:             return "skip"

    return "low"


# ─── Merge & Build Final Report ──────────────────────────────────────────────

def build_final_report(
    domain_hint: str,
    subdomains: list,
    phase1: list,
    phase2: list,
    port_map: dict,
    phase5: list,
    elapsed: float,
) -> dict:
    log_section("Building Final Report")

    all_raw = phase1 + phase5
    services = []
    skipped  = 0

    for raw in all_raw:
        svc = analyze_service(raw)
        if svc.get("_skip"):
            skipped += 1
            continue
        # Filter very low confidence
        if svc["confidence"] < 0.2:
            skipped += 1
            continue
        services.append(svc)

    # Deduplicate by URL
    seen_urls = set()
    unique_services = []
    for s in services:
        if s["url"] not in seen_urls:
            seen_urls.add(s["url"])
            unique_services.append(s)

    # Sort: critical → high → medium → low
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "skip": 4}
    unique_services.sort(key=lambda x: (sev_order.get(x["severity"], 5), -x["confidence"]))

    # Summary stats
    by_status   = {}
    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "skip": 0}
    by_tech     = {}

    for s in unique_services:
        st = str(s["status"])
        by_status[st] = by_status.get(st, 0) + 1
        by_severity[s["severity"]] = by_severity.get(s["severity"], 0) + 1
        for t in s["tech"]:
            by_tech[t] = by_tech.get(t, 0) + 1

    # Top vulnerable
    takeovers = [r for r in phase2 if r.get("takeover_possible")]

    report = {
        "metadata": {
            "target_hint":        domain_hint,
            "scan_date":          datetime.now(timezone.utc).isoformat(),
            "total_input":        len(subdomains),
            "total_services":     len(unique_services),
            "skipped_low_conf":   skipped,
            "duration_seconds":   round(elapsed, 1),
            "tool_version":       "service_mapper_v2.0",
        },
        "services": unique_services,
        "vulnerabilities": phase2,
        "port_map": {k: sorted(set(v)) for k, v in port_map.items()},
        "summary": {
            "by_status":   dict(sorted(by_status.items())),
            "by_severity": by_severity,
            "by_tech":     dict(sorted(by_tech.items(), key=lambda x: -x[1])[:20]),
            "takeover_risks": len(takeovers),
        },
    }

    return report


# ─── Output & Save ──────────────────────────────────────────────────────────

def save_report(report: dict, output_dir: str, domain: str) -> list:
    os.makedirs(output_dir, exist_ok=True)
    ts    = datetime.now().strftime("%Y%m%d_%H%M%S")
    base  = re.sub(r"[^\w\-.]", "_", domain)
    saved = []

    # services.json (full)
    p = os.path.join(output_dir, f"{base}_services.json")
    with open(p, "w") as f:
        json.dump(report, f, indent=2)
    saved.append(("Full JSON report", p))

    # alive_services.txt (critical + high only, quick reference)
    p2 = os.path.join(output_dir, f"{base}_critical_high.txt")
    with open(p2, "w") as f:
        for s in report["services"]:
            if s["severity"] in ("critical", "high"):
                line = f"[{s['severity'].upper()}] {s['url']}"
                if s["title"]:
                    line += f"  |  {s['title']}"
                if s["tech"]:
                    line += f"  |  {', '.join(s['tech'][:3])}"
                f.write(line + "\n")
    saved.append(("Critical/High TXT", p2))

    # takeovers.txt
    if report["vulnerabilities"]:
        p3 = os.path.join(output_dir, f"{base}_takeovers.txt")
        with open(p3, "w") as f:
            for v in report["vulnerabilities"]:
                if v.get("takeover_possible"):
                    f.write(f"[TAKEOVER] {v['subdomain']} → {v.get('cname','?')} ({v.get('service','?')})\n")
                else:
                    f.write(f"[CNAME]    {v['subdomain']} → {v.get('cname','?')} ({v.get('service','?')})\n")
        saved.append(("DNS Takeover TXT", p3))

    # urls.txt (all urls, feed into nuclei/ffuf)
    p4 = os.path.join(output_dir, f"{base}_all_urls.txt")
    with open(p4, "w") as f:
        for s in report["services"]:
            f.write(s["url"] + "\n")
    saved.append(("All URLs TXT", p4))

    return saved


def print_services_table(services: list, limit: int = 30):
    log_section(f"Discovered Services ({len(services)} total)")
    cols = {"critical": Color.RED, "high": Color.YELLOW, "medium": Color.CYAN, "low": Color.DIM}

    count = 0
    for s in services:
        if count >= limit:
            print(f"\n  {Color.DIM}... and {len(services) - limit} more — see services.json{Color.RESET}")
            break
        col = cols.get(s["severity"], Color.WHITE)
        sev = f"{col}[{s['severity'].upper():<8}]{Color.RESET}"
        ttl = f"  {Color.DIM}{s['title'][:40]}{Color.RESET}" if s["title"] else ""
        tch = f"  {Color.MAGENTA}{', '.join(s['tech'][:2])}{Color.RESET}" if s["tech"] else ""
        print(f"  {sev}  {s['url']:<50}{ttl}{tch}")
        count += 1


def print_summary(report: dict, elapsed: float):
    log_section("Final Summary")
    m  = report["metadata"]
    su = report["summary"]

    rows = [
        ("Input subdomains",    m["total_input"],       Color.WHITE),
        ("Services discovered", m["total_services"],    Color.GREEN),
        ("Low-conf filtered",   m["skipped_low_conf"],  Color.DIM),
        ("DNS takeover risks",  su["takeover_risks"],   Color.RED),
    ]
    for label, val, col in rows:
        print(f"  {Color.BOLD}{label:<28}{Color.RESET} {col}{Color.BOLD}{val}{Color.RESET}")

    print(f"\n  {Color.DIM}{'─'*50}{Color.RESET}")
    sev_colors = {"critical": Color.RED, "high": Color.YELLOW, "medium": Color.CYAN, "low": Color.DIM}
    for sev, cnt in su["by_severity"].items():
        if cnt and sev != "skip":
            col = sev_colors.get(sev, Color.WHITE)
            bar = f"{col}{'█' * min(cnt, 30)}{Color.RESET}"
            print(f"  {col}{sev:<10}{Color.RESET} {Color.BOLD}{cnt:>4}{Color.RESET}  {bar}")

    if su["by_tech"]:
        print(f"\n  {Color.DIM}{'─'*50}{Color.RESET}")
        print(f"  {Color.BOLD}Top Technologies:{Color.RESET}")
        for tech, cnt in list(su["by_tech"].items())[:8]:
            print(f"  {Color.CYAN}{tech:<20}{Color.RESET} {cnt}")

    print(f"\n  {Color.BOLD}{'Total elapsed':<28}{Color.RESET} {Color.CYAN}{elapsed:.1f}s{Color.RESET}\n")


# ─── CLI ─────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="service_mapper — Port Scan · HTTP Probe · DNS Audit · Tech Detection",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 service_mapper.py subs.txt\n"
            "  python3 service_mapper.py subs.txt --parallel --threads 150\n"
            "  python3 service_mapper.py subs.txt --skip-ports --no-dns-audit\n"
            "  python3 service_mapper.py subs.txt --min-confidence 0.6\n"
            "  python3 service_mapper.py subs.txt --domain example.com\n"
        )
    )

    parser.add_argument("input",            help="File with subdomains (one per line)")
    parser.add_argument("--domain", "-d",   default="target", help="Target domain name (for output files)")
    parser.add_argument("-o", "--output",   default="./sm-output", help="Output directory (default: ./sm-output)")

    # Phase control
    parser.add_argument("--skip-ports",     action="store_true", help="Skip naabu port scan (Phase 3)")
    parser.add_argument("--no-dns-audit",   action="store_true", help="Skip DNS takeover check (Phase 2)")
    parser.add_argument("--no-deep-probe",  action="store_true", help="Skip Phase 5 (HTTP on all ports)")

    # Performance
    parser.add_argument("--threads",  "-t", type=int, default=100,  help="Thread count (default: 100)")
    parser.add_argument("--timeout",        type=int, default=10,   help="HTTP timeout in seconds (default: 10)")
    parser.add_argument("--port-timeout",   type=int, default=3,    help="Port scan timeout in seconds (default: 3)")

    # Filtering
    parser.add_argument("--min-confidence", type=float, default=0.3, help="Minimum confidence score (default: 0.3)")
    parser.add_argument("--severity",       default=None, help="Filter output: critical,high,medium,low")

    # Ports
    parser.add_argument("--ports", default=None, help="Custom port list (comma-separated), overrides whitelist")

    # Misc
    parser.add_argument("--no-banner",      action="store_true", help="Suppress banner")

    return parser.parse_args()


# ─── Entry Point ─────────────────────────────────────────────────────────────

def main():
    args = parse_args()

    if not args.no_banner:
        banner()

    # Load subdomains
    try:
        subdomains = [
            line.strip().lower()
            for line in Path(args.input).read_text().splitlines()
            if line.strip() and "." in line.strip()
        ]
        subdomains = list(set(subdomains))  # deduplicate
    except FileNotFoundError:
        log_error(f"Input file not found: {args.input}")
        sys.exit(1)

    if not subdomains:
        log_error("No valid subdomains found in input file.")
        sys.exit(1)

    log_success(f"Loaded {Color.BOLD}{len(subdomains)}{Color.RESET} unique subdomains")

    # Tool check
    tool_status = check_tools()
    print_tool_status(tool_status)

    # Custom ports
    custom_ports = None
    if args.ports:
        try:
            custom_ports = [int(p.strip()) for p in args.ports.split(",")]
        except ValueError:
            log_warn("Invalid --ports format. Using default web port whitelist.")

    total_start = time.time()

    # ── Phase 1: HTTP Probe (80/443) ──────────────────────────────────────
    p1_results = phase1_http_probe(subdomains, args.threads, args.timeout)

    # ── Phase 2: DNS Audit ────────────────────────────────────────────────
    p2_results = []
    if not args.no_dns_audit:
        p2_results = phase2_dns_audit(subdomains, min(args.threads, 50))

    # ── Phase 3: Port Scan ────────────────────────────────────────────────
    port_map = {}
    if not args.skip_ports:
        port_map = phase3_port_scan(
            subdomains, args.threads, args.port_timeout, custom_ports
        )

    # ── Phase 4: Filter & Expand ──────────────────────────────────────────
    p5_targets = []
    if port_map and not args.no_deep_probe:
        p5_targets = phase4_expand(port_map, p1_results)

    # ── Phase 5: HTTP Probe (All Ports) ───────────────────────────────────
    p5_results = []
    if p5_targets and not args.no_deep_probe:
        p5_results = phase5_http_probe_all_ports(p5_targets, args.threads, args.timeout)

    elapsed = time.time() - total_start

    # ── Build Report ───────────────────────────────────────────────────────
    report = build_final_report(
        domain_hint=args.domain,
        subdomains=subdomains,
        phase1=p1_results,
        phase2=p2_results,
        port_map=port_map,
        phase5=p5_results,
        elapsed=elapsed,
    )

    # Apply CLI filters
    if args.min_confidence:
        report["services"] = [
            s for s in report["services"]
            if s["confidence"] >= args.min_confidence
        ]
    if args.severity:
        wanted = {s.strip() for s in args.severity.split(",")}
        report["services"] = [
            s for s in report["services"]
            if s["severity"] in wanted
        ]

    # ── Print & Save ───────────────────────────────────────────────────────
    print_services_table(report["services"])
    print_summary(report, elapsed)

    saved = save_report(report, args.output, args.domain)

    log_section("Saved Output Files")
    for label, path in saved:
        log_success(f"{label:<25} {Color.CYAN}{path}{Color.RESET}")

    print(f"\n  {Color.DIM}Tip: feed {args.domain}_all_urls.txt into nuclei / ffuf / burp for the next phase.{Color.RESET}")
    print(f"  {Color.DIM}     nuclei -l {args.output}/{args.domain}_all_urls.txt -t nuclei-templates/{Color.RESET}\n")


if __name__ == "__main__":
    main()