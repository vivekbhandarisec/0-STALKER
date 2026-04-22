#!/usr/bin/env python3
"""
url_mapper.py — Passive URL Gathering & Intelligence Tool
Version: 1.0

Pipeline:
  Phase 1: Wayback Machine  — Historical URLs (deleted endpoints)
  Phase 2: GAU              — Google Cache + Wayback + OTX
  Phase 3: Katana           — Live site crawling (JS-aware)
  Phase 4: Merge & Analyze  — Dedup, score, tag, output

Intelligence Layer:
  - Source-based confidence scoring
  - CDN/tracking URL filtering
  - Junk parameter removal
  - Parameter injection risk flagging
  - API endpoint detection
  - Admin panel detection
  - Temporal confidence (recent = more reliable)
  - Normalized deduplication

Author: Built for ethical bug bounty hunting
Usage : python3 url_mapper.py -d example.com [options]
        python3 url_mapper.py -l services.json [options]
"""

import subprocess
import sys
import os
import re
import json
import time
import argparse
import shutil
import tempfile
import hashlib
import concurrent.futures
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


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
{Color.CYAN}{Color.BOLD}
  ██╗   ██╗██████╗ ██╗         ███╗   ███╗ █████╗ ██████╗ ██████╗ ███████╗██████╗
  ██║   ██║██╔══██╗██║         ████╗ ████║██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔══██╗
  ██║   ██║██████╔╝██║         ██╔████╔██║███████║██████╔╝██████╔╝█████╗  ██████╔╝
  ██║   ██║██╔══██╗██║         ██║╚██╔╝██║██╔══██║██╔═══╝ ██╔═══╝ ██╔══╝  ██╔══██╗
  ╚██████╔╝██║  ██║███████╗    ██║ ╚═╝ ██║██║  ██║██║     ██║     ███████╗██║  ██║
   ╚═════╝ ╚═╝  ╚═╝╚══════╝    ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝
{Color.RESET}
{Color.DIM}  Wayback Machine · GAU · Katana · Smart Dedup · Confidence Scoring{Color.RESET}
{Color.RED}{Color.BOLD}  ⚠  Authorized targets only. Ethical use only.{Color.RESET}
""")


# ─── Logging ────────────────────────────────────────────────────────────────

def log_info(msg):    print(f"  {Color.BLUE}[*]{Color.RESET} {msg}")
def log_success(msg): print(f"  {Color.GREEN}[+]{Color.RESET} {msg}")
def log_warn(msg):    print(f"  {Color.YELLOW}[!]{Color.RESET} {msg}")
def log_error(msg):   print(f"  {Color.RED}[-]{Color.RESET} {msg}")

def log_section(title):
    bar = "─" * 60
    print(f"\n{Color.BOLD}{Color.CYAN}{bar}{Color.RESET}")
    print(f"  {Color.BOLD}{Color.CYAN}{title}{Color.RESET}")
    print(f"{Color.BOLD}{Color.CYAN}{bar}{Color.RESET}\n")


# ─── Constants ──────────────────────────────────────────────────────────────

# Patterns to filter — CDN, tracking, analytics, ad networks
SKIP_URL_PATTERNS = [
    r'google.*analytics',
    r'googletagmanager',
    r'doubleclick\.net',
    r'amazon-adsystem',
    r'googlesyndication',
    r'facebook\.com/tr',
    r'connect\.facebook\.net',
    r'hotjar\.com',
    r'mouseflow\.com',
    r'crazyegg\.com',
    r'segment\.com',
    r'mixpanel\.com',
    r'intercom\.io',
    r'zendesk\.com/embeddable',
    r'wp-json/oembed',
    r'/wp-cron\.php',
    r'xmlrpc\.php',
    r'favicon\.ico$',
    r'apple-touch-icon',
    r'\.woff2?$',
    r'\.ttf$',
    r'\.eot$',
    r'\.map$',                    # Source map files
    r'/static/[a-f0-9]{16,}[./]',  # Hashed static assets
    r'/dist/[a-f0-9]{16,}[./]',   # Hashed dist files
]

# Junk query parameters — remove these before dedup
JUNK_PARAMS = {
    'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
    'fbclid', 'gclid', 'msclkid', 'twclid', 'li_fat_id',
    '_ga', '_gid', '_gac',
    'session_id', 'nonce', 'timestamp', 'cb', 'cachebuster',
    'ref', 'source', 'medium', 'campaign',
    '__cf_chl_rt_tk', '__cf_chl_jschl_tk__',
    'PHPSESSID', 'JSESSIONID', 'ASP.NET_SessionId',
}

# Parameters that are interesting from a security perspective
INTERESTING_PARAMS = {
    # Injection risks
    'id', 'uid', 'user_id', 'user', 'userid',
    'file', 'filename', 'filepath', 'path', 'dir', 'folder',
    'url', 'link', 'redirect', 'next', 'return', 'returnurl', 'return_url',
    'callback', 'cb', 'redir', 'destination', 'target',
    'cmd', 'command', 'exec', 'execute', 'run',
    'query', 'q', 'search', 'keyword', 'term',
    'template', 'theme', 'skin', 'layout',
    'include', 'require', 'load', 'fetch',
    'debug', 'test', 'mode',
    # API/backend
    'action', 'method', 'op', 'operation', 'fn', 'function',
    'page', 'view', 'controller', 'module',
    'format', 'type', 'output',
    # Auth
    'token', 'key', 'api_key', 'apikey', 'secret', 'password', 'pass',
    'auth', 'access_token', 'oauth_token',
    'admin', 'role', 'privilege',
}

# File extensions to skip (static assets)
SKIP_EXTENSIONS = {
    '.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg', '.ico',
    '.mp4', '.mp3', '.avi', '.mov', '.webm',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx',
    '.zip', '.tar', '.gz', '.rar',
    '.woff', '.woff2', '.ttf', '.eot', '.otf',
    '.css',   # CSS alone - not interesting from security POV
}

# Extensions that ARE interesting
INTERESTING_EXTENSIONS = {
    '.php', '.asp', '.aspx', '.jsp', '.jspx',
    '.cfm', '.pl', '.cgi', '.py', '.rb',
    '.json', '.xml', '.yaml', '.yml',
    '.bak', '.backup', '.old', '.orig', '.tmp',
    '.log', '.sql', '.db',
    '.env', '.config', '.conf', '.cfg',
    '.key', '.pem', '.cert',
    '.git', '.svn',
}

# URL patterns indicating interesting endpoints
URL_FLAG_PATTERNS = {
    'admin_panel':    [r'/admin', r'/administrator', r'/panel', r'/control', r'/manage', r'/cpanel', r'/wp-admin'],
    'api_endpoint':   [r'/api/', r'/v\d+/', r'/rest/', r'/graphql', r'/swagger', r'/openapi'],
    'login_page':     [r'/login', r'/signin', r'/auth', r'/oauth', r'/sso', r'/saml'],
    'upload':         [r'/upload', r'/file', r'/attach', r'/import', r'/media'],
    'config':         [r'/config', r'/settings', r'\.env', r'\.config', r'\.conf', r'/setup'],
    'backup':         [r'\.bak$', r'\.backup$', r'\.old$', r'\.orig$', r'\.tmp$'],
    'debug':          [r'/debug', r'/test', r'/dev', r'/staging', r'/phpinfo', r'/info\.php'],
    'database':       [r'/phpmyadmin', r'/adminer', r'/db', r'/database', r'/mysql'],
    'sensitive':      [r'\.git', r'\.svn', r'/\.env', r'/\.htaccess', r'/web\.config'],
    'parameter_injection': [],  # Filled dynamically based on params
}

# Severity per flag
FLAG_SEVERITY = {
    'sensitive':           'critical',
    'backup':              'critical',
    'database':            'critical',
    'debug':               'high',
    'admin_panel':         'high',
    'config':              'high',
    'login_page':          'high',
    'parameter_injection': 'high',
    'api_endpoint':        'medium',
    'upload':              'medium',
}


# ─── Tool Check ─────────────────────────────────────────────────────────────

def check_tools() -> dict:
    return {
        'waybackurls': shutil.which('waybackurls') is not None,
        'gau':         shutil.which('gau') is not None,
        'katana':      shutil.which('katana') is not None,
    }

def print_tool_status(status: dict):
    log_section("Tool Availability Check")
    installs = {
        'waybackurls': 'go install github.com/tomnomnom/waybackurls@latest',
        'gau':         'go install github.com/lc/gau/v2/cmd/gau@latest',
        'katana':      'go install github.com/projectdiscovery/katana/cmd/katana@latest',
    }
    available_count = 0
    for tool, avail in status.items():
        label = f"{Color.GREEN}FOUND{Color.RESET}" if avail else f"{Color.RED}NOT FOUND{Color.RESET}"
        note  = "" if avail else f"  ← {installs[tool]}"
        print(f"  {Color.CYAN}{tool:<16}{Color.RESET} {label}{Color.DIM}{note}{Color.RESET}")
        if avail:
            available_count += 1
    if available_count == 0:
        log_error("No URL gathering tools found. Install at least one.")
        sys.exit(1)
    print()
    return available_count


# ─── Domain Extraction ──────────────────────────────────────────────────────

def load_domains(args) -> list:
    """Load target domains from -d flag, -l list file, or services.json."""
    domains = []

    if args.domain:
        domains = [args.domain.strip().lower()]

    elif args.list:
        path = Path(args.list)
        if not path.exists():
            log_error(f"File not found: {args.list}")
            sys.exit(1)

        content = path.read_text()

        # Check if it's a services.json from service_mapper
        try:
            data = json.loads(content)
            if 'services' in data:
                log_info("Detected services.json format — extracting domains...")
                seen = set()
                for svc in data.get('services', []):
                    sub = svc.get('subdomain', '')
                    if sub and sub not in seen:
                        domains.append(sub)
                        seen.add(sub)
                # Also extract from port_map
                for host in data.get('port_map', {}).keys():
                    if host not in seen:
                        domains.append(host)
                        seen.add(host)
                # Also extract alive_subs if present
                for sub in data.get('alive_subdomains', []):
                    if sub not in seen:
                        domains.append(sub)
                        seen.add(sub)
                log_success(f"Extracted {len(domains)} domains from services.json")
            else:
                # Plain JSON array of domains
                domains = [d.strip().lower() for d in data if isinstance(d, str)]
        except json.JSONDecodeError:
            # Plain text file — one domain per line
            domains = [
                line.strip().lower()
                for line in content.splitlines()
                if line.strip() and '.' in line.strip() and not line.startswith('#')
            ]

    if not domains:
        log_error("No domains loaded. Use -d example.com or -l domains.txt")
        sys.exit(1)

    # Deduplicate
    domains = list(dict.fromkeys(d for d in domains if d))
    return domains


# ─── Phase 1: Wayback Machine ───────────────────────────────────────────────

def phase1_wayback(domains: list, timeout: int) -> dict:
    log_section("Phase 1 — Wayback Machine")

    if not shutil.which('waybackurls'):
        log_warn("waybackurls not found. Skipping Phase 1.")
        return {}

    log_info(f"Fetching historical URLs for {len(domains)} domain(s) ...")
    t0 = time.time()

    results = {}
    total = 0

    for domain in domains:
        try:
            r = subprocess.run(
                ['waybackurls', domain],
                capture_output=True, text=True, timeout=timeout
            )
            urls = {line.strip() for line in r.stdout.splitlines() if line.strip()}
            results[domain] = urls
            total += len(urls)
            log_success(f"  wayback  {domain:<40} {Color.BOLD}{len(urls)}{Color.RESET} URLs")
        except subprocess.TimeoutExpired:
            log_warn(f"  wayback  {domain} timed out")
            results[domain] = set()
        except FileNotFoundError:
            log_warn("waybackurls not in PATH")
            break
        except Exception as e:
            log_error(f"  wayback  {domain}: {e}")
            results[domain] = set()

    log_success(f"Phase 1 complete → {Color.BOLD}{total}{Color.RESET} raw URLs ({time.time()-t0:.1f}s)")
    return results


# ─── Phase 2: GAU ───────────────────────────────────────────────────────────

def phase2_gau(domains: list, timeout: int, threads: int) -> dict:
    log_section("Phase 2 — GAU (Google + Wayback + OTX)")

    if not shutil.which('gau'):
        log_warn("gau not found. Skipping Phase 2.")
        return {}

    log_info(f"Fetching URLs via GAU for {len(domains)} domain(s) ...")
    t0 = time.time()

    results = {}
    total = 0

    for domain in domains:
        try:
            cmd = [
                'gau', domain,
                '--threads', str(threads),
                '--timeout', str(timeout),
                '--retries', '2',
            ]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout * 2)
            urls = {line.strip() for line in r.stdout.splitlines() if line.strip()}
            results[domain] = urls
            total += len(urls)
            log_success(f"  gau      {domain:<40} {Color.BOLD}{len(urls)}{Color.RESET} URLs")
        except subprocess.TimeoutExpired:
            log_warn(f"  gau      {domain} timed out")
            results[domain] = set()
        except FileNotFoundError:
            log_warn("gau not in PATH")
            break
        except Exception as e:
            log_error(f"  gau      {domain}: {e}")
            results[domain] = set()

    log_success(f"Phase 2 complete → {Color.BOLD}{total}{Color.RESET} raw URLs ({time.time()-t0:.1f}s)")
    return results


# ─── Phase 3: Katana ────────────────────────────────────────────────────────

def phase3_katana(domains: list, depth: int, timeout: int, threads: int) -> dict:
    log_section("Phase 3 — Katana (Live Crawl + JS Parsing)")

    if not shutil.which('katana'):
        log_warn("katana not found. Skipping Phase 3.")
        return {}

    log_info(f"Crawling {len(domains)} domain(s) (depth={depth}) ...")
    t0 = time.time()

    results = {}
    total = 0

    for domain in domains:
        # Build target URL
        target = f"https://{domain}" if not domain.startswith('http') else domain

        try:
            cmd = [
                'katana',
                '-u', target,
                '-d', str(depth),
                '-jc',                 # JS parsing / crawling
                '-silent',
                '-no-color',
                '-timeout', str(timeout),
                '-c', str(threads),
                '-ef', 'css,woff,woff2,ttf,eot,png,jpg,jpeg,gif,svg,ico,mp4,mp3',
            ]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout * 3)
            urls = {line.strip() for line in r.stdout.splitlines() if line.strip()}
            results[domain] = urls
            total += len(urls)
            log_success(f"  katana   {domain:<40} {Color.BOLD}{len(urls)}{Color.RESET} URLs")
        except subprocess.TimeoutExpired:
            log_warn(f"  katana   {domain} timed out")
            results[domain] = set()
        except FileNotFoundError:
            log_warn("katana not in PATH")
            break
        except Exception as e:
            log_error(f"  katana   {domain}: {e}")
            results[domain] = set()

    log_success(f"Phase 3 complete → {Color.BOLD}{total}{Color.RESET} raw URLs ({time.time()-t0:.1f}s)")
    return results


# ─── Phase 4: Merge & Intelligence ──────────────────────────────────────────

def normalize_url(url: str) -> str:
    """
    Normalize URL for deduplication:
    - Lowercase scheme + host
    - Remove trailing slash
    - Remove junk query parameters
    - Sort remaining params for consistency
    """
    try:
        parsed = urlparse(url)
        # Normalize scheme + host
        scheme = parsed.scheme.lower()
        host   = parsed.netloc.lower()
        path   = parsed.path.rstrip('/') or '/'

        # Parse and clean params
        params = parse_qs(parsed.query, keep_blank_values=False)
        cleaned = {k: v for k, v in params.items() if k.lower() not in JUNK_PARAMS}
        new_query = urlencode(sorted(cleaned.items()), doseq=True)

        normalized = urlunparse((scheme, host, path, parsed.params, new_query, ''))
        return normalized
    except Exception:
        return url.lower().rstrip('/')


def should_skip_url(url: str) -> bool:
    """Return True if URL should be filtered out."""
    url_lower = url.lower()

    # Skip patterns
    for pattern in SKIP_URL_PATTERNS:
        if re.search(pattern, url_lower):
            return True

    # Skip by extension
    try:
        path = urlparse(url).path.lower()
        ext = os.path.splitext(path)[1]
        if ext in SKIP_EXTENSIONS:
            return True
    except Exception:
        pass

    # Must be a valid URL
    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return True
        if parsed.scheme not in ('http', 'https'):
            return True
    except Exception:
        return True

    return False


def extract_params(url: str) -> dict:
    """Extract query parameters from URL."""
    try:
        params = parse_qs(urlparse(url).query, keep_blank_values=False)
        return {k: v[0] if v else '' for k, v in params.items()}
    except Exception:
        return {}


def find_interesting_params(params: dict) -> list:
    """Return list of security-interesting parameters."""
    found = []
    for param in params:
        if param.lower() in INTERESTING_PARAMS:
            found.append(param)
    return found


def get_flags(url: str, params: dict) -> list:
    """Tag URL with security-relevant flags."""
    flags = []
    url_lower = url.lower()

    for flag_name, patterns in URL_FLAG_PATTERNS.items():
        if flag_name == 'parameter_injection':
            continue
        for pat in patterns:
            if re.search(pat, url_lower):
                if flag_name not in flags:
                    flags.append(flag_name)
                break

    # Parameter injection risk
    interesting = find_interesting_params(params)
    if interesting:
        flags.append('parameter_injection')

    # Interesting extension
    try:
        ext = os.path.splitext(urlparse(url).path)[1].lower()
        if ext in INTERESTING_EXTENSIONS:
            flags.append('interesting_extension')
    except Exception:
        pass

    return flags


def get_severity(flags: list) -> str:
    """Compute severity from flags."""
    for sev in ('critical', 'high', 'medium', 'low'):
        for flag in flags:
            if FLAG_SEVERITY.get(flag) == sev:
                return sev
    return 'info'


def compute_confidence(
    source_count: int,
    total_sources: int,
    has_interesting_params: bool,
    has_interesting_ext: bool,
    is_api: bool,
) -> float:
    score = 0.30  # baseline

    # More sources = more confidence
    if source_count >= 3:      score += 0.35
    elif source_count == 2:    score += 0.20
    else:                      score += 0.05

    # Interesting characteristics
    if has_interesting_params: score += 0.15
    if has_interesting_ext:    score += 0.15
    if is_api:                 score += 0.10

    return round(min(1.0, max(0.0, score)), 2)


def phase4_merge(
    wayback: dict,
    gau: dict,
    katana: dict,
    domains: list,
    min_confidence: float,
) -> list:
    log_section("Phase 4 — Merge, Deduplicate & Analyze")

    t0 = time.time()

    # Invert: URL → set of sources
    url_sources: dict[str, set] = {}

    source_map = [
        ('wayback', wayback),
        ('gau',     gau),
        ('katana',  katana),
    ]

    total_sources_active = sum(1 for _, d in source_map if d)
    total_raw = 0

    for source_name, source_data in source_map:
        for domain, urls in source_data.items():
            for url in urls:
                total_raw += 1
                if should_skip_url(url):
                    continue
                norm = normalize_url(url)
                url_sources.setdefault(norm, set()).add(source_name)

    log_info(f"Raw URLs total:      {Color.BOLD}{total_raw}{Color.RESET}")
    log_info(f"After dedup/filter:  {Color.BOLD}{len(url_sources)}{Color.RESET}")

    # Build records
    records = []
    skipped_low_conf = 0

    for norm_url, sources in url_sources.items():
        params            = extract_params(norm_url)
        interesting_p     = find_interesting_params(params)
        flags             = get_flags(norm_url, params)
        severity          = get_severity(flags)
        is_api            = 'api_endpoint' in flags
        has_ext           = 'interesting_extension' in flags
        source_count      = len(sources)
        total_src         = max(total_sources_active, 1)

        confidence = compute_confidence(
            source_count=source_count,
            total_sources=total_src,
            has_interesting_params=bool(interesting_p),
            has_interesting_ext=has_ext,
            is_api=is_api,
        )

        if confidence < min_confidence:
            skipped_low_conf += 1
            continue

        # Extract path cleanly
        try:
            parsed = urlparse(norm_url)
            path   = parsed.path or '/'
            host   = parsed.netloc
        except Exception:
            path = '/'
            host = ''

        records.append({
            'url':                norm_url,
            'host':               host,
            'path':               path,
            'sources':            sorted(sources),
            'source_count':       source_count,
            'parameters':         list(params.keys()),
            'interesting_params': interesting_p,
            'flags':              flags,
            'severity':           severity,
            'confidence':         confidence,
        })

    # Sort: highest severity + confidence first
    sev_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
    records.sort(key=lambda x: (sev_order.get(x['severity'], 5), -x['confidence']))

    log_info(f"Skipped low-conf:    {Color.DIM}{skipped_low_conf}{Color.RESET}")
    log_success(f"Phase 4 complete → {Color.BOLD}{len(records)}{Color.RESET} unique URLs ({time.time()-t0:.1f}s)")
    return records


# ─── Output ─────────────────────────────────────────────────────────────────

def build_report(domain: str, records: list, wayback: dict, gau: dict, katana: dict, elapsed: float) -> dict:
    by_severity = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    by_source   = {'wayback': 0, 'gau': 0, 'katana': 0}
    by_flag     = {}
    top_params  = {}

    total_wayback = sum(len(v) for v in wayback.values())
    total_gau     = sum(len(v) for v in gau.values())
    total_katana  = sum(len(v) for v in katana.values())

    for r in records:
        by_severity[r['severity']] = by_severity.get(r['severity'], 0) + 1
        for src in r['sources']:
            by_source[src] = by_source.get(src, 0) + 1
        for flag in r['flags']:
            by_flag[flag] = by_flag.get(flag, 0) + 1
        for p in r['interesting_params']:
            top_params[p] = top_params.get(p, 0) + 1

    return {
        'metadata': {
            'target':             domain,
            'scan_date':          datetime.now(timezone.utc).isoformat(),
            'total_urls':         len(records),
            'tool_version':       'url_mapper_v1.0',
            'duration_seconds':   round(elapsed, 1),
        },
        'sources_raw': {
            'wayback': total_wayback,
            'gau':     total_gau,
            'katana':  total_katana,
            'total':   total_wayback + total_gau + total_katana,
        },
        'urls': records,
        'summary': {
            'by_severity':    by_severity,
            'by_source':      by_source,
            'by_flag':        dict(sorted(by_flag.items(), key=lambda x: -x[1])),
            'top_interesting_params': dict(sorted(top_params.items(), key=lambda x: -x[1])[:15]),
        },
    }


def save_report(report: dict, output_dir: str, domain: str) -> list:
    os.makedirs(output_dir, exist_ok=True)
    base  = re.sub(r'[^\w\-.]', '_', domain)
    saved = []

    # Full JSON
    p = os.path.join(output_dir, f'{base}_urls.json')
    with open(p, 'w') as f:
        json.dump(report, f, indent=2)
    saved.append(('Full JSON (urls.json)', p))

    # Plain URL list (feed into other tools)
    p2 = os.path.join(output_dir, f'{base}_all_urls.txt')
    with open(p2, 'w') as f:
        for r in report['urls']:
            f.write(r['url'] + '\n')
    saved.append(('All URLs TXT', p2))

    # High-value only (critical + high severity)
    p3 = os.path.join(output_dir, f'{base}_high_value.txt')
    with open(p3, 'w') as f:
        for r in report['urls']:
            if r['severity'] in ('critical', 'high'):
                line = r['url']
                if r['flags']:
                    line += f"  # {', '.join(r['flags'])}"
                f.write(line + '\n')
    saved.append(('High-Value TXT', p3))

    # URLs with interesting params (feed into fuzzer)
    p4 = os.path.join(output_dir, f'{base}_params.txt')
    with open(p4, 'w') as f:
        for r in report['urls']:
            if r['interesting_params']:
                f.write(r['url'] + '\n')
    saved.append(('Param URLs TXT (for fuzzing)', p4))

    return saved


def print_table(records: list, limit: int = 25):
    log_section(f"Discovered URLs ({len(records)} total, top {min(limit, len(records))} shown)")
    sev_colors = {
        'critical': Color.RED, 'high': Color.YELLOW,
        'medium': Color.CYAN, 'low': Color.DIM, 'info': Color.WHITE,
    }
    shown = 0
    for r in records:
        if shown >= limit:
            print(f"\n  {Color.DIM}... and {len(records) - limit} more — see urls.json{Color.RESET}")
            break
        col = sev_colors.get(r['severity'], Color.WHITE)
        sev = f"{col}[{r['severity'].upper():<8}]{Color.RESET}"
        src = f"{Color.DIM}[{'+'.join(r['sources'])}]{Color.RESET}"
        flg = f"  {Color.MAGENTA}{r['flags'][0]}{Color.RESET}" if r['flags'] else ''
        print(f"  {sev} {src} {r['url'][:65]}{flg}")
        shown += 1


def print_summary(report: dict, elapsed: float):
    log_section("Final Summary")
    m  = report['metadata']
    sr = report['sources_raw']
    su = report['summary']

    print(f"  {Color.BOLD}{'Target':<28}{Color.RESET} {Color.WHITE}{m['target']}{Color.RESET}")
    print(f"  {Color.BOLD}{'Total URLs (after filter)':<28}{Color.RESET} {Color.GREEN}{Color.BOLD}{m['total_urls']}{Color.RESET}")
    print(f"  {Color.BOLD}{'Raw from all sources':<28}{Color.RESET} {sr['total']}")

    print(f"\n  {Color.DIM}{'─'*50}{Color.RESET}")
    print(f"  {Color.BOLD}Source breakdown:{Color.RESET}")
    for src, cnt in sr.items():
        if src != 'total' and cnt > 0:
            print(f"  {Color.CYAN}{src:<16}{Color.RESET} {cnt}")

    print(f"\n  {Color.DIM}{'─'*50}{Color.RESET}")
    sev_c = {'critical': Color.RED, 'high': Color.YELLOW, 'medium': Color.CYAN, 'low': Color.DIM}
    for sev, cnt in su['by_severity'].items():
        if cnt:
            col = sev_c.get(sev, Color.WHITE)
            bar = f"{col}{'█' * min(cnt, 30)}{Color.RESET}"
            print(f"  {col}{sev:<12}{Color.RESET} {Color.BOLD}{cnt:>5}{Color.RESET}  {bar}")

    if su.get('top_interesting_params'):
        print(f"\n  {Color.DIM}{'─'*50}{Color.RESET}")
        print(f"  {Color.BOLD}Top Interesting Parameters:{Color.RESET}")
        for param, cnt in list(su['top_interesting_params'].items())[:8]:
            print(f"  {Color.YELLOW}{param:<20}{Color.RESET} found in {cnt} URLs")

    print(f"\n  {Color.BOLD}{'Total elapsed':<28}{Color.RESET} {Color.CYAN}{elapsed:.1f}s{Color.RESET}\n")


# ─── CLI ────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description='url_mapper — Passive URL Gathering: Wayback + GAU + Katana',
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            'Examples:\n'
            '  python3 url_mapper.py -d example.com\n'
            '  python3 url_mapper.py -l ./sm-output/example_services.json\n'
            '  python3 url_mapper.py -d example.com --no-katana --threads 50\n'
            '  python3 url_mapper.py -d example.com --min-confidence 0.5\n'
        )
    )

    # Target
    target = p.add_mutually_exclusive_group(required=True)
    target.add_argument('-d', '--domain', help='Single target domain  (e.g. example.com)')
    target.add_argument('-l', '--list',   help='File with domains or services.json from service_mapper')

    # Output
    p.add_argument('-o', '--output',   default='./um-output', help='Output directory (default: ./um-output)')

    # Phase control
    p.add_argument('--no-wayback', action='store_true', help='Skip Wayback Machine (Phase 1)')
    p.add_argument('--no-gau',     action='store_true', help='Skip GAU (Phase 2)')
    p.add_argument('--no-katana',  action='store_true', help='Skip Katana live crawl (Phase 3)')

    # Katana
    p.add_argument('--depth',    type=int, default=3,   help='Katana crawl depth (default: 3)')

    # Performance
    p.add_argument('--threads',  type=int, default=50,  help='Thread count (default: 50)')
    p.add_argument('--timeout',  type=int, default=60,  help='Per-tool timeout in seconds (default: 60)')

    # Filtering
    p.add_argument('--min-confidence', type=float, default=0.3, help='Min confidence score 0.0-1.0 (default: 0.3)')
    p.add_argument('--severity',       default=None, help='Filter: critical,high,medium,low,info')

    # Misc
    p.add_argument('--no-banner', action='store_true')

    return p.parse_args()


# ─── Entry Point ────────────────────────────────────────────────────────────

def main():
    args = parse_args()

    if not args.no_banner:
        banner()

    tool_status = check_tools()
    print_tool_status(tool_status)

    domains = load_domains(args)
    log_success(f"Loaded {Color.BOLD}{len(domains)}{Color.RESET} domain(s)")

    domain_hint = args.domain or Path(args.list).stem

    total_start = time.time()

    # Phase 1
    wayback = {}
    if not args.no_wayback:
        wayback = phase1_wayback(domains, args.timeout)

    # Phase 2
    gau_results = {}
    if not args.no_gau:
        gau_results = phase2_gau(domains, args.timeout, args.threads)

    # Phase 3
    katana_results = {}
    if not args.no_katana:
        katana_results = phase3_katana(domains, args.depth, args.timeout, args.threads)

    # Phase 4
    records = phase4_merge(
        wayback=wayback,
        gau=gau_results,
        katana=katana_results,
        domains=domains,
        min_confidence=args.min_confidence,
    )

    # Apply severity filter
    if args.severity:
        wanted = {s.strip().lower() for s in args.severity.split(',')}
        records = [r for r in records if r['severity'] in wanted]

    elapsed = time.time() - total_start

    # Build + save report
    report = build_report(domain_hint, records, wayback, gau_results, katana_results, elapsed)
    saved  = save_report(report, args.output, domain_hint)

    # Print
    print_table(records)
    print_summary(report, elapsed)

    log_section("Saved Output Files")
    for label, path in saved:
        log_success(f"{label:<35} {Color.CYAN}{path}{Color.RESET}")

    print(f"\n  {Color.DIM}Tip: Feed {domain_hint}_all_urls.txt into directory_mapper.py for active discovery.{Color.RESET}")
    print(f"  {Color.DIM}     python3 directory_mapper.py -l {args.output}/{domain_hint}_urls.json{Color.RESET}\n")


if __name__ == '__main__':
    main()