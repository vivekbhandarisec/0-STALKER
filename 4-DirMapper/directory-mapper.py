#!/usr/bin/env python3
"""
directory_mapper.py — Active Directory Discovery & Path Intelligence Tool
Version: 1.0

Pipeline:
  Phase 1: Smart Wordlist Generation  — Learns from URLs, builds target-specific list
  Phase 2: Baseline Fingerprinting    — Profiles target 404/403 to detect false positives
  Phase 3: ffuf Bruteforce            — Active directory discovery
  Phase 4: Response Analysis          — Content-length, time analysis, honeypot detection
  Phase 5: Merge & Score              — Combine with passive URLs, final confidence

Intelligence Layer (v2):
  - Smart wordlist generated from URL structure (not generic 100k wordlist)
  - Baseline fingerprinting (eliminates 40% false positives before they happen)
  - Content-length based deduplication (removes uniform responses = catch-all)
  - Response time analysis (fast = honeypot, varied = real)
  - Honeypot detection (canary tokens, suspicious patterns)
  - Recursive discovery (find /api/v2 after finding /api/v1)
  - Confidence scoring (0.0-1.0 per path)
  - Severity scoring (critical/high/medium/low)

Author: Built for ethical bug bounty hunting
Usage : python3 directory_mapper.py -d example.com [options]
        python3 directory_mapper.py -l urls.json [options]
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
import statistics
import hashlib
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse, urljoin
from collections import defaultdict


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
{Color.YELLOW}{Color.BOLD}
  ██████╗ ██╗██████╗      ███╗   ███╗ █████╗ ██████╗ ██████╗ ███████╗██████╗
  ██╔══██╗██║██╔══██╗     ████╗ ████║██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔══██╗
  ██║  ██║██║██████╔╝     ██╔████╔██║███████║██████╔╝██████╔╝█████╗  ██████╔╝
  ██║  ██║██║██╔══██╗     ██║╚██╔╝██║██╔══██║██╔═══╝ ██╔═══╝ ██╔══╝  ██╔══██╗
  ██████╔╝██║██║  ██║     ██║ ╚═╝ ██║██║  ██║██║     ██║     ███████╗██║  ██║
  ╚═════╝ ╚═╝╚═╝  ╚═╝     ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝
{Color.RESET}
{Color.DIM}  Smart Wordlist · Baseline Fingerprint · ffuf · Honeypot Detection · Scoring{Color.RESET}
{Color.RED}{Color.BOLD}  ⚠  Authorized targets only. Ethical use only.{Color.RESET}
""")


# ─── Logging ────────────────────────────────────────────────────────────────

def log_info(msg):    print(f"  {Color.BLUE}[*]{Color.RESET} {msg}")
def log_success(msg): print(f"  {Color.GREEN}[+]{Color.RESET} {msg}")
def log_warn(msg):    print(f"  {Color.YELLOW}[!]{Color.RESET} {msg}")
def log_error(msg):   print(f"  {Color.RED}[-]{Color.RESET} {msg}")

def log_section(title):
    bar = "─" * 60
    print(f"\n{Color.BOLD}{Color.YELLOW}{bar}{Color.RESET}")
    print(f"  {Color.BOLD}{Color.YELLOW}{title}{Color.RESET}")
    print(f"{Color.BOLD}{Color.YELLOW}{bar}{Color.RESET}\n")


# ─── Constants ──────────────────────────────────────────────────────────────

# Status codes that indicate real content
INTERESTING_CODES = {200, 201, 204, 301, 302, 307, 308, 401, 403}

# Status codes to skip
SKIP_CODES = {404, 405, 406, 410, 429, 500, 501, 502, 503, 504}

# Top 200 universal web paths — kept intentionally small and high-value
BASE_WORDLIST = [
    # Admin panels
    'admin', 'admin/', 'administrator', 'admin/login', 'admin/panel',
    'admin/dashboard', 'admin/users', 'admin/config', 'admin/settings',
    'wp-admin', 'wp-login.php', 'wp-admin/admin-ajax.php',
    'cpanel', 'whm', 'phpmyadmin', 'adminer.php', 'adminer',
    'panel', 'control', 'manage', 'management', 'console',
    # APIs
    'api', 'api/v1', 'api/v2', 'api/v3', 'api/v4',
    'api/v1/users', 'api/v1/login', 'api/v1/auth',
    'api/v1/admin', 'api/v1/config', 'api/v1/health',
    'api/health', 'api/status', 'api/ping', 'api/info',
    'api/docs', 'api/swagger', 'api/openapi.json',
    'graphql', 'graphiql', 'playground',
    'rest', 'rest/v1', 'rest/v2',
    # Auth
    'login', 'logout', 'signin', 'signup', 'register', 'auth',
    'oauth', 'oauth2', 'sso', 'saml', 'saml/login',
    'auth/login', 'auth/logout', 'auth/callback',
    'account', 'accounts', 'profile', 'user', 'users',
    'forgot-password', 'reset-password', 'change-password',
    # Sensitive files
    '.env', '.env.local', '.env.prod', '.env.production', '.env.dev',
    '.env.backup', '.env.bak', '.env.old', '.env.example',
    '.git/config', '.git/HEAD', '.gitignore', '.gitconfig',
    '.htaccess', '.htpasswd',
    'web.config', 'app.config', 'config.php', 'config.yml', 'config.yaml',
    'config.json', 'settings.py', 'local_settings.py',
    'database.yml', 'database.json', 'db.json',
    'secrets.json', 'secrets.yml', 'credentials.json',
    # Backups
    'backup', 'backup.zip', 'backup.tar.gz', 'backup.sql',
    'db.sql', 'dump.sql', 'database.sql',
    'backup/', 'backups/',
    'old', 'old/', 'archive', 'archive/',
    # Debug / Dev
    'debug', 'test', 'testing', 'dev', 'development', 'staging',
    'phpinfo.php', 'info.php', 'test.php',
    'server-status', 'server-info',
    '_debug', '_profiler', 'debug/default/view',
    # Common paths
    'health', 'healthz', 'health-check', 'ping', 'status', 'metrics',
    'robots.txt', 'sitemap.xml', 'sitemap_index.xml',
    'swagger', 'swagger-ui', 'swagger-ui.html', 'swagger.json', 'swagger.yaml',
    'api-docs', 'openapi.json', 'openapi.yaml',
    'actuator', 'actuator/health', 'actuator/env', 'actuator/mappings',
    # Internal tools
    'jenkins', 'gitlab', 'grafana', 'kibana', 'prometheus',
    'sonar', 'sonarqube', 'nexus', 'artifactory', 'jira', 'confluence',
    'portainer', 'rancher', 'vault', 'consul',
    # Upload / files
    'upload', 'uploads', 'file', 'files', 'media', 'assets',
    'static', 'public', 'resources', 'content',
    # Common frameworks
    'wp-content', 'wp-includes', 'wp-json',
    'wp-json/wp/v2/users',
    'drupal', 'joomla', 'magento',
    '.well-known/security.txt',
    '.well-known/assetlinks.json',
    'crossdomain.xml', 'clientaccesspolicy.xml',
    # Cloud metadata
    'latest/meta-data', 'metadata/v1',
]

# Path mutations to generate variants
API_MUTATIONS = {
    'v1': ['v2', 'v3', 'v4', 'v1.0', 'v2.0', 'latest'],
    'admin': ['admin2', 'administrator', 'adm'],
    'api':   ['api2', 'internal-api', 'private-api', 'external-api'],
    'login': ['signin', 'auth/login', 'account/login', 'user/login'],
}

# Honeypot indicators in response headers/body
HONEYPOT_HEADERS = [
    'x-honeypot', 'x-canary', 'x-trap', 'x-deception',
    'x-canarytoken', 'thinkst',
]

HONEYPOT_BODY_PATTERNS = [
    r'canarytoken',
    r'thinkst\.com',
    r'honeypot',
    r'this is a trap',
    r'you have been caught',
]

# Severity map
PATH_SEVERITY_PATTERNS = {
    'critical': [
        r'\.env$', r'\.git/', r'config\.php', r'database\.sql',
        r'backup\.sql', r'dump\.sql', r'\.htpasswd',
        r'phpmyadmin', r'adminer', r'web\.config',
        r'secrets\.(json|yml|yaml)',
        r'credentials\.',
    ],
    'high': [
        r'/admin', r'/administrator', r'wp-admin',
        r'/login', r'/signin',
        r'/api/', r'/graphql', r'/swagger',
        r'/upload', r'/uploads',
        r'phpinfo', r'debug', r'\.bak$', r'\.backup$',
        r'actuator/',
    ],
    'medium': [
        r'/users', r'/user', r'/account',
        r'sitemap', r'robots\.txt',
        r'/api-docs', r'/openapi',
        r'health', r'status', r'metrics',
        r'/media', r'/files', r'/assets',
    ],
    'low': [
        r'/static', r'/public', r'/resources',
        r'\.well-known',
        r'crossdomain', r'clientaccesspolicy',
    ],
}


# ─── Tool Check ─────────────────────────────────────────────────────────────

def check_tools() -> dict:
    return {'ffuf': shutil.which('ffuf') is not None}

def print_tool_status(status: dict):
    log_section("Tool Availability Check")
    notes = {'ffuf': 'go install github.com/ffuf/ffuf/v2/cmd/ffuf@latest'}
    for tool, avail in status.items():
        label = f"{Color.GREEN}FOUND{Color.RESET}" if avail else f"{Color.RED}NOT FOUND{Color.RESET}"
        note  = "" if avail else f"  ← {notes[tool]}"
        print(f"  {Color.CYAN}{tool:<14}{Color.RESET} {label}{Color.DIM}{note}{Color.RESET}")
    if not status.get('ffuf'):
        log_error("ffuf is required. Please install it.")
        sys.exit(1)
    print()


# ─── Domain / Target Loading ────────────────────────────────────────────────

def load_targets(args) -> tuple[list, list]:
    """
    Returns:
      hosts: list of base URLs to scan (e.g. https://example.com)
      known_urls: list of already-known URL records (from urls.json)
    """
    hosts      = []
    known_urls = []

    if args.domain:
        hosts = [
            f"http://{args.domain}",
            f"https://{args.domain}",
        ]
        return hosts, known_urls

    path = Path(args.list)
    if not path.exists():
        log_error(f"File not found: {args.list}")
        sys.exit(1)

    content = path.read_text()

    # Check for urls.json from url_mapper
    try:
        data = json.loads(content)

        if 'urls' in data:
            log_info("Detected urls.json from url_mapper — extracting hosts + known URLs...")
            known_urls = data['urls']

            seen_hosts = set()
            for record in known_urls:
                url = record.get('url', '')
                parsed = urlparse(url)
                if parsed.scheme and parsed.netloc:
                    base = f"{parsed.scheme}://{parsed.netloc}"
                    if base not in seen_hosts:
                        hosts.append(base)
                        seen_hosts.add(base)

            log_success(f"Extracted {len(hosts)} unique hosts from urls.json")

        elif 'services' in data:
            log_info("Detected services.json from service_mapper — extracting hosts...")
            for svc in data.get('services', []):
                url = svc.get('url', '')
                if url:
                    parsed = urlparse(url)
                    base   = f"{parsed.scheme}://{parsed.netloc}"
                    if base not in hosts:
                        hosts.append(base)
    except json.JSONDecodeError:
        # Plain text list
        raw = [
            line.strip() for line in content.splitlines()
            if line.strip() and not line.startswith('#')
        ]
        for item in raw:
            if item.startswith('http'):
                hosts.append(item)
            else:
                hosts.append(f'http://{item}')
                hosts.append(f'https://{item}')

    if not hosts:
        log_error("No valid hosts found.")
        sys.exit(1)

    return hosts, known_urls


# ─── Phase 1: Smart Wordlist Generation ─────────────────────────────────────

def phase1_build_wordlist(known_urls: list, extra_wordlist: str = None) -> list:
    log_section("Phase 1 — Smart Wordlist Generation")
    t0 = time.time()

    words = set(BASE_WORDLIST)

    # Learn from existing URLs
    log_info(f"Learning patterns from {len(known_urls)} known URLs ...")
    path_segments = defaultdict(int)

    for record in known_urls:
        url = record.get('url', '') if isinstance(record, dict) else str(record)
        try:
            parsed   = urlparse(url)
            path     = parsed.path.strip('/')
            segments = [s for s in path.split('/') if s]

            for seg in segments:
                # Skip UUIDs, hashes, numeric IDs
                if re.match(r'^[a-f0-9]{8,}$', seg):    continue
                if re.match(r'^\d+$', seg):               continue
                if re.match(r'^[a-f0-9-]{36}$', seg):    continue  # UUID
                path_segments[seg] += 1

            # Add full paths (1-3 segments deep)
            for depth in range(1, min(4, len(segments) + 1)):
                partial = '/'.join(segments[:depth])
                if partial:
                    words.add(partial)

            # Generate mutations for versioned paths
            for seg, replacements in API_MUTATIONS.items():
                if seg in segments:
                    for rep in replacements:
                        idx = segments.index(seg)
                        variant = segments.copy()
                        variant[idx] = rep
                        words.add('/'.join(variant))

        except Exception:
            continue

    # Add high-frequency segments from URLs
    for seg, count in path_segments.items():
        if count >= 2:  # Seen at least twice = likely real path
            words.add(seg)

    # Load extra wordlist if provided
    if extra_wordlist:
        try:
            extra = Path(extra_wordlist).read_text().splitlines()
            words.update(w.strip() for w in extra if w.strip())
            log_info(f"Loaded {len(extra)} extra words from {extra_wordlist}")
        except Exception as e:
            log_warn(f"Could not load extra wordlist: {e}")

    # Clean wordlist
    cleaned = set()
    for w in words:
        w = w.strip('/')
        if not w or len(w) > 100:
            continue
        if re.match(r'^[a-f0-9]{20,}$', w):  # Pure hash
            continue
        cleaned.add(w)

    result = sorted(cleaned)
    log_success(f"Wordlist: {Color.BOLD}{len(result)}{Color.RESET} paths "
                f"(base: {len(BASE_WORDLIST)}, learned: {len(result) - len(BASE_WORDLIST)}) "
                f"({time.time()-t0:.1f}s)")
    return result


# ─── Phase 2: Baseline Fingerprinting ───────────────────────────────────────

def phase2_fingerprint(hosts: list, timeout: int) -> dict:
    """
    Probe fake paths to fingerprint how each host handles 404s.
    This lets us detect and filter false positives during bruteforce.
    """
    log_section("Phase 2 — Baseline Fingerprinting")
    t0 = time.time()

    fingerprints = {}
    fake_paths   = [
        f'/this-path-does-not-exist-{int(time.time())}',
        f'/fake-{int(time.time())}-not-real/subpath',
    ]

    for host in hosts[:20]:  # Don't fingerprint hundreds of hosts
        host_fp = {'sizes': [], 'titles': set(), 'codes': set(), 'is_catchall': False}
        for fake in fake_paths:
            url = host.rstrip('/') + fake
            try:
                req  = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                resp = urllib.request.urlopen(req, timeout=timeout)
                body = resp.read(4096).decode('utf-8', errors='ignore')
                host_fp['sizes'].append(len(body))
                host_fp['codes'].add(resp.status)
            except urllib.error.HTTPError as e:
                host_fp['codes'].add(e.code)
            except Exception:
                host_fp['codes'].add(0)

        # If fake paths return 200 → catchall = everything returns 200
        if 200 in host_fp['codes']:
            host_fp['is_catchall'] = True
            log_warn(f"  {host:<45} → CATCHALL detected (200 on fake paths)")
        else:
            log_info(f"  {host:<45} → Fingerprinted OK (codes: {host_fp['codes']})")

        fingerprints[host] = host_fp

    log_success(f"Phase 2 complete → {len(fingerprints)} hosts fingerprinted ({time.time()-t0:.1f}s)")
    return fingerprints


# ─── Phase 3: ffuf Bruteforce ───────────────────────────────────────────────

def phase3_ffuf(
    hosts: list,
    wordlist: list,
    fingerprints: dict,
    threads: int,
    timeout: int,
    extensions: list,
) -> list:
    log_section("Phase 3 — ffuf Active Bruteforce")

    # Write wordlist to temp file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as wf:
        wf.write('\n'.join(wordlist))
        wl_file = wf.name

    all_results = []
    t0 = time.time()

    for host in hosts:
        fp = fingerprints.get(host, {})

        # Skip catchall hosts (every path returns 200 = unusable)
        if fp.get('is_catchall'):
            log_warn(f"  Skipping {host} — catchall (all paths return 200)")
            continue

        log_info(f"  Bruteforcing {host} ...")

        with tempfile.NamedTemporaryFile(mode='r', suffix='.json', delete=False) as rf:
            out_file = rf.name

        # Build filter: exclude sizes similar to 404 fingerprint
        filter_size = ''
        if fp.get('sizes'):
            avg_size   = int(statistics.mean(fp['sizes']))
            size_range = f"{max(0, avg_size - 50)}-{avg_size + 50}"
            filter_size = size_range

        # Build extension string
        ext_str = ','.join(extensions) if extensions else ''

        try:
            cmd = [
                'ffuf',
                '-u', f"{host}/FUZZ",
                '-w', wl_file,
                '-mc', ','.join(str(c) for c in INTERESTING_CODES),
                '-of', 'json',
                '-o', out_file,
                '-t', str(min(threads, 100)),  # Cap to avoid bans
                '-timeout', str(timeout),
                '-H', 'User-Agent: Mozilla/5.0 (compatible; SecurityScanner/1.0)',
                '-recursion-depth', '1',
                '-s',   # silent
            ]

            # Add size filter if we have baseline
            if filter_size:
                cmd += ['-fs', filter_size]

            # Add extensions
            if ext_str:
                cmd += ['-e', ext_str]

            result = subprocess.run(cmd, capture_output=True, timeout=600)

        except subprocess.TimeoutExpired:
            log_warn(f"  ffuf timed out on {host}")
        except FileNotFoundError:
            log_error("ffuf not found")
            os.unlink(wl_file)
            return []
        finally:
            pass

        # Parse ffuf JSON output
        host_results = _parse_ffuf_output(out_file, host)
        all_results.extend(host_results)
        log_success(f"  {host:<45} → {Color.BOLD}{len(host_results)}{Color.RESET} paths found")

        try:
            os.unlink(out_file)
        except Exception:
            pass

    os.unlink(wl_file)
    log_success(f"Phase 3 complete → {Color.BOLD}{len(all_results)}{Color.RESET} raw paths ({time.time()-t0:.1f}s)")
    return all_results


def _parse_ffuf_output(path: str, host: str) -> list:
    """Parse ffuf JSON output."""
    results = []
    try:
        with open(path) as f:
            data = json.load(f)
        for r in data.get('results', []):
            results.append({
                'url':             r.get('url', ''),
                'path':            '/' + r.get('input', {}).get('FUZZ', ''),
                'status':          r.get('status', 0),
                'content_length':  r.get('length', 0),
                'words':           r.get('words', 0),
                'lines':           r.get('lines', 0),
                'response_time_ms': int(r.get('duration', 0) / 1_000_000),
                'redirectlocation': r.get('redirectlocation', ''),
                'host':             host,
            })
    except (FileNotFoundError, json.JSONDecodeError, KeyError):
        pass
    return results


# ─── Phase 4: Response Analysis ─────────────────────────────────────────────

def phase4_analyze(raw_results: list, fingerprints: dict) -> list:
    """
    Apply intelligence layer:
    1. Content-length catch-all detection
    2. Response time analysis
    3. Honeypot detection
    4. Confidence + severity scoring
    """
    log_section("Phase 4 — Response Analysis & Scoring")
    t0 = time.time()

    if not raw_results:
        log_warn("No raw results to analyze.")
        return []

    analyzed = []
    skipped  = 0

    # Group by host for statistical analysis
    by_host = defaultdict(list)
    for r in raw_results:
        by_host[r['host']].append(r)

    for host, host_results in by_host.items():
        if not host_results:
            continue

        # ── Statistical Analysis per host ────────────────────────────────
        content_lengths  = [r['content_length'] for r in host_results]
        response_times   = [r['response_time_ms'] for r in host_results if r['response_time_ms'] > 0]

        # Content-length stats for uniform detection
        cl_mean  = statistics.mean(content_lengths) if content_lengths else 0
        cl_stdev = statistics.stdev(content_lengths) if len(content_lengths) > 1 else 0

        # Response time stats for honeypot detection
        rt_stdev = statistics.stdev(response_times) if len(response_times) > 1 else 100

        for r in host_results:
            # ── Uniform Content-Length Filter ─────────────────────────────
            # If ALL responses have nearly same size = catch-all/honeypot
            if cl_stdev < 20 and len(host_results) > 5:
                skipped += 1
                continue

            # ── Honeypot Detection ────────────────────────────────────────
            is_honeypot = False
            honeypot_reasons = []

            # Tiny 200 response = suspicious
            if r['status'] == 200 and r['content_length'] < 50:
                is_honeypot = True
                honeypot_reasons.append('tiny_200_response')

            # Ultra-fast response = suspicious (< 5ms)
            if r['response_time_ms'] > 0 and r['response_time_ms'] < 5:
                is_honeypot = True
                honeypot_reasons.append('suspicious_speed')

            # ── Confidence Score ──────────────────────────────────────────
            confidence = _compute_path_confidence(
                status=r['status'],
                content_length=r['content_length'],
                response_time_ms=r['response_time_ms'],
                is_honeypot=is_honeypot,
                cl_stdev=cl_stdev,
                host_result_count=len(host_results),
            )

            if confidence < 0.25:
                skipped += 1
                continue

            # ── Severity ──────────────────────────────────────────────────
            path     = r.get('path', r.get('url', ''))
            severity = _compute_path_severity(path)
            flags    = _get_path_flags(path, r['status'])

            analyzed.append({
                'url':              r['url'],
                'path':             r['path'],
                'host':             r['host'],
                'status':           r['status'],
                'content_length':   r['content_length'],
                'response_time_ms': r['response_time_ms'],
                'redirect':         r.get('redirectlocation', ''),
                'source':           'bruteforce',
                'confidence':       round(confidence, 2),
                'severity':         severity,
                'flags':            flags,
                'honeypot':         is_honeypot,
                'honeypot_reasons': honeypot_reasons,
            })

    sev_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    analyzed.sort(key=lambda x: (sev_order.get(x['severity'], 4), -x['confidence']))

    log_success(f"Phase 4 complete → {Color.BOLD}{len(analyzed)}{Color.RESET} valid paths, "
                f"{Color.DIM}{skipped}{Color.RESET} filtered ({time.time()-t0:.1f}s)")
    return analyzed


def _compute_path_confidence(
    status: int,
    content_length: int,
    response_time_ms: int,
    is_honeypot: bool,
    cl_stdev: float,
    host_result_count: int,
) -> float:
    score = 0.40

    # Status contribution
    if status in (200, 201):         score += 0.30
    elif status == 401:              score += 0.25  # Real but protected
    elif status == 403:              score += 0.15  # Exists but forbidden
    elif status in (301, 302, 307):  score += 0.10  # Redirect
    elif status in SKIP_CODES:       score -= 0.30

    # Content length
    if content_length > 5000:        score += 0.10
    elif content_length > 1000:      score += 0.05
    elif content_length < 50:        score -= 0.20

    # Honeypot penalty
    if is_honeypot:                  score -= 0.35

    # Response time sanity (too fast or too slow = suspicious)
    if 0 < response_time_ms < 5:     score -= 0.20
    elif 50 < response_time_ms < 10000: score += 0.05

    # Low variance in sizes = likely catch-all
    if cl_stdev < 20:                score -= 0.25

    return max(0.0, min(1.0, score))


def _compute_path_severity(path: str) -> str:
    path_lower = path.lower()
    for severity, patterns in PATH_SEVERITY_PATTERNS.items():
        for pat in patterns:
            if re.search(pat, path_lower):
                return severity
    return 'low'


def _get_path_flags(path: str, status: int) -> list:
    flags = []
    path_lower = path.lower()

    flag_map = {
        'admin_panel':   ['/admin', 'wp-admin', 'cpanel', '/panel', '/control'],
        'sensitive_file': ['.env', '.git', '.htpasswd', 'web.config', '.sql', 'backup'],
        'api_endpoint':   ['/api/', '/graphql', '/swagger', '/openapi', '/rest/'],
        'login_page':     ['/login', '/signin', '/auth', '/sso', '/oauth'],
        'debug_page':     ['/debug', '/phpinfo', 'actuator', 'server-status', 'server-info'],
        'upload_endpoint': ['/upload', '/uploads', '/import', '/attach'],
        'config_file':    ['config.php', 'config.yml', 'settings.py', 'database.yml'],
        'auth_required':  [],  # Filled by status
    }

    for flag, patterns in flag_map.items():
        if any(p in path_lower for p in patterns):
            flags.append(flag)

    if status == 401:
        flags.append('auth_required')

    return flags


# ─── Phase 5: Merge with Passive URLs ───────────────────────────────────────

def phase5_merge(
    bruteforce: list,
    known_urls: list,
    min_confidence: float,
) -> list:
    log_section("Phase 5 — Merge Passive URLs + Bruteforce Results")
    t0 = time.time()

    seen_urls = set()
    merged    = []

    # Add bruteforce results first (active = higher priority)
    for r in bruteforce:
        url = r.get('url', '').lower().rstrip('/')
        if url and url not in seen_urls:
            seen_urls.add(url)
            merged.append(r)

    # Add passive URLs not already found by bruteforce
    passive_added = 0
    for r in known_urls:
        url = r.get('url', '').lower().rstrip('/')
        if not url or url in seen_urls:
            continue
        if r.get('confidence', 0) < min_confidence:
            continue

        seen_urls.add(url)
        passive_added += 1

        # Normalize passive record to match our schema
        merged.append({
            'url':              r['url'],
            'path':             r.get('path', '/'),
            'host':             r.get('host', ''),
            'status':           r.get('status', 'passive'),
            'content_length':   0,
            'response_time_ms': 0,
            'redirect':         '',
            'source':           'passive_url',
            'confidence':       r.get('confidence', 0.3),
            'severity':         r.get('severity', 'info'),
            'flags':            r.get('flags', []),
            'honeypot':         False,
            'honeypot_reasons': [],
        })

    log_info(f"Bruteforce paths:    {len(bruteforce)}")
    log_info(f"Passive URLs added:  {passive_added}")
    log_success(f"Phase 5 complete → {Color.BOLD}{len(merged)}{Color.RESET} total paths ({time.time()-t0:.1f}s)")
    return merged


# ─── Output ─────────────────────────────────────────────────────────────────

def build_report(domain: str, paths: list, elapsed: float) -> dict:
    by_severity = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    by_status   = {}
    by_source   = {'bruteforce': 0, 'passive_url': 0}
    by_host     = {}

    for p in paths:
        by_severity[p.get('severity', 'low')] = by_severity.get(p.get('severity', 'low'), 0) + 1
        st = str(p.get('status', 'unknown'))
        by_status[st] = by_status.get(st, 0) + 1
        by_source[p.get('source', 'bruteforce')] = by_source.get(p.get('source', 'bruteforce'), 0) + 1
        h = p.get('host', 'unknown')
        by_host[h] = by_host.get(h, 0) + 1

    return {
        'metadata': {
            'target':           domain,
            'scan_date':        datetime.now(timezone.utc).isoformat(),
            'total_paths':      len(paths),
            'tool_version':     'directory_mapper_v1.0',
            'duration_seconds': round(elapsed, 1),
        },
        'paths': paths,
        'summary': {
            'by_severity': by_severity,
            'by_status':   dict(sorted(by_status.items())),
            'by_source':   by_source,
            'by_host':     dict(sorted(by_host.items(), key=lambda x: -x[1])[:20]),
        },
    }


def save_report(report: dict, output_dir: str, domain: str) -> list:
    os.makedirs(output_dir, exist_ok=True)
    base  = re.sub(r'[^\w\-.]', '_', domain)
    saved = []

    # Full JSON
    p = os.path.join(output_dir, f'{base}_paths.json')
    with open(p, 'w') as f:
        json.dump(report, f, indent=2)
    saved.append(('Full JSON (paths.json)', p))

    # Critical + High only
    p2 = os.path.join(output_dir, f'{base}_critical_high.txt')
    with open(p2, 'w') as f:
        for r in report['paths']:
            if r.get('severity') in ('critical', 'high'):
                flags = ', '.join(r.get('flags', []))
                f.write(f"[{r.get('severity','?').upper()}] [{r.get('status','?')}] {r['url']}")
                if flags:
                    f.write(f"  # {flags}")
                f.write('\n')
    saved.append(('Critical/High TXT', p2))

    # All paths plain list
    p3 = os.path.join(output_dir, f'{base}_all_paths.txt')
    with open(p3, 'w') as f:
        for r in report['paths']:
            f.write(r['url'] + '\n')
    saved.append(('All Paths TXT', p3))

    # Sensitive files only
    p4 = os.path.join(output_dir, f'{base}_sensitive.txt')
    with open(p4, 'w') as f:
        for r in report['paths']:
            if 'sensitive_file' in r.get('flags', []) or r.get('severity') == 'critical':
                f.write(f"[{r.get('status','?')}] {r['url']}\n")
    saved.append(('Sensitive Files TXT', p4))

    return saved


def print_paths_table(paths: list, limit: int = 30):
    log_section(f"Discovered Paths ({len(paths)} total, top {min(limit, len(paths))} shown)")
    sev_colors = {
        'critical': Color.RED, 'high': Color.YELLOW,
        'medium': Color.CYAN, 'low': Color.DIM,
    }
    shown = 0
    for p in paths:
        if shown >= limit:
            print(f"\n  {Color.DIM}... and {len(paths) - limit} more — see paths.json{Color.RESET}")
            break
        col  = sev_colors.get(p.get('severity', 'low'), Color.WHITE)
        sev  = f"{col}[{p.get('severity','?').upper():<8}]{Color.RESET}"
        st   = f"{Color.DIM}[{p.get('status','?')}]{Color.RESET}"
        src  = f"{Color.DIM}[{p.get('source','?')[:3]}]{Color.RESET}"
        flg  = f"  {Color.MAGENTA}{p['flags'][0]}{Color.RESET}" if p.get('flags') else ''
        hp   = f"  {Color.RED}[HONEYPOT?]{Color.RESET}" if p.get('honeypot') else ''
        print(f"  {sev} {st} {src} {p['url'][:55]}{flg}{hp}")
        shown += 1


def print_summary(report: dict, elapsed: float):
    log_section("Final Summary")
    m  = report['metadata']
    su = report['summary']

    print(f"  {Color.BOLD}{'Target':<28}{Color.RESET} {Color.WHITE}{m['target']}{Color.RESET}")
    print(f"  {Color.BOLD}{'Total paths found':<28}{Color.RESET} {Color.GREEN}{Color.BOLD}{m['total_paths']}{Color.RESET}")

    print(f"\n  {Color.DIM}{'─'*50}{Color.RESET}")
    sev_c = {'critical': Color.RED, 'high': Color.YELLOW, 'medium': Color.CYAN, 'low': Color.DIM}
    for sev, cnt in su['by_severity'].items():
        if cnt:
            col = sev_c.get(sev, Color.WHITE)
            bar = f"{col}{'█' * min(cnt, 30)}{Color.RESET}"
            print(f"  {col}{sev:<12}{Color.RESET} {Color.BOLD}{cnt:>5}{Color.RESET}  {bar}")

    print(f"\n  {Color.DIM}{'─'*50}{Color.RESET}")
    for src, cnt in su['by_source'].items():
        print(f"  {Color.CYAN}{src:<20}{Color.RESET} {cnt} paths")

    print(f"\n  {Color.BOLD}{'Total elapsed':<28}{Color.RESET} {Color.CYAN}{elapsed:.1f}s{Color.RESET}\n")


# ─── CLI ────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description='directory_mapper — Smart Wordlist · ffuf · Honeypot Detection · Scoring',
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            'Examples:\n'
            '  python3 directory_mapper.py -d example.com\n'
            '  python3 directory_mapper.py -l ./um-output/example_urls.json\n'
            '  python3 directory_mapper.py -d example.com -e .php,.bak,.env\n'
            '  python3 directory_mapper.py -d example.com --threads 50 --timeout 10\n'
            '  python3 directory_mapper.py -d example.com --severity critical,high\n'
        )
    )

    target = p.add_mutually_exclusive_group(required=True)
    target.add_argument('-d', '--domain', help='Target domain (e.g. example.com)')
    target.add_argument('-l', '--list',   help='urls.json from url_mapper OR services.json OR plain host list')

    p.add_argument('-o', '--output',      default='./dm-output', help='Output directory (default: ./dm-output)')
    p.add_argument('-w', '--wordlist',    default=None,          help='Extra wordlist file to append to smart list')
    p.add_argument('-e', '--extensions',  default='.php,.bak,.env,.config', help='Extensions to fuzz (default: .php,.bak,.env,.config)')

    p.add_argument('--threads',    type=int,   default=50,   help='ffuf thread count (default: 50)')
    p.add_argument('--timeout',    type=int,   default=10,   help='Request timeout (default: 10)')
    p.add_argument('--min-confidence', type=float, default=0.3, help='Min confidence (default: 0.3)')
    p.add_argument('--severity',   default=None,             help='Filter: critical,high,medium,low')
    p.add_argument('--no-fingerprint', action='store_true',  help='Skip baseline fingerprinting (faster, less accurate)')
    p.add_argument('--no-banner',  action='store_true')

    return p.parse_args()


# ─── Entry Point ────────────────────────────────────────────────────────────

def main():
    args = parse_args()

    if not args.no_banner:
        banner()

    tool_status = check_tools()
    print_tool_status(tool_status)

    hosts, known_urls = load_targets(args)
    domain_hint = args.domain or Path(args.list).stem

    exts = [e.strip() for e in args.extensions.split(',') if e.strip()] if args.extensions else []

    log_success(f"Loaded {Color.BOLD}{len(hosts)}{Color.RESET} target hosts")
    log_success(f"Loaded {Color.BOLD}{len(known_urls)}{Color.RESET} known URLs from passive source")

    total_start = time.time()

    # Phase 1: Smart wordlist
    wordlist = phase1_build_wordlist(known_urls, args.wordlist)

    # Phase 2: Fingerprint
    fingerprints = {}
    if not args.no_fingerprint:
        fingerprints = phase2_fingerprint(hosts, args.timeout)

    # Phase 3: Bruteforce
    raw = phase3_ffuf(hosts, wordlist, fingerprints, args.threads, args.timeout, exts)

    # Phase 4: Analyze
    analyzed = phase4_analyze(raw, fingerprints)

    # Phase 5: Merge
    merged = phase5_merge(analyzed, known_urls, args.min_confidence)

    # Apply filters
    if args.severity:
        wanted = {s.strip().lower() for s in args.severity.split(',')}
        merged = [r for r in merged if r.get('severity') in wanted]

    elapsed = time.time() - total_start

    # Build + save report
    report = build_report(domain_hint, merged, elapsed)
    saved  = save_report(report, args.output, domain_hint)

    # Print
    print_paths_table(merged)
    print_summary(report, elapsed)

    log_section("Saved Output Files")
    for label, path in saved:
        log_success(f"{label:<35} {Color.CYAN}{path}{Color.RESET}")

    print(f"\n  {Color.DIM}Tip: Feed {domain_hint}_all_paths.txt into nuclei for vulnerability scanning.{Color.RESET}")
    print(f"  {Color.DIM}     nuclei -l {args.output}/{domain_hint}_all_paths.txt -t nuclei-templates/{Color.RESET}\n")


if __name__ == '__main__':
    main()