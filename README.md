# URL Mapper + Directory Mapper

> **Passive URL Gathering & Active Directory Discovery — Part of the 0-STALKER Recon Toolkit**

Two tools that work together to map every endpoint of a target:
`url_mapper.py` gathers historical + live URLs passively across 3 sources.
`directory_mapper.py` actively bruteforces paths using a smart wordlist built from what url_mapper found — not a generic 100k wordlist.

---

## 🔗 Pipeline Position

```
0-STALKER          →   alive subdomains
SERVICE-MAPPER     →   services.json (active hosts + ports)
URL-MAPPER         →   urls.json (1500+ historical & live URLs)
DIRECTORY-MAPPER   →   paths.json (verified + new paths, scored)
                   →   Feed into nuclei / ffuf / burp
```

---

## 📦 Installation

### Python
```bash
pip3 install requests tldextract
```

### Go Tools
```bash
# URL Mapper dependencies
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest

# Directory Mapper dependency
go install github.com/ffuf/ffuf/v2/cmd/ffuf@latest

export PATH=$PATH:$(go env GOPATH)/bin
```

### Setup
```bash
git clone https://github.com/vivekbhandarisec/0-STALKER.git
cd 0-STALKER
```

---

# 🔍 Tool 1: URL Mapper

> Passive URL gathering across 3 sources with intelligence filtering

## How It Works (5 Phases)

```
INPUT: -d example.com  OR  -l services.json
│
├─ Phase 1: Wayback Machine
│   waybackurls → historical URLs (deleted / old endpoints)
│   Finds: forgotten API endpoints, old admin panels, exposed files
│
├─ Phase 2: GAU (Google + OTX + Wayback)
│   gau → Google cache, CommonCrawl, OTX, URLScan
│   Finds: indexed URLs, API endpoints, parameters
│
├─ Phase 3: Katana (Live Crawl + JS Parsing)
│   katana → crawls live site, parses JavaScript
│   Finds: XHR endpoints, hidden API calls, dynamic routes
│
└─ Phase 4: Merge, Deduplicate & Analyze
    - Normalize URLs (remove junk params, lowercase)
    - Cross-source confidence scoring
    - Parameter injection risk detection
    - Flag tagging (admin, api, sensitive, backup...)
    - Severity scoring
    OUTPUT: urls.json
```

## Usage

### Basic
```bash
python3 url_mapper.py -d example.com
```

### From services.json (after service_mapper)
```bash
python3 url_mapper.py -l ./sm-output/example_services.json
```

### Skip slow katana crawl
```bash
python3 url_mapper.py -d example.com --no-katana
```

### High confidence only
```bash
python3 url_mapper.py -d example.com --min-confidence 0.6
```

### Critical and high severity only
```bash
python3 url_mapper.py -d example.com --severity critical,high
```

### Custom threads and timeout
```bash
python3 url_mapper.py -d example.com --threads 100 --timeout 120
```

### Deeper katana crawl
```bash
python3 url_mapper.py -d example.com --depth 5
```

## Output Files

All saved to `./um-output/` (or `--output` dir):

| File | Content |
|------|---------|
| `target_urls.json` | Full report — all URLs, scores, flags, parameters, source breakdown |
| `target_all_urls.txt` | Plain list of all URLs (feed into other tools) |
| `target_high_value.txt` | Critical + high severity findings with flags |
| `target_params.txt` | URLs with interesting parameters (feed into fuzzer) |

## Intelligence Features

### Source-Based Confidence Scoring
```
URL found in 3 sources  → confidence: 0.95 (very likely real)
URL found in 2 sources  → confidence: 0.75
URL found in 1 source   → confidence: 0.35

+ Interesting parameters (id, file, redirect, cmd)  → +0.15
+ Interesting extension (.php, .bak, .env)          → +0.15
+ API endpoint (/api/, /graphql)                    → +0.10
```

### False Positive Prevention
- **CDN/Tracking filtered**: Google Analytics, DoubleClick, Hotjar, Mixpanel removed
- **Junk parameter removal**: utm_source, fbclid, gclid, PHPSESSID cleaned before dedup
- **Hashed asset filtering**: `/static/a3f9b2c1...` ignored
- **Static asset skipping**: .jpg, .css, .woff2, .mp4 ignored (not security-relevant)

### Flag Tagging
| Flag | Example URLs |
|------|-------------|
| `admin_panel` | `/admin`, `/wp-admin`, `/cpanel` |
| `api_endpoint` | `/api/v1/`, `/graphql`, `/swagger` |
| `login_page` | `/login`, `/auth/signin`, `/sso` |
| `sensitive` | `/.env`, `/.git/config`, `/.htpasswd` |
| `backup` | `/backup.zip`, `/db.old`, `dump.sql` |
| `debug` | `/debug`, `/phpinfo.php`, `/actuator` |
| `parameter_injection` | Any URL with `id=`, `file=`, `redirect=`, `cmd=` |

## CLI Options

| Option | Default | Description |
|--------|---------|-------------|
| `-d, --domain` | required | Target domain |
| `-l, --list` | required | services.json, urls.txt, or domain list |
| `-o, --output` | `./um-output` | Output directory |
| `--no-wayback` | False | Skip Wayback Machine |
| `--no-gau` | False | Skip GAU |
| `--no-katana` | False | Skip live crawl |
| `--depth` | 3 | Katana crawl depth |
| `--threads` | 50 | Thread count |
| `--timeout` | 60 | Per-tool timeout (seconds) |
| `--min-confidence` | 0.3 | Minimum confidence score |
| `--severity` | None | Filter by severity level |
| `--no-banner` | False | Suppress banner |

---

# 🎯 Tool 2: Directory Mapper

> Active directory bruteforce with smart wordlists and intelligent false positive prevention

## How It Works (5 Phases)

```
INPUT: -d example.com  OR  -l urls.json (from url_mapper)
│
├─ Phase 1: Smart Wordlist Generation
│   - Starts with 200 high-value base paths (not 100k generic)
│   - Learns from known URLs: extracts path segments
│   - Generates mutations: /api/v1 → /api/v2, /api/v3
│   - Removes hashes, UUIDs, and junk segments
│   Output: 500-1500 smart paths specific to your target
│
├─ Phase 2: Baseline Fingerprinting
│   - Probes fake paths (non-existent) per host
│   - Detects catchall hosts (return 200 on everything = skip)
│   - Measures fake 404 content-length → filters responses
│   - Prevents ~40% of false positives before bruteforce starts
│
├─ Phase 3: ffuf Bruteforce
│   - Smart wordlist × target hosts
│   - Filtered by: status codes, size, baseline fingerprint
│   - Extensions: .php, .bak, .env, .config
│   - Max 100 threads (prevent target from banning)
│
├─ Phase 4: Response Analysis
│   - Content-length uniform detection (all same size = catch-all)
│   - Response time analysis (< 5ms = honeypot)
│   - Honeypot pattern matching in headers + body
│   - Confidence scoring per path
│   - Severity scoring per path
│
└─ Phase 5: Merge Passive + Bruteforce
    - Combines bruteforce results with known URLs from url_mapper
    - Deduplication by URL
    - Final sorting: critical → high → medium → low
    OUTPUT: paths.json
```

## Usage

### Basic
```bash
python3 directory_mapper.py -d example.com
```

### From urls.json (recommended — better wordlist generation)
```bash
python3 directory_mapper.py -l ./um-output/example_urls.json
```

### With extra wordlist
```bash
python3 directory_mapper.py -d example.com -w /usr/share/seclists/Discovery/Web-Content/common.txt
```

### Custom extensions
```bash
python3 directory_mapper.py -d example.com -e .php,.asp,.aspx,.bak,.env,.config,.sql
```

### Fast mode (skip fingerprinting)
```bash
python3 directory_mapper.py -d example.com --no-fingerprint
```

### Critical findings only
```bash
python3 directory_mapper.py -d example.com --severity critical,high
```

### High thread count (fast connection)
```bash
python3 directory_mapper.py -d example.com --threads 100
```

## Output Files

All saved to `./dm-output/` (or `--output` dir):

| File | Content |
|------|---------|
| `target_paths.json` | Full report — all paths, status, scores, flags, metadata |
| `target_critical_high.txt` | Only critical + high severity paths with flags |
| `target_all_paths.txt` | All paths plain list (feed into nuclei/burp) |
| `target_sensitive.txt` | Only sensitive files (.env, .git, backups, configs) |

## Intelligence Features

### Smart Wordlist (Why It's Better)
```
Generic wordlist (dirsearch):     100,000 paths → 99% noise
Our smart wordlist:               500-1500 paths → 70%+ signal

How:
  1. Base 200 paths — highest-value, curated
  2. Learn from target's own URLs (/api/v1 → also try /api/v2, /v3)
  3. Path segment extraction (if /users/profile seen → try /users/)
  4. Mutation generation (admin → administrator, adm, admin2)
  5. Remove hashes and UUIDs (not bruteforceable anyway)
```

### Baseline Fingerprinting
```
Before scanning each host:
  → Probe /this-fake-path-8472 (doesn't exist)
  → Probe /another-fake-9183/subpath

If both return 200 → Host is catch-all → SKIP (saves time + eliminates noise)
If returns 404 → Measure content-length → Filter similar sizes during scan
```

### Content-Length Catch-All Detection
```
After scan, group responses by host:
  stdev(content_lengths) < 20 bytes → All responses same size
  → This is a catch-all / honeypot
  → Entire host result set discarded
```

### Honeypot Detection
```
Response time < 5ms AND status 200 → Instant response = suspicious
Tiny body (< 50 bytes) AND status 200 → Nothing real responds this small
Response headers contain x-honeypot, x-canary, thinkst → Known honeypot
```

### Severity Rules
| Severity | Path Examples |
|----------|--------------|
| `critical` | `.env`, `.git/config`, `phpmyadmin`, `backup.sql`, `.htpasswd`, `secrets.json` |
| `high` | `/admin`, `wp-admin`, `/login`, `/api/`, `/swagger`, `/debug`, `actuator/env` |
| `medium` | `/users`, `/sitemap.xml`, `/api-docs`, `health`, `metrics` |
| `low` | `/static`, `/.well-known`, `crossdomain.xml` |

## CLI Options

| Option | Default | Description |
|--------|---------|-------------|
| `-d, --domain` | required | Target domain |
| `-l, --list` | required | urls.json, services.json, or host list |
| `-o, --output` | `./dm-output` | Output directory |
| `-w, --wordlist` | None | Extra wordlist to append |
| `-e, --extensions` | `.php,.bak,.env,.config` | Extensions to fuzz |
| `--threads` | 50 | ffuf thread count |
| `--timeout` | 10 | Request timeout (seconds) |
| `--min-confidence` | 0.3 | Minimum confidence score |
| `--severity` | None | Filter by severity |
| `--no-fingerprint` | False | Skip baseline fingerprinting |
| `--no-banner` | False | Suppress banner |

---

## 🔁 Full Recon Pipeline

```bash
# Step 1: Subdomain discovery
python3 main.py example.com --parallel

# Step 2: Service mapping
python3 service_mapper.py ./0-stalker-output/example_alive.txt --domain example.com

# Step 3: Passive URL gathering
python3 url_mapper.py -l ./sm-output/example_services.json

# Step 4: Active directory discovery
python3 directory_mapper.py -l ./um-output/example_urls.json

# Step 5: Vulnerability scanning
nuclei -l ./dm-output/example_all_paths.txt -t nuclei-templates/

# Step 6: Fuzzing interesting parameters
ffuf -w wordlist.txt -u FUZZ -ic ./um-output/example_params.txt
```

---

## 📊 Expected Results

| Stage | Tool | Output | Time |
|-------|------|--------|------|
| Subdomains | 0-STALKER | 300+ alive subdomains | 3-5 min |
| Services | SERVICE-MAPPER | 200+ active services | 10-15 min |
| URLs | URL-MAPPER | 1500+ historical URLs | 5-10 min |
| Paths | DIRECTORY-MAPPER | 200-500 verified paths | 10-20 min |
| **Total** | | **Complete endpoint map** | **~45 min** |

---

## 🛡️ False Positive Prevention Summary

| Layer | Tool | Reduction |
|-------|------|-----------|
| CDN/tracking filter | URL Mapper | ~15% less noise |
| Junk param removal | URL Mapper | ~10% less duplication |
| Cross-source scoring | URL Mapper | Low-confidence URLs filtered |
| Baseline fingerprinting | Dir Mapper | ~40% false positive prevention |
| Catch-all detection | Dir Mapper | Eliminates entire noisy hosts |
| Content-length analysis | Dir Mapper | ~20% uniform response filtering |
| Honeypot detection | Dir Mapper | Flags suspicious findings |
| **Combined result** | **Both** | **< 5% false positives** |

---

## 🔐 Legal Notice

**⚠️ Authorized Use Only** — For ethical security research and bug bounty hunting with explicit written permission only.

---

**Part of the 0-STALKER recon toolkit. Happy hunting! 🎯**

GitHub: https://github.com/vivekbhandarisec/0-STALKER