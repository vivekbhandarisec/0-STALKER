# Service Mapper v2.0

> **Advanced Service Discovery, Tech Fingerprinting & Vulnerability Detection**

Plug-in after **0-STALKER**. Takes alive subdomains, discovers every exposed service across all web ports, fingerprints technologies, detects subdomain takeovers, and scores every finding by confidence and severity — all with intelligent false positive prevention.

---

## 🔗 Pipeline Position

```
0-STALKER                         Service Mapper
──────────────────────────────    ─────────────────────────────────────────
subfinder + assetfinder + amass → alive_subs.txt → Port Scan · HTTP Probe
dnsx alive check                                   DNS Audit · Tech Detection
                                                   Confidence Score · Severity
                                                   services.json  ←──────────
```

---

## ⚡ Features

### v1 Core
- **Phase 1** — HTTP Probe on 80/443 (quick web service detection)
- **Phase 2** — DNS CNAME Audit (top 20 vulnerable services for takeover)
- **Phase 3** — Port Scan via naabu (web-ports whitelist only, ~70 ports)
- **Phase 4** — Filter & Expand (removes timeouts, skips already-probed)
- **Phase 5** — HTTP Probe on all discovered ports (finds hidden panels)

### v2 Intelligence Layer
- **Timeout Detection** — Timeouts ≠ alive services, filtered out completely
- **Status Code Filtering** — Only trusts: `200, 201, 204, 301, 302, 400, 401, 403`
- **Default Page Detection** — Removes Apache/Nginx defaults, parking pages
- **Tech Stack Fingerprinting** — 30+ technologies (Jenkins, Grafana, Swagger, etc.)
- **Confidence Scoring** — 0.0–1.0 score per service based on 8 signals
- **Severity Scoring** — `critical / high / medium / low` per finding
- **Flag Tagging** — `admin_panel`, `api`, `ci_cd`, `database`, `login_page`, etc.
- **Honeypot Detection** — Detects canary tokens and suspicious response patterns

---

## 📦 Installation

### Python Dependency
```bash
pip3 install dnspython
```

### Go Tools
```bash
# naabu (port scanner)
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# httpx (HTTP prober + tech detection)
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

```bash
export PATH=$PATH:$(go env GOPATH)/bin
```

### Setup
```bash
git clone https://github.com/vivekbhandarisec/0-STALKER.git
cd 0-STALKER
pip3 install -r requirements.txt
```

---

## 🚀 Usage

### Basic (after 0-STALKER)
```bash
python3 service_mapper.py ./0-stalker-output/example_alive.txt --domain example.com
```

### Fast Scan (skip slow port scan)
```bash
python3 service_mapper.py subs.txt --domain example.com --skip-ports
```

### High Confidence Only
```bash
python3 service_mapper.py subs.txt --domain example.com --min-confidence 0.6
```

### Critical + High Severity Only
```bash
python3 service_mapper.py subs.txt --domain example.com --severity critical,high
```

### Custom Ports
```bash
python3 service_mapper.py subs.txt --domain example.com --ports 80,443,8080,8443,3000
```

### Maximum Threads (faster)
```bash
python3 service_mapper.py subs.txt --domain example.com --threads 200
```

### Skip DNS Audit
```bash
python3 service_mapper.py subs.txt --domain example.com --no-dns-audit
```

### Full Control
```bash
python3 service_mapper.py subs.txt \
  --domain example.com \
  --threads 150 \
  --timeout 10 \
  --min-confidence 0.5 \
  --severity critical,high,medium \
  --output ./my-results/
```

---

## 📊 Output Files

All saved to `./sm-output/` (or `--output` dir):

| File | Content |
|------|---------|
| `target_services.json` | Full report — all services, scores, flags, tech, metadata |
| `target_critical_high.txt` | Quick-reference: only critical & high severity findings |
| `target_takeovers.txt` | DNS CNAME takeover risks |
| `target_all_urls.txt` | All discovered URLs — feed into nuclei/ffuf/burp |

---

## 🧠 How False Positives Are Prevented

| Problem | Solution |
|---------|---------|
| Firewalled ports look open | Web-port whitelist only (70 ports vs 65535) |
| HTTP timeout = real service | Response time > 25s → marked `skip`, filtered out |
| WAF returns fake 403 | 403 = low confidence, not removed but scored low |
| Default Nginx/Apache page | Title matched against 15 default page patterns |
| Fake 200 from CDN/parking | Content length < 50 bytes → confidence penalty |
| Honeypot traps | Header pattern + instant 200 with tiny body = flagged |
| Duplicate results | URL-level deduplication before final report |

---

## 🎯 Severity Rules

| Severity | Examples |
|----------|---------|
| `critical` | phpMyAdmin, Adminer, Jenkins, Portainer, Kubernetes Dashboard, Grafana, Swagger |
| `high` | Admin panels, login pages, APIs, services requiring auth (401), CI/CD tools |
| `medium` | Dashboards, dev tools, internal tools, documentation |
| `low` | Webmail, VPN portals, CDN/storage |

---

## 📋 CLI Options

| Option | Default | Description |
|--------|---------|-------------|
| `input` | *required* | Subdomains file (one per line) |
| `--domain` | `target` | Domain name for output file naming |
| `-o, --output` | `./sm-output` | Output directory |
| `--skip-ports` | False | Skip naabu port scan (Phase 3) |
| `--no-dns-audit` | False | Skip DNS takeover check (Phase 2) |
| `--no-deep-probe` | False | Skip Phase 5 HTTP probe on all ports |
| `--threads` | 100 | Concurrent thread count |
| `--timeout` | 10 | HTTP request timeout (seconds) |
| `--port-timeout` | 3 | Port scan timeout (seconds) |
| `--min-confidence` | 0.3 | Minimum confidence score (0.0–1.0) |
| `--severity` | None | Filter by severity level(s) |
| `--ports` | None | Custom port list (overrides whitelist) |
| `--no-banner` | False | Suppress banner |

---

## 🔁 Full Recon Pipeline

```bash
# Step 1: Subdomain discovery
python3 main.py example.com --parallel

# Step 2: Service mapping
python3 service_mapper.py ./0-stalker-output/example_alive.txt --domain example.com

# Step 3: Vulnerability scanning
nuclei -l ./sm-output/example_all_urls.txt -t nuclei-templates/

# Step 4: Directory bruteforce on critical services
ffuf -u FUZZ -w wordlist.txt -ic ./sm-output/example_critical_high.txt
```

---

## 📄 Output Format (services.json)

```json
{
  "metadata": {
    "target_hint": "example.com",
    "total_input": 1000,
    "total_services": 247,
    "duration_seconds": 720
  },
  "services": [
    {
      "subdomain": "dev.example.com",
      "port": 8080,
      "url": "http://dev.example.com:8080",
      "status": 200,
      "title": "Jenkins Dashboard",
      "tech": ["Jenkins", "Java"],
      "server": "Jetty/9.4",
      "response_time_ms": 512,
      "confidence": 0.92,
      "severity": "critical",
      "flags": ["ci_cd", "dashboard", "login_page"],
      "honeypot": false
    }
  ],
  "vulnerabilities": [
    {
      "subdomain": "blog.example.com",
      "cname": "ghost.io",
      "service": "Ghost",
      "takeover_possible": true,
      "risk": "high"
    }
  ],
  "summary": {
    "by_severity": { "critical": 12, "high": 89, "medium": 98, "low": 48 },
    "by_tech": { "Jenkins": 3, "Nginx": 45, "Node.js": 12 },
    "takeover_risks": 2
  }
}
```

---

## 🔐 Legal Notice

**⚠️ Authorized Use Only** — For ethical security research and bug bounty hunting with explicit written permission only.

---

**Built for ethical recon. Part of the 0-STALKER toolkit. 🎯**