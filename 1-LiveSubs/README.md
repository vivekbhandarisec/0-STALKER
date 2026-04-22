# 0-STALKER

> **Advanced Subdomain Enumeration & Alive Validation Tool**

A fast, multi-tool subdomain discovery framework that leverages **subfinder**, **assetfinder**, and **amass** for comprehensive enumeration, followed by intelligent deduplication and **dnsx** validation to identify only alive subdomains.

---

## ⚡ Features

- **Multi-Source Enumeration**: Parallel/sequential execution of subfinder, assetfinder, and amass
- **Smart Deduplication**: Remove wildcards, duplicates, and invalid hostnames
- **DNS Validation**: Use dnsx to verify only alive subdomains
- **Aggressive Cleaning**: Optional filtering of CDN/parking noise tokens
- **Multiple Output Formats**: TXT, JSON, CSV reports
- **Custom DNS Resolvers**: Supply your own resolver list for optimized lookups
- **Detailed Reporting**: Per-tool statistics, dedup analysis, and elapsed time metrics
- **Thread Control**: Adjustable concurrent threads for DNS validation

---

## 📦 Installation

### Requirements
- Python 3.7+
- At least one of: `subfinder`, `assetfinder`, `amass`
- `dnsx` (for alive validation)

### Install Tools

**Subfinder** (recommended – fastest & most comprehensive)
```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

**Assetfinder**
```bash
go install -v github.com/tomnomnom/assetfinder@latest
```

**Amass**
```bash
go install -v github.com/OWASP/Amass/v3/...@master
```

**dnsx** (required for alive checks)
```bash
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
```

Ensure Go's `bin` directory is in your `$PATH`:
```bash
export PATH=$PATH:$(go env GOPATH)/bin
```

### Setup 0-STALKER
```bash
git clone https://github.com/vivekbhandarisec/0-STALKER.git
cd 0-STALKER
```

---

## 🚀 Usage

### Basic Scan
```bash
python3 main.py target.com
```

### Parallel Enumeration (faster)
```bash
python3 main.py target.com --parallel
```

### High-Thread DNS Validation
```bash
python3 main.py target.com --threads 200
```

### With Custom Resolvers
```bash
python3 main.py target.com --resolvers resolvers.txt
```

### Aggressive Cleaning (remove CDN/parking noise)
```bash
python3 main.py target.com --aggressive-clean
```

### Skip DNS Validation
```bash
python3 main.py target.com --no-dns
```

### Specify Output Tools
```bash
python3 main.py target.com --only subfinder,assetfinder
```

### All Options with Custom Output
```bash
python3 main.py target.com \
  --parallel \
  --threads 150 \
  --aggressive-clean \
  --format txt,json,csv \
  --output ./my-results \
  --timeout 300
```

### View All Options
```bash
python3 main.py --help
```

---

## 📊 Output Files

Results are saved to `./0-stalker-output/` (or custom `--output` dir) with timestamp:

| File | Format | Content |
|------|--------|---------|
| `target_alive.txt` | Text | One alive subdomain per line (quick reference) |
| `target_report.json` | JSON | Complete report: per-tool results, clean list, alive subdomains, dnsx raw output |
| `target_alive.csv` | CSV | Structured data: subdomain, discovery tool(s), alive status |

---

## ⚙️ Architecture

### Phase 1: Enumeration
Runs available tools (subfinder → assetfinder → amass) sequentially or in parallel. Merges results into a deduplicated set.

### Phase 2: Cleaning
1. Lowercase & strip whitespace
2. Remove wildcard entries (`*.domain.com`)
3. Validate against RFC 1123 hostname regex
4. Filter to in-scope domains only
5. *(Optional)* Strip parking/CDN noise tokens

### Phase 3: DNS Validation
Pipes cleaned subdomains to `dnsx` with configurable:
- Thread count (default: 100)
- Custom resolver list
- Per-query timeout (default: 5s)

---

## 🎯 Examples

**Quick reconnaissance on a target:**
```bash
python3 main.py example.com --parallel
```

**Deep enumeration with aggressive noise filtering:**
```bash
python3 main.py example.com --parallel --aggressive-clean --threads 200
```

**Enumeration only (skip DNS):**
```bash
python3 main.py example.com --no-dns --format txt,json
```

**Feed results into httpx for HTTP status checking:**
```bash
python3 main.py example.com --parallel
cat ./0-stalker-output/example_alive.txt | httpx -silent
```

**Use with Nuclei for vulnerability scanning:**
```bash
python3 main.py example.com --parallel
nuclei -l ./0-stalker-output/example_alive.txt -t nuclei-templates/
```

---

## 📋 CLI Options Reference

| Option | Default | Description |
|--------|---------|-------------|
| `domain` | *required* | Target domain (e.g., `example.com`) |
| `-o, --output` | `./0-stalker-output` | Output directory |
| `-f, --format` | `txt,json` | Output formats: `txt`, `json`, `csv` (comma-separated) |
| `--parallel` | False | Run enum tools in parallel |
| `-t, --timeout` | 300 | Per-tool timeout (seconds) |
| `--only` | None | Comma-separated tools to use (`subfinder,assetfinder,amass`) |
| `--aggressive-clean` | False | Filter parking/CDN noise tokens |
| `--no-dns` | False | Skip DNS validation |
| `--threads` | 100 | dnsx thread count |
| `--resolvers` | None | Custom resolvers file (one per line) |
| `--dns-timeout` | 5 | Per-query DNS timeout (seconds) |
| `--no-banner` | False | Suppress ASCII banner |

---

## 🔐 Legal Notice

**⚠️ Authorized Use Only**

This tool is designed for authorized security testing and bug bounty hunting. Ensure you have explicit written permission before scanning any target. Unauthorized access to computer systems is illegal.

---

## 🤝 Contributing

Found a bug or have a feature request? Please open an issue on [GitHub](https://github.com/vivekbhandarisec/0-STALKER).

---

## 📄 License

Check the LICENSE file in the repository for details.

---

## 🔗 Links

- **GitHub**: https://github.com/vivekbhandarisec/0-STALKER
- **Subfinder**: https://github.com/projectdiscovery/subfinder
- **Assetfinder**: https://github.com/tomnomnom/assetfinder
- **Amass**: https://github.com/OWASP/Amass
- **dnsx**: https://github.com/projectdiscovery/dnsx

---

**Built for ethical security research. Happy hunting! 🎯**