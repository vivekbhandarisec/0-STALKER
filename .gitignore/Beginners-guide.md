# 0-STALKER: Scanning Options Guide for Beginners

This guide explains **which scanning command to use and when**, based on your bug hunting scenario.

---

## 🎯 Quick Decision Tree

```
START
  │
  ├─→ "I'm just starting, show me everything"
  │   └─→ Use: Basic Scan (DEFAULT)
  │
  ├─→ "I want results FAST"
  │   └─→ Use: Parallel Enumeration
  │
  ├─→ "I have a custom DNS resolver list"
  │   └─→ Use: Custom Resolvers
  │
  ├─→ "I only care about subdomains, skip DNS check"
  │   └─→ Use: Skip DNS Validation
  │
  ├─→ "I want maximum accuracy, remove fake subdomains"
  │   └─→ Use: Aggressive Cleaning
  │
  └─→ "I want ALL data (TXT + JSON + CSV)"
      └─→ Use: All Formats
```

---

## 📚 Scanning Options Explained

### 1️⃣ **BASIC SCAN** (START HERE IF BEGINNER)
```bash
python3 main.py target.com
```

**When to use:**
- ✅ You're a beginner and just want to learn
- ✅ You have time and don't mind waiting
- ✅ You want balanced speed + accuracy
- ✅ First time scanning a target

**What it does:**
- Runs all 3 enumeration tools (subfinder, assetfinder, amass) one after another
- Cleans up duplicates and invalid entries
- Uses dnsx to check which subdomains are actually alive
- Saves results in TXT + JSON format

**Time taken:** 2-5 minutes (depends on target size)

**Output:** Simple text file + detailed JSON report

**Example:**
```bash
python3 main.py google.com
# Output: google_alive.txt (all working subdomains) + google_report.json (detailed data)
```

---

### 2️⃣ **PARALLEL ENUMERATION** (FASTEST - RECOMMENDED)
```bash
python3 main.py target.com --parallel
```

**When to use:**
- ✅ You want results **as fast as possible**
- ✅ You're in a time-constrained bug bounty
- ✅ Your computer has decent specs (4+ CPU cores)
- ✅ You're scanning a large company

**What it does:**
- Runs all 3 tools **at the same time** instead of waiting for each one
- Saves 2-3 minutes compared to basic scan
- Everything else is the same

**Time taken:** 1-2 minutes

**Speed improvement:** ~50-60% faster

**Example:**
```bash
python3 main.py facebook.com --parallel
# Finishes in ~1-2 minutes instead of 3-5 minutes
```

**When NOT to use:**
- ❌ Your internet connection is slow/unstable
- ❌ You're running on a laptop with low CPU
- ❌ You're on a VPS with limited resources

---

### 3️⃣ **HIGH-THREAD DNS VALIDATION**
```bash
python3 main.py target.com --threads 200
```

**When to use:**
- ✅ You found 5000+ subdomains and want to verify them faster
- ✅ Your DNS resolver is stable and fast
- ✅ You want to speed up the **DNS checking phase**

**What it does:**
- Default: checks 100 DNS queries at once
- This: checks 200 DNS queries at once
- Faster verification of which subdomains actually exist

**Time saved:** 30-60 seconds on large lists

**Common thread values:**
- `--threads 50` = Slow, safe (for weak connection)
- `--threads 100` = Default, balanced
- `--threads 200` = Fast (good connection needed)
- `--threads 300` = Very fast (strong connection needed)

**Example:**
```bash
python3 main.py microsoft.com --parallel --threads 200
# Fastest possible scan
```

---

### 4️⃣ **WITH CUSTOM RESOLVERS**
```bash
python3 main.py target.com --resolvers resolvers.txt
```

**When to use:**
- ✅ You have a list of fast/reliable DNS resolvers
- ✅ You're doing advanced reconnaissance
- ✅ Public DNS servers are being blocked
- ✅ You want to avoid rate limiting

**What it does:**
- Uses your custom DNS server list instead of system default
- Faster/more reliable DNS lookups
- Avoids rate limiting by spreading queries

**How to prepare resolvers.txt:**
```
8.8.8.8
1.1.1.1
208.67.222.222
75.75.75.75
```

**Example:**
```bash
python3 main.py target.com --resolvers resolvers.txt --parallel
# Uses both parallel + custom resolvers for maximum speed
```

**Note:** Most beginners **don't need this** - skip unless you know what you're doing.

---

### 5️⃣ **AGGRESSIVE CLEANING**
```bash
python3 main.py target.com --aggressive-clean
```

**When to use:**
- ✅ You want **maximum accuracy**
- ✅ You're getting fake subdomains from CDN/parking sites
- ✅ You want only real, important subdomains
- ✅ You have limited time to manually verify each subdomain

**What it does:**
- Removes parking domain entries
- Filters out obvious CDN noise
- Removes fake/spam subdomains
- Result: fewer subdomains, but they're real

**Trade-off:**
- ✅ Fewer results, but higher quality
- ❌ Might miss some legitimate subdomains

**Example:**
```bash
python3 main.py target.com --aggressive-clean --parallel
# Gets only real, important subdomains
```

**When NOT to use:**
- ❌ You want to find every possible subdomain
- ❌ You have time to manually review results

---

### 6️⃣ **SKIP DNS VALIDATION**
```bash
python3 main.py target.com --no-dns
```

**When to use:**
- ✅ You only need subdomain names, don't care if they're alive
- ✅ You'll manually check them later with another tool
- ✅ You want to skip the slowest phase (DNS validation)
- ✅ You just want a quick list of all discovered names

**What it does:**
- Runs enumeration + cleaning
- **Skips dnsx verification**
- Gives you all subdomains (alive or dead)

**Time saved:** 1-2 minutes

**Example:**
```bash
python3 main.py target.com --no-dns
# Gets all subdomain names in seconds, you verify later with httpx
```

**Next step:** Feed results to httpx later:
```bash
cat ./0-stalker-output/target_alive.txt | httpx -silent
# This checks HTTP status of all discovered subdomains
```

---

### 7️⃣ **SPECIFY WHICH TOOLS TO USE**
```bash
python3 main.py target.com --only subfinder,assetfinder
```

**When to use:**
- ✅ One enumeration tool is broken/not installed
- ✅ You know subfinder is fastest for your target
- ✅ You want to skip slow tools (e.g., amass)
- ✅ You're testing which tool is best

**What it does:**
- Runs **only** the tools you specify
- Skips others (faster)

**Best tools:**
- `subfinder` = Fastest, most comprehensive (USE THIS)
- `assetfinder` = Quick, good results
- `amass` = Slowest, finds unique subdomains (can take 10+ min)

**Example:**
```bash
python3 main.py target.com --only subfinder
# Fastest, just uses subfinder (2-3 min)

python3 main.py target.com --only subfinder,assetfinder
# Skip slow amass tool
```

---

### 8️⃣ **ALL OUTPUT FORMATS**
```bash
python3 main.py target.com --format txt,json,csv
```

**When to use:**
- ✅ You want all data formats for different tools
- ✅ You'll use CSV for spreadsheet/reporting
- ✅ You want JSON for automation/scripting
- ✅ You want TXT for quick reference

**What it does:**
Saves in 3 formats:

| Format | File | Use Case |
|--------|------|----------|
| **TXT** | `target_alive.txt` | Simple list, feed to other tools |
| **JSON** | `target_report.json` | Complete data, automation, APIs |
| **CSV** | `target_alive.csv` | Spreadsheet, reporting, analysis |

**Example:**
```bash
python3 main.py target.com --format txt,json,csv --parallel
```

---

## 🚀 Real-World Scenarios

### Scenario 1: "I'm a beginner, just starting"
```bash
python3 main.py example.com --parallel
```
**Why:** Fast, simple, gives you everything needed

---

### Scenario 2: "I have 1 hour and need to scan 3 targets"
```bash
python3 main.py target1.com --parallel
python3 main.py target2.com --parallel
python3 main.py target3.com --parallel
```
**Why:** Parallel = faster, run them back-to-back

---

### Scenario 3: "I only care about live subdomains, nothing else"
```bash
python3 main.py example.com --parallel --aggressive-clean
```
**Why:** Parallel (fast) + aggressive clean (high quality results)

---

### Scenario 4: "I want to feed results into httpx immediately"
```bash
python3 main.py example.com --parallel --no-dns
cat ./0-stalker-output/example_alive.txt | httpx -silent
```
**Why:** Skip DNS check, httpx does HTTP verification

---

### Scenario 5: "Maximum speed, all data formats"
```bash
python3 main.py example.com --parallel --threads 200 --format txt,json,csv
```
**Why:** Fastest possible + all output formats

---

### Scenario 6: "Only use fast enumeration tool"
```bash
python3 main.py example.com --parallel --only subfinder
```
**Why:** Subfinder is fastest, skip slow amass

---

### Scenario 7: "I'm on a slow VPS/connection"
```bash
python3 main.py example.com --threads 50
```
**Why:** Default parallel might overload, lower threads = safer

---

## ⚡ Speed Comparison

| Command | Time | Best For |
|---------|------|----------|
| Basic | 3-5 min | Learning |
| `--parallel` | 1-2 min | Speed |
| `--no-dns` | 30 sec | Just names |
| `--parallel --only subfinder` | 1 min | Ultra-fast |
| `--parallel --threads 200` | 1-2 min | Large scans |

---

## 📊 Quality vs Speed Trade-off

```
                   QUALITY
                      ↑
                      │
    --aggressive-clean │         Basic Scan
         │             │              │
         └─────────────┼──────────────┘
                       │
                   SPEED →

More accurate but slower ←→ Faster but might have noise
```

- **Left side** (Aggressive): More time filtering, fewer but real results
- **Right side** (Fast): Less filtering, more results but some might be fake

---

## ❓ FAQ

**Q: Which option should I use as a beginner?**
A: Start with:
```bash
python3 main.py target.com --parallel
```

**Q: Will `--threads 300` make it faster?**
A: Yes, but only if your connection is stable. Too high = errors.

**Q: Can I combine options?**
A: Yes! Example:
```bash
python3 main.py target.com --parallel --aggressive-clean --threads 200
```

**Q: What if enumeration tools aren't installed?**
A: Install them first (see README.md Installation section)

**Q: How do I save results in a specific folder?**
A: Use `--output`:
```bash
python3 main.py target.com --parallel --output ./my-results/
```

**Q: Which gives the most subdomains?**
A: Basic scan (all tools) or `--parallel` (all tools, same results, just faster)

**Q: I'm on a VPS with limited resources?**
A: Use:
```bash
python3 main.py target.com --only subfinder --threads 50
```

---

## ✅ Recommended For Beginners

```bash
# First scan (learn the tool)
python3 main.py example.com

# Second scan (faster version)
python3 main.py example.com --parallel

# Production scan (best quality)
python3 main.py example.com --parallel --aggressive-clean

# Next step: Feed to httpx
cat ./0-stalker-output/example_alive.txt | httpx -silent
```

---

**Remember:** Start simple, add options as you learn! 🎓