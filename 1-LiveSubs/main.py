#!/usr/bin/env python3
"""
0-stalker.py — Advanced Subdomain Enumeration & Validation Tool
Layers:
  1. Enumeration  — subfinder + assetfinder + amass (parallel or sequential)
  2. Cleaning     — dedup, wildcard strip, scope filter, regex sanitize
  3. Validation   — dnsx DNS resolution → alive subdomains only

Author: Built for ethical bug bounty hunting
Usage : python3 0-stalker.py target.com [options]
"""

import subprocess
import sys
import os
import re
import argparse
import json
import time
import shutil
import tempfile
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


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
  ██████╗       ███████╗████████╗ █████╗ ██╗     ██╗  ██╗███████╗██████╗
 ██╔═████╗      ██╔════╝╚══██╔══╝██╔══██╗██║     ██║ ██╔╝██╔════╝██╔══██╗
 ██║██╔██║█████╗███████╗   ██║   ███████║██║     █████╔╝ █████╗  ██████╔╝
 ████╔╝██║╚════╝╚════██║   ██║   ██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗
 ╚██████╔╝      ███████║   ██║   ██║  ██║███████╗██║  ██╗███████╗██║  ██║
  ╚═════╝       ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
{Color.RESET}
{Color.DIM}  Subdomain Recon · Dedup & Clean · DNS Alive Check{Color.RESET}
{Color.DIM}  subfinder + assetfinder + amass + dnsx{Color.RESET}
{Color.RED}{Color.BOLD}  ⚠  Authorized targets only. Happy hunting.{Color.RESET}
""")


# ─── Logging ────────────────────────────────────────────────────────────────

def log_info(msg):
    print(f"  {Color.BLUE}[*]{Color.RESET} {msg}")

def log_success(msg):
    print(f"  {Color.GREEN}[+]{Color.RESET} {msg}")

def log_warn(msg):
    print(f"  {Color.YELLOW}[!]{Color.RESET} {msg}")

def log_error(msg):
    print(f"  {Color.RED}[-]{Color.RESET} {msg}")

def log_section(title):
    bar = "─" * 58
    print(f"\n{Color.BOLD}{Color.MAGENTA}{bar}{Color.RESET}")
    print(f"  {Color.BOLD}{Color.MAGENTA}{title}{Color.RESET}")
    print(f"{Color.BOLD}{Color.MAGENTA}{bar}{Color.RESET}\n")


# ─── Tool Check ─────────────────────────────────────────────────────────────

ENUM_TOOLS = ["subfinder", "assetfinder", "amass"]
REQUIRED_TOOLS = ENUM_TOOLS + ["dnsx"]

def check_tools(skip_dnsx: bool = False) -> dict:
    tools_to_check = ENUM_TOOLS + ([] if skip_dnsx else ["dnsx"])
    status = {t: shutil.which(t) is not None for t in tools_to_check}
    return status

def print_tool_status(status: dict):
    log_section("Tool Availability Check")
    for tool, available in status.items():
        label = f"{Color.GREEN}FOUND{Color.RESET}" if available else f"{Color.RED}NOT FOUND{Color.RESET}"
        note  = "" if available else ("  (will skip)" if tool != "dnsx" else "  ← install: go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest")
        print(f"  {Color.CYAN}{tool:<16}{Color.RESET} {label}{Color.DIM}{note}{Color.RESET}")

    if not any(v for t, v in status.items() if t in ENUM_TOOLS):
        log_error("No enumeration tools found. Install subfinder, assetfinder, or amass.")
        sys.exit(1)

    print()


# ─── Enumeration Layer ──────────────────────────────────────────────────────

def run_subfinder(domain: str, timeout: int) -> set:
    try:
        log_info(f"subfinder   → {domain} ...")
        t0 = time.time()
        r = subprocess.run(
            ["subfinder", "-d", domain, "-silent", "-all"],
            capture_output=True, text=True, timeout=timeout
        )
        subs = {l.strip().lower() for l in r.stdout.splitlines() if l.strip()}
        log_success(f"subfinder   → {Color.BOLD}{len(subs)}{Color.RESET} found ({time.time()-t0:.1f}s)")
        return subs
    except subprocess.TimeoutExpired:
        log_warn(f"subfinder timed out after {timeout}s")
        return set()
    except FileNotFoundError:
        log_warn("subfinder not in PATH, skipping")
        return set()
    except Exception as e:
        log_error(f"subfinder: {e}")
        return set()


def run_assetfinder(domain: str, timeout: int) -> set:
    try:
        log_info(f"assetfinder → {domain} ...")
        t0 = time.time()
        r = subprocess.run(
            ["assetfinder", "--subs-only", domain],
            capture_output=True, text=True, timeout=timeout
        )
        subs = {
            l.strip().lower() for l in r.stdout.splitlines()
            if l.strip() and domain in l.strip()
        }
        log_success(f"assetfinder → {Color.BOLD}{len(subs)}{Color.RESET} found ({time.time()-t0:.1f}s)")
        return subs
    except subprocess.TimeoutExpired:
        log_warn(f"assetfinder timed out after {timeout}s")
        return set()
    except FileNotFoundError:
        log_warn("assetfinder not in PATH, skipping")
        return set()
    except Exception as e:
        log_error(f"assetfinder: {e}")
        return set()


def run_amass(domain: str, timeout: int) -> set:
    try:
        log_info(f"amass       → {domain} (passive, may be slow) ...")
        t0 = time.time()
        r = subprocess.run(
            ["amass", "enum", "-passive", "-d", domain, "-nocolor"],
            capture_output=True, text=True, timeout=timeout
        )
        subs = set()
        for line in r.stdout.splitlines():
            line = line.strip().lower()
            if line and domain in line:
                subs.add(line.split()[0])
        log_success(f"amass       → {Color.BOLD}{len(subs)}{Color.RESET} found ({time.time()-t0:.1f}s)")
        return subs
    except subprocess.TimeoutExpired:
        log_warn(f"amass timed out after {timeout}s — partial results used")
        return set()
    except FileNotFoundError:
        log_warn("amass not in PATH, skipping")
        return set()
    except Exception as e:
        log_error(f"amass: {e}")
        return set()


def enumerate_subdomains(domain: str, tool_status: dict, timeout: int, parallel: bool) -> dict:
    log_section(f"Phase 1 — Enumeration  »  {domain}")

    runners = {
        "subfinder":   lambda: run_subfinder(domain, timeout),
        "assetfinder": lambda: run_assetfinder(domain, timeout),
        "amass":       lambda: run_amass(domain, timeout),
    }
    active = {t: fn for t, fn in runners.items() if tool_status.get(t)}
    per_tool = {}

    if parallel:
        log_info("Mode: parallel\n")
        with ThreadPoolExecutor(max_workers=3) as ex:
            futures = {ex.submit(fn): name for name, fn in active.items()}
            for fut in as_completed(futures):
                per_tool[futures[fut]] = fut.result()
    else:
        log_info("Mode: sequential\n")
        for name, fn in active.items():
            per_tool[name] = fn()

    all_raw = set().union(*per_tool.values()) if per_tool else set()
    return {"per_tool": per_tool, "raw": all_raw}


# ─── Cleaning Layer ──────────────────────────────────────────────────────────
#
#  Filters applied (in order):
#    1. Lowercase + strip whitespace
#    2. Remove wildcard entries  (*.)
#    3. Enforce valid hostname regex  (RFC 1123)
#    4. Scope check — must end with the target domain
#    5. Remove obvious CDN/parking noise tokens (optional, --no-clean to skip)
#
# ─────────────────────────────────────────────────────────────────────────────

# Valid hostname label: letters, digits, hyphens; no leading/trailing hyphens
_HOSTNAME_RE = re.compile(
    r'^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$'
)

# Common noise tokens that usually indicate parking / CDN artefacts
_NOISE_TOKENS = {
    "wildcard", "localhost", "invalid", "test123",
    "placeholder", "default", "undefined",
}

def clean_subdomains(raw: set, domain: str, aggressive: bool = False) -> dict:
    """
    Clean and deduplicate a raw set of subdomains.
    Returns a dict with stats and the clean set.
    """
    log_section("Phase 2 — Deduplication & Cleaning")

    original_count = len(raw)
    removed = {
        "wildcard":   set(),
        "invalid":    set(),
        "out_scope":  set(),
        "noise":      set(),
    }

    cleaned = set()
    for sub in raw:
        sub = sub.strip().lower()

        # 1. strip wildcard prefix
        if sub.startswith("*."):
            removed["wildcard"].add(sub)
            sub = sub[2:]           # keep the base, still validate below

        # 2. valid hostname regex
        if not _HOSTNAME_RE.match(sub):
            removed["invalid"].add(sub)
            continue

        # 3. scope check
        if not (sub == domain or sub.endswith("." + domain)):
            removed["out_scope"].add(sub)
            continue

        # 4. noise tokens (only when aggressive cleaning enabled)
        if aggressive:
            labels = sub.split(".")
            if any(tok in labels for tok in _NOISE_TOKENS):
                removed["noise"].add(sub)
                continue

        cleaned.add(sub)

    # Stats
    log_success(f"Raw input       : {Color.BOLD}{original_count}{Color.RESET}")
    log_info(   f"Wildcards fixed : {len(removed['wildcard'])}")
    log_info(   f"Invalid hosts   : {len(removed['invalid'])}")
    log_info(   f"Out-of-scope    : {len(removed['out_scope'])}")
    if aggressive:
        log_info(f"Noise removed   : {len(removed['noise'])}")
    log_success(f"Clean unique    : {Color.BOLD}{Color.GREEN}{len(cleaned)}{Color.RESET}")

    return {
        "clean": cleaned,
        "removed": removed,
        "original_count": original_count,
    }


# ─── DNS Validation Layer (dnsx) ─────────────────────────────────────────────

def run_dnsx(subdomains: set, domain: str, threads: int = 100, resolvers: list = None,
             timeout_sec: int = 5) -> dict:
    """
    Feed subdomains into dnsx and return only those that resolve.
    Uses a temporary file to avoid shell arg-length limits.
    """
    log_section("Phase 3 — DNS Validation with dnsx")

    if not subdomains:
        log_warn("No subdomains to validate.")
        return {"alive": set(), "dead": set(), "dnsx_raw": []}

    if not shutil.which("dnsx"):
        log_warn("dnsx not found — skipping DNS validation.")
        log_warn("Install: go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest")
        return {"alive": subdomains, "dead": set(), "dnsx_raw": []}

    # Write subs to a temp file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
        tmp.write("\n".join(sorted(subdomains)))
        tmp_path = tmp.name

    try:
        log_info(f"Running dnsx on {len(subdomains)} subdomains (threads={threads}) ...")
        t0 = time.time()

        cmd = [
            "dnsx",
            "-l", tmp_path,
            "-silent",
            "-resp",               # show resolved IPs
            "-a",                  # resolve A records
            "-aaaa",               # resolve AAAA records
            "-cname",              # follow CNAMEs
            "-threads", str(threads),
            "-timeout", str(timeout_sec),
            "-retry", "2",
        ]

        if resolvers:
            # write resolvers to a temp file too
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as rf:
                rf.write("\n".join(resolvers))
                resolver_path = rf.name
            cmd += ["-r", resolver_path]
        else:
            resolver_path = None

        result = subprocess.run(cmd, capture_output=True, text=True)

        elapsed = time.time() - t0

        alive = set()
        dnsx_raw = []

        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            dnsx_raw.append(line)
            # dnsx -resp output: "sub.domain.com [1.2.3.4]"  or  "sub.domain.com"
            host = line.split()[0].lower().rstrip(".")
            if host:
                alive.add(host)

        dead = subdomains - alive

        log_success(f"dnsx finished in {elapsed:.1f}s")
        log_success(f"Alive subs      : {Color.BOLD}{Color.GREEN}{len(alive)}{Color.RESET}")
        log_info(   f"Non-resolving   : {Color.YELLOW}{len(dead)}{Color.RESET}")

        return {"alive": alive, "dead": dead, "dnsx_raw": dnsx_raw}

    except Exception as e:
        log_error(f"dnsx error: {e}")
        return {"alive": set(), "dead": subdomains, "dnsx_raw": []}

    finally:
        os.unlink(tmp_path)
        if resolvers and resolver_path:
            try:
                os.unlink(resolver_path)
            except Exception:
                pass


# ─── Output ──────────────────────────────────────────────────────────────────

def save_all(domain: str, results: dict, output_dir: str, formats: list):
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = f"{domain.replace('.', '_')}_{ts}"
    saved = []

    raw_subs   = sorted(results["enum"]["raw"])
    clean_subs = sorted(results["clean"]["clean"])
    alive_subs = sorted(results["dns"]["alive"])

    # ── plain text ──
    if "txt" in formats:
        # all-subs
        p = os.path.join(output_dir, f"{base}_all.txt")
        with open(p, "w") as f:
            f.write(f"# 0-stalker | {domain} | {datetime.now()}\n")
            f.write(f"# All unique subdomains before DNS check: {len(clean_subs)}\n\n")
            f.write("\n".join(clean_subs))
        saved.append(("All subdomains", p))

        # alive-only
        p2 = os.path.join(output_dir, f"{base}_alive.txt")
        with open(p2, "w") as f:
            f.write(f"# 0-stalker | {domain} | {datetime.now()}\n")
            f.write(f"# Alive (DNS-resolved) subdomains: {len(alive_subs)}\n\n")
            f.write("\n".join(alive_subs))
        saved.append(("Alive subdomains", p2))

    # ── json ──
    if "json" in formats:
        p = os.path.join(output_dir, f"{base}_report.json")
        report = {
            "meta": {
                "tool":      "0-stalker",
                "domain":    domain,
                "timestamp": datetime.now().isoformat(),
            },
            "stats": {
                "raw_total":         len(results["enum"]["raw"]),
                "after_clean":       len(clean_subs),
                "alive_dns":         len(alive_subs),
                "wildcards_fixed":   len(results["clean"]["removed"]["wildcard"]),
                "invalid_removed":   len(results["clean"]["removed"]["invalid"]),
                "out_scope_removed": len(results["clean"]["removed"]["out_scope"]),
                "noise_removed":     len(results["clean"]["removed"]["noise"]),
            },
            "per_tool": {t: sorted(list(s)) for t, s in results["enum"]["per_tool"].items()},
            "clean_subdomains": clean_subs,
            "alive_subdomains": alive_subs,
            "dnsx_raw_output":  results["dns"]["dnsx_raw"],
        }
        with open(p, "w") as f:
            json.dump(report, f, indent=2)
        saved.append(("Full JSON report", p))

    # ── csv ──
    if "csv" in formats:
        p = os.path.join(output_dir, f"{base}_alive.csv")
        per_tool = results["enum"]["per_tool"]
        with open(p, "w") as f:
            f.write("subdomain,found_by,dns_alive\n")
            # write alive first
            for sub in sorted(results["clean"]["clean"]):
                tools = "+".join(t for t, s in per_tool.items() if sub in s)
                alive = "yes" if sub in results["dns"]["alive"] else "no"
                f.write(f"{sub},{tools},{alive}\n")
        saved.append(("CSV report", p))

    return saved


def print_alive(alive: set, limit: int = 40):
    subs = sorted(alive)
    log_section(f"Alive Subdomains ({len(subs)} total)")
    for sub in subs[:limit]:
        print(f"  {Color.GREEN}✔{Color.RESET}  {sub}")
    if len(subs) > limit:
        print(f"\n  {Color.DIM}... and {len(subs)-limit} more — see output files{Color.RESET}")


def print_summary(domain: str, results: dict, elapsed: float):
    log_section("Final Summary")
    e = results["enum"]
    c = results["clean"]
    d = results["dns"]

    # per-tool bar chart
    total_raw = max(len(e["raw"]), 1)
    for tool, subs in e["per_tool"].items():
        bar_len = int((len(subs) / total_raw) * 28)
        bar = f"{Color.CYAN}{'█'*bar_len}{Color.DIM}{'░'*(28-bar_len)}{Color.RESET}"
        print(f"  {Color.CYAN}{tool:<15}{Color.RESET} {Color.BOLD}{len(subs):>5}{Color.RESET}  {bar}")

    # unique-to-each-tool
    print()
    for tool, subs in e["per_tool"].items():
        others = set().union(*(s for t, s in e["per_tool"].items() if t != tool))
        unique = subs - others
        if unique:
            log_info(f"{tool} exclusively found {Color.YELLOW}{len(unique)}{Color.RESET} subdomains")

    # pipeline stats
    print(f"\n  {'─'*48}")
    rows = [
        ("Raw (all tools merged)",   len(e["raw"]),          Color.WHITE),
        ("After dedup + clean",      len(c["clean"]),         Color.CYAN),
        ("Alive (DNS resolved)",      len(d["alive"]),         Color.GREEN),
        ("Dead / non-resolving",      len(d["dead"]),          Color.DIM),
    ]
    for label, val, col in rows:
        print(f"  {Color.BOLD}{label:<30}{Color.RESET} {col}{Color.BOLD}{val}{Color.RESET}")

    print(f"\n  {Color.BOLD}{'Target':<30}{Color.RESET} {Color.WHITE}{domain}{Color.RESET}")
    print(f"  {Color.BOLD}{'Total elapsed':<30}{Color.RESET} {Color.CYAN}{elapsed:.1f}s{Color.RESET}\n")


# ─── CLI ─────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="0-stalker — Subdomain Enum · Clean · DNS Alive Check",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 0-stalker.py target.com\n"
            "  python3 0-stalker.py target.com --parallel --threads 200\n"
            "  python3 0-stalker.py target.com --no-dns -f txt,csv\n"
            "  python3 0-stalker.py target.com --aggressive-clean --only subfinder,assetfinder\n"
            "  python3 0-stalker.py target.com --resolvers resolvers.txt\n"
        )
    )

    # Target
    parser.add_argument("domain", help="Target domain  e.g. example.com")

    # Output
    parser.add_argument("-o", "--output",  default="./0-stalker-output",
                        help="Output directory  (default: ./0-stalker-output)")
    parser.add_argument("-f", "--format",  default="txt,json",
                        help="Output formats: txt,json,csv  (default: txt,json)")

    # Enumeration
    parser.add_argument("--only",     help="Comma-separated tools to use: subfinder,assetfinder,amass")
    parser.add_argument("--parallel", action="store_true", help="Run enum tools in parallel")
    parser.add_argument("-t", "--timeout", type=int, default=300,
                        help="Per-tool timeout in seconds  (default: 300)")

    # Cleaning
    parser.add_argument("--aggressive-clean", action="store_true",
                        help="Remove parking/noise token subdomains")

    # DNS validation
    parser.add_argument("--no-dns",    action="store_true",
                        help="Skip dnsx DNS validation")
    parser.add_argument("--threads",   type=int, default=100,
                        help="dnsx thread count  (default: 100)")
    parser.add_argument("--resolvers", default=None,
                        help="File with custom DNS resolvers (one per line)")
    parser.add_argument("--dns-timeout", type=int, default=5,
                        help="Per-query DNS timeout in seconds  (default: 5)")

    # Misc
    parser.add_argument("--no-banner", action="store_true", help="Suppress banner")
    return parser.parse_args()


# ─── Entry Point ─────────────────────────────────────────────────────────────

def main():
    args = parse_args()

    if not args.no_banner:
        banner()

    # Validate domain
    domain = args.domain.strip().lower()
    if not domain or "." not in domain:
        log_error("Invalid domain. Example: python3 0-stalker.py example.com")
        sys.exit(1)

    # Tool check
    tool_status = check_tools(skip_dnsx=args.no_dns)
    print_tool_status(tool_status)

    # Filter by --only
    if args.only:
        wanted = {t.strip() for t in args.only.split(",")}
        tool_status = {t: v for t, v in tool_status.items() if t in wanted or t == "dnsx"}

    # Load custom resolvers
    resolvers = None
    if args.resolvers:
        try:
            resolvers = Path(args.resolvers).read_text().splitlines()
            resolvers = [r.strip() for r in resolvers if r.strip()]
            log_info(f"Loaded {len(resolvers)} custom resolvers from {args.resolvers}")
        except Exception as e:
            log_warn(f"Could not load resolvers file: {e} — using system defaults")

    total_start = time.time()

    # ── Phase 1: Enumerate ──
    enum_results = enumerate_subdomains(
        domain=domain,
        tool_status=tool_status,
        timeout=args.timeout,
        parallel=args.parallel,
    )

    if not enum_results["raw"]:
        log_warn("No subdomains found. Check your connection or tool installation.")
        sys.exit(0)

    # ── Phase 2: Clean ──
    clean_results = clean_subdomains(
        raw=enum_results["raw"],
        domain=domain,
        aggressive=args.aggressive_clean,
    )

    # ── Phase 3: DNS Validation ──
    if args.no_dns:
        log_warn("DNS validation skipped (--no-dns)")
        dns_results = {
            "alive":    clean_results["clean"],
            "dead":     set(),
            "dnsx_raw": [],
        }
    else:
        dns_results = run_dnsx(
            subdomains=clean_results["clean"],
            domain=domain,
            threads=args.threads,
            resolvers=resolvers,
            timeout_sec=args.dns_timeout,
        )

    total_elapsed = time.time() - total_start

    # Bundle results
    results = {
        "enum":  enum_results,
        "clean": clean_results,
        "dns":   dns_results,
    }

    # ── Print & Save ──
    print_alive(dns_results["alive"])
    print_summary(domain, results, total_elapsed)

    formats = [f.strip() for f in args.format.split(",")]
    saved = save_all(domain, results, args.output, formats)

    log_section("Saved Output Files")
    for label, path in saved:
        log_success(f"{label:<25} {Color.CYAN}{path}{Color.RESET}")

    print(f"\n  {Color.DIM}Tip: feed alive_subs into httpx / nuclei / ffuf for the next recon phase.{Color.RESET}\n")


if __name__ == "__main__":
    main()