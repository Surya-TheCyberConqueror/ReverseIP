#!/usr/bin/env python3

"""
============================================================
                    REVERSEIP
             Reverse IP / Shared-IP OSINT
============================================================

Created by : cyb3rconqu3ror
Version    : 1.0
Platform   : Kali Linux
Language   : Python 3

Passive OSINT reconnaissance tool for discovering domains
associated with an IP address.

Use only for authorized security research.
============================================================
"""

import argparse
import csv
import ipaddress
import json
import os
import re
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote

import dns.resolver
import requests


# ============================================================
# Configuration
# ============================================================

VERSION = "1.0"
AUTHOR = "cyb3rconqu3ror"
TOOL_NAME = "ReverseIP"
TIMEOUT = 15
DEFAULT_WORKERS = 20

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) "
    "AppleWebKit/537.36 Chrome/120 Safari/537.36 "
    "ReverseIP-OSINT/1.0"
)


session = requests.Session()

session.headers.update({
    "User-Agent": USER_AGENT,
    "Accept": "*/*",
})


# ============================================================
# Terminal Colors
# ============================================================

class Colors:
    RESET = "\033[0m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    MAGENTA = "\033[95m"
    BOLD = "\033[1m"
    DIM = "\033[2m"


def c(text, color):
    return f"{color}{text}{Colors.RESET}"


# ============================================================
# Screen
# ============================================================

def clear_screen():
    os.system("clear")


# ============================================================
# Banner
# ============================================================

def banner(clear=True):

    if clear:
        clear_screen()

    print(c(r"""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ██████╗ ███████╗██╗   ██╗███████╗██████╗ ███████╗██████╗ ║
║   ██╔══██╗██╔════╝██║   ██║██╔════╝██╔══██╗██╔════╝██╔══██╗║
║   ██████╔╝█████╗  ██║   ██║█████╗  ██████╔╝█████╗  ██████╔╝║
║   ██╔══██╗██╔══╝  ╚██╗ ██╔╝██╔══╝  ██╔═══╝ ██╔══╝  ██╔══██╗║
║   ██║  ██║███████╗ ╚████╔╝ ███████╗██║     ███████╗██║  ██║║
║   ╚═╝  ╚═╝╚══════╝  ╚═══╝  ╚══════╝╚═╝     ╚══════╝╚═╝  ╚═╝║
║                                                              ║
║              REVERSE IP / SHARED-IP OSINT                   ║
║                                                              ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║              Created by : cyb3rconqu3ror                    ║
║              Version    : 1.0                                ║
║              Platform   : Kali Linux                         ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
""", Colors.CYAN))

    print(
        c(
            "  [!] Passive reconnaissance / OSINT tool",
            Colors.YELLOW
        )
    )

    print(
        c(
            "  [!] Use only for authorized security research.",
            Colors.YELLOW
        )
    )

    print()


# ============================================================
# Domain Helpers
# ============================================================

def clean_domain(domain):

    domain = domain.strip().lower()

    # Remove HTTP/HTTPS
    domain = re.sub(
        r"^https?://",
        "",
        domain
    )

    # Remove path
    domain = domain.split("/")[0]

    # Remove port
    if ":" in domain and not re.match(
        r"^\d+\.\d+\.\d+\.\d+$",
        domain
    ):
        domain = domain.split(":")[0]

    # Remove trailing dot
    domain = domain.rstrip(".")

    return domain


def is_ip(value):

    try:
        ipaddress.ip_address(value)
        return True

    except ValueError:
        return False


# ============================================================
# DNS Resolution
# ============================================================

def resolve_domain(domain):

    ips = set()

    resolver = dns.resolver.Resolver()

    resolver.timeout = 5
    resolver.lifetime = 5

    for record_type in ["A", "AAAA"]:

        try:

            answers = resolver.resolve(
                domain,
                record_type
            )

            for answer in answers:
                ips.add(str(answer))

        except Exception:
            pass

    return sorted(ips)


def reverse_dns(ip):

    try:

        hostname = socket.gethostbyaddr(ip)[0]

        return hostname

    except Exception:

        return None


# ============================================================
# HTTP Helper
# ============================================================

def get_url(url):

    try:

        response = session.get(
            url,
            timeout=TIMEOUT,
            allow_redirects=True
        )

        if response.status_code == 200:
            return response.text

    except requests.RequestException:
        pass

    return None


# ============================================================
# SOURCE 1 - HackerTarget
# ============================================================

def source_hackertarget(ip):

    results = set()

    url = (
        "https://api.hackertarget.com/"
        "reverseiplookup/"
        f"?q={quote(ip)}"
    )

    data = get_url(url)

    if not data:
        return results

    if "error" in data.lower():
        return results

    for line in data.splitlines():

        domain = clean_domain(line)

        if domain and "." in domain:
            results.add(domain)

    return results


# ============================================================
# SOURCE 2 - RapidDNS
# ============================================================

def source_rapiddns(ip):

    results = set()

    url = (
        "https://rapiddns.io/sameip/"
        f"{quote(ip)}?full=1"
    )

    data = get_url(url)

    if not data:
        return results

    patterns = [

        r'<td[^>]*>'
        r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})'
        r'</td>',

        r'href=["\']https?://'
        r'([^/"\']+)'

    ]

    for pattern in patterns:

        matches = re.findall(
            pattern,
            data,
            flags=re.IGNORECASE
        )

        for domain in matches:

            domain = clean_domain(domain)

            if domain and "." in domain:
                results.add(domain)

    return results


# ============================================================
# SOURCE 3 - CRT.SH
# ============================================================

def source_crtsh(ip):

    results = set()

    hostname = reverse_dns(ip)

    if not hostname:
        return results

    url = (
        "https://crt.sh/?q="
        f"{quote(hostname)}&output=json"
    )

    try:

        response = session.get(
            url,
            timeout=TIMEOUT
        )

        if response.status_code != 200:
            return results

        data = response.json()

    except Exception:
        return results

    for item in data:

        names = item.get(
            "name_value",
            ""
        )

        for name in names.splitlines():

            name = name.strip().lower()

            if name.startswith("*."):
                name = name[2:]

            name = clean_domain(name)

            if (
                name
                and "." in name
                and not is_ip(name)
            ):
                results.add(name)

    return results


# ============================================================
# SOURCE 4 - DNSlytics
# ============================================================

def source_dnslytics(ip):

    results = set()

    url = (
        "https://dnslytics.com/reverse-ip/"
        f"{quote(ip)}"
    )

    data = get_url(url)

    if not data:
        return results

    pattern = (
        r"\b"
        r"(?:[a-zA-Z0-9-]+\.)+"
        r"[a-zA-Z]{2,}"
        r"\b"
    )

    matches = re.findall(
        pattern,
        data
    )

    for domain in matches:

        domain = clean_domain(domain)

        if domain and "." in domain:
            results.add(domain)

    return results


# ============================================================
# SOURCE 5 - ViewDNS
# ============================================================

def source_viewdns(ip):

    results = set()

    url = (
        "https://viewdns.info/reverseip/"
        f"?host={quote(ip)}&t=1"
    )

    data = get_url(url)

    if not data:
        return results

    pattern = (
        r"<td[^>]*>"
        r"\s*([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"
        r"\s*</td>"
    )

    matches = re.findall(
        pattern,
        data,
        flags=re.IGNORECASE
    )

    for domain in matches:

        domain = clean_domain(domain)

        if domain and "." in domain:
            results.add(domain)

    return results


# ============================================================
# OSINT Sources
# ============================================================

SOURCES = {

    "HackerTarget":
        source_hackertarget,

    "RapidDNS":
        source_rapiddns,

    "CRT.SH":
        source_crtsh,

    "DNSlytics":
        source_dnslytics,

    "ViewDNS":
        source_viewdns,
}


# ============================================================
# Query OSINT Sources
# ============================================================

def query_sources(
    ip,
    selected_sources=None
):

    results = {}

    sources = SOURCES

    if selected_sources:

        sources = {
            name: SOURCES[name]
            for name in selected_sources
            if name in SOURCES
        }

    print()

    print(
        c(
            f"[*] Querying {len(sources)} OSINT sources...",
            Colors.BLUE
        )
    )

    print()

    with ThreadPoolExecutor(
        max_workers=len(sources)
    ) as executor:

        future_map = {

            executor.submit(
                function,
                ip
            ): name

            for name, function
            in sources.items()
        }

        for future in as_completed(
            future_map
        ):

            source_name = future_map[
                future
            ]

            try:

                domains = future.result()

            except Exception as e:

                domains = set()

                print(
                    c(
                        f"[-] {source_name}: {e}",
                        Colors.RED
                    )
                )

            results[
                source_name
            ] = domains

            print(
                c(
                    f"[+] {source_name:<15} "
                    f"{len(domains)} domains",
                    Colors.GREEN
                )
            )

    return results


# ============================================================
# Build Source Map
# ============================================================

def build_source_map(
    source_results
):

    domain_sources = {}

    for source, domains in source_results.items():

        for domain in domains:

            if domain not in domain_sources:

                domain_sources[
                    domain
                ] = set()

            domain_sources[
                domain
            ].add(source)

    return domain_sources


# ============================================================
# Confidence
# ============================================================

def calculate_confidence(
    domain,
    domain_sources
):

    source_count = len(
        domain_sources.get(
            domain,
            set()
        )
    )

    if source_count >= 3:
        return "HIGH"

    if source_count == 2:
        return "MEDIUM"

    return "LOW"


# ============================================================
# Validate Domains
# ============================================================

def validate_domains(
    domains,
    target_ips,
    workers=20
):

    validated = []

    if not domains:
        return validated

    print()

    print(
        c(
            "[*] Validating discovered domains...",
            Colors.BLUE
        )
    )

    with ThreadPoolExecutor(
        max_workers=workers
    ) as executor:

        future_map = {

            executor.submit(
                resolve_domain,
                domain
            ): domain

            for domain in domains
        }

        completed = 0
        total = len(domains)

        for future in as_completed(
            future_map
        ):

            domain = future_map[
                future
            ]

            completed += 1

            try:

                domain_ips = future.result()

            except Exception:

                domain_ips = []

            if any(
                ip in domain_ips
                for ip in target_ips
            ):

                validated.append(
                    domain
                )

            print(
                f"\r"
                f"{c('[*]', Colors.BLUE)} "
                f"Validated "
                f"{completed}/{total}",
                end="",
                flush=True
            )

    print()

    return sorted(
        set(validated)
    )


# ============================================================
# Print Results
# ============================================================

def print_results(
    target,
    ips,
    source_results,
    validated,
    domain_sources
):

    print()

    print(
        c(
            "╔════════════════════════════════════════════════════════════╗",
            Colors.CYAN
        )
    )

    print(
        c(
            "║                  REVERSE IP RESULTS                       ║",
            Colors.CYAN
        )
    )

    print(
        c(
            "╚════════════════════════════════════════════════════════════╝",
            Colors.CYAN
        )
    )

    print()

    print(
        c("Target      : ", Colors.YELLOW)
        + target
    )

    print(
        c("IP Address  : ", Colors.YELLOW)
        + ", ".join(ips)
    )

    print(
        c("Domains     : ", Colors.YELLOW)
        + str(len(validated))
    )

    print()

    if not validated:

        print(
            c(
                "[-] No validated shared-IP domains found.",
                Colors.RED
            )
        )

        return

    print(
        c(
            f"{'DOMAIN':<42}"
            f"{'SOURCES':<30}"
            f"CONFIDENCE",
            Colors.BOLD
        )
    )

    print("-" * 90)

    for domain in validated:

        sources = domain_sources.get(
            domain,
            set()
        )

        source_text = ", ".join(
            sorted(sources)
        )

        confidence = calculate_confidence(
            domain,
            domain_sources
        )

        display_domain = domain

        if len(display_domain) > 41:

            display_domain = (
                display_domain[:38]
                + "..."
            )

        print(
            f"{display_domain:<42}"
            f"{source_text:<30}"
            f"{confidence}"
        )

    print("-" * 90)


# ============================================================
# Save JSON
# ============================================================

def save_json(
    filename,
    target,
    ips,
    validated,
    domain_sources
):

    output = {

        "tool": TOOL_NAME,

        "version": VERSION,

        "author": AUTHOR,

        "target": target,

        "ips": ips,

        "timestamp": int(
            time.time()
        ),

        "domains": []

    }

    for domain in validated:

        sources = sorted(
            domain_sources.get(
                domain,
                []
            )
        )

        output["domains"].append({

            "domain": domain,

            "sources": sources,

            "confidence":
                calculate_confidence(
                    domain,
                    domain_sources
                )

        })

    with open(
        filename,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            output,
            f,
            indent=4
        )

    print()

    print(
        c(
            f"[+] JSON saved: {filename}",
            Colors.GREEN
        )
    )


# ============================================================
# Save CSV
# ============================================================

def save_csv(
    filename,
    validated,
    domain_sources
):

    with open(
        filename,
        "w",
        newline="",
        encoding="utf-8"
    ) as f:

        writer = csv.writer(f)

        writer.writerow([
            "Domain",
            "Sources",
            "Confidence"
        ])

        for domain in validated:

            sources = sorted(
                domain_sources.get(
                    domain,
                    []
                )
            )

            writer.writerow([

                domain,

                ", ".join(
                    sources
                ),

                calculate_confidence(
                    domain,
                    domain_sources
                )

            ])

    print(
        c(
            f"[+] CSV saved: {filename}",
            Colors.GREEN
        )
    )


# ============================================================
# Resolve Target
# ============================================================

def resolve_target(target):

    target = clean_domain(
        target
    )

    if is_ip(target):

        return target, [target]

    print(
        c(
            f"[*] Resolving {target}...",
            Colors.BLUE
        )
    )

    ips = resolve_domain(
        target
    )

    if not ips:

        print(
            c(
                "[-] Could not resolve target.",
                Colors.RED
            )
        )

        return None, []

    return target, ips


# ============================================================
# Reverse IP Scan
# ============================================================

def run_reverse_ip(
    target,
    workers=DEFAULT_WORKERS,
    selected_sources=None,
    verify=True
):

    target, ips = resolve_target(
        target
    )

    if not target or not ips:

        return (
            None,
            [],
            {},
            [],
            {}
        )

    all_domains = set()

    all_source_results = {}

    # --------------------------------------------------------
    # Process every resolved IP
    # --------------------------------------------------------

    for ip in ips:

        print()

        print(
            c(
                "=" * 72,
                Colors.CYAN
            )
        )

        print(
            c(
                f"[*] Target IP: {ip}",
                Colors.BOLD
            )
        )

        print(
            c(
                "=" * 72,
                Colors.CYAN
            )
        )

        hostname = reverse_dns(
            ip
        )

        if hostname:

            print(
                c(
                    f"[+] Reverse DNS: {hostname}",
                    Colors.GREEN
                )
            )

        else:

            print(
                c(
                    "[-] Reverse DNS: Not available",
                    Colors.YELLOW
                )
            )

        source_results = query_sources(
            ip,
            selected_sources
        )

        for source, domains in source_results.items():

            if source not in all_source_results:

                all_source_results[
                    source
                ] = set()

            all_source_results[
                source
            ].update(domains)

        for domains in source_results.values():

            all_domains.update(
                domains
            )

    # --------------------------------------------------------
    # Remove target domain
    # --------------------------------------------------------

    all_domains.discard(
        clean_domain(target)
    )

    print()

    print(
        c(
            f"[+] Unique domains discovered: "
            f"{len(all_domains)}",
            Colors.GREEN
        )
    )

    # --------------------------------------------------------
    # Validation
    # --------------------------------------------------------

    if verify:

        validated = validate_domains(
            all_domains,
            ips,
            workers
        )

    else:

        validated = sorted(
            all_domains
        )

    # --------------------------------------------------------
    # Source map
    # --------------------------------------------------------

    domain_sources = build_source_map(
        all_source_results
    )

    # --------------------------------------------------------
    # Results
    # --------------------------------------------------------

    print_results(
        target,
        ips,
        all_source_results,
        validated,
        domain_sources
    )

    return (
        target,
        ips,
        all_source_results,
        validated,
        domain_sources
    )


# ============================================================
# Interactive Menu
# ============================================================

def interactive_menu():

    while True:

        banner()

        print(
            c(
                "  ┌─────────────────────────────────────────────┐",
                Colors.BLUE
            )
        )

        print(
            c(
                "  │                MAIN MENU                    │",
                Colors.BLUE
            )
        )

        print(
            c(
                "  ├─────────────────────────────────────────────┤",
                Colors.BLUE
            )
        )

        print(
            c(
                "  │  [1] Reverse IP Lookup                      │",
                Colors.WHITE
            )
        )

        print(
            c(
                "  │  [2] About ReverseIP                        │",
                Colors.WHITE
            )
        )

        print(
            c(
                "  │  [3] OSINT Sources                           │",
                Colors.WHITE
            )
        )

        print(
            c(
                "  │  [4] Help                                    │",
                Colors.WHITE
            )
        )

        print(
            c(
                "  │  [0] Exit                                    │",
                Colors.WHITE
            )
        )

        print(
            c(
                "  └─────────────────────────────────────────────┘",
                Colors.BLUE
            )
        )

        print()

        try:

            choice = input(
                c(
                    "  ReverseIP > ",
                    Colors.GREEN
                )
            ).strip()

        except EOFError:

            return

        # ----------------------------------------------------
        # Reverse IP
        # ----------------------------------------------------

        if choice == "1":

            clear_screen()

            banner(
                clear=False
            )

            print(
                c(
                    "  ┌─────────────────────────────────────────────┐",
                    Colors.BLUE
                )
            )

            print(
                c(
                    "  │              REVERSE IP LOOKUP              │",
                    Colors.BLUE
                )
            )

            print(
                c(
                    "  └─────────────────────────────────────────────┘",
                    Colors.BLUE
                )
            )

            print()

            try:

                target = input(
                    c(
                        "  Enter Domain / IP: ",
                        Colors.GREEN
                    )
                ).strip()

            except EOFError:

                return

            if not target:

                print(
                    c(
                        "\n[-] Target cannot be empty.",
                        Colors.RED
                    )
                )

                input(
                    "\nPress Enter to continue..."
                )

                continue

            print()

            run_reverse_ip(
                target
            )

            print()

            input(
                c(
                    "Press Enter to return to menu...",
                    Colors.YELLOW
                )
            )

        # ----------------------------------------------------
        # About
        # ----------------------------------------------------

        elif choice == "2":

            clear_screen()

            banner(
                clear=False
            )

            print(
                c(
                    "  ABOUT REVERSEIP",
                    Colors.MAGENTA
                )
            )

            print()

            print(
                "  Tool       : ReverseIP"
            )

            print(
                "  Purpose    : Reverse IP / Shared-IP OSINT"
            )

            print(
                "  Version    : " + VERSION
            )

            print(
                "  Author     : " + AUTHOR
            )

            print(
                "  Platform   : Kali Linux"
            )

            print(
                "  Language   : Python 3"
            )

            print()

            print(
                "  ReverseIP discovers domains associated"
            )

            print(
                "  with an IP address using passive/public"
            )

            print(
                "  OSINT sources."
            )

            print()

            print(
                c(
                    "  NOTE: Shared IP does not necessarily mean",
                    Colors.YELLOW
                )
            )

            print(
                c(
                    "  the domains are hosted on the same physical",
                    Colors.YELLOW
                )
            )

            print(
                c(
                    "  server.",
                    Colors.YELLOW
                )
            )

            print()

            input(
                c(
                    "Press Enter to return to menu...",
                    Colors.YELLOW
                )
            )

        # ----------------------------------------------------
        # Sources
        # ----------------------------------------------------

        elif choice == "3":

            clear_screen()

            banner(
                clear=False
            )

            print(
                c(
                    "  OSINT SOURCES",
                    Colors.MAGENTA
                )
            )

            print()

            for number, source in enumerate(
                SOURCES.keys(),
                start=1
            ):

                print(
                    c(
                        f"  [{number}] {source}",
                        Colors.WHITE
                    )
                )

            print()

            input(
                c(
                    "Press Enter to return to menu...",
                    Colors.YELLOW
                )
            )

        # ----------------------------------------------------
        # Help
        # ----------------------------------------------------

        elif choice == "4":

            clear_screen()

            banner(
                clear=False
            )

            print(
                c(
                    "  HELP",
                    Colors.MAGENTA
                )
            )

            print()

            print(
                c(
                    "  Interactive Mode:",
                    Colors.YELLOW
                )
            )

            print(
                "      python3 reverseip.py"
            )

            print()

            print(
                c(
                    "  Direct Domain Lookup:",
                    Colors.YELLOW
                )
            )

            print(
                "      python3 reverseip.py example.com"
            )

            print()

            print(
                c(
                    "  Direct IP Lookup:",
                    Colors.YELLOW
                )
            )

            print(
                "      python3 reverseip.py 1.2.3.4"
            )

            print()

            print(
                c(
                    "  JSON Export:",
                    Colors.YELLOW
                )
            )

            print(
                "      python3 reverseip.py example.com "
                "--json results.json"
            )

            print()

            print(
                c(
                    "  CSV Export:",
                    Colors.YELLOW
                )
            )

            print(
                "      python3 reverseip.py example.com "
                "--csv results.csv"
            )

            print()

            print(
                c(
                    "  Skip Verification:",
                    Colors.YELLOW
                )
            )

            print(
                "      python3 reverseip.py example.com "
                "--no-verify"
            )

            print()

            input(
                c(
                    "Press Enter to return to menu...",
                    Colors.YELLOW
                )
            )

        # ----------------------------------------------------
        # Exit
        # ----------------------------------------------------

        elif choice == "0":

            clear_screen()

            print()

            print(
                c(
                    "  ReverseIP",
                    Colors.CYAN
                )
            )

            print(
                c(
                    "  Created by cyb3rconqu3ror",
                    Colors.MAGENTA
                )
            )

            print(
                c(
                    "\n  Goodbye.\n",
                    Colors.GREEN
                )
            )

            sys.exit(0)

        else:

            print()

            print(
                c(
                    "[-] Invalid option.",
                    Colors.RED
                )
            )

            time.sleep(1)


# ============================================================
# Argument Parser
# ============================================================

def main():

    parser = argparse.ArgumentParser(
        description=(
            "ReverseIP - Reverse IP / Shared-IP OSINT "
            "by cyb3rconqu3ror"
        )
    )

    parser.add_argument(
        "target",
        nargs="?",
        help="Domain or IP address"
    )

    parser.add_argument(
        "--json",
        metavar="FILE",
        help="Save results as JSON"
    )

    parser.add_argument(
        "--csv",
        metavar="FILE",
        help="Save results as CSV"
    )

    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Do not verify discovered domains"
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        help=(
            f"DNS validation threads "
            f"(default: {DEFAULT_WORKERS})"
        )
    )

    parser.add_argument(
        "--source",
        action="append",
        choices=list(SOURCES.keys()),
        help="Use a specific OSINT source"
    )

    args = parser.parse_args()

    # ========================================================
    # No target = Interactive Mode
    # ========================================================

    if args.target is None:

        interactive_menu()

        return

    # ========================================================
    # Direct CLI Mode
    # ========================================================

    banner()

    (
        target,
        ips,
        source_results,
        validated,
        domain_sources
    ) = run_reverse_ip(
        args.target,
        workers=args.workers,
        selected_sources=args.source,
        verify=not args.no_verify
    )

    if not target:

        sys.exit(1)

    # ========================================================
    # Export
    # ========================================================

    if args.json:

        save_json(
            args.json,
            target,
            ips,
            validated,
            domain_sources
        )

    if args.csv:

        save_csv(
            args.csv,
            validated,
            domain_sources
        )

    print()

    print(
        c(
            "[+] Scan complete.",
            Colors.GREEN
        )
    )

    print(
        c(
            "[!] Shared IP does not necessarily mean "
            "same physical server.",
            Colors.YELLOW
        )
    )


# ============================================================
# Entry Point
# ============================================================

if __name__ == "__main__":

    try:

        main()

    except KeyboardInterrupt:

        print()

        print(
            c(
                "[!] Interrupted by user.",
                Colors.RED
            )
        )

        print()

        sys.exit(130)

    except Exception as e:

        print()

        print(
            c(
                f"[!] Unexpected error: {e}",
                Colors.RED
            )
        )

        print()

        sys.exit(1)
