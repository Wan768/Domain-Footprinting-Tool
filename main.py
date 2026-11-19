import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone

from modules.dns_emails import check_dmarc, check_spf, get_dns_records
from modules.subdomain_enum import enumerate_subdomains
from modules.utils import finding, validate_domain
from modules.web_whois import check_http_headers, check_whois


def save_output(domain, data):
    os.makedirs("output", exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = os.path.join("output", f"{domain}_footprint_{timestamp}.json")
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)
    print(f"\n[+] Full JSON report saved locally to: {filename}")

def run_analysis(domain, delay=1.0, dry_run=False):
    domain = validate_domain(domain)
    result = {
        "domain": domain,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "records": {},
        "subdomains": [],
        "whois": {},
        "findings": [],
        "summary": {}
    }

    if dry_run:
        print(f"[DRY RUN] Would query DNS records for {domain}")
        print(f"[DRY RUN] Would query _dmarc.{domain}")
        enumerate_subdomains(domain, delay=delay, dry_run=True)
        print(f"[DRY RUN] Would send an HTTP request to {domain}")
        print(f"[DRY RUN] Would query WHOIS for {domain}")
        print("[DRY RUN] No requests were sent")
        return result

    print(f"\n[*] Gathering DNS records for {domain}...")
    records = get_dns_records(domain)
    result["records"] = records

    if "error" in records:
        result["findings"].append(finding("Domain does not exist", "Info", records["error"], "dns"))
        return result

    result["findings"] += check_spf(records)

    time.sleep(delay)
    print("[*] Checking DMARC policy...")
    result["findings"] += check_dmarc(domain, records)

    time.sleep(delay)
    print("[*] Enumerating subdomains (passive crt.sh + active wordlist)...")
    sub_data = enumerate_subdomains(domain, delay=delay, dry_run=False)
    result["subdomains"] = sub_data["subdomains"]
    result["findings"] += sub_data["findings"]

    time.sleep(delay)
    print("[*] Inspecting HTTP security headers...")
    result["findings"] += check_http_headers(domain)

    time.sleep(delay)
    print("[*] Querying WHOIS registration details...")
    whois_info, whois_findings = check_whois(domain)
    result["whois"] = whois_info
    result["findings"] += whois_findings

    summary = {"High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for item in result["findings"]:
        summary[item["severity"]] += 1
    result["summary"] = summary

    return result

def print_readable_summary(result):
    print("\n" + "=" * 70)
    print(f" FOOTPRINTING & SECURITY SUMMARY: {result['domain']}")
    print("=" * 70)

    print(f"\n[+] Subdomains Discovered ({len(result['subdomains'])}):")
    if result["subdomains"]:
        for sub in result["subdomains"]:
            print(f"  -> {sub['name']} ({sub['source']})")
    else:
        print("  -> None discovered")

    print("\n[+] Security Findings:")
    if result["findings"]:
        for item in result["findings"]:
            print(f"  -> [{item['severity']}] ({item['category'].upper()}) {item['title']}: {item['detail']}")
    else:
        print("  -> No security issues flagged")

    if result["summary"]:
        s = result["summary"]
        print(f"\n[+] Severity Breakdown: High={s['High']} | Medium={s['Medium']} | Low={s['Low']} | Info={s['Info']}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Modular Domain Footprinting & Offensive OSINT Tool",
        epilog="Examples:\n  python main.py example.com\n  python main.py example.com --delay 0.5\n  python main.py example.com --dry-run",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("domain", nargs="?", default="example.com",
                        help="Target domain (default: example.com)")
    parser.add_argument("--delay", type=float, default=1.0,
                        help="Seconds to wait between network steps (default: 1.0)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would be done without sending requests")
    args = parser.parse_args()

    try:
        target = validate_domain(args.domain)
    except ValueError as error:
        parser.error(str(error))

    try:

        result = run_analysis(target, delay=max(0, args.delay), dry_run=args.dry_run)
        if not args.dry_run:
            print_readable_summary(result)
    except KeyboardInterrupt:
        sys.exit(0)
