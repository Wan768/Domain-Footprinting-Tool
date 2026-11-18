import json
import time
import re
import argparse
import whois
import requests
import dns.exception
import dns.resolver
from datetime import datetime, timezone

RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT']

PUBLIC_RESOLVERS = ['8.8.8.8', '1.1.1.1']

USER_AGENT = "FootPrinter/1.0 (authorized-scan)"

EXPECTED_HEADERS = {
    "strict-transport-security": ("Missing HSTS", "Medium"),
    "content-security-policy": ("Missing CSP", "Medium"),
    "x-frame-options": ("Missing X-Frame-Options", "Low"),
    "x-content-type-options": ("Missing X-Content-Type-Options", "Low"),
}

def make_resolver(nameservers=None):
    resolver = dns.resolver.Resolver()
    if nameservers:
        resolver.nameservers = nameservers
    resolver.lifetime = 5
    return resolver

def finding(title, severity, detail, category):
    return {"title": title, "severity": severity,
            "detail": detail, "category": category}

def resolve_with_fallback(name, rtype):
    system_resolver = make_resolver()
    public_resolver = make_resolver(PUBLIC_RESOLVERS)
    try:
        return system_resolver.resolve(name, rtype)
    except dns.exception.Timeout:
        return public_resolver.resolve(name, rtype)

def check_spf(records):
    findings = []

    if "error" in records:
        return findings

    if "TXT" in records.get("_failed", []):
        findings.append(finding("SPF check skipped", "Info",
                                "TXT lookup failed, cannot confirm whether SPF exists", "email"))
        return findings
    
    spf_records = [t.strip('"') for t in records.get("TXT", []) if "v=spf1" in t]

    if len(spf_records) == 0:
        findings.append(finding("No SPF record", "High",
                                "Domain does not have an SPF record, anyone can spoof the email", "email"))
        return findings

    if len(spf_records) > 1:
        findings.append(finding("Multiple SPF records", "Medium",
                                "Having more than one SPF record is invalid", "email"))

    spf = spf_records[0]
    if spf.endswith("+all"):
        findings.append(finding("SPF allows all senders", "High",
                                "SPF ends with +all, anyone can send email as this domain", "email"))
    elif spf.endswith("?all"):
        findings.append(finding("SPF neutral policy", "Medium",
                                "SPF ends with ?all, it does not give any protection against spoofing", "email"))
    elif spf.endswith("~all"):
        findings.append(finding("SPF softfail policy", "Low",
                                "SPF ends with ~all, spoofed mail will be marked suspicious but not rejected", "email"))
    elif spf.endswith("-all"):
        pass  
    else:
        findings.append(finding("SPF has no all mechanism", "Low",
                                "SPF does not end with an all qualifier, policy may be incomplete", "email"))

    return findings

def lookup_txt(name):
    try:
        answers = resolve_with_fallback(name, 'TXT')
        return [str(r).strip('"') for r in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []
    except dns.exception.Timeout:
        return None

def check_dmarc(domain, records):
    findings = []

    if "error" in records:
        return findings

    txt = lookup_txt(f"_dmarc.{domain}")
    if txt is None:
        findings.append(finding("DMARC check skipped", "Info",
                                "Lookup failed, cannot confirm whether DMARC exists", "email"))
        return findings

    dmarc_records = [t for t in txt if t.lower().startswith("v=dmarc1")]
    if not dmarc_records:
        findings.append(finding("No DMARC record", "High",
                                "Domain has no DMARC policy, spoofed email is not instructed to be rejected", "email"))
        return findings

    tags = {}
    for part in dmarc_records[0].split(";"):
        if "=" in part:
            key, value = part.strip().split("=", 1)
            tags[key.strip().lower()] = value.strip().lower()

    policy = tags.get("p")

    if policy == "none":
        findings.append(finding("DMARC monitoring only", "Medium",
                                "DMARC policy is p=none, spoofed mail will be reported but can still be delivered", "email"))
    elif policy == "quarantine":
        findings.append(finding("DMARC quarantine policy", "Low",
                                "DMARC policy is p=quarantine, spoofed mail will go to spam but does not get rejected", "email"))
    elif policy == "reject":
        pass  
    else:
        findings.append(finding("Invalid DMARC policy", "Medium",
                                "DMARC record has missing or unknown p tag, so it is not implemented", "email"))
    if "rua" not in tags:
        findings.append(finding("No DMARC reporting address", "Low",
                                "DMARC has no rua tag, domain owner will not receive reports", "email"))

    return findings  

def check_http_headers(domain):
    findings = []
    headers = None

    for scheme in ("https", "http"):
        try:
            response = requests.get(f"{scheme}://{domain}", timeout=5,
                                    headers={"User-Agent": USER_AGENT},
                                    allow_redirects=True)
            headers = {k.lower(): v for k, v in response.headers.items()}
            break
        except requests.RequestException:
            continue

    if headers is None:
        findings.append(finding("HTTP check skipped", "Info",
                                "Could not connect to the web server", "web"))
        return findings

    for name, (title, severity) in EXPECTED_HEADERS.items():
        if name not in headers:
            findings.append(finding(title, severity,
                                    f"The {name} header is not set", "web"))

    for name in ("server", "x-powered-by"):
        value = headers.get(name, "")
        if re.search(r"\d+\.\d+", value):
            findings.append(finding(f"Version disclosed in {name}", "Low",
                                    f"The {name} header reveals a version: {value}", "web"))

    return findings

def to_utc(d):
    # sesetengah tarikh WHOIS tiada timezone, kita seragamkan
    if d.tzinfo is None:
        return d.replace(tzinfo=timezone.utc)
    return d


def pick_date(value, pick):
    # python-whois kadang return list tarikh, kadang satu tarikh, kadang None
    if isinstance(value, list):
        dates = [to_utc(d) for d in value if isinstance(d, datetime)]
        return pick(dates) if dates else None
    if isinstance(value, datetime):
        return to_utc(value)
    return None


def check_whois(domain):
    findings = []
    try:
        w = whois.whois(domain)
    except Exception as e:
        reason = str(e).splitlines()[0] if str(e) else "unknown error"
        findings.append(finding("WHOIS lookup failed", "Info", reason, "whois"))
        return {}, findings

    created = pick_date(w.creation_date, min)
    expiry = pick_date(w.expiration_date, min)

    name_servers = w.name_servers or []
    if isinstance(name_servers, str):
        name_servers = [name_servers]

    info = {
        "registrar": w.registrar,
        "creation_date": str(created),
        "expiration_date": str(expiry),
        "name_servers": sorted({n.lower() for n in name_servers}),
    }

    if expiry is None:
        findings.append(finding("WHOIS expiry unknown", "Info",
                                "No expiration date found in WHOIS data", "whois"))
        return info, findings

    days_left = (expiry - datetime.now(timezone.utc)).days
    if days_left < 0:
        findings.append(finding("Domain expired", "High",
                                f"Domain expired {abs(days_left)} days ago", "whois"))
    elif days_left < 30:
        findings.append(finding("Domain expiring soon", "Medium",
                                f"Domain will expire in {days_left} days", "whois"))
    return info, findings

def get_dns_records(domain):
    results = {"_failed": []}
    for rtype in RECORD_TYPES:
        try:
            answers = resolve_with_fallback(domain, rtype)
            results[rtype] = [str(r) for r in answers]
        except dns.resolver.NoAnswer:
            results[rtype] = []
        except dns.resolver.NXDOMAIN:
            return {"error": f"Domain {domain} does not exist"}
        except dns.exception.Timeout:
            results[rtype] = []
            results["_failed"].append(rtype)
    return results

def run_analysis(domain, delay=1.0, dry_run=False):
    result = {"domain": domain, "records": {}, "whois": {},
              "findings": [], "summary": {}}

    if dry_run:
        print(f"[DRY RUN] Would query DNS records for {domain}")
        print(f"[DRY RUN] Would query _dmarc.{domain}")
        print(f"[DRY RUN] Would send an HTTP request to {domain}")
        print(f"[DRY RUN] Would query WHOIS for {domain}")
        print("[DRY RUN] No requests were sent")
        return result

    records = get_dns_records(domain)
    result["records"] = records

    if "error" in records:
        result["findings"].append(finding("Domain does not exist", "Info",
                                          records["error"], "dns"))
        return result

    result["findings"] += check_spf(records)

    time.sleep(delay)
    result["findings"] += check_dmarc(domain, records)

    time.sleep(delay)
    result["findings"] += check_http_headers(domain)

    time.sleep(delay)
    whois_info, whois_findings = check_whois(domain)
    result["whois"] = whois_info
    result["findings"] += whois_findings

    summary = {"High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for item in result["findings"]:
        summary [item["severity"]] += 1
    result["summary"] = summary

    return result

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DNS, email security and web header analyzer")
    parser.add_argument("domain", nargs="?", default="example.com",
                        help="Target domain (default: example.com)")
    parser.add_argument("--delay", type=float, default=1.0,
                        help="Seconds to wait between network steps (default: 1.0)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would be done without sending requests")
    args = parser.parse_args()

    result = run_analysis(args.domain, delay=max(0, args.delay), dry_run=args.dry_run)
    print(json.dumps(result, indent=2, default=str))