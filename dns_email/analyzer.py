import re
import argparse
import whois
import requests
import dns.exception
import dns.resolver

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
    system_resolver = make_resolver()
    public_resolver = make_resolver(PUBLIC_RESOLVERS)
    try:
        try:
            answers = system_resolver.resolve(name, 'TXT')
        except dns.exception.Timeout:
            answers = public_resolver.resolve(name, 'TXT')
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
                                "DMARC policy is p=none, spoofed mail will be reported but can still delivered", "email"))
    elif policy == "quarantine":
        findings.append(finding("DMARC quarantine policy", "Low",
                                "DMARC policy is p=quarantine, spoofed mail will go to spam but does not get rejected", "email"))
    elif policy == "reject":
        pass  
    else:
        findings.append(finding("Invalid DMARC policy", "Medium",
                                "DMARC record has missing or unknown p tag, so it is not implemented", "email"))

    if "rua" not in tags:
        ...

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

def get_dns_records(domain):
    results = {"_failed": []}
    system_resolver = make_resolver()
    public_resolver = make_resolver(PUBLIC_RESOLVERS)
    for rtype in RECORD_TYPES:
        try:
            try:
                answers = system_resolver.resolve(domain, rtype)
            except dns.exception.Timeout:
                answers = public_resolver.resolve(domain, rtype)
            results[rtype] = [str(r) for r in answers]
        except dns.resolver.NoAnswer:
            results[rtype] = []
        except dns.resolver.NXDOMAIN:
            return {"error": f"Domain {domain} does not exist"}
        except dns.exception.Timeout:
            results[rtype] = []
            results["_failed"].append(rtype)
    return results

def get_whois_info(domain):
    print(f"\n[+] Fetching WHOIS Registration Data...")
    try:
        w = whois.whois(domain)
        print(f"  -> Registrar: {w.registrar}")
        print(f"  -> Creation Date: {w.creation_date}")
        print(f"  -> Expiration Date: {w.expiration_date}")
        print(f"  -> Name Servers: {w.name_servers}")
    except Exception as e:
        print(f"  -> WHOIS lookup failed: {e}")

def get_http_headers(domain):
    print(f"\n[+] Inspecting HTTP Headers & Security Controls...")
    urls = [f"https://{domain}", f"http://{domain}"]
    for url in urls:
        try:
            response = requests.get(url, timeout=5, allow_redirects=True)
            print(f"  -> Target URL: {url} (Status: {response.status_code})")
            print("  -> Key Headers:")
            for header, value in response.headers.items():
                if header.lower() in ['server', 'x-powered-by', 'strict-transport-security', 'content-security-policy', 'x-frame-options', 'via']:
                    print(f"     {header}: {value}")
            break
        except requests.RequestException:
            continue

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple Domain Footprinting Tool")
    parser.add_argument("domain", help="Target domain name (e.g., example.com)")
    args = parser.parse_args()
    
    print(f"[*] Starting reconnaissance on: {args.domain}")
    records = get_dns_records(args.domain)
    print(records)
    print(check_spf(records))
    print(check_dmarc(args.domain, records))
    print(check_http_headers(args.domain))
    get_whois_info(args.domain)
    get_http_headers(args.domain)
    print("\n[+] Footprinting complete.")