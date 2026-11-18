import argparse
import whois
import requests
import dns.exception
import dns.resolver

RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT']

PUBLIC_RESOLVERS = ['8.8.8.8', '1.1.1.1']

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
        pass  # strict policy, this is the correct configuration
    else:
        findings.append(finding("SPF has no all mechanism", "Low",
                                "SPF does not end with an all qualifier, policy may be incomplete", "email"))

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
    get_whois_info(args.domain)
    get_http_headers(args.domain)
    print("\n[+] Footprinting complete.")