import argparse
import dns.resolver
import whois
import requests

def get_dns_records(domain):
    print(f"\n[+] Gathering DNS Records for {domain}...")
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT']
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            print(f"  -> {rtype} Records:")
            for rdata in answers:
                print(f"     {rdata}")
        except Exception:
            print(f"  -> {rtype} Records: None found")

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
    get_dns_records(args.domain)
    get_whois_info(args.domain)
    get_http_headers(args.domain)
    print("\n[+] Footprinting complete.")