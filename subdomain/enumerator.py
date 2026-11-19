import time
import uuid
import dns.exception
import dns.resolver
import requests

from dns_email.analyzer import finding, resolve_with_fallback, validate_domain

USER_AGENT = "FootPrinter/1.0 (authorized-scan)"

DEFAULT_WORDLIST = ["www", "mail", "dev", "test", "api", "admin", "ftp",
                    "staging", "blog", "portal", "vpn", "shop", "support",
                    "app", "cdn", "ns1", "ns2", "smtp", "webmail", "m"]

def fetch_crtsh(domain, timeout=15):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        response = requests.get(url, timeout=timeout,
                                headers={"User-Agent": USER_AGENT})
        response.raise_for_status()
        entries = response.json()
    except (requests.RequestException, ValueError):
        return None 

    names = set()
    for entry in entries:
        for name in entry.get("name_value", "").split("\n"):
            name = name.strip().lower().removeprefix("*.")
            if name == domain or name.endswith(f".{domain}"):
                names.add(name)
    return names

def resolves(name):
    # True = ada A record, False = tiada, None = lookup gagal
    try:
        resolve_with_fallback(name, "A")
        return True
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return False
    except (dns.exception.Timeout, dns.resolver.NoNameservers):
        return None


def has_wildcard(domain):
    label = uuid.uuid4().hex[:12]
    return resolves(f"{label}.{domain}") is True
    pass


def brute_force(domain, wordlist=DEFAULT_WORDLIST, delay=0.5):
    if has_wildcard(domain):
        return set(), True  

    found = set()
    for word in wordlist:
        name = f"{word}.{domain}"
        if resolves(name):
            found.add(name)
        time.sleep(delay)
    return found, False

if __name__ == "__main__":
    import sys
    target = validate_domain(sys.argv[1] if len(sys.argv) > 1 else "example.com")
    print("crt.sh:", sorted(fetch_crtsh(target) or []))
    print("wildcard:", has_wildcard(target))
    print("brute:", brute_force(target, delay=0.2))