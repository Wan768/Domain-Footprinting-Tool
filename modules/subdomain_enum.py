import time
import uuid
import dns.exception
import dns.resolver
import requests
from modules.utils import USER_AGENT, finding, resolve_with_fallback, validate_domain

DEFAULT_WORDLIST = [
    "www", "mail", "dev", "test", "api", "admin", "ftp",
    "staging", "blog", "portal", "vpn", "shop", "support",
    "app", "cdn", "ns1", "ns2", "smtp", "webmail", "m"
]

def fetch_crtsh(domain, timeout=15):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        response = requests.get(url, timeout=timeout, headers={"User-Agent": USER_AGENT})
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

def enumerate_subdomains(domain, delay=0.5, dry_run=False, wordlist=DEFAULT_WORDLIST):
    domain = validate_domain(domain)
    result = {"subdomains": [], "findings": []}

    if dry_run:
        print(f"[DRY RUN] Would query crt.sh for {domain}")
        print(f"[DRY RUN] Would check wildcard DNS for {domain}")
        print(f"[DRY RUN] Would try {len(wordlist)} wordlist names under {domain}")
        return result

    passive = fetch_crtsh(domain)
    if passive is None:
        result["findings"].append(finding("crt.sh lookup failed", "Info",
                                          "Could not reach crt.sh, passive results are missing", "subdomain"))
        passive = set()

    time.sleep(delay)
    active, wildcard = brute_force(domain, wordlist=wordlist, delay=delay)
    if wildcard:
        result["findings"].append(finding("Wildcard DNS detected", "Info",
                                          "Any subdomain resolves, brute-force results were skipped", "subdomain"))

    for name in sorted(passive | active):
        if name in passive and name in active:
            source = "passive and active"
        elif name in passive:
            source = "crt.sh"
        else:
            source = "bruteforce"
        result["subdomains"].append({"name": name, "source": source})
    return result