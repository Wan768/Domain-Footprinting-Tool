import re
from datetime import datetime, timezone
import requests
import whois
from modules.utils import USER_AGENT, finding

EXPECTED_HEADERS = {
    "strict-transport-security": ("Missing HSTS", "Medium"),
    "content-security-policy": ("Missing CSP", "Medium"),
    "x-frame-options": ("Missing X-Frame-Options", "Low"),
    "x-content-type-options": ("Missing X-Content-Type-Options", "Low"),
}

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
    # Standardize WHOIS dates that lack timezone info
    if d.tzinfo is None:
        return d.replace(tzinfo=timezone.utc)
    return d

def pick_date(value, pick):
    # python-whois may return a list of dates, a single datetime, or None
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