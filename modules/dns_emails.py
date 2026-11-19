import dns.exception
import dns.resolver
from modules.utils import finding, resolve_with_fallback

RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT']

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

def lookup_txt(name):
    try:
        answers = resolve_with_fallback(name, 'TXT')
        return [str(r).strip('"') for r in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []
    except dns.exception.Timeout:
        return None

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
    elif not spf.endswith("-all"):
        findings.append(finding("SPF has no all mechanism", "Low",
                                "SPF does not end with an all qualifier, policy may be incomplete", "email"))

    return findings

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
    elif policy != "reject":
        findings.append(finding("Invalid DMARC policy", "Medium",
                                "DMARC record has missing or unknown p tag, so it is not implemented", "email"))

    if "rua" not in tags:
        findings.append(finding("No DMARC reporting address", "Low",
                                "DMARC has no rua tag, domain owner will not receive reports", "email"))

    return findings