import re
import dns.exception
import dns.resolver

PUBLIC_RESOLVERS = ['8.8.8.8', '1.1.1.1']
USER_AGENT = "FootPrinter/1.0 (authorized-scan)"
LABEL_PATTERN = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)")

def finding(title, severity, detail, category):
    return {
        "title": title,
        "severity": severity,
        "detail": detail,
        "category": category
    }

def validate_domain(domain):
    domain = domain.strip().lower().rstrip(".")
    if not domain or len(domain) > 253:
        raise ValueError("Domain is empty or too long")
    for label in domain.split("."):
        if not LABEL_PATTERN.fullmatch(label):
            raise ValueError(f"Invalid domain name: {domain}")
    return domain

def make_resolver(nameservers=None):
    resolver = dns.resolver.Resolver()
    if nameservers:
        resolver.nameservers = nameservers
    resolver.lifetime = 5
    return resolver

def resolve_with_fallback(name, rtype):
    system_resolver = make_resolver()
    public_resolver = make_resolver(PUBLIC_RESOLVERS)
    try:
        return system_resolver.resolve(name, rtype)
    except dns.exception.Timeout:
        return public_resolver.resolve(name, rtype)