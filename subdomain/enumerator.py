import requests

USER_AGENT = "FootPrinter/1.0 (authorized-scan)"


def fetch_crtsh(domain, timeout=15):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        response = requests.get(url, timeout=timeout,
                                headers={"User-Agent": USER_AGENT})
        response.raise_for_status()
        entries = response.json()
    except (requests.RequestException, ValueError):
        return None  # None = lookup gagal, bukan "tiada subdomain"

    names = set()
    for entry in entries:
        for name in entry.get("name_value", "").split("\n"):
            name = name.strip().lower().removeprefix("*.")
            if name == domain or name.endswith(f".{domain}"):
                names.add(name)
    return names


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    print(fetch_crtsh(target))