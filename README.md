# Domain-Footprinting-Tool

`git clone https://github.com/Wan768/Domain-Footprinting-Tool.git`


`cd Domain-Footprinting-Tool`


`pip install -r requirements.txt`


to run the code: `python main.py example.com`

## Ethical Considerations

This tool is built with defensive guardrails and safe-by-design principles to minimize risk during security assessments:
* **Explicit Authorization Gate:** On startup, the tool displays a legal warning banner and requires explicit user confirmation (`y`) before any network activity begins.
* **Safe Defaults & Dry-Run Mode:** If no target domain is provided, the tool defaults safely to `example.com`. Users can also pass `--dry-run` to preview all planned reconnaissance steps without sending a single network packet.
* **Rate Limiting (`--delay`):** Configurable delays (defaulting to `1.0` second between stages and `0.5` seconds during subdomain checks) prevent request flooding, service disruption, or accidental Denial-of-Service (DoS).
* **Local-Only Data Handling:** All collected reconnaissance data and security findings are stored strictly locally in the `Scan_output/` directory (`<domain-name>_footprint_<timestamp>.json`) with clear labeling, and are excluded from version control via `.gitignore`. No data is transmitted to external third-party servers.
* **Clean Kill Switch:** Pressing `Ctrl+C` (`KeyboardInterrupt`) immediately halts execution and exits cleanly without leaving hanging processes.

---

## Rules of Engagement (RoE)

Any operator using this tool must strictly adhere to the following Rules of Engagement:
* **Authorized Scope:** Testing must only be conducted against domains, subdomains, and infrastructure explicitly owned by the operator or covered under a signed, written authorization agreement.
* **Time Windows:** Active reconnaissance (such as DNS subdomain brute-forcing and HTTP header requests) should be performed during agreed-upon testing windows or off-peak hours to avoid interfering with production traffic.
* **Permitted Techniques:** Passive OSINT queries (public DNS records, WHOIS lookups, and Certificate Transparency logs via `crt.sh`) and low-rate, non-intrusive HTTP `GET` header inspections.
* **Prohibited Actions:** Exploitation of discovered vulnerabilities, brute-forcing credentials, aggressive high-speed flooding (`--delay 0` against unauthorized targets), or modifying target systems.
* **Emergency Stop Procedures:** If anomalous behavior, rate-limit warnings, or service instability occurs, the operator must immediately press `Ctrl+C` to trigger the tool's built-in kill switch and halt all network requests.

---

## Responsible Disclosure

If this tool uncovers security misconfigurations (such as missing SPF/DMARC policies allowing email spoofing, missing HSTS/CSP headers, or exposed staging/admin subdomains) on an authorized target, operators must follow responsible disclosure practices:
* **Who to Report To:** Report findings directly to the target organization's designated security team.
* **When to Report:** Disclose high-severity findings (such as absent SPF/DMARC records or expired domains) promptly upon verification, allowing the organization a reasonable remediation window (typically 30–90 days) before any public discussion.
* **How to Report:** Provide a clear, confidential, and reproducible technical summary containing the affected domain/subdomain, the specific misconfiguration observed, potential security impact, and actionable remediation steps—without including sensitive or exfiltrated data.

---

## Legal Disclaimer

 **WARNING:** This tool is developed strictly for educational purposes, academic research, and authorized security auditing. 

Unauthorized scanning, enumeration, or probing of computer systems and networks without explicit prior written permission from the asset owner is illegal under the **Computer Crimes Act 1997 (Malaysia)** and applicable local and international cybersecurity laws. The authors and contributors assume no liability and are not responsible for any misuse, unauthorized activity, or damage caused by this software. By running this tool, you accept full legal responsibility for ensuring your actions remain within authorized boundaries.

---

## Limitations

* **Small Built-In Subdomain Wordlist:** The active brute-force module uses a compact 20-word list of common subdomains (`www`, `mail`, `dev`, `admin`, etc.) to stay fast and non-intrusive, meaning uncommon or custom subdomain names may not be detected unless discovered via `crt.sh`.
* **Wildcard DNS Suppression:** When a target domain configures wildcard DNS (`*.domain.com`), the tool intentionally skips active brute-force results to avoid false positives, relying solely on passive Certificate Transparency data.
* **Third-Party Rate Limits & Availability:** Passive subdomain discovery depends on the availability and response time of `crt.sh`, while WHOIS lookups may occasionally return incomplete dates or face rate limits depending on the domain registrar's WHOIS server.
* **Passive / Header-Level Analysis Only:** This tool performs non-intrusive reconnaissance and configuration auditing only; it does not perform deep port scanning, service exploitation, or authenticated web vulnerability testing.
