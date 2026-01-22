from urllib.parse import urlparse
import re

SUSPICIOUS_TLDS = [".ru", ".tk", ".cn", ".xyz"]
MAX_URL_LENGTH = 75
MAX_SUBDOMAINS = 3

def analyze_url(url):
    reasons = []

    parsed = urlparse(url)

    if re.match(r"^\d+\.\d+\.\d+\.\d+$", parsed.netloc):
        reasons.append("Uses IP address instead of domain")

    if len(url) > MAX_URL_LENGTH:
        reasons.append("Unusually long URL")

    domain_parts = parsed.netloc.split(".")
    if len(domain_parts) - 2 > MAX_SUBDOMAINS:
        reasons.append("Excessive subdomains")

    for tld in SUSPICIOUS_TLDS:
        if parsed.netloc.endswith(tld):
            reasons.append("Suspicious top-level domain")

    if "@" in url:
        reasons.append("Contains '@' symbol (URL redirection trick)")

    return reasons
