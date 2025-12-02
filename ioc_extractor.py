import re
from urllib.parse import urlparse

# IOC REGEX PATTERNS
URL_REGEX = r'(https?://[^\s"\']+)'
IP_REGEX = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
EMAIL_REGEX = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
FILE_REGEX = r'([a-zA-Z]:\\[^\s"]+)'
DOMAIN_REGEX = r'\b(?!\d+\.\d+\.\d+\.\d+)([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b'

# Normalization for obfuscated IOC formats
def normalize_ioc(ioc):
    return (
        ioc.replace("[.]", ".")
           .replace("(.)", ".")
           .replace("{.}", ".")
           .replace("hxxp://", "http://")
           .replace("hxxps://", "https://")
           .replace(":///", "://")
    )

def extract_iocs(cmd):
    # Raw pattern matches
    urls_raw = re.findall(URL_REGEX, cmd)
    ips = re.findall(IP_REGEX, cmd)
    emails = re.findall(EMAIL_REGEX, cmd)
    file_paths = re.findall(FILE_REGEX, cmd)

    # Normalize URLs before parsing
    urls = []
    domains = []

    for u in urls_raw:
        clean = normalize_ioc(u)

        try:
            parsed = urlparse(clean)
        except ValueError:
            # Skip anything urlparse can't handle
            continue

        if parsed.scheme and parsed.netloc:
            urls.append(clean)

            host = parsed.hostname
            if host and not re.fullmatch(IP_REGEX, host):
                domains.append(host)

    return type("IOCs", (object,), {
        "urls": urls or None,
        "ips": ips or None,
        "domains": domains or None,
        "emails": emails or None,
        "files": file_paths or None
    })()
