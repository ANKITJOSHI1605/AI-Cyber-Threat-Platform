import ipaddress
import re
from urllib.parse import urlparse


SUSPICIOUS_KEYWORDS = {
    "account", "confirm", "login", "password", "secure", "signin",
    "suspend", "update", "verification", "verify", "wallet",
}

SHORTENER_HOSTS = {
    "bit.ly", "cutt.ly", "goo.gl", "is.gd", "ow.ly", "rebrand.ly",
    "shorturl.at", "t.co", "tinyurl.com",
}


def _is_ip_address(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _normalize_url(raw_url: str) -> str:
    value = raw_url.strip()
    if not value:
        raise ValueError("URL cannot be empty.")
    if "://" not in value:
        value = f"https://{value}"

    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Enter a valid HTTP or HTTPS URL.")
    return value


def analyze_url(raw_url: str) -> dict:
    normalized_url = _normalize_url(raw_url)
    parsed = urlparse(normalized_url)
    hostname = (parsed.hostname or "").lower()
    host_is_ip = _is_ip_address(hostname)
    labels = hostname.split(".")
    subdomain_count = max(0, len(labels) - 2) if not host_is_ip else 0
    lowered_url = normalized_url.lower()
    digit_count = sum(character.isdigit() for character in normalized_url)
    special_character_count = len(re.findall(r"[^a-zA-Z0-9]", normalized_url))

    signals: list[dict] = []

    def add_signal(name: str, weight: int, description: str) -> None:
        signals.append({"name": name, "weight": weight, "description": description})

    if parsed.scheme != "https":
        add_signal("insecure_protocol", 15, "The URL uses HTTP instead of HTTPS.")
    if host_is_ip:
        add_signal("ip_address_host", 30, "The hostname is a raw IP address.")
    if "xn--" in hostname:
        add_signal("punycode_domain", 25, "The domain contains punycode and may imitate another name.")
    if hostname in SHORTENER_HOSTS:
        add_signal("url_shortener", 20, "A URL shortener hides the final destination.")
    if "@" in normalized_url:
        add_signal("at_symbol", 20, "The URL contains an @ symbol that can obscure its destination.")
    if subdomain_count >= 3:
        add_signal("excessive_subdomains", 15, "The hostname contains many nested subdomains.")
    if len(normalized_url) > 100:
        add_signal("long_url", 10, "The URL is unusually long.")
    if parsed.port and parsed.port not in {80, 443}:
        add_signal("unusual_port", 15, "The URL uses a non-standard web port.")

    matched_keywords = sorted(keyword for keyword in SUSPICIOUS_KEYWORDS if keyword in lowered_url)
    if matched_keywords:
        weight = min(25, 5 * len(matched_keywords))
        add_signal(
            "suspicious_keywords",
            weight,
            f"Sensitive terms detected: {', '.join(matched_keywords)}.",
        )

    risk_score = min(100, sum(signal["weight"] for signal in signals))
    verdict = "malicious" if risk_score >= 70 else "suspicious" if risk_score >= 30 else "low_risk"

    return {
        "normalized_url": normalized_url,
        "verdict": verdict,
        "risk_score": risk_score,
        "signals": signals,
        "features": {
            "length": len(normalized_url),
            "subdomain_count": subdomain_count,
            "digit_count": digit_count,
            "special_character_count": special_character_count,
            "uses_https": parsed.scheme == "https",
            "host_is_ip": host_is_ip,
        },
    }
