import math
import re


URGENCY_TERMS = {"urgent", "immediately", "expire", "suspended", "verify now", "act now"}
CREDENTIAL_TERMS = {"password", "login", "sign in", "credentials", "account verification"}
FINANCIAL_TERMS = {"payment", "invoice", "bank", "refund", "gift card", "wire transfer"}
THREAT_TERMS = {"blocked", "closed", "legal action", "penalty", "unauthorized"}


def _verdict(score: int) -> str:
    return "malicious" if score >= 70 else "suspicious" if score >= 30 else "low_risk"


def analyze_email(text: str, sender: str | None = None) -> dict:
    content = text.strip()
    if len(content) < 10:
        raise ValueError("Email content must contain at least 10 characters.")

    lowered = content.lower()
    signals = []

    def detect(name: str, terms: set[str], weight: int, description: str) -> int:
        matches = sorted(term for term in terms if term in lowered)
        if matches:
            signals.append({"name": name, "weight": weight, "description": f"{description}: {', '.join(matches)}."})
        return int(bool(matches))

    urgency = detect("urgency_language", URGENCY_TERMS, 18, "Urgent language detected")
    credentials = detect("credential_request", CREDENTIAL_TERMS, 25, "Credential-related language detected")
    financial = detect("financial_request", FINANCIAL_TERMS, 18, "Financial language detected")
    threats = detect("pressure_or_threat", THREAT_TERMS, 16, "Pressure language detected")
    links = len(re.findall(r"https?://|www\.", lowered))
    if links:
        signals.append({"name": "embedded_links", "weight": min(18, links * 9), "description": f"The message contains {links} web link(s)."})

    sender_mismatch = bool(sender and re.search(r"@(gmail|outlook|yahoo|protonmail)\.", sender.lower()) and (financial or credentials))
    if sender_mismatch:
        signals.append({"name": "consumer_email_sender", "weight": 15, "description": "A sensitive request comes from a consumer email domain."})

    # Explainable logistic baseline. Coefficients can be retrained as labelled data grows.
    logit = -3.1 + 1.25 * urgency + 1.65 * credentials + 1.1 * financial + 1.0 * threats + 0.55 * min(links, 3) + 0.9 * sender_mismatch
    probability = 1 / (1 + math.exp(-logit))
    score = min(100, round(probability * 100))
    return {
        "analysis_type": "email",
        "verdict": _verdict(score),
        "risk_score": score,
        "signals": signals,
        "features": {"urgency": urgency, "credentials": credentials, "financial": financial, "threats": threats, "links": links, "sender_mismatch": sender_mismatch},
        "summary": "Potential phishing language detected." if score >= 30 else "No strong phishing indicators detected.",
    }


def analyze_network_event(event: dict) -> dict:
    failed = event["failed_login_count"]
    rate = event["requests_per_minute"]
    outbound = event["bytes_out"]
    hour = event["hour"]
    signals = []

    def add(condition: bool, name: str, weight: int, description: str) -> None:
        if condition:
            signals.append({"name": name, "weight": weight, "description": description})

    add(failed >= 5, "repeated_login_failures", min(35, failed * 3), f"{failed} failed login attempts were observed.")
    add(rate >= 120, "request_rate_spike", min(30, rate // 10), f"Traffic reached {rate} requests per minute.")
    add(outbound >= 50_000_000, "large_data_transfer", 25, "Outbound transfer exceeded 50 MB.")
    add(hour < 6 or hour >= 23, "off_hours_activity", 12, "Activity occurred outside normal working hours.")
    add(event["is_new_country"], "new_country", 20, "The source country has not been observed before.")
    add(event["privileged_action"], "privileged_action", 18, "The event performed a privileged operation.")
    score = min(100, sum(signal["weight"] for signal in signals))
    return {
        "analysis_type": "network",
        "verdict": _verdict(score),
        "risk_score": score,
        "signals": signals,
        "features": event,
        "summary": "Network anomaly requires investigation." if score >= 30 else "Network event is within the baseline.",
    }
