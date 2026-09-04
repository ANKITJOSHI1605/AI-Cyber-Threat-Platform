import base64
import os

import httpx


def lookup_virustotal(url: str) -> dict:
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return {"provider": "VirusTotal", "configured": False, "status": "not_configured", "message": "Add VIRUSTOTAL_API_KEY to enable live reputation data."}
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    try:
        response = httpx.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers={"x-apikey": api_key}, timeout=10)
        if response.status_code == 404:
            return {"provider": "VirusTotal", "configured": True, "status": "unknown", "message": "This URL has not been analyzed by VirusTotal."}
        response.raise_for_status()
        attributes = response.json()["data"]["attributes"]
        stats = attributes.get("last_analysis_stats", {})
        return {"provider": "VirusTotal", "configured": True, "status": "found", "malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0), "harmless": stats.get("harmless", 0), "reputation": attributes.get("reputation", 0), "last_analysis_date": attributes.get("last_analysis_date")}
    except (httpx.HTTPError, KeyError, TypeError, ValueError):
        return {"provider": "VirusTotal", "configured": True, "status": "unavailable", "message": "Threat-intelligence lookup is temporarily unavailable."}
