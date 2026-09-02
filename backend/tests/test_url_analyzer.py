import pytest

from backend.app.services.url_analyzer import analyze_url


def test_normalizes_domain_without_scheme() -> None:
    result = analyze_url("example.com")
    assert result["normalized_url"] == "https://example.com"
    assert result["risk_score"] == 0
    assert result["verdict"] == "low_risk"


def test_flags_ip_host_and_insecure_protocol() -> None:
    result = analyze_url("http://192.168.1.10/login/verify")
    signal_names = {signal["name"] for signal in result["signals"]}
    assert "ip_address_host" in signal_names
    assert "insecure_protocol" in signal_names
    assert "suspicious_keywords" in signal_names
    assert result["risk_score"] >= 50


def test_rejects_invalid_url() -> None:
    with pytest.raises(ValueError):
        analyze_url("http://")
