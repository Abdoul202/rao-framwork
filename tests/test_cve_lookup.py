"""Tests for CVE lookup parsing."""

from rao.tools.cve_lookup import CVELookup


def test_parse_empty_response():
    lookup = CVELookup()
    result = lookup._parse_response({"vulnerabilities": []})
    assert result == []


def test_parse_response_with_cve():
    lookup = CVELookup()
    data = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-0001",
                    "descriptions": [
                        {"lang": "en", "value": "Test vulnerability description"}
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseScore": 9.8,
                                    "baseSeverity": "CRITICAL",
                                }
                            }
                        ]
                    },
                }
            }
        ]
    }

    result = lookup._parse_response(data)
    assert len(result) == 1
    assert result[0]["id"] == "CVE-2024-0001"
    assert result[0]["severity"] == "critical"
    assert result[0]["score"] == 9.8


def test_extract_cvss_fallback():
    severity, score = CVELookup._extract_cvss({"metrics": {}})
    assert severity == "medium"
    assert score == 0.0
