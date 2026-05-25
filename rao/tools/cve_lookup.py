"""CVE lookup via the NVD (National Vulnerability Database) API."""

from __future__ import annotations

import logging
import time

import requests

from rao.config import settings

logger = logging.getLogger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class CVELookup:
    """Query NVD for CVEs matching a keyword (service name + version)."""

    def __init__(self) -> None:
        self.api_key = settings.nvd_api_key
        self._last_request_time = 0.0
        # NVD rate limit: 5 req/30s without key, 50 req/30s with key
        self._min_interval = 0.6 if self.api_key else 6.0
        # Local cache to survive NVD outages
        from rao.tools.cve_cache import CVECache
        self._cache = CVECache()

    def search(self, keyword: str, max_results: int = 10) -> list[dict]:
        """
        Search NVD for CVEs matching the keyword.

        Returns list of dicts with keys: id, description, severity, score.
        Results are cached locally for 7 days to survive API outages.
        """
        # Check local cache first
        cached = self._cache.get(keyword)
        if cached is not None:
            return cached

        self._rate_limit()

        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        params = {
            "keywordSearch": keyword,
            "resultsPerPage": max_results,
        }

        try:
            resp = requests.get(
                NVD_API_URL, params=params, headers=headers, timeout=30
            )
            resp.raise_for_status()
            data = resp.json()
        except requests.RequestException as e:
            logger.warning("NVD API request failed for '%s': %s", keyword, e)
            return []

        results = self._parse_response(data)
        # Store in cache for future offline use
        self._cache.set(keyword, results)
        return results

    def _parse_response(self, data: dict) -> list[dict]:
        """Extract relevant fields from the NVD API response."""
        results = []
        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "UNKNOWN")

            descriptions = cve.get("descriptions", [])
            description = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"),
                "No description available",
            )

            severity, score = self._extract_cvss(cve)

            results.append(
                {
                    "id": cve_id,
                    "description": description,
                    "severity": severity,
                    "score": score,
                }
            )
        return results

    @staticmethod
    def _extract_cvss(cve: dict) -> tuple[str, float]:
        """Extract CVSS severity and score from CVE metrics."""
        metrics = cve.get("metrics", {})

        # Try CVSS v3.1 first, then v3.0, then v2.0
        for version_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(version_key, [])
            if metric_list:
                cvss = metric_list[0].get("cvssData", {})
                score = cvss.get("baseScore", 0.0)
                severity = cvss.get("baseSeverity", "MEDIUM")
                return severity.lower(), score

        return "medium", 0.0

    def _rate_limit(self) -> None:
        """Enforce NVD rate limiting."""
        elapsed = time.time() - self._last_request_time
        if elapsed < self._min_interval:
            time.sleep(self._min_interval - elapsed)
        self._last_request_time = time.time()
