"""
Web Scanner - HTTP reconnaissance and security header analysis.

Checks:
    - Security headers (CSP, HSTS, X-Frame-Options, etc.)
    - Technology fingerprinting (Server, X-Powered-By, cookies)
    - Common sensitive paths discovery
    - SSL/TLS basic checks
    - CORS misconfiguration detection
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from urllib.parse import urljoin

import requests
from requests.exceptions import ConnectionError, Timeout

logger = logging.getLogger(__name__)

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "medium",
        "description": "HSTS header missing - vulnerable to SSL stripping attacks",
    },
    "Content-Security-Policy": {
        "severity": "medium",
        "description": "CSP header missing - increased XSS risk",
    },
    "X-Content-Type-Options": {
        "severity": "low",
        "description": "X-Content-Type-Options missing - MIME sniffing possible",
    },
    "X-Frame-Options": {
        "severity": "medium",
        "description": "X-Frame-Options missing - clickjacking possible",
    },
    "X-XSS-Protection": {
        "severity": "low",
        "description": "X-XSS-Protection missing (legacy but still relevant)",
    },
    "Referrer-Policy": {
        "severity": "low",
        "description": "Referrer-Policy missing - referrer information may leak",
    },
    "Permissions-Policy": {
        "severity": "low",
        "description": "Permissions-Policy missing - browser features not restricted",
    },
}

SENSITIVE_PATHS = [
    "/.env",
    "/.git/HEAD",
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/wp-login.php",
    "/admin",
    "/administrator",
    "/.DS_Store",
    "/server-status",
    "/server-info",
    "/phpinfo.php",
    "/api/docs",
    "/swagger.json",
    "/graphql",
    "/.htaccess",
    "/backup.sql",
    "/debug",
    "/console",
    "/elmah.axd",
]


@dataclass
class WebScanResult:
    url: str
    status_code: int = 0
    server: str = ""
    technologies: list[str] = field(default_factory=list)
    missing_headers: list[dict] = field(default_factory=list)
    exposed_paths: list[dict] = field(default_factory=list)
    cors_issues: list[str] = field(default_factory=list)
    cookies_issues: list[dict] = field(default_factory=list)
    info_leaks: list[str] = field(default_factory=list)


class WebScanner:
    """HTTP-level reconnaissance and security assessment."""

    def __init__(self, timeout: int = 10) -> None:
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(
            {"User-Agent": "RAO-Framework/0.1 (Security Assessment)"}
        )
        self.session.verify = False  # Allow self-signed certs in lab envs
        # Suppress InsecureRequestWarning for lab environments
        requests.packages.urllib3.disable_warnings(
            requests.packages.urllib3.exceptions.InsecureRequestWarning
        )

    def scan(self, target: str) -> WebScanResult | None:
        """Full web scan against an HTTP target."""
        url = self._normalize_url(target)
        logger.info("Web scanning %s", url)

        try:
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
        except (ConnectionError, Timeout) as e:
            logger.warning("Cannot reach %s: %s", url, e)
            return None

        result = WebScanResult(url=url, status_code=resp.status_code)

        self._check_server_header(resp, result)
        self._fingerprint_technologies(resp, result)
        self._check_security_headers(resp, result)
        self._check_cors(url, result)
        self._check_cookies(resp, result)
        self._enumerate_paths(url, result)
        self._check_info_leaks(resp, result)

        return result

    def _normalize_url(self, target: str) -> str:
        if target.startswith(("http://", "https://")):
            return target
        return f"https://{target}"

    def _check_server_header(self, resp: requests.Response, result: WebScanResult) -> None:
        server = resp.headers.get("Server", "")
        if server:
            result.server = server
            result.info_leaks.append(f"Server header exposes: {server}")

        powered_by = resp.headers.get("X-Powered-By", "")
        if powered_by:
            result.info_leaks.append(f"X-Powered-By exposes: {powered_by}")

    def _fingerprint_technologies(
        self, resp: requests.Response, result: WebScanResult
    ) -> None:
        headers = resp.headers
        body = resp.text[:5000].lower()

        # Header-based detection
        if "X-Powered-By" in headers:
            result.technologies.append(headers["X-Powered-By"])
        if "X-AspNet-Version" in headers:
            result.technologies.append(f"ASP.NET {headers['X-AspNet-Version']}")
        if "Server" in headers:
            result.technologies.append(headers["Server"])

        # Body-based detection
        tech_signatures = {
            "wp-content": "WordPress",
            "drupal": "Drupal",
            "joomla": "Joomla",
            "laravel": "Laravel",
            "next.js": "Next.js",
            "react": "React",
            "vue.js": "Vue.js",
            "angular": "Angular",
            "django": "Django",
            "flask": "Flask",
            "express": "Express.js",
            "spring": "Spring",
        }
        for sig, tech in tech_signatures.items():
            if sig in body:
                result.technologies.append(tech)

        result.technologies = list(set(result.technologies))

    def _check_security_headers(
        self, resp: requests.Response, result: WebScanResult
    ) -> None:
        for header, info in SECURITY_HEADERS.items():
            if header not in resp.headers:
                result.missing_headers.append(
                    {
                        "header": header,
                        "severity": info["severity"],
                        "description": info["description"],
                    }
                )

    def _check_cors(self, url: str, result: WebScanResult) -> None:
        """Check for CORS misconfiguration."""
        try:
            evil_origin = "https://evil.attacker.com"
            resp = self.session.get(
                url,
                headers={"Origin": evil_origin},
                timeout=self.timeout,
            )
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            if acao == "*":
                result.cors_issues.append(
                    "CORS allows any origin (Access-Control-Allow-Origin: *)"
                )
            elif evil_origin in acao:
                result.cors_issues.append(
                    f"CORS reflects arbitrary origin: {evil_origin}"
                )

            if resp.headers.get("Access-Control-Allow-Credentials") == "true" and acao:
                result.cors_issues.append(
                    "CORS allows credentials with permissive origin - high risk"
                )
        except Exception:
            pass

    def _check_cookies(self, resp: requests.Response, result: WebScanResult) -> None:
        """Check cookie security flags."""
        for cookie in resp.cookies:
            issues = []
            if not cookie.secure:
                issues.append("missing Secure flag")
            if not cookie.has_nonstandard_attr("HttpOnly"):
                issues.append("missing HttpOnly flag")
            raw_header = resp.headers.get("Set-Cookie", "")
            if "samesite" not in raw_header.lower():
                issues.append("missing SameSite attribute")

            if issues:
                result.cookies_issues.append(
                    {"name": cookie.name, "issues": issues}
                )

    def _enumerate_paths(self, base_url: str, result: WebScanResult) -> None:
        """Check for common sensitive paths."""
        for path in SENSITIVE_PATHS:
            try:
                url = urljoin(base_url, path)
                resp = self.session.get(
                    url, timeout=self.timeout, allow_redirects=False
                )
                if resp.status_code in (200, 403):
                    size = len(resp.content)
                    result.exposed_paths.append(
                        {
                            "path": path,
                            "status": resp.status_code,
                            "size": size,
                        }
                    )
                    logger.info("Found: %s [%d] (%d bytes)", path, resp.status_code, size)
            except Exception:
                continue

    def _check_info_leaks(self, resp: requests.Response, result: WebScanResult) -> None:
        """Check response for common information leakage patterns."""
        body = resp.text[:10000]

        leak_patterns = [
            ("stack trace", "Stack trace detected in response body"),
            ("traceback", "Python traceback exposed"),
            ("sql syntax", "SQL error message exposed"),
            ("fatal error", "Fatal error message exposed"),
            ("debug mode", "Debug mode appears enabled"),
            ("internal server error", "Internal server error details exposed"),
        ]

        for pattern, description in leak_patterns:
            if pattern in body.lower():
                result.info_leaks.append(description)
