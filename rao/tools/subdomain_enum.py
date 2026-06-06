"""
Subdomain Enumerator - Passive and active subdomain discovery.

Passive sources
---------------
1. crt.sh          — Certificate Transparency logs (primary)
2. HackerTarget    — Free subdomain search API (fallback for crt.sh)
3. AlienVault OTX  — Open Threat Exchange passive DNS (free, no key required)
4. URLScan.io      — Search engine for web scans (free, no key required)
5. RapidDNS        — Fast passive subdomain search (free, no key required)
6. VirusTotal      — Subdomain API (requires VT_API_KEY env var, optional)
7. SecurityTrails  — Subdomain API (requires SECURITYTRAILS_API_KEY, optional)

Active sources
--------------
8. DNS brute-force — ~500-word common subdomain list (threaded)
"""

from __future__ import annotations

import logging
import os
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

logger = logging.getLogger(__name__)

# ── DNS brute-force wordlist (500+ common prefixes) ───────────────────────────

COMMON_SUBDOMAINS = [
    # Generic mail / DNS
    "www", "www1", "www2", "www3",
    "mail", "ftp", "webmail", "smtp", "pop", "pop3", "imap",
    "ns1", "ns2", "ns3", "ns4", "ns5", "ns6", "dns", "dns1", "dns2", "dns3", "dns4",
    "mx", "mx1", "mx2", "relay", "gateway",
    # Admin / internal
    "admin", "administrator", "manage", "manager", "management",
    "portal", "intranet", "internal", "corp", "corp2", "vpn", "remote", "rdp",
    "sso", "auth", "login", "idp", "ldap", "ad", "ad2", "ldap2", "directory",
    "intra", "staff", "employees", "users", "members",
    # Environments
    "dev", "dev1", "dev2", "dev3", "dev4", "development", "devel",
    "staging", "stage", "stg", "staging2", "stage2",
    "uat", "uat2", "qa", "qas", "perf", "performance", "load",
    "test", "test1", "test2", "test3", "test4", "testing", "demo",
    "beta", "preview", "sandbox", "lab", "labs",
    "alpha", "canary", "green", "blue",
    "old", "new", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "legacy",
    "prod", "production", "preprod", "pre-prod", "int", "integration",
    # API / services
    "api", "api1", "api2", "api3", "api4", "api-v1", "api-v2", "api-v3", "api-v4",
    "graphql", "rest", "ws", "websocket", "socket", "rpc",
    "webhook", "hooks", "events",
    "internal-api", "private-api", "partner-api", "test-api", "mock", "stub",
    # App / products
    "app", "app1", "app2", "app3", "apps",
    "mobile", "m", "ios", "android",
    "web", "portal", "dashboard", "panel",
    # Version control / CI-CD
    "git", "gitlab", "github", "bitbucket", "gitea", "gogs", "svn",
    "jenkins", "ci", "cd", "build", "deploy", "actions",
    "circleci", "travis", "drone", "argocd", "bamboo", "teamcity",
    "nexus", "artifactory", "jfrog", "harbor", "quay",
    "sonar", "sonarqube", "sonarcloud", "codecov",
    "registry", "docker", "containers", "k8s", "kubernetes",
    # Monitoring / observability
    "monitor", "monitoring", "metrics", "logs", "logging",
    "grafana", "kibana", "elastic", "elasticsearch", "logstash",
    "prometheus", "alertmanager", "jaeger", "zipkin",
    "sentry", "datadog", "newrelic",
    "zabbix", "nagios", "icinga", "prtg",
    "statsd", "influxdb", "graphite", "loki", "tempo", "victoria", "thanos", "cortex",
    "uptimerobot", "pingdom",
    # Status / health
    "status", "status2", "health", "ping", "alive", "uptime",
    "incident", "maintenance",
    # Databases / storage
    "db", "db1", "db2", "db3", "db4", "database", "mysql", "postgres", "postgresql",
    "redis", "mongo", "mongodb", "cassandra", "kafka", "kafka1", "kafka2", "rabbitmq",
    "minio", "s3", "storage", "backup", "backups", "objectstore",
    "zookeeper", "etcd", "couchdb",
    "nas", "san", "nfs", "smb", "sftp",
    # Search
    "search", "solr", "sphinx", "typesense", "meilisearch",
    # Data / ML / AI
    "data", "data1", "data2", "analytics", "bi", "reporting", "reports",
    "warehouse", "datalake", "etl",
    "hadoop", "spark", "hive", "flink", "airflow", "dbt",
    "snowflake", "redshift", "bigquery", "databricks",
    "ml", "ai", "model", "inference", "notebook", "jupyter", "mlflow", "ray",
    # CDN / static / media
    "cdn", "cdn1", "cdn2", "cdn3", "cdn4",
    "static", "assets", "img", "images",
    "media", "media2", "files", "downloads", "upload", "uploads",
    "live", "stream", "streaming", "rtmp", "hls", "dash", "vod",
    # Email / comms
    "email", "autorespond", "autodiscover", "autodiscover2",
    "owa", "exchange", "webmail", "smtp", "pop", "imap", "mta",
    "lists", "mailman",
    "voice", "voip", "pbx", "sip", "asterisk",
    # Docs / wiki / support
    "docs", "doc", "wiki", "knowledge", "help", "support",
    "blog", "news", "forum", "community", "discuss",
    "jira", "confluence", "notion", "trac", "bugzilla",
    "cms", "wcms", "strapi", "ghost", "wp", "wp2",
    # E-commerce / billing
    "shop", "store", "cart", "checkout",
    "pay", "payment", "billing", "invoice", "accounts",
    # Networking / LB / proxy
    "proxy", "lb", "lb1", "lb2", "lb3", "loadbalancer", "haproxy", "traefik", "nginx",
    "edge", "gateway", "fw", "firewall", "router",
    "f5", "vip", "virtual", "adc", "netscaler",
    "cluster", "node", "node1", "node2", "node3",
    "shard", "replica", "primary", "secondary", "master",
    "nat", "dmz", "vlan",
    # VPN / remote access
    "vpn", "ovpn", "wireguard", "openvpn", "anyconnect",
    "pulse", "globalprotect", "citrix", "rdweb", "rds",
    "bastion", "jump", "jumphost",
    # Security
    "waf", "ids", "ips", "siem", "soc", "noc",
    "security", "pentest", "audit", "scan", "vuln",
    "vault", "pam", "certs", "pki", "ca", "signing",
    # Network management
    "mgmt", "nms", "ops", "syslog", "snmp", "ntp", "dhcp",
    "tftp", "radius", "tacacs", "ipam", "netflow",
    # Auth / IAM
    "keycloak", "okta", "saml", "oauth", "token",
    # Cloud platforms
    "aws", "azure", "gcp", "cloud", "cloud1", "cloud2", "ec2", "bucket",
    # Chat / collaboration
    "chat", "slack", "teams", "teams2", "meet", "video", "zoom",
    "mattermost", "rocketchat",
    # Enterprise apps
    "sap", "oracle", "dynamics", "servicenow",
    "zendesk", "freshdesk", "intercom", "hubspot", "salesforce",
    "workday", "bamboohr", "sharepoint",
    "crm", "erp", "hr", "finance", "legal", "marketing",
    # Messaging / queuing
    "nsq", "nats", "activemq", "pubsub", "queue", "worker", "consumer",
    # File sharing
    "nextcloud", "owncloud", "seafile",
    "transfer", "sync", "sync2", "mirror", "archive", "archives",
    # Regional / geographic
    "us", "us-east", "us-west",
    "eu", "eu-west", "eu-central",
    "ap", "ap-southeast", "ap-northeast",
    "uk", "de", "fr", "es", "it", "jp", "cn", "br", "au", "ca",
    "sg", "in", "mx", "ru", "za",
    "nyc", "lon", "ams", "fra", "tok", "syd", "dub",
    # Business
    "home", "public", "private", "secure", "ssl", "tls",
    "partner", "partners", "vendor", "suppliers",
    "extranet", "client", "clients", "customer", "customers",
    "subscriber", "subscribers", "newsletter",
    "jobs", "careers", "press", "ir", "investor",
    "compliance", "risk", "gdpr", "privacy",
    # Stats / misc
    "stats", "report", "analytics2", "history",
    "cron", "scheduler", "task",
    "hook", "callback", "redirect", "short", "link",
    # IoT
    "iot", "mqtt", "broker", "device", "devices", "sensor", "sensors", "collector",
    # Misc infra
    "gateway2", "noc1", "dnsbl", "nms2",
]


# ── Source implementations ────────────────────────────────────────────────────

class SubdomainEnumerator:
    """Discover subdomains via multiple passive + active methods."""

    REQUEST_TIMEOUT = 15

    def __init__(self, timeout: int = 5, max_workers: int = 30) -> None:
        self.timeout = timeout
        self.max_workers = max_workers
        self._vt_api_key = os.getenv("VT_API_KEY", "")
        self._st_api_key = os.getenv("SECURITYTRAILS_API_KEY", "")

    def enumerate(self, domain: str) -> list[dict]:
        """Discover subdomains for a domain.

        Returns list of dicts: {subdomain, ip, source}.
        Deduplicates by subdomain name; first source wins.
        """
        logger.info("Enumerating subdomains for %s", domain)
        found: dict[str, dict] = {}

        # ── Passive sources (ordered by reliability) ──────────────────────────
        passive_results: list[tuple[str, str]] = []  # (subdomain, source)

        for subdomain, source in self._query_crtsh(domain):
            passive_results.append((subdomain, source))
        for subdomain, source in self._query_otx(domain):
            passive_results.append((subdomain, source))
        for subdomain, source in self._query_urlscan(domain):
            passive_results.append((subdomain, source))
        for subdomain, source in self._query_rapiddns(domain):
            passive_results.append((subdomain, source))
        if self._vt_api_key:
            for subdomain, source in self._query_virustotal(domain):
                passive_results.append((subdomain, source))
        if self._st_api_key:
            for subdomain, source in self._query_securitytrails(domain):
                passive_results.append((subdomain, source))

        # Resolve passively discovered subdomains
        for sub, source in passive_results:
            if sub not in found:
                ip = self._resolve(sub)
                if ip:
                    found[sub] = {"subdomain": sub, "ip": ip, "source": source}

        # ── Active: DNS brute-force ───────────────────────────────────────────
        for sub, ip in self._dns_bruteforce(domain):
            if sub not in found:
                found[sub] = {"subdomain": sub, "ip": ip, "source": "dns-brute"}

        results = list(found.values())
        logger.info("Found %d unique subdomains for %s", len(results), domain)
        return results

    # ── Source: crt.sh ────────────────────────────────────────────────────────

    def _query_crtsh(self, domain: str) -> list[tuple[str, str]]:
        """Certificate Transparency via crt.sh."""
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            resp = requests.get(url, timeout=self.REQUEST_TIMEOUT)
            resp.raise_for_status()
            entries = resp.json()
            subdomains: set[str] = set()
            for entry in entries:
                for line in entry.get("name_value", "").split("\n"):
                    line = line.strip().lower()
                    if (line.endswith(f".{domain}") or line == domain) and not line.startswith("*"):
                        subdomains.add(line)
            logger.info("crt.sh: %d subdomains", len(subdomains))
            return [(s, "crt.sh") for s in subdomains]
        except Exception as e:
            logger.warning("crt.sh failed: %s", e)
            return self._query_hackertarget(domain)

    def _query_hackertarget(self, domain: str) -> list[tuple[str, str]]:
        """HackerTarget fallback."""
        try:
            resp = requests.get(
                f"https://api.hackertarget.com/hostsearch/?q={domain}",
                timeout=self.REQUEST_TIMEOUT,
            )
            resp.raise_for_status()
            results = set()
            for line in resp.text.strip().splitlines():
                if "," in line:
                    sub = line.split(",")[0].strip().lower()
                    if sub.endswith(f".{domain}") or sub == domain:
                        results.add(sub)
            logger.info("HackerTarget: %d subdomains", len(results))
            return [(s, "hackertarget") for s in results]
        except Exception as e:
            logger.warning("HackerTarget also failed: %s", e)
            return []

    # ── Source: AlienVault OTX ────────────────────────────────────────────────

    def _query_otx(self, domain: str) -> list[tuple[str, str]]:
        """AlienVault OTX passive DNS — free, no API key required."""
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
            resp = requests.get(url, timeout=self.REQUEST_TIMEOUT)
            resp.raise_for_status()
            data = resp.json()
            results: set[str] = set()
            for record in data.get("passive_dns", []):
                hostname = record.get("hostname", "").lower().strip()
                if hostname.endswith(f".{domain}") or hostname == domain:
                    results.add(hostname)
            logger.info("OTX: %d subdomains", len(results))
            return [(s, "alienvault-otx") for s in results]
        except Exception as e:
            logger.debug("OTX query failed: %s", e)
            return []

    # ── Source: URLScan.io ────────────────────────────────────────────────────

    def _query_urlscan(self, domain: str) -> list[tuple[str, str]]:
        """URLScan.io search — free, no API key required."""
        try:
            url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=200"
            headers = {"User-Agent": "Mozilla/5.0 (SecurityResearcher)"}
            resp = requests.get(url, headers=headers, timeout=self.REQUEST_TIMEOUT)
            resp.raise_for_status()
            data = resp.json()
            results: set[str] = set()
            for result in data.get("results", []):
                task = result.get("task", {})
                page = result.get("page", {})
                for field in (task.get("domain", ""), page.get("domain", "")):
                    field = field.lower().strip()
                    if field.endswith(f".{domain}") or field == domain:
                        results.add(field)
            logger.info("URLScan.io: %d subdomains", len(results))
            return [(s, "urlscan.io") for s in results]
        except Exception as e:
            logger.debug("URLScan.io query failed: %s", e)
            return []

    # ── Source: RapidDNS ──────────────────────────────────────────────────────

    def _query_rapiddns(self, domain: str) -> list[tuple[str, str]]:
        """RapidDNS subdomain search — free, no API key required."""
        try:
            url = f"https://rapiddns.io/subdomain/{domain}?full=1"
            headers = {"User-Agent": "Mozilla/5.0 (SecurityResearcher)"}
            resp = requests.get(url, headers=headers, timeout=self.REQUEST_TIMEOUT)
            resp.raise_for_status()
            import re
            matches = re.findall(r'href="/subdomain/([^"]+)"', resp.text)
            results: set[str] = set()
            for match in matches:
                sub = match.lower().strip()
                if sub.endswith(f".{domain}") or sub == domain:
                    results.add(sub)
            logger.info("RapidDNS: %d subdomains", len(results))
            return [(s, "rapiddns") for s in results]
        except Exception as e:
            logger.debug("RapidDNS query failed: %s", e)
            return []

    # ── Source: VirusTotal (optional — requires VT_API_KEY) ──────────────────

    def _query_virustotal(self, domain: str) -> list[tuple[str, str]]:
        """VirusTotal subdomain API — requires VT_API_KEY env var."""
        if not self._vt_api_key:
            return []
        try:
            url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
            headers = {"x-apikey": self._vt_api_key}
            results: set[str] = set()
            cursor = None
            for _ in range(3):  # max 3 pages = 300 results
                params: dict = {"limit": 100}
                if cursor:
                    params["cursor"] = cursor
                resp = requests.get(url, headers=headers, params=params, timeout=self.REQUEST_TIMEOUT)
                resp.raise_for_status()
                data = resp.json()
                for item in data.get("data", []):
                    sub = item.get("id", "").lower()
                    if sub:
                        results.add(sub)
                cursor = data.get("meta", {}).get("cursor")
                if not cursor:
                    break
            logger.info("VirusTotal: %d subdomains", len(results))
            return [(s, "virustotal") for s in results]
        except Exception as e:
            logger.debug("VirusTotal query failed: %s", e)
            return []

    # ── Source: SecurityTrails (optional — requires SECURITYTRAILS_API_KEY) ───

    def _query_securitytrails(self, domain: str) -> list[tuple[str, str]]:
        """SecurityTrails subdomain API — requires SECURITYTRAILS_API_KEY env var."""
        if not self._st_api_key:
            return []
        try:
            url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
            headers = {"apikey": self._st_api_key, "Accept": "application/json"}
            resp = requests.get(url, headers=headers, timeout=self.REQUEST_TIMEOUT)
            resp.raise_for_status()
            data = resp.json()
            subs = [f"{sub}.{domain}" for sub in data.get("subdomains", [])]
            logger.info("SecurityTrails: %d subdomains", len(subs))
            return [(s, "securitytrails") for s in subs]
        except Exception as e:
            logger.debug("SecurityTrails query failed: %s", e)
            return []

    # ── Active: DNS brute-force ───────────────────────────────────────────────

    def _dns_bruteforce(self, domain: str) -> list[tuple[str, str]]:
        """Resolve common subdomain names via DNS (threaded)."""
        results = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {}
            for prefix in COMMON_SUBDOMAINS:
                fqdn = f"{prefix}.{domain}"
                futures[executor.submit(self._resolve, fqdn)] = fqdn

            for future in as_completed(futures):
                fqdn = futures[future]
                try:
                    ip = future.result()
                    if ip:
                        results.append((fqdn, ip))
                except Exception:
                    continue

        return results

    def _resolve(self, hostname: str) -> str | None:
        """Resolve hostname to IP address with explicit timeout (BUG #24 fix)."""
        old_timeout = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(self.timeout)
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            return None
        finally:
            socket.setdefaulttimeout(old_timeout)
