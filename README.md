# RAO-Framework

**Multi-Agent Autonomous Red Teaming System** — v0.5.0

RAO-Framework automates the offensive security assessment pipeline using coordinated AI agents. Each agent handles a specialized phase of a penetration test, from reconnaissance to validation, orchestrated by a central command system.

> **Disclaimer**: This tool is designed for authorized security testing, CTF challenges, and educational purposes only. Always obtain explicit written permission before testing any system.

## Architecture

```
┌──────────────────────────────────────────────────────┐
│               OCC (Orchestrator)                     │
│            LangGraph State Machine                   │
├──────┬──────────┬──────────┬──────────┬──────────────┤
│      │          │          │          │              │
│  Scout    Librarian    Critic    Operator   WebScanner│
│  (recon)  (analysis)   (valid)   (v0.2)    (http)    │
│      │          │          │                │        │
├──────┴──────┬───┴──────────┴────────────────┴────────┤
│             │                                        │
│   Neo4j (attack graph)  ChromaDB (vectors)           │
│             │                                        │
│   Scope Validator    Session Manager                 │
└──────────────────────────────────────────────────────┘
```

### Agents

| Agent | Role | Status |
|-------|------|--------|
| **Scout** | Reconnaissance via nmap — port scanning, service detection, OS fingerprinting | ✅ Done |
| **Librarian** | CVE correlation via NVD API + LLM-powered relevance assessment | ✅ Done |
| **Critic** | False positive filtering + exploitability validation using LLM reasoning | ✅ Done |
| **Operator** | Exploitation planning + structured AttackStep output (Pydantic) | ✅ Done |
| **OCC** | LangGraph orchestrator coordinating the full pipeline | ✅ Done |

### Tools

| Tool | Function | Status |
|------|----------|--------|
| **Web Scanner** | 21 detection methods — SQLi, XSS, SSTI, XXE, CMDi, CRLF, SSRF, IDOR, NoSQL, GraphQL, Open Redirect, Path Traversal, PII, SRI, HTTP Methods, directory listing, default creds, rate limiting | ✅ Done |
| **JWT Analyzer** | alg:none attack, weak secret brute-force (HS256/384/512), claims validation, PII in payload | ✅ Done |
| **SSL Analyzer** | TLS protocol probing, certificate parsing, HSTS, cipher suites, Heartbleed indicator | ✅ Done |
| **Nuclei Plugin** | Wrapper around Nuclei with 9000+ templates, result parsing, severity filtering | ✅ Done |
| **OSINT** | Multi-source OSINT (Shodan, Censys, WHOIS, LeakIX, URLScan, GreyNoise, HaveIBeenPwned) | ✅ Done |
| **Subdomain Enumerator** | Passive enumeration (crt.sh, Cert Transparency) + active DNS brute-force | ✅ Done |
| **Scope Validator** | Target authorization, CIDR/domain validation, scope creep prevention | ✅ Done |
| **Nmap Wrapper** | Port scanning, service/version detection, OS fingerprinting | ✅ Done |
| **CVE Lookup** | NVD API integration with rate limiting and CVSS extraction | ✅ Done |

### Knowledge Layer

- **Neo4j** - Graph database storing hosts, services, vulnerabilities, and attack paths (optionnel)
- **ChromaDB** - Vector store for semantic search over CVE descriptions (optionnel — `pip install -e ".[vector]"`)

## Tech Stack

- **Python 3.10+**
- **LangGraph** - Agent orchestration as a state machine
- **LangChain** - LLM abstraction (supports Groq, Ollama)
- **Click** - Professional CLI interface
- **Rich** - Terminal UI, tables, progress spinners
- **Neo4j** - Attack path graph database *(optional)*
- **ChromaDB** - Vector embeddings for CVE knowledge *(optional — requires python3-devel)*
- **python-nmap** - Network reconnaissance
- **Jinja2** - HTML report templating
- **NVD API** - Vulnerability intelligence

## Quick Start

### Prerequisites

- Python 3.10+
- nmap installed (`sudo apt install nmap` / `sudo dnf install nmap`)
- Docker (for Neo4j)

### Setup

```bash
# Clone
git clone https://github.com/Abdoul202/rao-framework.git
cd rao-framework

# Virtual environment
python -m venv venv
source venv/bin/activate

# Install (CLI + all runtime dependencies)
pip install -e .

# Optional: vector search support (requires python3-devel / python3-dev)
pip install -e ".[vector]"

# Configuration
cp .env.example .env
# Edit .env with your API keys (Groq is free: https://console.groq.com)

# Optional: start Neo4j
docker compose up -d
```

### CLI Usage

```bash
# Full mission (nmap + CVE + web scan + subdomains + validation)
# --confirm is REQUIRED: confirms you have written authorization to scan
rao scan 192.168.1.100 --confirm --html --save

# Full mission with custom scope
rao scan target.local --confirm -s 192.168.1.0/24 -s 10.0.0.0/8 --html

# Recon only (nmap + web scan, no CVE/LLM analysis)
rao recon 192.168.1.100 --confirm

# Web-only scan (headers, paths, CORS, cookies, tech fingerprint)
rao webscan https://target.local --confirm

# Web scan with active injection testing
rao webscan https://target.local --confirm --inject

# Web scan with auth testing (default credentials + rate limiting)
rao webscan https://target.local --confirm --inject --test-auth

# JWT security analysis (offline — no network needed)
rao jwt-scan eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SIGNATURE

# JWT + live alg:none probe on a target
rao jwt-scan <token> --target https://api.example.com/protected

# SSL/TLS deep analysis
rao ssl https://target.local

# OSINT gathering
rao osint example.com

# Nuclei vulnerability scan
rao nuclei-scan https://target.local

# Subdomain enumeration (crt.sh + DNS brute-force) — passive, no --confirm needed
rao subdomains example.com

# Session management
rao sessions list
rao sessions resume session_name --html

# Skip specific phases
rao scan 192.168.1.100 --confirm --no-web --no-subdomains

# Verbose output
rao scan 192.168.1.100 --confirm -v --html --save
```

### Programmatic Usage

```python
from rao.core.orchestrator import OCC

occ = OCC()
mission = occ.execute(target="192.168.1.100", scope=["192.168.1.0/24"])

print(f"Hosts: {len(mission.hosts)}")
print(f"Findings: {len(mission.validated_findings)}")
```

### Tests

```bash
pytest tests/ -v
```

## Pipeline Flow

```
1. Scope Validator    → Verify target is authorized
2. Scout              → Nmap scan → discover hosts, ports, services
3. Librarian          → Query NVD → correlate CVEs → LLM assesses relevance
4. Critic             → Review findings → filter false positives → validate
5. Web Scanner        → HTTP headers, paths, CORS, cookies, tech detection
6. Subdomain Enum     → crt.sh + DNS brute-force (if target is a domain)
7. Report             → Console (Rich) + JSON + HTML
8. Session Save       → Serialize mission for later resume
```

## Report Formats

| Format | Description |
|--------|-------------|
| **Console** | Rich terminal output with colored tables and severity badges |
| **JSON** | Machine-readable full report for integration with other tools |
| **HTML** | Professional dark-themed report with severity distribution, host details, web scan results, subdomain table |

## Project Structure

```
rao-framework/
├── rao/
│   ├── cli.py                 # Click CLI (9 commands)
│   ├── config.py              # Pydantic settings from .env
│   ├── core/
│   │   ├── orchestrator.py    # OCC - LangGraph pipeline
│   │   ├── state.py           # Shared mission state
│   │   ├── llm.py             # LLM provider factory
│   │   ├── session.py         # Save/resume missions
│   │   └── structured_output.py # AttackStep Pydantic model
│   ├── agents/
│   │   ├── scout.py           # Reconnaissance agent
│   │   ├── librarian.py       # CVE correlation agent
│   │   ├── critic.py          # Validation agent
│   │   └── operator.py        # Exploitation planning (AttackStep)
│   ├── knowledge/
│   │   ├── neo4j_store.py     # Attack graph store
│   │   └── chroma_store.py    # Vector knowledge base
│   ├── tools/
│   │   ├── nmap_wrapper.py    # Nmap scanner
│   │   ├── cve_lookup.py      # NVD API client
│   │   ├── cve_cache.py       # SQLite CVE cache
│   │   ├── web_scanner.py     # HTTP security scanner (21 detection methods)
│   │   ├── jwt_analyzer.py    # JWT security analysis
│   │   ├── ssl_analyzer.py    # SSL/TLS deep analysis
│   │   ├── osint.py           # OSINT (7 sources)
│   │   ├── nuclei_plugin.py   # Nuclei wrapper (9000+ templates)
│   │   ├── subdomain_enum.py  # Subdomain discovery
│   │   └── scope_validator.py # Target authorization
│   └── reporting/
│       ├── report_generator.py  # Console + JSON reports
│       └── html_report.py       # HTML report with Jinja2
├── tests/                     # 213 tests, 100% passing
│   ├── test_web_scanner.py
│   ├── test_web_scanner_advanced.py
│   ├── test_jwt_analyzer.py
│   ├── test_ssl_analyzer.py
│   ├── test_nuclei_plugin.py
│   └── ...
├── docs/                      # Full documentation
│   ├── cli-reference.md
│   ├── architecture.md
│   └── ...
├── examples/
│   └── demo_scan.py
├── docker-compose.yml         # Neo4j service
├── pyproject.toml
└── .env.example
```

## Web Scanner — OWASP Top 10 Coverage

| OWASP | Category | Score | Detection Methods |
|---|---|---|---|
| **A01** | Broken Access Control | 90% | HTTP methods (TRACE/PUT/DELETE), directory listing, IDOR (numeric ID enum), forceful browsing (admin paths without auth) |
| **A02** | Cryptographic Failures | 90% | Cleartext PII (CC/SSN/passwords), token in URL, missing Cache-Control, HTTPS downgrade links |
| **A03** | Injection | 90% | SQLi (GET/POST/Blind), XSS, SSTI (5 engines), XXE, OS command injection, CRLF, NoSQL ($gt/$ne/$regex), GraphQL introspection |
| **A04** | Insecure Design | 50% | Negative business value params (price=-1), rate limiting absence — *ceiling for automated scanners* |
| **A05** | Security Misconfiguration | 90% | 500+ sensitive paths, security headers, cloud metadata endpoints, source map exposure, debug endpoints, WAF detection |
| **A06** | Vulnerable Components | 90% | CVE/NVD correlation, Nuclei 9000+ templates, component version detection in headers |
| **A07** | Auth Failures | 90% | JWT analysis (alg:none, weak secrets, claims), default credentials (12 pairs), rate limiting test, cookie security flags |
| **A08** | Software Integrity | 60% | SRI missing on CDN resources, mixed HTTP content on HTTPS, source map exposure — *supply chain requires source code access* |
| **A09** | Logging Failures | 90% | `/.well-known/security.txt` absence, error responses without X-Request-Id/trace headers, verbose error details |
| **A10** | SSRF | 90% | URL-accepting params injected with AWS/GCP/DO metadata IPs, internal IP disclosure in headers/body, SSRF-redirect detection |

### Active vs Passive

```bash
# Passive (always runs — no payload sent)
rao webscan https://target.com --confirm

# + Active injection testing (SQLi, XSS, SSTI, XXE, CMDi, CRLF, NoSQL, SSRF, IDOR…)
rao webscan https://target.com --confirm --inject

# + Authentication testing (default credentials, rate limiting)
rao webscan https://target.com --confirm --inject --test-auth
```


## Author

**OUEDRAOGO Abdoulaye** - [GitHub](https://github.com/Abdoul202)

## License

MIT
