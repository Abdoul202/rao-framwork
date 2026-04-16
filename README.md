# RAO-Framework

**Multi-Agent Autonomous Red Teaming System**

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
| **Scout** | Reconnaissance via nmap - port scanning, service detection, OS fingerprinting | Done |
| **Librarian** | CVE correlation via NVD API + LLM-powered relevance assessment | Done |
| **Critic** | False positive filtering + exploitability validation using LLM reasoning | Done |
| **Operator** | Exploitation planning + attack path generation | Planned (v0.2) |
| **OCC** | LangGraph orchestrator coordinating the full pipeline | Done |

### Tools

| Tool | Function | Status |
|------|----------|--------|
| **Web Scanner** | HTTP security headers, tech fingerprinting, sensitive path discovery, CORS checks, cookie audit | Done |
| **Subdomain Enumerator** | Passive enumeration (crt.sh) + active DNS brute-force | Done |
| **Scope Validator** | Target authorization, CIDR/domain validation, scope creep prevention | Done |
| **Nmap Wrapper** | Port scanning, service/version detection, OS fingerprinting | Done |
| **CVE Lookup** | NVD API integration with rate limiting and CVSS extraction | Done |

### Knowledge Layer

- **Neo4j** - Graph database storing hosts, services, vulnerabilities, and attack paths
- **ChromaDB** - Vector store for semantic search over CVE descriptions and security knowledge

## Tech Stack

- **Python 3.10+**
- **LangGraph** - Agent orchestration as a state machine
- **LangChain** - LLM abstraction (supports Groq, Ollama)
- **Click** - Professional CLI interface
- **Rich** - Terminal UI, tables, progress spinners
- **Neo4j** - Attack path graph database
- **ChromaDB** - Vector embeddings for CVE knowledge
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

# Dependencies
pip install -r requirements.txt
pip install -e .  # Install CLI

# Configuration
cp .env.example .env
# Edit .env with your API keys (Groq is free: https://console.groq.com)

# Start Neo4j
docker compose up -d
```

### CLI Usage

```bash
# Full mission (nmap + CVE analysis + web scan + subdomains + validation)
rao scan 192.168.1.100 --html --save

# Full mission with custom scope
rao scan target.local -s 192.168.1.0/24 -s 10.0.0.0/8 --html

# Recon only (nmap + web scan, no CVE/LLM analysis)
rao recon 192.168.1.100

# Web-only scan (headers, paths, CORS, cookies, tech fingerprint)
rao webscan https://target.local

# Subdomain enumeration (crt.sh + DNS brute-force)
rao subdomains example.com

# Session management
rao sessions list
rao sessions resume session_name --html

# Skip specific phases
rao scan 192.168.1.100 --no-web --no-subdomains

# Verbose output
rao scan 192.168.1.100 -v --html --save
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
│   ├── cli.py                 # Click CLI (rao command)
│   ├── config.py              # Pydantic settings from .env
│   ├── core/
│   │   ├── orchestrator.py    # OCC - LangGraph pipeline
│   │   ├── state.py           # Shared mission state
│   │   ├── llm.py             # LLM provider factory
│   │   └── session.py         # Save/resume missions
│   ├── agents/
│   │   ├── scout.py           # Reconnaissance agent
│   │   ├── librarian.py       # CVE correlation agent
│   │   ├── critic.py          # Validation agent
│   │   └── operator.py        # Exploitation agent (stub)
│   ├── knowledge/
│   │   ├── neo4j_store.py     # Attack graph store
│   │   └── chroma_store.py    # Vector knowledge base
│   ├── tools/
│   │   ├── nmap_wrapper.py    # Nmap scanner
│   │   ├── cve_lookup.py      # NVD API client
│   │   ├── web_scanner.py     # HTTP security scanner
│   │   ├── subdomain_enum.py  # Subdomain discovery
│   │   └── scope_validator.py # Target authorization
│   └── reporting/
│       ├── report_generator.py  # Console + JSON reports
│       └── html_report.py       # HTML report with Jinja2
├── tests/
│   ├── test_state.py
│   ├── test_critic.py
│   ├── test_cve_lookup.py
│   ├── test_web_scanner.py
│   ├── test_scope_validator.py
│   ├── test_session.py
│   └── test_subdomain_enum.py
├── examples/
│   └── demo_scan.py
├── docker-compose.yml         # Neo4j service
├── setup.py                   # CLI entry point
├── requirements.txt
└── .env.example
```

## Web Scanner Capabilities

| Check | Description |
|-------|-------------|
| **Security Headers** | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| **Tech Fingerprinting** | Server header, X-Powered-By, body signatures (WordPress, React, Django, Laravel, etc.) |
| **Sensitive Paths** | /.env, /.git/HEAD, /phpinfo.php, /admin, /swagger.json, /graphql, /backup.sql, etc. (20+ paths) |
| **CORS** | Wildcard origin, origin reflection, credentials with permissive origin |
| **Cookies** | Secure flag, HttpOnly flag, SameSite attribute |
| **Info Leakage** | Stack traces, SQL errors, debug mode, fatal errors in response body |

## Roadmap

- [x] **v0.1** - MVP: Scout + Librarian + Critic + OCC pipeline
- [x] **v0.1.1** - Web scanner, subdomain enum, CLI, HTML reports, sessions, scope validation
- [ ] **v0.2** - Operator agent (exploitation planning), Neo4j attack path visualization
- [ ] **v0.3** - Streamlit dashboard for mission monitoring
- [ ] **v0.4** - Plugin system for custom tools
- [ ] **v1.0** - Full autonomous red team cycle with human-in-the-loop controls

## Author

**OUEDRAOGO Abdoulaye** - [GitHub](https://github.com/Abdoul202)

## License

MIT
