# RAO-Framework

**Multi-Agent Autonomous Red Teaming System** — v0.6.0

RAO-Framework automates the offensive security assessment pipeline using coordinated AI agents. Each agent handles a specialized phase of a penetration test, from reconnaissance to validation, orchestrated by a central command system.

> **Disclaimer**: This tool is designed for authorized security testing, CTF challenges, and educational purposes only. Always obtain explicit written permission before testing any system.

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    OCC (Orchestrator)                        │
│                 LangGraph State Machine                      │
├────────┬──────────┬──────────┬──────────┬────────────────────┤
│        │          │          │          │                    │
│  Scout  Librarian  Critic    Operator   WebScanner (v0.6)   │
│ (recon) (analysis) (valid)   (plan)     (30 attack types)   │
│        │          │          │                │              │
├────────┴────┬─────┴──────────┴────────────────┴──────────────┤
│             │                                                │
│   Neo4j (attack graph)   ChromaDB (vectors)                 │
│             │                                                │
│   Scope Validator      Session Manager                      │
└──────────────────────────────────────────────────────────────┘
```

> **LLM Red Teaming (v0.7 POC)** runs as a **standalone async pipeline** (not part
> of the OCC graph): it targets an LLM endpoint, proves each finding with
> deterministic detectors + a conservative judge, and supports continuous
> baseline/CI gating. See [docs/LLM_REDTEAM.md](docs/LLM_REDTEAM.md).

### Agents

| Agent | Role | Status |
|-------|------|--------|
| **Scout** | Reconnaissance via nmap — port scanning, service detection, OS fingerprinting | Done |
| **Librarian** | CVE correlation via NVD API + LLM-powered relevance assessment | Done |
| **Critic** | False positive filtering + exploitability validation using LLM (visible per-finding) | Done |
| **Operator** | Exploitation planning + structured AttackStep output + console display | Done |
| **OCC** | LangGraph orchestrator coordinating the full pipeline | Done |

### Tools

| Tool | Function | Status |
|------|----------|--------|
| **Web Scanner** | **30 detection methods** — SQLi (GET/POST/Blind), XSS, SSTI, XXE, CMDi, CRLF, SSRF, IDOR, NoSQL, GraphQL, Open Redirect, Path Traversal, Log4Shell, Host Header, LDAP, XPath, Prototype Pollution, HTTP Smuggling, Deserialization, CSRF + passifs | ✅ v0.6 |
| **LLM Red Team** | Continuous, evidence-based red teaming of LLM endpoints — OWASP LLM Top 10 (2025) + MITRE ATLAS, deterministic detectors + conservative judge (0-FP bias), baseline/CI regression gate, async engine | 🧪 v0.7 POC |
| **JWT Analyzer** | alg:none attack, weak secret brute-force (HS256/384/512), claims validation, PII in payload | Done |
| **SSL Analyzer** | TLS protocol probing, certificate parsing, HSTS, cipher suites, Heartbleed indicator | Done |
| **Nuclei Plugin** | Wrapper around Nuclei with 9000+ templates, result parsing, severity filtering | Done |
| **OSINT** | Multi-source OSINT (Shodan, Censys, WHOIS, LeakIX, URLScan, GreyNoise, HaveIBeenPwned) | Done |
| **Subdomain Enumerator** | Passive enumeration (crt.sh, Cert Transparency) + active DNS brute-force (500+ prefixes) | Done |
| **Scope Validator** | Target authorization, CIDR/domain validation, scope creep prevention | Done |
| **Nmap Wrapper** | Port scanning, service/version detection, OS fingerprinting | Done |
| **CVE Lookup** | NVD API integration with rate limiting and CVSS extraction | Done |

### Knowledge Layer

- **Neo4j** - Graph database storing hosts, services, vulnerabilities, and attack paths (optionnel)
- **ChromaDB** - Vector store for semantic search over CVE descriptions (optionnel — `pip install -e "[vector]"`)

## Tech Stack

- **Python 3.10+**
- **LangGraph** - Agent orchestration as a state machine
- **LangChain** - LLM abstraction (supports Groq, Ollama)
- **Click** - Professional CLI interface
- **Rich** - Terminal UI, tables, progress spinners
- **httpx** - Async HTTP client (LLM red teaming engine)
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
pip install -e "[vector]"

# Configuration
cp .env.example .env
# Edit .env with your API keys (Groq is free: https://console.groq.com)

# Optional: start Neo4j
docker compose up -d
```

### CLI Usage

```bash
# ── Audit complet (recommandé) ─────────────────────────────────────────────
# Lance TOUS les modules : nmap, CVE, web (30 types d'injection), SSL,
# OSINT, Nuclei, subdomains, Critic LLM visible, plan d'attaque Operator
rao audit https://target.com --confirm --html --save

# Audit sans Nuclei (plus rapide)
rao audit https://target.com --confirm --no-nuclei --html

# Audit sans CVE/nmap (cible web uniquement)
rao audit https://target.com --confirm --no-cve --html

# Audit avec analyse JWT
rao audit https://target.com --confirm --jwt eyJhbGc...

# ── Commandes individuelles ────────────────────────────────────────────────
# Scan nmap + CVE + LLM uniquement
rao scan 192.168.1.100 --confirm --html --save

# Web-only scan (passif)
rao webscan https://target.local --confirm

# Web scan + injections actives (30 types)
rao webscan https://target.local --confirm --inject

# Web scan + auth testing
rao webscan https://target.local --confirm --inject --test-auth

# JWT security analysis
rao jwt-scan eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SIGNATURE

# Continuous LLM red teaming (OWASP LLM Top 10 + MITRE ATLAS) — see docs/LLM_REDTEAM.md
rao llm-redteam --openai http://localhost:8000/v1 --model my-model --judge --confirm --json
rao llm-redteam --profile target.yaml --baseline --ci --confirm   # CI regression gate
rao llm-eval                                                       # prove FP=0 / measure recall

# SSL/TLS deep analysis
rao ssl https://target.local

# OSINT gathering
rao osint example.com

# Nuclei vulnerability scan
rao nuclei-scan https://target.local

# Subdomain enumeration
rao subdomains example.com

# Session management
rao sessions list
rao sessions resume session_name --html
```

### Programmatic Usage

```python
from rao.core.orchestrator import OCC

occ = OCC()
mission = occ.execute(target="192.168.1.100", scope=["192.168.1.0/24"])

print(f"Hosts: {len(mission.hosts)}")
print(f"Findings: {len(mission.validated_findings)}")
print(f"Attack steps: {len(mission.attack_steps)}")
```

### Tests

```bash
pytest tests/ -v
```

## Pipeline Flow — `rao audit`

```
1.  Scope Validator    → Verify target is authorized
2.  Scout              → Nmap scan → discover hosts, ports, services
3.  Librarian (LLM)    → Query NVD → correlate CVEs → LLM assesses relevance
4.  Web Scanner        → 30 detection methods (active injections if --no-inject absent)
5.  SSL Analyzer       → TLS protocol, certificate, cipher suite analysis
6.  OSINT Collector    → 7-source passive intelligence gathering
7.  Nuclei Scanner     → 9000+ templates (if installed)
8.  Subdomain Enum     → crt.sh + DNS brute-force (500+ prefixes)
9.  JWT Analyzer       → Optional: --jwt TOKEN
10. Critic (LLM)       → Per-finding validation visible in terminal (✅ / ❌)
11. Operator (LLM)     → Attack plan generated for HIGH/CRITICAL findings (table display)
12. Reports            → JSON + HTML (named by domain: rao_report_example_com_XXXX)
13. Session Save       → Serialize mission for later resume
```

## Report Formats

| Format | Description |
|--------|-------------|
| **Console** | Rich terminal output with colored tables and severity badges |
| **JSON** | Machine-readable full report — includes `domain` field extracted from target URL |
| **HTML** | Professional dark-themed report with severity distribution, host details, web scan results, Nuclei findings, Attack Plan steps |

> **Note**: Report filenames are based on the clean domain name (e.g. `rao_report_opshero_me_20260606_120000.json`), not the raw URL. This prevents `FileNotFoundError` with URLs containing `://` or `/`.

## LLM Integration

The framework uses Groq (free API) or Ollama (local) for AI analysis:

```
  Critic LLM — validates each finding individually
  ✅ VALIDÉ   [HIGH]   Missing header: X-Frame-Options
  ❌ FAUX POSITIF [LOW] Missing header: X-XSS-Protection
  ✅ VALIDÉ   [CRITICAL] SQLi indicator in param 'id'

⚔ Operator LLM — generates an attack plan for HIGH/CRITICAL findings
  ┌───┬──────────┬─────────────────┬───────────┬──────────────────────────┐
  │ # │ Severity │ Finding         │ Tool      │ Approach                 │
  ├───┼──────────┼─────────────────┼───────────┼──────────────────────────┤
  │ 1 │ CRITICAL │ SQLi in param.. │ sqlmap    │ Use sqlmap --dbs to...   │
  └───┴──────────┴─────────────────┴───────────┴──────────────────────────┘
```

Configure in `.env`:
```env
LLM_PROVIDER=groq
GROQ_API_KEY=gsk_...    # Free at https://console.groq.com
# OR
LLM_PROVIDER=ollama
OLLAMA_MODEL=mistral    # ollama pull mistral
```

## Project Structure

```
rao-framework/
├── rao/
│   ├── cli.py                 # Click CLI (audit + 11 commands incl. llm-redteam/llm-eval)
│   ├── config.py              # Pydantic settings from .env
│   ├── core/
│   │   ├── orchestrator.py    # OCC - LangGraph pipeline
│   │   ├── state.py           # Shared mission state
│   │   ├── llm.py             # LLM provider factory (Groq/Ollama cascade)
│   │   ├── session.py         # Save/resume missions
│   │   └── structured_output.py # AttackStep, CriticVerdict Pydantic models
│   ├── agents/
│   │   ├── scout.py           # Reconnaissance agent
│   │   ├── librarian.py       # CVE correlation agent
│   │   ├── critic.py          # Validation agent (lazy LLM, offline fallback)
│   │   └── operator.py        # Exploitation planning (AttackStep)
│   ├── knowledge/
│   │   ├── neo4j_store.py     # Attack graph store
│   │   └── chroma_store.py    # Vector knowledge base
│   ├── tools/
│   │   ├── nmap_wrapper.py    # Nmap scanner
│   │   ├── cve_lookup.py      # NVD API client
│   │   ├── cve_cache.py       # SQLite CVE cache (7-day TTL)
│   │   ├── web_scanner.py     # HTTP security scanner (30 detection methods)
│   │   ├── jwt_analyzer.py    # JWT security analysis
│   │   ├── ssl_analyzer.py    # SSL/TLS deep analysis
│   │   ├── osint.py           # OSINT (7 sources)
│   │   ├── nuclei_plugin.py   # Nuclei wrapper (9000+ templates)
│   │   ├── subdomain_enum.py  # Subdomain discovery (500+ wordlist)
│   │   ├── scope_validator.py # Target authorization
│   │   └── llm_redteam/       # LLM red teaming (async, OWASP LLM Top 10 + ATLAS)
│   │       ├── target.py      # Async HTTP / OpenAI-compatible adapters
│   │       ├── probes.py      # Probe catalogue (data/llm_probes.yaml)
│   │       ├── detectors.py   # Deterministic detectors (0-FP)
│   │       ├── judge.py       # Conservative LLM judge
│   │       ├── scanner.py     # Async bounded scanner
│   │       ├── baseline.py    # Regression diff + CI gate
│   │       └── eval.py        # FP/FN harness + mock targets
│   └── reporting/
│       ├── report_generator.py  # Console + JSON reports (domain-safe filenames)
│       └── html_report.py       # HTML report with Jinja2 (domain-safe filenames)
├── tests/                     # 257 tests (18 files)
│   ├── test_web_scanner.py
│   ├── test_web_scanner_advanced.py
│   ├── test_jwt_analyzer.py
│   ├── test_ssl_analyzer.py
│   ├── test_nuclei_plugin.py
│   ├── test_llm_redteam_*.py  # scanner, detectors, target, judge, baseline, eval
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

## Web Scanner — OWASP Top 10 Coverage (v0.6)

| OWASP | Category | Score | Detection Methods |
|---|---|---|---|
| **A01** | Broken Access Control | 90% | HTTP methods, directory listing, IDOR, forceful browsing, CSRF |
| **A02** | Cryptographic Failures | 90% | Cleartext PII, token in URL, missing Cache-Control, HTTPS downgrade |
| **A03** | Injection | **95%** | SQLi (GET/POST/Blind), XSS, SSTI, XXE, CMDi, CRLF, NoSQL, GraphQL, LDAP, XPath, Prototype Pollution, Log4Shell, Open Redirect, Path Traversal |
| **A04** | Insecure Design | 50% | Negative business params, rate limiting absence |
| **A05** | Security Misconfiguration | 90% | 500+ paths, security headers, source maps, WAF detection |
| **A06** | Vulnerable Components | 90% | CVE/NVD correlation, Nuclei 9000+ templates |
| **A07** | Auth Failures | 90% | JWT (alg:none, weak secrets), default credentials, rate limiting, cookies |
| **A08** | Software Integrity | 65% | SRI missing, mixed content, source maps, Deserialization fingerprinting, HTTP Smuggling |
| **A09** | Logging Failures | 90% | security.txt, X-Request-Id, verbose error details |
| **A10** | SSRF | 90% | URL params + AWS/GCP/DO metadata, internal IP disclosure, Host Header Injection |

### Injection Types Detected (v0.6 — 30 total)

**Active (require `--inject` or `rao audit` default):**

| # | Type | Method | OWASP |
|---|------|--------|-------|
| 1 | SQLi GET (error-based) | `_test_sqli` | A03 |
| 2 | SQLi POST | `_test_sqli_post` | A03 |
| 3 | SQLi Blind (time-based) | `_test_sqli_blind` | A03 |
| 4 | XSS Reflected | `_test_xss` | A03 |
| 5 | SSTI (5 engines) | `_test_ssti` | A03 |
| 6 | XXE | `_test_xxe` | A05 |
| 7 | Command Injection | `_test_command_injection` | A03 |
| 8 | CRLF Injection | `_test_crlf` | A03 |
| 9 | NoSQL Injection | `_test_nosql_injection` | A03 |
| 10 | GraphQL Introspection | `_test_graphql` | A05 |
| 11 | SSRF | `_test_ssrf_params` | A10 |
| 12 | IDOR | `_test_idor` | A01 |
| 13 | Path Traversal / LFI | `_test_path_traversal` | A01 |
| 14 | Open Redirect | `_test_open_redirect` | A03 |
| 15 | Log4Shell (CVE-2021-44228) | `_test_log4j` | A06 |
| 16 | Host Header Injection | `_test_host_header_injection` | A10 |
| 17 | LDAP Injection | `_test_ldap_injection` | A03 |
| 18 | XPath Injection | `_test_xpath_injection` | A03 |
| 19 | Prototype Pollution | `_test_prototype_pollution` | A08 |
| 20 | HTTP Request Smuggling | `_test_http_request_smuggling` | A08 |
| 21 | Insecure Deserialization | `_test_deserialization` | A08 |
| 22 | CSRF Token Absence | `_check_csrf` | A01 |
| 23 | Forceful Browsing | `_check_forceful_browsing` | A01 |
| 24 | Business Logic (neg. values) | `_detect_insecure_workflow` | A04 |

**Passive (always active, no payloads sent):**

| # | Type |
|---|------|
| 25 | Security Headers missing |
| 26 | CORS misconfiguration |
| 27 | Cookie flags (Secure/HttpOnly/SameSite) |
| 28 | SRI missing on CDN resources |
| 29 | Source maps exposed |
| 30 | Token in URL / Cleartext PII |

### Active vs Passive

```bash
# Passive only (no payload sent)
rao webscan https://target.com --confirm

# + All 24 active injection types
rao webscan https://target.com --confirm --inject

# + Authentication testing (default creds, rate limiting)
rao webscan https://target.com --confirm --inject --test-auth
```

## Roadmap

### Versions publiées

| Version | Statut | Contenu |
|---|---|---|
| v0.1 | Done | MVP : Scout + Librarian + Critic + OCC pipeline |
| v0.1.1 | Done | Web scanner, subdomain enum, CLI, HTML reports, sessions, scope validation |
| v0.1.2 | Done | Plugin system, CVE cache, structured LLM output |
| v0.4.0 | Done | SSL Analyzer, OSINT (7 sources), Nuclei plugin, Operator (AttackStep) |
| v0.5.0 | Done | JWT Analyzer, 21 web scanner methods, OWASP Top 10 coverage 88%+, `rao audit` command |
| **v0.6.0** | CURRENT | +8 injection types (Log4Shell, Host Header, LDAP, XPath, Prototype Pollution, HTTP Smuggling, Deserialization, CSRF) · LLM Critic visible per-finding · Operator attack plan displayed · Domain-safe report filenames |
| **v0.7.0** | 🧪 POC | **Pivot — Continuous LLM Red Teaming** : module `rao llm-redteam` / `rao llm-eval`, OWASP LLM Top 10 (2025) + MITRE ATLAS, détecteurs déterministes + juge conservateur (biais 0-FP), baseline + gate CI, moteur async. Voir [docs/LLM_REDTEAM.md](docs/LLM_REDTEAM.md). |

---

### 🎯 Piste principale — Continuous LLM Red Teaming

> Direction produit depuis le pivot v0.7 (cf. audit stratégique). Principe :
> **prouver** chaque faille (0 faux positif), pas seulement la signaler. C'est la
> niche défendable où RAO part d'une longueur d'avance (stack IA déjà en place).

| Version | Objectif | Capacités clés |
|---|---|---|
| **v0.7** (POC livré ✅) | Prouver la faisabilité | `rao llm-redteam` / `llm-eval`, OWASP LLM Top 10 (2025) + MITRE ATLAS, détecteurs déterministes + juge conservateur (0-FP), baseline + gate CI, moteur async |
| **v0.8** | Couverture & preuve | `--known-secret` / `--system-marker` (LLM02/LLM07 déterministes), attaques multi-tours (crescendo), suffixes adverses (GCG), rapport HTML/exécutif, GitHub Action CI |
| **v0.9** | CTEM continu | scan planifié + diff temporel, alerting de régression (Slack / webhook), test de serveurs MCP, injection multimodale |
| **v1.0** | Plateforme | multi-cible, dashboard web, registry de probes communautaire, mapping ATLAS complet + éval publique reproductible |

---

### 🗄️ Piste legacy — Plateforme d'audit web (dépriorisée post-pivot)

> Ces fonctionnalités étaient planifiées **avant** le pivot v0.7. Elles ne sont
> **plus prioritaires** mais restent conservées ici pour référence / réutilisation
> éventuelle (le code d'audit web/réseau existant reste pleinement fonctionnel).

#### Phase A — Valeur immédiate *(legacy)*

| Feature | Impact | Description |
|---|---|---|
| **Risk Scoring normalisé** | Critique | Score global 0–100 avec grade A→F calculé depuis les findings. Comparaison avec le scan précédent du même domaine (régression / amélioration). |
| **Mission Memory (SQLite)** | Critique | Mémoire persistante entre scans. `rao audit` affiche automatiquement l'historique du domaine, les nouveaux findings et ceux résolus. Commande `rao history DOMAIN`. |
| **Rapport PDF exécutif** | Critique | Rapport PDF une page : score global, grade, radar chart OWASP Top 10, top 5 findings critiques, comparaison historique. Généré avec `--pdf`. |

---

#### Phase B — Différenciation forte *(legacy)*

| Feature | Impact | Description |
|---|---|---|
| **Mode Chat interactif (`rao chat`)** | Critique | Session interactive post-audit avec l'IA : *"Comment exploiter la SQLi ?"*, *"Génère le rapport pour mon client"*, *"Quelles remédiations pour le XSS ?"*. Aucun scanner OSS ne propose ça. |
| **Dashboard web (`rao serve`)** | Élevé | Interface FastAPI + HTMX sur `localhost:8080`. Lancement de scans via formulaire, logs en temps réel (WebSocket), historique des missions, API REST `/api/scans`. |

---

#### Phase C — Adoption communautaire *(legacy)*

| Feature | Impact | Description |
|---|---|---|
| **GitHub Action (`rao-action`)** | Élevé | Action publiée sur le GitHub Marketplace. Lance `rao audit` en CI/CD, uploade le rapport HTML comme artefact, fait échouer la PR si finding CRITICAL. |
| **Remediation Engine** | Élevé | Pour chaque finding validé → recommandations de correction ciblées (nginx / Apache / Django / Node.js) + références OWASP. Onglet "Plan de remédiation" dans le rapport HTML. |

---

#### Phase D — Enrichissement continu *(legacy)*

| Feature | Impact | Description |
|---|---|---|
| **OSINT 100% gratuit** | Moyen | 8 nouvelles sources sans API key : Wayback Machine (endpoints oubliés), favicon hash fingerprinting, robots.txt/sitemap, Google Dorks exécutés, ASN/BGP info. |
| **Neo4j Attack Graph visuel** | Moyen | Visualisation interactive du graphe d'attaque (hôtes → services → CVEs → attack paths) dans le dashboard web. |
| **Scan planifié (`rao schedule`)** | Moyen | Planifier des audits récurrents (cron-like) avec alertes sur nouveaux findings critiques (email / webhook Slack). |
| **Plugin marketplace** | Moyen | Système de plugins communautaires installables via `rao plugin install <nom>`. Registry public sur GitHub. |

---

### Métriques vérifiables (état actuel)

> Remplace les anciens scores de maturité auto-attribués par des chiffres
> mesurables et reproductibles.

| Métrique | Valeur | Comment la vérifier |
|---|---|---|
| Tests | **257** (18 fichiers), 0 échec | `pytest tests/ -q` |
| Faux positifs (éval LLM red team) | **0** sur cible durcie | `rao llm-eval` |
| Recall éval (avec juge) | **1.00** sur la suite vérité-terrain | `rao llm-eval --judge` |
| Couverture OWASP LLM Top 10 | 5/10 — LLM01, 02, 05, 06, 07 *(POC)* | `data/llm_probes.yaml` |
| Techniques MITRE ATLAS | AML.T0051, T0054, T0057 | `data/llm_probes.yaml` |
| Commandes CLI | 12 | `rao --help` |
| Lint | `ruff` clean | `ruff check rao/` |

---

## Author

**OUEDRAOGO Abdoulaye** - [GitHub](https://github.com/Abdoul202)

## Contributors

- **OUEDRAOGO Abdoulaye** — créateur & mainteneur
- **Claude (Anthropic)** — module *Continuous LLM Red Teaming* (v0.7), audit stratégique & documentation

## License

Released under the [MIT License](LICENSE) — Copyright (c) 2026 OUEDRAOGO Abdoulaye and contributors.
