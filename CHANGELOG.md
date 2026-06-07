# Changelog

All notable changes to RAO-Framework will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] — Planifié

### Pivot stratégique — Continuous LLM Red Teaming (v0.7 POC)

Nouveau module offensif IA : `rao/tools/llm_redteam/` — red teaming continu et
**fondé sur la preuve** d'endpoints LLM, mappé **OWASP LLM Top 10 (2025)** +
**MITRE ATLAS**. Premier socle **async** du projet (httpx + concurrence bornée).

#### Ajouté
- **`rao llm-redteam`** : attaque un LLM cible (profil HTTP générique ou raccourci
  OpenAI-compatible `--openai`) avec un catalogue de probes (injection directe/
  indirecte, fuite de system prompt, exfiltration de secret, sortie non sûre /
  XSS-via-LLM, excessive agency, jailbreaks). Détection **déterministe d'abord**
  (canary / sentinel / sortie exécutable / refus), juge LLM **conservateur**
  (biais 0 faux positif) uniquement sur les cas ambigus.
- **Couche « continue »** : baseline par cible + diff `NEW`/`FIXED`/`PERSISTENT`
  (`--baseline`), gate CI `--ci` (échec si nouvelle vulnérabilité).
- **Détection déterministe LLM02/LLM07** : `--known-secret` (exfil de secret) et
  `--system-marker` (fuite de system prompt) rendent ces probes déterministes
  quand le secret/marqueur est connu, au lieu de dépendre du juge. Nouveau
  détecteur `secret` (AMBIGUOUS → juge si inconnu, jamais de faux positif).
- **`rao llm-eval`** : harness d'évaluation mesurant FP/FN contre des cibles à
  vérité-terrain (mocks vulnérable/durci). Critère : **FP = 0**.
- `rao/tools/llm_redteam/` : `models.py`, `target.py` (adaptateurs async
  HTTP/OpenAI), `probes.py` + `data/llm_probes.yaml`, `detectors.py`, `judge.py`,
  `scanner.py`, `report.py`, `baseline.py`, `eval.py`, `mocks.py`.
- Réglages `LLMRedTeamSettings` (`LLM_REDTEAM_JUDGE`, `_CONCURRENCY`, `_TIMEOUT`).
- 46 tests unitaires (`tests/test_llm_redteam_*.py`) + serveur mock OpenAI-
  compatible (`tests/fixtures/mock_llm_server.py`). Dépendances : `httpx`,
  `pyyaml` (runtime), `respx` (dev).

### Phase A — v0.7.0 (Valeur immédiate)

#### Prévu — Risk Scoring normalisé
- **`rao/reporting/risk_scorer.py`** : Score global 0–100 avec grade A→F basé sur les findings validés. Pondération OWASP (CRITICAL=10, HIGH=7, MEDIUM=4, LOW=1). Comparaison automatique avec le scan précédent du même domaine (delta régression/amélioration).
- **`rao/reporting/pdf_report.py`** : Rapport PDF exécutif : score, grade, radar chart OWASP Top 10, top 5 findings, historique. Option `--pdf` dans `rao audit`.

#### Prévu — Mission Memory
- **`rao/core/memory.py`** : `MissionMemory` SQLite persistant entre sessions. Stocke : domaine, date, score, findings count. Commande `rao history DOMAIN` → tableau chronologique des scans.

### Phase B — v0.8.0 (Différenciation forte)

#### Prévu — `rao chat` (Mode interactif LLM)
- **`rao/agents/analyst.py`** : Agent conversationnel post-audit. Charge une session existante et répond aux questions sur les findings : exploitation, remédiation, rapport client.
- Commande : `rao chat --session opshero_me_20260607`

#### Prévu — Dashboard web (`rao serve`)
- **`rao/server/`** : Interface FastAPI + HTMX sur `localhost:8080`. Lancement de scans via formulaire, logs en temps réel (WebSocket), API REST `/api/scans`, historique des missions.

### Phase C — v0.9.0 (Adoption communautaire)

#### Prévu — GitHub Action (`rao-action`)
- **`action.yml`** : Action GitHub Marketplace. Lance `rao audit` en CI/CD, uploade le rapport HTML comme artefact, fait échouer la PR si finding CRITICAL. Option `fail_on_severity`.

#### Prévu — Remediation Engine
- **`rao/agents/remediation.py`** : Pour chaque finding validé → recommandations de correction nginx/Apache/Django/Node.js + références OWASP. Onglet "Remediation Plan" dans le rapport HTML.
- **`rao/data/remediation_kb.json`** : Base de connaissances locale 300+ entrées (pas de LLM requis pour les cas courants).

### Phase D — v1.0.0 (Plateforme complète)

#### Prévu
- **OSINT 100% gratuit** : Wayback Machine, favicon hash, robots.txt, Google Dorks exécutés, ASN/BGP — 8 nouvelles sources sans API key.
- **Neo4j Attack Graph visuel** : Visualisation interactive dans le dashboard web (hôtes → services → CVEs → attack paths).
- **`rao schedule`** : Scans récurrents (cron) avec alertes email/Slack sur nouveaux findings critiques.
- **Plugin marketplace** : `rao plugin install <nom>` — registry communautaire public sur GitHub.

---

## [0.6.0] — 2026-06-07

### 🧠 LLM Visibility + 30 Injection Types

#### Added — 8 new injection/attack detection methods (`rao/tools/web_scanner.py`)

| # | Type | Method | OWASP |
|---|------|--------|-------|
| 1 | **Log4Shell** (CVE-2021-44228) | `_test_log4j` | A06 |
| 2 | **Host Header Injection** | `_test_host_header_injection` | A10 |
| 3 | **LDAP Injection** (error-based) | `_test_ldap_injection` | A03 |
| 4 | **XPath Injection** (error-based) | `_test_xpath_injection` | A03 |
| 5 | **Prototype Pollution** (JSON POST + GET bracket) | `_test_prototype_pollution` | A08 |
| 6 | **HTTP Request Smuggling** (CL.TE raw socket probe) | `_test_http_request_smuggling` | A08 |
| 7 | **Insecure Deserialization** (magic bytes + patterns) | `_test_deserialization` | A08 |
| 8 | **CSRF Token Absence** (POST form HTML parsing) | `_check_csrf` | A01 |

- **Total injection types: 30** (22 active + 8 passive).
- New payload constants: `LOG4J_PAYLOADS`, `HOST_HEADER_PAYLOADS`, `LDAP_PAYLOADS`, `XPATH_PAYLOADS`, `PROTO_POLLUTION_PAYLOADS`, `DESERIAL_MAGIC_BYTES`, etc.
- New `WebScanResult` fields: `log4j_indicators`, `host_header_indicators`, `ldap_indicators`, `xpath_indicators`, `proto_pollution_indicators`, `smuggling_indicators`, `deserialization_indicators`, `csrf_missing`.

#### Added — LLM activity visible in terminal (`rao/cli.py`)

- **`_run_post_scan_critic()`** rewritten: each finding now shows a spinner during LLM analysis, then a per-finding verdict line:
  - `✅ VALIDÉ   [HIGH]   Missing header: X-Frame-Options`
  - `❌ FAUX POSITIF [LOW] Missing header: X-XSS-Protection`
- LLM provider name displayed on startup: `🧠 LLM actif: ChatGroq`.
- Summary panel after Critic pass: `Validés / Faux positifs / Total validés`.
- **`_run_operator_and_display()`** new function: runs `OperatorAgent` after Phase 8 and displays the attack plan as a Rich table (Finding / Tool / Approach / Risk) instead of hiding it in logs.
- Final summary panel now includes `Attack steps: N (LLM-generated)`.

#### Fixed — `FileNotFoundError` on URL targets (`rao/reporting/`)

- **`report_generator.py`**: `mission.target.replace('.', '_')` was not sanitizing `:` or `/` from URLs (e.g. `https://opshero.me/` → `results/https:/opshero_me/...` → crash). Now uses `urlparse` + `re.sub` to extract clean hostname: `opshero_me`.
- **`html_report.py`**: Same bug fixed with same approach. Both JSON and HTML reports now use domain-based filenames: `rao_report_opshero_me_20260607_120000.{json,html}`.
- **`report_generator.py`**: Added `"domain"` field to JSON report `meta` section (extracted hostname for easy identification).

#### Fixed — Silent report failures (`rao/cli.py`)

- `generate_report()` and `generate_html_report()` calls now wrapped in `try/except` — any error shows a visible warning (`⚠ JSON report failed: ...` / `✗ HTML report failed: ...`) instead of crashing silently.
- JSON report path now printed to console on success.

#### Changed

- `rao/__init__.py` — `__version__` bumped `0.5.0` → `0.6.0`.
- `pyproject.toml` — version `0.5.0` → `0.6.0`.

#### OWASP Top 10 Coverage (v0.6)

| # | Category | Score |
|---|---|---|
| A01 | Broken Access Control | 90% |
| A02 | Cryptographic Failures | 90% |
| A03 | Injection | **95%** |
| A04 | Insecure Design | 50% |
| A05 | Security Misconfiguration | 90% |
| A06 | Vulnerable Components | 90% |
| A07 | Auth Failures | 90% |
| A08 | Software Integrity | **65%** |
| A09 | Logging Failures | 90% |
| A10 | SSRF | 90% |

---

## [0.5.0] — 2026-06-06

### 🎯 OWASP Top 10 Coverage — 88%+ (average)

All 10 OWASP categories now have automated detection coverage.
7 categories are at or above 90%. A04 (Insecure Design) and A08 (Software Integrity)
have fundamental limits for automated scanning (~50% / ~60% respectively).

#### Added — JWT Security (A07)
- **`rao/tools/jwt_analyzer.py`** (`JWTAnalyzer`): Full JWT security analysis module.
  - Offline brute-force of HS256/HS384/HS512 weak secrets (40+ wordlist).
  - `alg:none` detection (header flag + optional live HTTP probe `--target`).
  - Claims validation: `exp`, `iat`, `nbf`, very-long expiry (>1 year).
  - Sensitive data detection in unencrypted payload (password, api_key, secret…).
  - `JWTResult.has_critical` property for pipeline integration.
- **`rao/cli.py`** — `rao jwt-scan <token>` command with `--target` for live alg:none test.
- **`tests/test_jwt_analyzer.py`**: 17 unit tests — all offline.

#### Added — Web Scanner v0.5 (A03: +22%)
- `_test_ssti()`: SSTI — arithmetic fingerprint `{{3764*3764}}=14167696` for 5 engines.
- `_test_open_redirect()`: 20 common redirect params → `evil.attacker.com`.
- `_test_path_traversal()`: LFI `../../../etc/passwd` on 12 file params.
- `_test_sqli_post()`: POST form fuzzing on 14 params with SQL error matching.
- `_test_sqli_blind()`: Time-based blind SQLi — SLEEP/WAITFOR/pg_sleep, 4.5s threshold.

#### Added — Web Scanner v0.5.1 (A01: +10%, A03: +10%, A07: +12%)
- `_test_xxe()`: XML External Entity via POST `application/xml`.
- `_test_command_injection()`: OS command injection `;id`, `|id`, `$(id)`.
- `_test_crlf()`: CRLF/response-splitting via `%0d%0a` injection.
- `_test_http_methods()`: Dangerous HTTP methods TRACE/PUT/DELETE/PATCH.
- `_detect_directory_listing()`: Pattern matching on response body.
- `_test_default_credentials()`: 12 default pairs on 6 login paths.
- `_test_rate_limiting()`: 15-request flood to `/login`, flag if no 429/lockout.
- New `test_auth=True` flag on `WebScanner` for auth-specific tests.

#### Added — Web Scanner v0.5.2 (A01: +10%, A02: +10%, A08: +60%, A09: +70%, A10: +75%)
- `_detect_cleartext_pii()`: PAN Visa/MC/Amex, SSN, passwords in JSON, API keys, Bearer tokens.
- `_check_token_in_url()`: Credentials/tokens in URL query string.
- `_check_cache_control()`: Missing `Cache-Control: no-store`.
- `_detect_https_downgrade()`: HTTP resources on HTTPS pages.
- `_check_sri_missing()`: External CDN scripts/styles without `integrity=` attribute.
- `_check_mixed_content()`: Active mixed content on HTTPS pages.
- `_check_source_maps()`: Exposed `.js.map` / `.css.map` source files.
- `_check_security_txt()`: `/.well-known/security.txt` presence check.
- `_check_error_correlation()`: Error responses without X-Request-Id/trace header.
- `_detect_internal_ip_disclosure()`: RFC-1918 IPs in response headers/body.
- `_test_ssrf_params()`: URL-accepting params injected with AWS/GCP metadata URLs.
- `_test_idor()`: Numeric ID enumeration in URL paths (adjacent ID comparison).
- `_check_forceful_browsing()`: Admin paths accessible without authentication.
- `_test_nosql_injection()`: MongoDB `$gt`, `$ne`, `$regex` payloads via JSON POST.
- `_test_graphql()`: GraphQL introspection at `/graphql`, `/api/graphql`, `/graphiql`.
- `_detect_insecure_workflow()`: Negative value acceptance on business params.
- **`WebScanResult`** — 26 total new fields across all versions.
- **`tests/test_web_scanner.py`**: Extended to 33 tests.
- **`tests/test_web_scanner_advanced.py`**: 44 tests for all v0.5.2 methods.

#### Changed
- `rao/__init__.py` — `__version__` bumped from `0.1.0` → `0.5.0`.
- `pyproject.toml` — version `0.4.0` → `0.5.0`.
- Total test suite: **211 tests**, all passing, 0 ruff errors.

#### OWASP Top 10 Coverage
| # | Category | Score |
|---|---|---|
| A01 | Broken Access Control | 90% |
| A02 | Cryptographic Failures | 90% |
| A03 | Injection | 90% |
| A04 | Insecure Design | 50% (theoretical scanner ceiling) |
| A05 | Security Misconfiguration | 90% |
| A06 | Vulnerable Components | 90% |
| A07 | Auth Failures | 90% |
| A08 | Software Integrity | 60% (theoretical scanner ceiling) |
| A09 | Logging Failures | 90% |
| A10 | SSRF | 90% |

---

## [0.4.0] — 2026-06-02

### 🎯 Security Assessment Maturity — 90% milestone

#### Added
- **`tests/test_ssl_analyzer.py`**: 44 unit tests for `SSLAnalyzer` — full coverage of protocol
  probing, certificate parsing, HSTS, Heartbleed indicator, and `_compile_findings` logic.
  All tests use socket/ssl mocks; no real network required.
- **`AttackStep` Pydantic model** (`rao/core/structured_output.py`): replaces fragile raw-string
  Operator output with typed objects. `AttackStep.parse_llm_response()` splits `---` delimited
  blocks into `finding / tool / approach / example / prerequisite / risk` fields.
- **`attack_steps`** field added to `MissionState` (`rao/core/state.py`): stores parsed
  `AttackStep` objects alongside the raw `attack_plan` string.
- **`_osint_to_findings()`** helper in `rao/cli.py`: OSINT findings (previously only stored in
  `mission.osint.findings`) are now injected into `mission.findings` so the Critic can validate
  them like any other finding.
- **`_run_post_scan_critic()`** in `rao/cli.py`: a second Critic pass runs after all supplementary
  scans (web / SSL / OSINT) complete, validating findings that bypassed the main OCC pipeline.
- **Nuclei section in HTML report** (`rao/reporting/html_report.py`): dedicated section with
  purple NUCLEI badge, severity badge, CVE tags, and evidence field. Rendered from
  `mission.nuclei_findings`.
- **Structured Attack Plan in HTML report**: `attack_steps` are rendered as an interactive card
  table (tool, approach, example `<code>` block, prerequisite, risk badge). Falls back to the
  raw pre-block when `attack_steps` is empty (backward compatible).
- **DNS brute-force wordlist expanded** (`rao/tools/subdomain_enum.py`): `COMMON_SUBDOMAINS`
  grows from ~100 to 500+ prefixes, covering cloud platforms, IAM, CI/CD extras, data/ML stack,
  messaging, regional endpoints, security tooling, enterprise apps, IoT, and remote access.

#### Fixed
- **`SSLAnalyzer._hostname_matches()`** — wildcard certificates (`*.example.com`) now correctly
  reject multi-level sub-subdomains (`deep.sub.example.com`) per RFC 6125 §6.4.3. Previously
  any hostname ending with the wildcard suffix was accepted regardless of label count.

---

## [0.3.0] — 2026-05-19

### 🛡️ Survival Plan — Hardening & Resilience Release

This release implements the 8-axis survival plan to ensure long-term project viability.

### Added
- **LLM cascade fallback** (`rao/core/llm.py`): Groq → Ollama → graceful degradation. The framework now operates without any external LLM API.
- **Structured LLM output models** (`rao/core/structured_output.py`): `CriticVerdict`, `AttackStep`, `OperatorPlan` Pydantic models replace fragile string parsing.
- **Operator Agent v0.2** (`rao/agents/operator.py`): Generates actionable, tool-specific exploitation plans from validated CRITICAL/HIGH findings.
- **CVE local cache** (`rao/tools/cve_cache.py`): SQLite cache with 7-day TTL. NVD API outages no longer block scans.
- **Subdomain enumeration fallback** (`rao/tools/subdomain_enum.py`): HackerTarget as secondary source when crt.sh is unavailable.
- **Plugin system** (`rao/tools/plugin.py`): `ToolPlugin` protocol for adding custom tools without modifying core code.
- **GitHub Actions CI** (`.github/workflows/ci.yml`): Matrix testing on Python 3.10/3.11/3.12, ruff linting, dep-sync check.
- **Dependency management** (`requirements.in`, `requirements-dev.in`, `Makefile`): Bounded version ranges + `pip-compile` workflow.
- **`CONTRIBUTING.md`**: Full contribution guide including security policy, plugin protocol, and dependency rules.
- **`docker-compose.dev.yml`**: One-command developer environment with Ollama + ChromaDB + Neo4j.

### Changed
- **`rao/core/orchestrator.py`**: Pipeline extended to `Scout → Librarian → Critic → Operator → Report`.
- **`rao/core/state.py`**: Added `attack_plan: list[AttackStep]` field to `MissionState`.
- **`rao/agents/critic.py`**: Fixed dangerous fallback (previously kept ALL findings when LLM was down; now only CRITICAL/HIGH pass through).
- **`rao/tools/web_scanner.py`**: Neutral User-Agent, SSRF protection, opt-in SSL verification.
- **`rao/tools/scope_validator.py`**: Added `CRITICAL_BLOCKLIST` blocking 169.254/16, 224/4, 240/4, cloud metadata endpoints. Added `CRITICAL_BLOCKLIST_DOMAINS`.
- **`rao/cli.py`**: `--confirm` flag now required before any scan. Authorization events written to `results/audit.log`.

### Fixed
- LangGraph API compatibility (`StateGraph` constructor updated for v0.1.x).
- `CriticAgent` no longer silently passes all findings when LLM is unavailable.
- `SubdomainEnumerator` no longer fails completely when crt.sh returns HTTP 5xx.

---

## [0.2.0] — 2026-04-16

### Added
- `LibrarianAgent`: CVE correlation against discovered services.
- `CriticAgent`: LLM-based false positive filtering with confidence scores.
- ChromaDB integration for persistent knowledge storage.
- Neo4j integration for mission graph persistence.
- Report generation (JSON, Markdown).

### Changed
- `ScoutAgent`: Added parallel port scanning, improved OS detection.

---

## [0.1.0] — 2026-04-02

### Added
- Initial project structure.
- `ScoutAgent`: nmap-based host and port discovery.
- `WebScanner`: HTTP technology fingerprinting.
- `SubdomainEnumerator`: crt.sh Certificate Transparency lookup.
- `CVELookup`: NVD API integration.
- `ScopeValidator`: basic target validation.
- LangGraph orchestrator skeleton.
- CLI with `scan` command.

[Unreleased]: https://github.com/your-org/rao-framework/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/your-org/rao-framework/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/your-org/rao-framework/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/your-org/rao-framework/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/your-org/rao-framework/releases/tag/v0.1.0
