# Changelog

All notable changes to RAO-Framework will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

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

[Unreleased]: https://github.com/your-org/rao-framework/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/your-org/rao-framework/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/your-org/rao-framework/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/your-org/rao-framework/releases/tag/v0.1.0
