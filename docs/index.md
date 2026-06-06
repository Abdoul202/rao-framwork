# RAO-Framework — Documentation

> **Multi-Agent Autonomous Red Teaming Framework v0.5.0** — OWASP Top 10 Coverage 88%+

## Table des matières

| Document | Description |
|---|---|
| [getting-started.md](getting-started.md) | Installation, configuration, premier scan |
| [cli-reference.md](cli-reference.md) | Référence complète de toutes les commandes CLI |
| [architecture.md](architecture.md) | Architecture du pipeline, agents, graphe LangGraph |
| [configuration.md](configuration.md) | Variables d'environnement, providers LLM, Neo4j |
| [api-reference.md](api-reference.md) | API Python — usage programmatique |
| [plugin-development.md](plugin-development.md) | Créer et enregistrer un plugin d'outil |
| [security-model.md](security-model.md) | Scope validator, protection SSRF, audit log |
| [reports.md](reports.md) | Formats de rapports JSON et HTML |
| [troubleshooting.md](troubleshooting.md) | Problèmes courants et solutions |

## Vue d'ensemble

RAO-Framework est un framework de red team autonome basé sur des agents LLM. Il orchestre un pipeline d'agents spécialisés (Scout, Librarian, Critic, Operator) via LangGraph pour automatiser la reconnaissance, la corrélation de CVEs et la validation de findings.

```
Scout → Librarian → Critic → Operator → Rapport
     ↘              ↘
WebScanner      SubdomainEnum
JWTAnalyzer     SSLAnalyzer
OSINT           Nuclei
```

**Prérequis système :** Python ≥ 3.10, nmap, une clé API Groq (gratuite) ou Ollama local.

## Outils disponibles

| Outil | Commande CLI | Catégorie |
|---|---|---|
| Web Scanner (21 méthodes) | `rao webscan` | Recon + OWASP |
| JWT Analyzer | `rao jwt-scan` | Auth (A07) |
| SSL Analyzer | `rao ssl` | Crypto (A02) |
| OSINT 7 sources | `rao osint` | Recon |
| Nuclei 9000+ templates | `rao nuclei-scan` | CVE |
| Nmap Scanner | `rao scan` / `rao recon` | Recon |
| Subdomain Enumerator | `rao subdomains` | Recon |
| CVE Lookup (NVD) | `rao scan` | CVE |
| Scope Validator | (intégré) | Sécurité |

## Roadmap

| Version | Statut | Contenu |
|---|---|---|
| v0.1 | ✅ | MVP : Scout + Librarian + Critic + OCC |
| v0.1.1 | ✅ | Web scanner, subdomains, CLI, HTML reports, sessions |
| v0.1.2 | ✅ | Plugin system, CVE cache, structured LLM output (AttackStep) |
| v0.4.0 | ✅ | SSL Analyzer, OSINT, Nuclei, 90% test coverage |
| **v0.5.0** | ✅ **CURRENT** | JWT Analyzer, 21 méthodes web, OWASP Top 10 coverage 88%+ |
| v0.6.0 | 🛠️ Planned | Operator agent : exploitation automatisée, Neo4j attack paths |
| v0.7.0 | 🛠️ Planned | Streamlit dashboard temps réel |
| v1.0.0 | 🛠️ Planned | Full autonomous red team cycle + human-in-the-loop |

