# RAO-Framework — Documentation

> **Multi-Agent Autonomous Red Teaming Framework v0.1.0**

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
```

**Prérequis système :** Python ≥ 3.10, nmap, une clé API Groq (gratuite) ou Ollama local.
