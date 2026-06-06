# Configuration — RAO-Framework v0.5.0

Toute la configuration passe par des variables d'environnement chargées depuis `.env`.

## Fichier `.env`

Copier le template :
```bash
cp .env.example .env
```

---

## Variables d'environnement

### LLM Provider

| Variable | Défaut | Description |
|---|---|---|
| `LLM_PROVIDER` | `groq` | Provider actif : `groq` ou `ollama` |
| `GROQ_API_KEY` | _(vide)_ | Clé API Groq (gratuite sur console.groq.com) |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | URL du serveur Ollama local |
| `OLLAMA_MODEL` | `mistral` | Modèle Ollama à utiliser |

**Cascade de fallback LLM :**

Le framework essaie les providers dans cet ordre :
1. Provider configuré via `LLM_PROVIDER`
2. L'autre provider en fallback automatique
3. Mode hors-ligne (Critic utilise des règles déterministes)

Aucune configuration LLM ne fait jamais crasher le framework — il dégrade gracieusement.

---

### Neo4j

| Variable | Défaut | Description |
|---|---|---|
| `NEO4J_URI` | `bolt://localhost:7687` | URI de connexion |
| `NEO4J_USER` | `neo4j` | Utilisateur |
| `NEO4J_PASSWORD` | _(vide)_ | Mot de passe — **obligatoire si Neo4j est activé** |

> Si `NEO4J_PASSWORD` est vide, un warning est affiché au démarrage mais le framework continue sans Neo4j.

---

### ChromaDB (recherche vectorielle)

| Variable | Défaut | Description |
|---|---|---|
| `CHROMA_PERSIST_DIR` | `<projet>/chroma_data` | Répertoire de persistance des embeddings |

ChromaDB est une **dépendance optionnelle** (`pip install -e ".[vector]"`). Sans lui, la `KnowledgeBase` se désactive automatiquement.

---

### NVD API

| Variable | Défaut | Description |
|---|---|---|
| `NVD_API_KEY` | _(vide)_ | Clé API NVD (National Vulnerability Database) |

Sans clé NVD, les requêtes sont limitées à 5 req/30s. Avec clé (gratuite sur [nvd.nist.gov](https://nvd.nist.gov/developers/request-an-api-key)) : 50 req/30s.

---

### OSINT (optionnel)

Chaque source OSINT fonctionne indépendamment. Sans clé, WHOIS et URLScan fonctionnent quand même.

| Variable | Source | Description |
|---|---|---|
| `SHODAN_API_KEY` | Shodan | Port scanning, services exposés |
| `CENSYS_API_ID` | Censys | Certificate transparency |
| `CENSYS_API_SECRET` | Censys | Certificate transparency |
| `LEAKIX_API_KEY` | LeakIX | Services vulnérables indexés |
| `GREYNOISE_API_KEY` | GreyNoise | Réputation IP (scanners connus) |

> `HIBP_API_KEY` (HaveIBeenPwned) optionnel pour la vérification de fuites email.

---

### Nuclei

| Variable | Défaut | Description |
|---|---|---|
| `NUCLEI_TEMPLATES_PATH` | `~/.local/nuclei-templates` | Répertoire des templates Nuclei |
| `NUCLEI_SEVERITY_FILTER` | `medium,high,critical` | Sévérités à rapporter |

---

### Rapports

| Variable | Défaut | Description |
|---|---|---|
| `REPORT_OUTPUT_DIR` | `<projet>/results` | Répertoire de sortie des rapports JSON/HTML |

---

## Providers LLM — Configuration avancée

### Groq (recommandé)

Groq offre une inférence très rapide de modèles open-source. Gratuit pour usage personnel.

```env
LLM_PROVIDER=groq
GROQ_API_KEY=gsk_xxxxxxxxxxxxxxxxxxxx
```

Modèle utilisé : **`llama-3.3-70b-versatile`** (hardcodé dans `rao/core/llm.py`).

### Ollama (local, sans internet)

```env
LLM_PROVIDER=ollama
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=mistral
```

Prérequis :
```bash
# Installer Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Télécharger le modèle
ollama pull mistral

# Vérifier qu'Ollama tourne
ollama list
```

> Le framework vérifie que le modèle est bien disponible localement avant de l'utiliser. Si `mistral` n'est pas pulled, il passe automatiquement à Groq.

---

## Accès programmatique à la configuration

```python
from rao.config import settings

print(settings.llm.provider)          # "groq"
print(settings.llm.groq_api_key)      # clé Groq
print(settings.neo4j.uri)             # "bolt://localhost:7687"
print(settings.report_output_dir)     # "/path/to/results"
print(settings.nvd_api_key)           # clé NVD
print(settings.chroma.persist_dir)    # "/path/to/chroma_data"
```
