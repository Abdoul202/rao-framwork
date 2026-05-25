# Troubleshooting — RAO-Framework

## Installation

### `BackendUnavailable: Cannot import 'setuptools.backends.legacy'`

**Cause :** La version de setuptools dans le venv est trop ancienne (< 71).

**Fix :**
```bash
# Le pyproject.toml utilise maintenant setuptools.build_meta (stable)
pip install -e .  # fonctionne avec setuptools >= 40
```

---

### `Failed building wheel for chroma-hnswlib`

**Cause :** ChromaDB nécessite de compiler du C++. Le header `Python.h` est manquant.

**Fix option 1 — Ignorer ChromaDB** (recommandé) :
```bash
pip install -e .  # chromadb est une dépendance optionnelle
```

**Fix option 2 — Installer les headers Python** :
```bash
# Fedora / RHEL
sudo dnf install python3-devel

# Debian / Ubuntu
sudo apt install python3-dev

# Puis installer avec vector support
pip install -e ".[vector]"
```

---

## Scan / CLI

### `ValueError: SSRF protection: blocked request to internal address`

**Cause :** L'ancienne version du web scanner bloquait toutes les IPs privées.

**Fix :** Ce bug est corrigé. Mettre à jour le code et réinstaller :
```bash
pip install -e .
```

---

### `RuntimeError: nmap is required for the Scout agent`

**Cause :** nmap n'est pas installé sur le système.

**Fix :**
```bash
# Fedora / RHEL
sudo dnf install nmap

# Debian / Ubuntu
sudo apt install nmap

# Vérifier l'installation
nmap --version
```

---

### `ERROR: You must pass --confirm`

**Cause :** Le flag d'autorisation est obligatoire pour toute commande active.

**Fix :**
```bash
rao scan <target> --confirm
rao recon <target> --confirm
rao webscan <target> --confirm
```

---

### `Scope error: Public IP X.X.X.X not allowed`

**Cause :** Le `ScopeValidator` bloque par défaut les IPs publiques (`allow_public=False`).

**Fix :** Pour scanner une IP publique (avec autorisation), passer le scope explicitement :
```bash
rao scan 203.0.113.100 --confirm -s 203.0.113.0/24
```

Ou en Python :
```python
from rao.tools.scope_validator import ScopeValidator
validator = ScopeValidator(
    allowed_targets=["203.0.113.0/24"],
    allow_private=False,
    allow_public=True
)
```

---

## LLM / Provider

### `No LLM provider available`

**Cause :** Ni Groq ni Ollama ne sont configurés ou accessibles.

**Fix Groq** (gratuit) :
```bash
# 1. Créer une clé sur https://console.groq.com
# 2. Ajouter dans .env
echo "GROQ_API_KEY=gsk_xxxxxxxxxxxx" >> .env
```

**Fix Ollama** :
```bash
# 1. Installer Ollama
curl -fsSL https://ollama.com/install.sh | sh

# 2. Télécharger un modèle
ollama pull mistral

# 3. Configurer dans .env
echo "LLM_PROVIDER=ollama" >> .env
echo "OLLAMA_MODEL=mistral" >> .env
```

> **Note :** Sans LLM, le framework fonctionne en mode offline — le Critic garde uniquement les findings CRITICAL/HIGH de façon déterministe.

---

### `Ollama: model 'mistral' not found locally`

**Cause :** Le modèle n'est pas téléchargé localement.

**Fix :**
```bash
ollama pull mistral
# ou le modèle configuré dans OLLAMA_MODEL
ollama list  # vérifier les modèles disponibles
```

---

## Neo4j

### `NEO4J_PASSWORD is not set`

**Cause :** La variable `NEO4J_PASSWORD` est vide dans `.env`.

**Fix :**
```bash
# Éditer .env
NEO4J_PASSWORD=votre_mot_de_passe_neo4j
```

> Ce warning est non-fatal — le framework continue sans Neo4j.

---

### Connexion Neo4j refusée

**Cause :** Neo4j n'est pas démarré.

**Fix :**
```bash
docker compose up -d
# Vérifier que Neo4j tourne
docker compose ps
```

---

## Tests

### `ModuleNotFoundError: No module named 'rao'`

**Cause :** Le package n'est pas installé dans l'environnement virtuel actif.

**Fix :**
```bash
source venv/bin/activate
pip install -e .
pytest tests/ -v
```

---

### Tests lents (timeout NVD API)

**Cause :** Les tests qui appellent la NVD API peuvent être lents sans clé API.

**Fix :**
```bash
# Ajouter une clé NVD dans .env
NVD_API_KEY=votre_cle_nvd
```

Ou mocker dans les tests (voir `tests/conftest.py`).

---

## Rapports

### Le rapport HTML ne s'ouvre pas

**Fix :**
```bash
# Chemin absolu
firefox /home/user/rao-framework/results/rao_report_*.html

# Ou servir via HTTP
cd results && python3 -m http.server 8080
# Ouvrir http://localhost:8080
```

---

### `results/` n'existe pas

**Cause :** Répertoire créé automatiquement au premier scan. Si absent :
```bash
mkdir -p results
```

---

## Logs de débogage

Pour obtenir des logs détaillés :

```bash
rao scan <target> --confirm -v
```

Ou en Python :
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

Les loggers utilisés :
- `rao.agents.scout` — Scout agent
- `rao.agents.librarian` — Librarian + NVD
- `rao.agents.critic` — Critic + LLM
- `rao.tools.nmap_wrapper` — Nmap
- `rao.tools.web_scanner` — Web scan
- `rao.tools.cve_lookup` — NVD API
- `rao.reporting.report_generator` — Rapports
