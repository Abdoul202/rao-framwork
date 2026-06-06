# Getting Started — RAO-Framework v0.5.0

## Prérequis

| Composant | Version minimale | Rôle |
|---|---|---|
| Python | 3.10+ | Runtime |
| nmap | 7.0+ | Scan réseau (Scout agent) |
| Groq API key **ou** Ollama | — | LLM pour analyse CVE et validation |

### Installer nmap

```bash
# Fedora / RHEL
sudo dnf install nmap

# Debian / Ubuntu
sudo apt install nmap

# macOS
brew install nmap
```

---

## Installation

### 1. Cloner le dépôt

```bash
git clone https://github.com/Abdoul202/rao-framework.git
cd rao-framework
```

### 2. Créer et activer un environnement virtuel

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Installer le framework

```bash
pip install -e .
```

> **Note :** Le paramètre `-e` installe en mode éditable — les modifications du code source sont prises en compte immédiatement sans réinstallation.

#### Activer la recherche vectorielle (optionnel)

ChromaDB nécessite des headers de développement Python pour compiler son extension C++ :

```bash
# Fedora / RHEL
sudo dnf install python3-devel

# Debian / Ubuntu
sudo apt install python3-dev

# Puis installer l'extra vector
pip install -e ".[vector]"
```

### 4. Configurer l'environnement

```bash
cp .env.example .env
```

Éditer `.env` avec vos clés :

```env
# LLM Provider (groq ou ollama)
LLM_PROVIDER=groq
GROQ_API_KEY=gsk_xxxxxxxxxxxxxxxxxxxxxxxx

# Neo4j (optionnel — désactivé par défaut)
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=votre_mot_de_passe

# NVD API (optionnel — améliore la recherche CVE)
NVD_API_KEY=votre_cle_nvd

# Répertoire de sortie des rapports
REPORT_OUTPUT_DIR=results
```

> **Groq est gratuit** : créez une clé sur [console.groq.com](https://console.groq.com)

#### Optionnel : Nuclei (pour `rao nuclei-scan`)

```bash
# Installer Nuclei (Go requis, ou binaire direct)
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
# OU télécharger le binaire depuis https://github.com/projectdiscovery/nuclei/releases
```

#### Optionnel : clés OSINT (pour `rao osint`)

Dans `.env`, ajouter les clés optionnelles pour activer chaque source :

```env
SHODAN_API_KEY=votre_cle_shodan
CENSYS_API_ID=votre_id_censys
CENSYS_API_SECRET=votre_secret_censys
LEAKIX_API_KEY=votre_cle_leakix
GREYNOISE_API_KEY=votre_cle_greynoise
# Sans clé : WHOIS + URLScan fonctionnent quand même
```

---

## Vérifier l'installation

```bash
# Vérifier la version (doit afficher 0.5.0)
rao --version

# Afficher l'aide générale
rao --help

# Lister toutes les commandes disponibles
rao scan --help
rao recon --help
rao webscan --help
rao jwt-scan --help
rao ssl --help
rao osint --help
rao nuclei-scan --help
rao subdomains --help
```

---

## Premier scan

> ⚠️ **Vous devez avoir une autorisation écrite explicite avant de scanner toute cible.**

### Reconnaissance rapide (nmap + web scan)

```bash
rao recon 192.168.1.100 --confirm
```

### Scan complet avec rapport HTML

```bash
rao scan 192.168.1.100 --confirm --html --save
```

### Scan d'un site web uniquement

```bash
# Scan passif (headers, paths, CORS, cookies, tech)
rao webscan https://example.com --confirm

# + Injections actives (SQLi, XSS, SSTI, SSRF, IDOR…)
rao webscan https://example.com --confirm --inject

# + Test auth (credentials par défaut + rate limiting)
rao webscan https://example.com --confirm --inject --test-auth
```

### Analyse JWT

```bash
# Analyse offline d'un token
rao jwt-scan eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyIn0.XYZ

# + test live alg:none
rao jwt-scan <token> --target https://api.example.com/profile
```

### OSINT + Nuclei

```bashao osint example.com
rao nuclei-scan https://example.com --confirm
rao ssl https://example.com
```

---

## Neo4j (optionnel)

Neo4j est utilisé pour persister le graphe de connaissances. Il est **optionnel** — le framework fonctionne entièrement sans lui.

Pour le démarrer :

```bash
docker compose up -d
```

Ou en mode développement avec monitoring :

```bash
docker compose -f docker-compose.dev.yml up -d
```

---

## Installation des dépendances de développement

```bash
pip install -e ".[dev]"

# Lancer les tests
pytest tests/ -v

# Linter
ruff check rao/
```
