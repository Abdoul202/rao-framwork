# CLI Reference — RAO-Framework v0.6.0

## Vue d'ensemble

```
rao [OPTIONS] COMMAND [ARGS]...

Options:
  --version   Afficher la version et quitter
  --help      Afficher l'aide

Commandes:
  audit       ⭐ Audit complet ALL-IN-ONE (RECOMMANDÉ)
  scan        Scan nmap + CVE + LLM
  recon       Reconnaissance rapide (nmap + web scan)
  webscan     Scan web (headers, paths, CORS, cookies, injections)
  ssl         Analyse SSL/TLS approfondie
  osint       Collecte OSINT multi-sources
  nuclei-scan Scan Nuclei (9000+ templates CVE)
  jwt-scan    Analyse de sécurité JWT
  llm-redteam Red teaming LLM continu (OWASP LLM Top 10 + ATLAS)
  llm-eval    Mesure FP/FN du scanner LLM (cibles vérité-terrain)
  subdomains  Énumération de sous-domaines (passif)
  sessions    Gestion des sessions sauvegardées
```

---

## `rao audit` — Audit complet ALL-IN-ONE ⭐ (RECOMMANDÉ)

Lance **tous les modules** en une seule commande orchestrée :
- Nmap + CVE + LLM (Librarian)
- Web scan (30 types d'injection actifs par défaut)
- SSL/TLS analysis
- OSINT (7 sources)
- Nuclei (si installé)
- Subdomain enumeration (500+ prefixes)
- LLM Critic validation **visible** (per-finding)
- LLM Operator attack plan **affiché** dans le terminal
- Rapports JSON + HTML

```bash
rao audit TARGET [OPTIONS]
```

### Arguments

| Argument | Description |
|---|---|
| `TARGET` | URL (`https://example.com`), IP, ou domaine |

### Options

| Option | Default | Description |
|---|---|---|
| `--confirm` | off | **REQUIS** — confirme l'autorisation écrite |
| `--scope, -s` | — | Scope supplémentaire (IP, CIDR, domaine). Répétable. |
| `--jwt TOKEN` | — | Token JWT à analyser (phase 7) |
| `--jwt-target URL` | — | URL pour le test live alg:none |
| `--no-web` | off | Ignorer le web scan |
| `--no-inject` | off | Ignorer les injections actives |
| `--no-auth` | off | Ignorer les tests d'authentification |
| `--no-ssl` | off | Ignorer l'analyse SSL |
| `--no-osint` | off | Ignorer l'OSINT |
| `--no-nuclei` | off | Ignorer Nuclei |
| `--no-subdomains` | off | Ignorer l'énumération |
| `--no-cve` | off | Ignorer nmap + CVE + LLM (Phase 1) |
| `--nuclei-severity` | `medium,high,critical` | Filtre de sévérité Nuclei |
| `--html` | on | Générer un rapport HTML |
| `--no-html` | off | Désactiver le rapport HTML |
| `--save` | off | Sauvegarder la session |
| `--verbose, -v` | off | Mode verbeux |

### Exemples

```bash
# Audit complet standard
rao audit https://example.com --confirm

# Avec rapport HTML + sauvegarde session
rao audit https://example.com --confirm --html --save

# Audit web uniquement (sans nmap/CVE)
rao audit https://example.com --confirm --no-cve --html

# Audit rapide (sans Nuclei ni subdomains)
rao audit https://example.com --confirm --no-nuclei --no-subdomains --html

# Audit passif uniquement (aucun payload actif)
rao audit https://example.com --confirm --no-inject --no-auth

# Avec analyse JWT
rao audit https://example.com --confirm --jwt eyJhbGc...
```

### Phases exécutées

```
1.  Scope Validator    → Vérifie l'autorisation de la cible
2.  Scout (nmap)       → Découverte hôtes, ports, services
3.  Librarian (LLM)   → Corrélation CVE + analyse LLM
4.  Web Scanner        → 30 types de détection (actifs + passifs)
5.  SSL Analyzer       → Protocoles, certificat, ciphers
6.  OSINT              → 7 sources (Shodan, Censys, WHOIS…)
7.  Nuclei             → 9000+ templates (si installé)
8.  Subdomain Enum     → crt.sh + DNS brute-force
9.  JWT Analyzer       → Si --jwt TOKEN
10. Critic (LLM) ✨    → Validation visible par finding (✅/❌)
11. Operator (LLM) ✨  → Plan d'attaque affiché (table Rich)
12. Reports            → JSON + HTML (nom basé sur le domaine)
13. Session Save       → Si --save
```

> **Filenames des rapports**: basés sur le domaine extrait de l'URL.
> `https://example.com/` → `results/rao_report_example_com_20260607_120000.json`

---

## `rao scan` — Scan complet

Lance le pipeline complet : Scout → Librarian → Critic → Operator + Web scan + Subdomains.

```bash
rao scan TARGET [OPTIONS]
```

### Arguments

| Argument | Description |
|---|---|
| `TARGET` | IP, CIDR, ou domaine cible |

### Options

| Option | Description |
|---|---|
| `--confirm` | **REQUIS** — confirme l'autorisation écrite de scanner |
| `--scope, -s` | Ajouter une entrée de scope (IP, CIDR, domaine). Répétable. |
| `--no-web` | Ignorer le web scan |
| `--no-subdomains` | Ignorer l'énumération de sous-domaines |
| `--html` | Générer un rapport HTML |
| `--save` | Sauvegarder la session pour reprise ultérieure |
| `--verbose, -v` | Mode verbeux (logs DEBUG) |

### Exemples

```bash
# Scan minimal
rao scan 192.168.1.100 --confirm

# Scan avec rapport HTML et sauvegarde
rao scan 192.168.1.100 --confirm --html --save

# Scan avec scope élargi
rao scan 192.168.1.100 --confirm -s 192.168.1.0/24 -s 10.0.0.0/8

# Sans web scan ni subdomains
rao scan 192.168.1.100 --confirm --no-web --no-subdomains

# Mode verbeux pour debug
rao scan 192.168.1.100 --confirm -v
```

### Phases exécutées

```
1. Scope Validator   → Vérifie que la cible est dans le scope déclaré
2. Scout             → nmap -sV -sC --top-ports 1000
3. Librarian         → Requêtes NVD + analyse LLM par service
4. Critic            → Validation LLM des findings
5. Operator          → Génération du plan d'attaque
6. Web Scanner       → Scan HTTP (si --no-web non spécifié)
7. Subdomain Enum    → crt.sh + DNS (si cible est un domaine)
8. Rapport           → Console + JSON (+ HTML si --html)
```

---

## `rao recon` — Reconnaissance rapide

Scout (nmap) + Web scan uniquement. **Pas d'analyse CVE ni LLM.**

```bash
rao recon TARGET [OPTIONS]
```

### Options

| Option | Description |
|---|---|
| `--confirm` | **REQUIS** |
| `--verbose, -v` | Mode verbeux |

### Exemples

```bash
rao recon 192.168.100.189 --confirm
rao recon 10.0.0.1 --confirm -v
```

### Sortie

```
Scout → découverte des hôtes et ports
Web Scanner → headers, paths, CORS, cookies
Rapport → Console + JSON
```

> **Quand utiliser recon vs scan ?**
> - `recon` : première exploration rapide, pas de LLM nécessaire
> - `scan` : analyse complète avec corrélation CVE et validation

---

## `rao webscan` — Scan web uniquement

Analyse HTTP d'une URL cible (pas de nmap).

```bash
rao webscan TARGET [OPTIONS]
```

### Arguments

| Argument | Description |
|---|---|
| `TARGET` | URL (`https://example.com`) ou IP/hostname (ajout `https://` automatique) |

### Options

| Option | Description |
|---|---|
| `--confirm` | **REQUIS** |
| `--verbose, -v` | Mode verbeux |

### Ce qui est vérifié (passif — toujours actif)

| Catégorie | Détails |
|---|---|
| **Security Headers** | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| **Technologies** | Détection via headers et body (WordPress, PHP, Django, React, Next.js…) |
| **Paths sensibles** | 500+ paths : `/.env`, `/.git/HEAD`, `/admin`, `/phpinfo.php`, `/graphql`… |
| **CORS** | Reflection d'origine arbitraire, wildcard avec credentials |
| **Cookies** | Flags Secure, HttpOnly, SameSite |
| **Info leaks** | Stack traces, SQL errors, debug mode |
| **Source maps** | `.js.map`, `.css.map` exposés |
| **SRI missing** | Scripts CDN sans `integrity=` |
| **Token in URL** | JWT/session dans query string |

### Injections actives (`--inject`) — 22 types

| # | Type | Méthode |
|---|---|---|
| 1 | SQLi GET (error-based) | `_test_sqli` |
| 2 | SQLi POST | `_test_sqli_post` |
| 3 | SQLi Blind (time-based) | `_test_sqli_blind` |
| 4 | XSS Reflected | `_test_xss` |
| 5 | SSTI (5 engines) | `_test_ssti` |
| 6 | XXE | `_test_xxe` |
| 7 | Command Injection | `_test_command_injection` |
| 8 | CRLF | `_test_crlf` |
| 9 | NoSQL Injection | `_test_nosql_injection` |
| 10 | GraphQL Introspection | `_test_graphql` |
| 11 | SSRF | `_test_ssrf_params` |
| 12 | IDOR | `_test_idor` |
| 13 | Path Traversal / LFI | `_test_path_traversal` |
| 14 | Open Redirect | `_test_open_redirect` |
| 15 | **Log4Shell** (CVE-2021-44228) | `_test_log4j` |
| 16 | **Host Header Injection** | `_test_host_header_injection` |
| 17 | **LDAP Injection** | `_test_ldap_injection` |
| 18 | **XPath Injection** | `_test_xpath_injection` |
| 19 | **Prototype Pollution** | `_test_prototype_pollution` |
| 20 | **HTTP Request Smuggling** | `_test_http_request_smuggling` |
| 21 | **Insecure Deserialization** | `_test_deserialization` |
| 22 | **CSRF Token Absence** | `_check_csrf` |

### Exemples

```bash
# Passif uniquement
rao webscan https://target.local --confirm

# + 22 injections actives
rao webscan https://target.local --confirm --inject

# + tests d'authentification
rao webscan https://target.local --confirm --inject --test-auth
```

---

## `rao jwt-scan` — Analyse de sécurité JWT

Analyse statique et dynamique d'un token JWT. **100% offline par défaut** (aucun appel réseau sans `--target`).

```bash
rao jwt-scan TOKEN [OPTIONS]
```

### Arguments

| Argument | Description |
|---|---|
| `TOKEN` | Token JWT complet (`eyJ...`) |

### Options

| Option | Description |
|---|---|
| `--target URL` | URL cible pour le test live alg:none (envoie le token forgé) |
| `--verbose, -v` | Mode verbeux |

### Ce qui est analysé

| Vecteur | Description |
|---|---|
| **alg:none** | Détecte si le header déclare `alg:none` (signature ignorée) |
| **Secret faible** | Brute-force offline HS256/HS384/HS512 (40+ secrets courants : `secret`, `password`, `changeme`…) |
| **Token expiré** | Vérifie le claim `exp` |
| **Durée excessive** | Flag si validité > 1 an |
| **`exp` absent** | Token valide à vie |
| **`iat` absent** | Impossible de valider l'âge du token |
| **Données sensibles** | Détecte `password`, `api_key`, `credit_card`… dans le payload non chiffré |

### Exemples

```bash
# Analyse complète offline
rao jwt-scan eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc

# + Test live alg:none sur une URL cible
rao jwt-scan <token> --target https://api.example.com/profile

# Exemple de sortie
# ┌─────────────────────────────────────────────┐
# │ JWT Security Analysis                        │
# ├──────────────┬──────────────────────────────┤
# │ Algorithm    │ HS256                        │
# │ Subject      │ user_42                      │
# │ Expires      │ 2027-01-01T00:00:00Z         │
# ├──────────────┴──────────────────────────────┤
# │ FINDINGS                                    │
# │ [HIGH] Weak secret found: "secret"          │
# │ [INFO] Token expires in 577 days (>1 year)  │
# └─────────────────────────────────────────────┘
```

---

## `rao ssl` — Analyse SSL/TLS

Analyse approfondie de la configuration TLS d'un serveur.

```bash
rao ssl TARGET [OPTIONS]
```

Vérifie : protocoles (SSLv2/3, TLS 1.0/1.1), certificat (expiry, CN, SANs), HSTS, chiffrement faible, indicateur Heartbleed.

---

## `rao osint` — Collecte OSINT

Collecte d'informations depuis 7 sources publiques (Shodan, Censys, WHOIS, LeakIX, URLScan, GreyNoise, HaveIBeenPwned).

```bash
rao osint TARGET [OPTIONS]
```

---

## `rao nuclei-scan` — Scan Nuclei

Lance Nuclei avec les templates communautaires (9000+) sur la cible.

```bash
rao nuclei-scan TARGET [OPTIONS]
```

---

## `rao subdomains` — Énumération de sous-domaines

Recherche passive + brute-force DNS. **Ne nécessite pas `--confirm`** (passif).

```bash
rao subdomains DOMAIN [OPTIONS]
```

### Options

| Option | Description |
|---|---|
| `--verbose, -v` | Mode verbeux |

### Méthodes utilisées

1. **crt.sh** — Certificate Transparency logs (passif)
2. **Brute-force DNS** — Wordlist intégrée de sous-domaines courants

### Exemple

```bash
rao subdomains example.com
rao subdomains target.local -v
```

---

## `rao sessions` — Gestion des sessions

Les sessions permettent de sauvegarder et reprendre une mission.

### `rao sessions list`

```bash
rao sessions list
```

Affiche un tableau de toutes les sessions sauvegardées :

```
┌──────────────────┬─────────────────┬──────────────────────┬───────┬──────────┬──────────────────────┐
│ Name             │ Target          │ Phase                │ Hosts │ Findings │ Saved At             │
├──────────────────┼─────────────────┼──────────────────────┼───────┼──────────┼──────────────────────┤
│ mission_20260525 │ 192.168.1.100   │ reporting            │ 3     │ 12       │ 2026-05-25T17:30:00  │
└──────────────────┴─────────────────┴──────────────────────┴───────┴──────────┴──────────────────────┘
```

### `rao sessions resume NAME`

Reprend une mission sauvegardée depuis la phase où elle s'était arrêtée.

```bash
rao sessions resume mission_20260525
rao sessions resume mission_20260525 --html   # + rapport HTML
```

---

## `rao llm-redteam` — Red teaming LLM continu

Attaque un endpoint LLM et **prouve** chaque faille (détecteurs déterministes
d'abord, juge LLM conservateur biaisé 0 faux positif ensuite). Findings mappés
**OWASP LLM Top 10 (2025)** + **MITRE ATLAS**. Premier moteur **async** du projet
(httpx + concurrence bornée). Voir [LLM_REDTEAM.md](LLM_REDTEAM.md).

```bash
# Endpoint OpenAI-compatible (OpenAI, Groq, vLLM, Ollama /v1, LM Studio…)
rao llm-redteam --openai http://localhost:8000/v1 --model my-model --judge --confirm --json

# Endpoint HTTP générique via profil YAML
rao llm-redteam --profile target.yaml --confirm

# Mode continu / gate CI : échoue si une NOUVELLE faille apparaît vs baseline
rao llm-redteam --profile target.yaml --baseline --ci --confirm
```

### Options

| Option | Default | Description |
|---|---|---|
| `--profile, -p PATH` | — | Profil cible YAML (voir `rao/tools/llm_redteam/data/targets/`) |
| `--openai BASE` | — | Mode rapide : `api_base` OpenAI-compatible (ex. `http://localhost:8000/v1`) |
| `--model NAME` | — | Nom du modèle (avec `--openai`) |
| `--api-key-env VAR` | `OPENAI_API_KEY` | Variable d'env contenant la clé API (avec `--openai`) |
| `--system TEXT` | — | System prompt sous lequel placer la cible (avec `--openai`) |
| `--categories LIST` | — | Filtre OWASP, ex. `LLM01,LLM07` |
| `--known-secret TEXT` | — | Secret connu présent dans le contexte de la cible → rend LLM02 (exfil) **déterministe**. Répétable. |
| `--system-marker TEXT` | — | Marqueur connu du system prompt de la cible → rend LLM07 (fuite) **déterministe**. Répétable. |
| `--judge / --no-judge` | config | Juge LLM conservateur pour les cas ambigus |
| `--baseline` | off | Compare et met à jour la baseline de la cible |
| `--ci` | off | Sort en code ≠ 0 si une faille `NEW` apparaît (implique `--baseline`) |
| `--json` | off | Écrit un rapport JSON (`results/llm_redteam/<id>/`) |
| `--confirm` | off | **REQUIS** — confirme l'autorisation écrite |
| `--verbose, -v` | off | Logs détaillés |

### Couverture (POC)

| OWASP LLM | Probe | Détecteur déterministe |
|---|---|---|
| LLM01 Prompt Injection | directe + indirecte (document empoisonné) | canary echo |
| LLM01 (ATLAS AML.T0054) | jailbreaks (DAN, encodage) | refus → bloqué ; sinon juge |
| LLM02 Sensitive Info Disclosure | extraction de secret/clé | canary / juge |
| LLM05 Improper Output Handling | XSS-via-LLM | markup exécutable |
| LLM06 Excessive Agency | invocation d'outil non autorisée | juge |
| LLM07 System Prompt Leakage | extraction verbatim | sentinel / juge |

---

## `rao llm-eval` — Évaluation FP/FN du scanner

Mesure le taux de faux positifs / faux négatifs du scanner contre des cibles à
vérité-terrain (mocks vulnérable + durci). Imprime une matrice de confusion et
**échoue si un seul faux positif** apparaît (critère : FP = 0).

```bash
rao llm-eval            # détecteurs déterministes seuls
rao llm-eval --judge    # avec le juge LLM (rappel plus élevé)
```

| Option | Default | Description |
|---|---|---|
| `--judge / --no-judge` | off | Utilise le juge LLM pendant l'évaluation |
| `--verbose, -v` | off | Logs détaillés |

---

## Codes de sortie

| Code | Description |
|---|---|
| `0` | Succès |
| `1` | Erreur (pas de `--confirm`, scope violation, cible inaccessible) ou, pour `llm-redteam --ci`, régression `NEW` détectée ; pour `llm-eval`, faux positif détecté |

---

## Audit log

Chaque scan avec `--confirm` génère une entrée dans `results/audit.log` :

```
2026-05-25T17:30:37.000000Z | AUTHORIZED_SCAN | target=192.168.1.100 | pid=12345
```
