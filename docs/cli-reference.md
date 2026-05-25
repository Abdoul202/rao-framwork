# CLI Reference — RAO-Framework

## Vue d'ensemble

```
rao [OPTIONS] COMMAND [ARGS]...

Options:
  --version   Afficher la version et quitter
  --help      Afficher l'aide

Commandes:
  scan        Scan complet (nmap + CVE + web + subdomains + rapport)
  recon       Reconnaissance rapide (nmap + web scan)
  webscan     Scan web uniquement (headers, paths, CORS, cookies)
  subdomains  Énumération de sous-domaines (passif)
  sessions    Gestion des sessions sauvegardées
```

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

### Ce qui est vérifié

| Catégorie | Détails |
|---|---|
| **Security Headers** | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, X-XSS-Protection |
| **Technologies** | Détection via headers et body (WordPress, PHP, Django, React, Next.js…) |
| **Paths sensibles** | `/.env`, `/.git/HEAD`, `/admin`, `/phpinfo.php`, `/swagger.json`, `/graphql`… |
| **CORS** | Reflection d'origine arbitraire, wildcard avec credentials |
| **Cookies** | Flags Secure, HttpOnly, SameSite |
| **Info leaks** | Stack traces, SQL errors, debug mode dans le body |

### Exemples

```bash
rao webscan https://target.local --confirm
rao webscan 192.168.1.100 --confirm
rao webscan http://api.example.com:8080 --confirm
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

## Codes de sortie

| Code | Description |
|---|---|
| `0` | Succès |
| `1` | Erreur (pas de `--confirm`, scope violation, cible inaccessible) |

---

## Audit log

Chaque scan avec `--confirm` génère une entrée dans `results/audit.log` :

```
2026-05-25T17:30:37.000000Z | AUTHORIZED_SCAN | target=192.168.1.100 | pid=12345
```
