# Modèle de Sécurité — RAO-Framework

Ce document décrit les mécanismes de sécurité intégrés au framework.

---

## 1. Autorisation explicite (`--confirm`)

**Toute commande active** (scan, recon, webscan) nécessite le flag `--confirm` :

```bash
rao scan 192.168.1.100 --confirm
```

Sans ce flag, le programme quitte immédiatement avec un message d'erreur (exit code 1). Cela prévient les scans accidentels.

Chaque scan confirmé génère une entrée dans `results/audit.log` :

```
2026-05-25T17:30:37.000000Z | AUTHORIZED_SCAN | target=192.168.1.100 | pid=12345
```

> `subdomains` est passif (requêtes DNS/crt.sh uniquement) et ne requiert pas `--confirm`.

---

## 2. Scope Validator

**Fichier :** `rao/tools/scope_validator.py`

Valide chaque cible avant tout scan. Supporte IPs, CIDRs, et domaines.

### Blocklist critique (non contournable)

Ces plages sont **absolument bloquées**, indépendamment du scope déclaré :

| Plage | Raison |
|---|---|
| `0.0.0.0/8` | "This" network (RFC 1122) |
| `127.0.0.0/8` | Loopback |
| `169.254.0.0/16` | Link-local — **métadonnées cloud** (AWS IMDSv1, GCP, Azure) |
| `224.0.0.0/4` | Multicast |
| `240.0.0.0/4` | Réservé (RFC 1112) |
| `255.255.255.255/32` | Broadcast |
| `::1/128` | Loopback IPv6 |
| `fe80::/10` | Link-local IPv6 |
| `ff00::/8` | Multicast IPv6 |

Domaines bloqués : `metadata.google.internal`, `instance-data`, `169.254.169.254`

### Comportement selon le mode

```python
# Mode interne (défaut CLI) — IPs privées autorisées
ScopeValidator(allowed_targets=["192.168.0.0/16"], allow_private=True, allow_public=False)

# Mode externe — IPs publiques autorisées, privées bloquées
ScopeValidator(allowed_targets=["203.0.113.0/24"], allow_private=False, allow_public=True)
```

### Résolution DNS avec timeout

Les domaines sont résolus avec un timeout de 5 secondes (évite les blocages indéfinis sur DNS lent) :

```python
socket.setdefaulttimeout(5.0)
ip_str = socket.gethostbyname(domain)
```

---

## 3. Protection SSRF dans le Web Scanner

**Fichier :** `rao/tools/web_scanner.py`

Le `WebScanner` dispose d'un mode strict SSRF via le paramètre `allow_private` :

```python
# Mode CLI (défaut) — IPs privées autorisées, protection gérée par ScopeValidator + --confirm
WebScanner(allow_private=True)

# Mode API serveur — bloquer toute IP privée/loopback/link-local
WebScanner(allow_private=False)
```

En mode strict (`allow_private=False`), toute tentative de scan d'une IP interne lève une `ValueError` avant d'effectuer la requête HTTP.

---

## 4. Sanitisation des données NVD (protection prompt injection)

**Fichier :** `rao/agents/librarian.py`

Les descriptions CVE proviennent de la NVD (source externe non fiable). Avant injection dans un prompt LLM, elles sont sanitisées :

```python
# Supprime les lignes contenant des patterns de prompt injection
_INJECTION_PATTERNS = re.compile(
    r"^\s*(VERDICT|FINDING|TOOL|SEVERITY|CVE_ID|...):",
    re.IGNORECASE | re.MULTILINE
)

def _sanitize_for_prompt(text: str) -> str:
    sanitized = _INJECTION_PATTERNS.sub("", text)
    # Supprime les caractères de contrôle
    sanitized = "".join(c for c in sanitized if ord(c) >= 32 or c == "\n")
    return sanitized.strip()[:200]  # Limite à 200 chars
```

---

## 5. Pas de secrets dans le code source

**Fichier :** `rao/config.py`

Aucun mot de passe ni clé API n'est hardcodé. Tous les secrets passent par variables d'environnement :

```python
# BUG #29 fix: pas de mot de passe par défaut dans le code
password: str = Field(default="", alias="NEO4J_PASSWORD")
```

Un warning est émis si `NEO4J_PASSWORD` est vide au démarrage.

---

## 6. User-Agent neutre

Le web scanner utilise un User-Agent générique qui n'identifie pas l'outil :

```python
DEFAULT_USER_AGENT = "Mozilla/5.0 (compatible; SecurityScanner/1.0)"
```

---

## 7. Suppression ciblée des warnings SSL

Les warnings `InsecureRequestWarning` de urllib3 sont désactivés **uniquement sur la session HTTP du scanner**, pas globalement :

```python
# Correct — scope limité à la session
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Incorrect — affecterait tout le process
# warnings.filterwarnings("ignore")
```

---

## 8. Rate-limiting des probes de paths

Entre chaque probe de path (`/.env`, `/.git/HEAD`, etc.), un délai configurable est ajouté pour éviter de déclencher les WAF/IDS :

```python
WebScanner(path_scan_delay=0.05)  # 50ms entre chaque probe
```

---

## 9. Fallback offline du Critic

Quand le LLM est indisponible, le Critic applique une politique conservative :

- **Garde** : findings CRITICAL et HIGH (avec `validated=False`)
- **Supprime** : MEDIUM, LOW, INFO (trop de bruit sans validation LLM)

---

## Checklist de déploiement sécurisé

- [ ] `.env` n'est pas committé (vérifié dans `.gitignore`)
- [ ] `NEO4J_PASSWORD` est défini dans `.env`
- [ ] `GROQ_API_KEY` est défini dans `.env`
- [ ] Scans effectués uniquement sur des cibles avec autorisation écrite
- [ ] `results/audit.log` archivé après chaque mission
- [ ] `allow_private=False` si WebScanner est exposé comme API
