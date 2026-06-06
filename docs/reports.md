# Rapports — RAO-Framework v0.5.0

Les rapports sont générés automatiquement à la fin de chaque scan dans le répertoire `results/`.

---

## Formats disponibles

| Format | Commande | Fichier généré |
|---|---|---|
| **Console** | Toujours actif | Affiché dans le terminal |
| **JSON** | Toujours actif | `results/rao_report_<ip>_<timestamp>.json` |
| **HTML** | `--html` | `results/rao_report_<ip>_<timestamp>.html` |

---

## Rapport Console

Affiché automatiquement via Rich. Exemple de sortie :

```
============================================================
  RAO-Framework - Mission Report
============================================================

Target: 192.168.100.189
Hosts discovered: 1
Total findings: 7
Validated findings: 3

╭───────────────────────── Mission Complete ──────────────────────────╮
│ Hosts: 1  |  Findings: 7  |  Validated: 3  |  Web scans: 1  |      │
│ Subdomains: 0  |  Errors: 0                                         │
╰─────────────────────────────────────────────────────────────────────╯
```

---

## Rapport JSON

Fichier machine-readable pour intégration avec d'autres outils (SIEM, Jira, etc.).

### Structure

```json
{
  "meta": {
    "framework": "RAO-Framework",
    "version": "0.5.0",
    "timestamp": "2026-05-25T17:30:37.537055+00:00",
    "target": "192.168.100.189"
  },
  "summary": {
    "hosts_discovered": 1,
    "total_findings": 7,
    "validated_findings": 3,
    "by_severity": {
      "critical": 0,
      "high": 2,
      "medium": 4,
      "low": 1,
      "info": 0
    }
  },
  "hosts": [
    {
      "ip": "192.168.100.189",
      "hostname": "fedora",
      "os": "",
      "open_ports": [
        {
          "port": 80,
          "protocol": "tcp",
          "service": "http",
          "version": "Apache httpd 2.4.67 (Fedora Linux)"
        },
        {
          "port": 3306,
          "protocol": "tcp",
          "service": "mysql",
          "version": "MariaDB unauthorized"
        }
      ]
    }
  ],
  "findings": [
    {
      "title": "CVE-2024-XXXX - Remote Code Execution",
      "severity": "high",
      "host": "192.168.100.189",
      "port": 80,
      "description": "...",
      "evidence": "...",
      "cve_ids": ["CVE-2024-XXXX"],
      "validated": true,
      "false_positive": false
    }
  ],
  "attack_steps": [
    {
      "finding": "CVE-2024-XXXX",
      "tool": "metasploit",
      "approach": "Exploit Apache RCE via module exploit/multi/http/...",
      "example": "use exploit/multi/http/... ; set RHOSTS 192.168.100.189",
      "prerequisite": "Accès réseau au port 80",
      "risk": "HIGH"
    }
  ],
  "attack_plan": "Phase 1: Exploit Apache RCE...\nPhase 2: Privesc...",
  "web_scans": [
    {
      "url": "http://192.168.100.189:80",
      "status_code": 500,
      "server": "Apache/2.4.67 (Fedora Linux)",
      "technologies": ["Apache/2.4.67", "PHP/8.5.6"],
      "missing_headers_count": 7,
      "exposed_paths_count": 2,
      "cors_issues_count": 0,
      "sqli_indicators": [],
      "xss_indicators": [],
      "ssti_indicators": [],
      "ssrf_indicators": [],
      "idor_indicators": [],
      "nosql_indicators": [],
      "cleartext_pii": [],
      "sri_missing": [],
      "security_txt_present": false,
      "rate_limiting_absent": false
    }
  ],
  "subdomains": [],
  "errors": []
}
```

### Lire le JSON en Python

```python
import json
from pathlib import Path

report = json.loads(Path("results/rao_report_192_168_100_189_20260525.json").read_text())

print(f"Cible : {report['meta']['target']}")
print(f"Hôtes : {report['summary']['hosts_discovered']}")
print(f"High  : {report['summary']['by_severity']['high']}")

for finding in report['findings']:
    print(f"[{finding['severity'].upper()}] {finding['title']}")
```

---

## Rapport HTML

Généré avec `--html`. Thème dark premium.

### Ouvrir le rapport

```bash
# Linux
xdg-open results/rao_report_*.html

# Firefox
firefox results/rao_report_*.html

# Chromium
chromium results/rao_report_*.html
```

### Sections du rapport HTML

| Section | Contenu |
|---|---|
| **Header** | Target, timestamp, version du framework (v0.5.0) |
| **Summary** | Compteurs (hôtes, findings par sévérité, web scans) |
| **Distribution de sévérité** | Graphique visuel des findings |
| **Hôtes découverts** | Tableau IP, hostname, ports ouverts, services, versions |
| **Findings** | Tableau complet avec sévérité colorée, CVEs, hôte, port |
| **Web Scan Results** | 26 champs OWASP : headers, paths, CORS, cookies, SQLi, XSS, SSTI, SSRF, IDOR, PII, SRI… |
| **Subdomains** | Tableau sous-domaines (si énumération effectuée) |
| **Attack Plan** | AttackSteps structurés : finding, tool, approach, example, risk |

---

## Audit Log

Chaque scan avec `--confirm` génère une ligne dans `results/audit.log` :

```
2026-05-25T17:30:37.000000Z | AUTHORIZED_SCAN | target=192.168.1.100 | pid=12345
2026-05-25T17:45:12.000000Z | AUTHORIZED_SCAN | target=10.0.0.1 | pid=12346
```

Ce fichier sert de trace légale des scans effectués.

---

## Intégration avec d'autres outils

### Export CSV (exemple)

```python
import csv, json
from pathlib import Path

data = json.loads(Path("results/rao_report_*.json").read_text())

with open("findings.csv", "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=["title", "severity", "host", "port", "cve_ids"])
    writer.writeheader()
    for finding in data["findings"]:
        writer.writerow({
            "title": finding["title"],
            "severity": finding["severity"],
            "host": finding["host"],
            "port": finding.get("port", ""),
            "cve_ids": ", ".join(finding.get("cve_ids", [])),
        })
```

### Servir le rapport HTML localement

```bash
# Python built-in HTTP server
cd results/
python3 -m http.server 8080
# Ouvrir http://localhost:8080
```
