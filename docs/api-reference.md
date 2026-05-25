# API Python — RAO-Framework

Le framework peut être utilisé directement depuis du code Python, sans passer par le CLI.

---

## Usage minimal

```python
from rao.core.orchestrator import OCC

occ = OCC()
mission = occ.execute(target="192.168.1.100", scope=["192.168.1.0/24"])

print(f"Hôtes découverts : {len(mission.hosts)}")
print(f"Findings bruts   : {len(mission.findings)}")
print(f"Findings validés : {len(mission.validated_findings)}")
```

---

## OCC — Orchestrateur principal

```python
from rao.core.orchestrator import OCC

occ = OCC()
mission = occ.execute(
    target="192.168.1.100",
    scope=["192.168.1.0/24", "10.0.0.0/8"]  # optionnel, défaut = [target]
)
```

### Retour : `MissionState`

```python
mission.target               # str — cible principale
mission.scope                # list[str] — scope déclaré
mission.hosts                # list[HostInfo]
mission.findings             # list[Finding] — bruts
mission.validated_findings   # list[Finding] — validés par le Critic
mission.web_scans            # list[WebScanInfo]
mission.subdomains           # list[SubdomainInfo]
mission.current_phase        # str — phase finale ("reporting")
mission.errors               # list[str] — erreurs non-fatales
mission.attack_plan          # str — plan d'attaque (si Operator a tourné)
```

---

## Agents — Usage individuel

### ScoutAgent

```python
from rao.agents.scout import ScoutAgent
from rao.core.state import MissionState

mission = MissionState(target="192.168.1.100", scope=["192.168.1.100"])
scout = ScoutAgent()
mission = scout.run(mission)

for host in mission.hosts:
    print(f"{host.ip} ({host.hostname})")
    for port in host.ports:
        print(f"  {port.port}/{port.protocol} - {port.service} {port.version}")
```

### LibrarianAgent

```python
from rao.agents.librarian import LibrarianAgent

librarian = LibrarianAgent()
mission = librarian.run(mission)  # mission contient déjà les hosts

for finding in mission.findings:
    print(f"[{finding.severity.value.upper()}] {finding.title}")
    print(f"  CVEs: {', '.join(finding.cve_ids)}")
```

### CriticAgent

```python
from rao.agents.critic import CriticAgent

critic = CriticAgent()
mission = critic.run(mission)

print(f"Validés: {len(mission.validated_findings)}/{len(mission.findings)}")
```

### OperatorAgent

```python
from rao.agents.operator import OperatorAgent

operator = OperatorAgent()
mission = operator.run(mission)

print(mission.attack_plan)
```

---

## WebScanner

```python
from rao.tools.web_scanner import WebScanner

scanner = WebScanner(
    timeout=10,
    verify_ssl=False,
    allow_private=True,     # True = autorise les IPs privées (défaut CLI)
    path_scan_delay=0.05,   # délai entre les probes de paths (s)
)

result = scanner.scan("http://192.168.1.100:80")
if result:
    print(f"Status: {result.status_code}")
    print(f"Server: {result.server}")
    print(f"Technologies: {result.technologies}")
    print(f"Missing headers: {len(result.missing_headers)}")
    print(f"Exposed paths: {result.exposed_paths}")
    print(f"CORS issues: {result.cors_issues}")
    print(f"Cookie issues: {result.cookies_issues}")
```

#### Mode strict SSRF (pour API web)

```python
scanner = WebScanner(allow_private=False)
# Lèvera ValueError pour toute IP privée
```

---

## ScopeValidator

```python
from rao.tools.scope_validator import ScopeValidator, ScopeError

validator = ScopeValidator(
    allowed_targets=["192.168.1.0/24", "example.com"],
    allow_private=True,   # autoriser IPs privées
    allow_public=False,   # bloquer IPs publiques
)

# Valider une cible unique
try:
    validator.validate("192.168.1.100")  # OK
    validator.validate("8.8.8.8")        # ScopeError si allow_public=False
except ScopeError as e:
    print(f"Hors scope: {e}")

# Valider une liste (retourne seulement les valides)
valides = validator.validate_all(["192.168.1.1", "8.8.8.8", "10.0.0.1"])
```

---

## CVELookup

```python
from rao.tools.cve_lookup import CVELookup

lookup = CVELookup()
cves = lookup.search("apache 2.4.67")

for cve in cves:
    print(f"{cve['id']} [{cve['severity']}] score={cve['score']}")
    print(f"  {cve['description'][:100]}")
```

---

## SubdomainEnumerator

```python
from rao.tools.subdomain_enum import SubdomainEnumerator

enum = SubdomainEnumerator()
results = enum.enumerate("example.com")

for r in results:
    print(f"{r['subdomain']} → {r['ip']} (source: {r['source']})")
```

---

## Reporting

### Rapport console + JSON

```python
from rao.reporting.report_generator import generate_report

generate_report(mission)
# Affiche sur la console et sauvegarde results/rao_report_*.json
```

### Rapport HTML

```python
from rao.reporting.html_report import generate_html_report

path = generate_html_report(
    mission,
    web_results=web_results,    # list[WebScanResult], optionnel
    subdomains=subdomains,       # list[dict], optionnel
)
print(f"Rapport HTML : {path}")
```

---

## Sessions

### Sauvegarder

```python
from rao.core.session import save_session

path = save_session(mission)
print(f"Session sauvegardée : {path}")
```

### Lister

```python
from rao.core.session import list_sessions

sessions = list_sessions()
for s in sessions:
    print(f"{s['name']} — {s['target']} — {s['saved_at']}")
```

### Charger

```python
from rao.core.session import load_session

mission = load_session("mission_20260525")
print(f"Reprise : phase={mission.current_phase}, findings={len(mission.findings)}")
```

---

## LLM Factory

```python
from rao.core.llm import get_llm, get_llm_or_none

# Lève RuntimeError si aucun provider disponible
llm = get_llm()

# Retourne None si aucun provider disponible (usage recommandé)
llm = get_llm_or_none()
if llm:
    response = llm.invoke("Résume ce CVE : CVE-2024-12345")
    print(response.content)
```

---

## Types de données

### `HostInfo`
```python
@dataclass
class HostInfo:
    ip: str
    hostname: str = ""
    os_guess: str = ""
    ports: list[PortInfo] = field(default_factory=list)
```

### `PortInfo`
```python
@dataclass
class PortInfo:
    port: int
    protocol: str       # "tcp" | "udp"
    state: str          # "open" | "closed" | "filtered"
    service: str        # "http" | "ssh" | "mysql" ...
    version: str = ""
```

### `Finding`
```python
@dataclass
class Finding:
    title: str
    severity: Severity      # CRITICAL | HIGH | MEDIUM | LOW | INFO
    description: str
    evidence: str
    host: str
    port: int | None = None
    cve_ids: list[str] = field(default_factory=list)
    validated: bool = False
    false_positive: bool = False
```

### `Severity`
```python
class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
```
