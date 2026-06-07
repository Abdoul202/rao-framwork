# API Python — RAO-Framework v0.5.0

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
mission.attack_steps         # list[AttackStep] — étapes structurées (Pydantic)
mission.attack_plan          # str — plan d'attaque (résumé textuel)
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
from rao.core.structured_output import AttackStep

operator = OperatorAgent()
mission = operator.run(mission)

# Résultat structuré
for step in mission.attack_steps:
    print(f"[{step.risk}] {step.finding}")
    print(f"  Tool: {step.tool}")
    print(f"  Approach: {step.approach}")
    print(f"  Example: {step.example}")

# Résumé textuel
print(mission.attack_plan)
```

---

## WebScanner

```python
from rao.tools.web_scanner import WebScanner

scanner = WebScanner(
    timeout=10,
    verify_ssl=False,
    allow_private=True,
    path_scan_delay=0.05,
    test_injections=True,   # Active les tests d'injection (SQLi, XSS, SSTI, SSRF…)
    test_auth=True,         # Active les tests d'auth (creds par défaut, rate limiting)
)

result = scanner.scan("http://192.168.1.100:80")
if result:
    print(f"Status  : {result.status_code}")
    print(f"Server  : {result.server}")
    print(f"Tech    : {result.technologies}")
    print(f"OWASP A01 — IDOR: {result.idor_indicators}")
    print(f"OWASP A01 — Forceful browsing: {result.forceful_browsing}")
    print(f"OWASP A02 — PII: {result.cleartext_pii}")
    print(f"OWASP A02 — Token in URL: {result.token_in_url}")
    print(f"OWASP A03 — SQLi: {result.sqli_indicators}")
    print(f"OWASP A03 — NoSQL: {result.nosql_indicators}")
    print(f"OWASP A03 — GraphQL: {result.graphql_issues}")
    print(f"OWASP A07 — Default creds: {result.default_creds_found}")
    print(f"OWASP A08 — SRI missing: {result.sri_missing}")
    print(f"OWASP A09 — security.txt: {result.security_txt_present}")
    print(f"OWASP A10 — SSRF: {result.ssrf_indicators}")
```

---

## JWTAnalyzer

```python
from rao.tools.jwt_analyzer import JWTAnalyzer

analyzer = JWTAnalyzer()
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyIn0.XYZ"

result = analyzer.analyze(token)

print(f"Algorithm : {result.algorithm}")
print(f"alg:none  : {result.alg_none_detected}")
print(f"Expired   : {result.is_expired}")
print(f"Weak secret found : {result.weak_secret}")
print(f"PII in payload    : {result.sensitive_payload_keys}")
print(f"Is critical       : {result.has_critical}")

# Test live alg:none (optionnel)
result_live = analyzer.test_alg_none_live(token, "https://api.example.com/profile")
print(f"Live bypass succeeded: {result_live}")
```

---

## SSLAnalyzer

```python
from rao.tools.ssl_analyzer import SSLAnalyzer

analyzer = SSLAnalyzer()
result = analyzer.analyze("https://example.com")

print(f"Protocol min : {result.min_protocol}")
print(f"Cert expire  : {result.cert_expiry}")
print(f"HSTS         : {result.hsts_present}")
print(f"Heartbleed   : {result.heartbleed_indicator}")
print(f"Weak ciphers : {result.weak_ciphers}")
print(f"Findings     : {result.findings}")
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

## LLM Red Teaming

Attaque un endpoint LLM et **prouve** chaque faille (détecteurs déterministes,
puis juge LLM conservateur). Voir [LLM_REDTEAM.md](LLM_REDTEAM.md).

```python
from rao.tools.llm_redteam import LLMRedTeamScanner, build_target
from rao.tools.llm_redteam.judge import LLMJudge

# Cible OpenAI-compatible (ou {"type": "http", "url": ..., "body": {...}, "response_path": ...})
target = build_target({
    "type": "openai",
    "api_base": "http://localhost:8000/v1",
    "model": "my-model",
    "api_key_env": "OPENAI_API_KEY",
})

scanner = LLMRedTeamScanner(concurrency=5, judge=LLMJudge())
result = scanner.scan(target)          # LLMRedTeamResult

print(f"{len(result.successes)} / {result.total} probes vulnérables")
for f in result.successes:
    print(f"  [{f.owasp_id.value}] {f.name} — détecteur={f.detector} conf={f.confidence:.2f}")

print(result.coverage())               # couverture par catégorie OWASP LLM
```

Mode continu (baseline + diff) et harness d'éval :

```python
from rao.tools.llm_redteam.baseline import load_baseline, probe_status, diff_baseline, save_baseline
from rao.tools.llm_redteam.eval import run_eval

# Régression vs baseline
prior = load_baseline(result.target_id)
diff = diff_baseline(prior, probe_status(result))
save_baseline(result.target_id, probe_status(result))
print(diff.summary())                  # NEW=.. FIXED=.. PERSISTENT=..

# Mesurer FP/FN contre des cibles vérité-terrain (critère FP = 0)
report = run_eval(LLMRedTeamScanner())
print(report.confusion_str())
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
