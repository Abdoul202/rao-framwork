# Développement de Plugins — RAO-Framework

RAO-Framework expose une API de plugins stable pour ajouter de nouveaux outils sans modifier le code core.

---

## Vue d'ensemble

Un plugin est une classe qui implémente le protocole `ToolPlugin`. Il est enregistré dans le `ToolRegistry` global et peut être invoqué par n'importe quel agent ou depuis le CLI.

---

## Créer un plugin

### 1. Implémenter `ToolPlugin`

Créer un fichier dans `rao/tools/` :

```python
# rao/tools/port_knocker.py

from rao.tools.plugin import ToolPlugin, ToolResult


class PortKnocker(ToolPlugin):
    """Tente des séquences de port-knocking courantes."""

    name = "port_knocker"
    description = "Attempts common port-knock sequences on a target."
    version = "1.0.0"
    author = "VotreNom"
    requires = ["nmap"]   # dépendances système requises

    def run(self, target: str, **kwargs) -> ToolResult:
        """
        Exécuter le tool.

        Parameters
        ----------
        target : str
            IP ou hostname validé par ScopeValidator.
        **kwargs
            Paramètres spécifiques au tool (ex: ports, timeout).

        Returns
        -------
        ToolResult
            Ne jamais lever d'exception — toujours retourner ToolResult.
        """
        try:
            # Votre logique ici
            ports_tried = [80, 443, 8080]
            result_data = {"ports_tried": ports_tried, "target": target}

            return ToolResult(
                success=True,
                data=result_data,
                raw=f"Port knock attempted on {target}",
                duration_ms=42.0,
            )
        except Exception as e:
            return ToolResult(
                success=False,
                error=str(e),
            )
```

### 2. Enregistrer dans le registre

Dans `rao/tools/__init__.py` :

```python
from rao.tools.plugin import registry
from rao.tools.port_knocker import PortKnocker

registry.register(PortKnocker())
```

### 3. Utiliser le plugin

```python
from rao.tools.plugin import registry

tool = registry.get("port_knocker")
if tool:
    result = tool.run("192.168.1.100", timeout=5)
    if result:
        print(result.data)
    else:
        print(f"Erreur: {result.error}")
```

---

## Interface `ToolPlugin`

```python
from typing import Protocol, runtime_checkable
from rao.tools.plugin import ToolResult

@runtime_checkable
class ToolPlugin(Protocol):
    name: str           # Identifiant unique snake_case
    description: str    # Description courte (affichée dans l'aide)
    version: str        # Semver (ex: "1.0.0")
    author: str         # Nom du contributeur
    requires: list[str] # Dépendances système (ex: ["nmap", "ffuf"])

    def run(self, target: str, **kwargs) -> ToolResult:
        ...
```

### Règles importantes

- **Ne jamais lever d'exception** dans `run()` — retourner `ToolResult(success=False, error=...)`
- `name` doit être **unique** (snake_case) — collision = `ValueError`
- La cible `target` est **déjà validée** par `ScopeValidator` avant l'appel
- `requires` est informatif (affiché dans `registry.list_tools()`)

---

## `ToolResult`

```python
@dataclass
class ToolResult:
    success: bool                       # True si l'exécution a réussi
    data: dict[str, Any] = {}          # Données structurées (résultats)
    raw: str = ""                       # Sortie brute (logs, texte)
    error: str | None = None           # Message d'erreur si success=False
    duration_ms: float = 0.0           # Durée d'exécution en ms

    def __bool__(self) -> bool:
        return self.success             # Permet: if result: ...
```

---

## `ToolRegistry` — API complète

```python
from rao.tools.plugin import registry

# Enregistrer (lève ValueError si le nom existe déjà)
registry.register(MonTool())

# Remplacer un tool existant
registry.override(MonTool())

# Récupérer un tool
tool = registry.get("mon_tool")   # None si non trouvé

# Lister tous les tools
for t in registry.list_tools():
    print(f"{t['name']} v{t['version']} by {t['author']}: {t['description']}")

# Vérifier l'existence
if "mon_tool" in registry:
    print("Tool disponible")

# Compter
print(f"{len(registry)} tools enregistrés")
```

---

## Exemple complet — Scanner de bannières

```python
# rao/tools/banner_grabber.py

import socket
from rao.tools.plugin import ToolPlugin, ToolResult


class BannerGrabber(ToolPlugin):
    """Grab service banners via raw TCP connections."""

    name = "banner_grabber"
    description = "Grabs TCP service banners from open ports."
    version = "1.0.0"
    author = "RAO-Community"
    requires = []

    def run(self, target: str, **kwargs) -> ToolResult:
        port = kwargs.get("port", 80)
        timeout = kwargs.get("timeout", 3)

        try:
            with socket.create_connection((target, port), timeout=timeout) as sock:
                sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = sock.recv(1024).decode("utf-8", errors="replace")

            return ToolResult(
                success=True,
                data={"target": target, "port": port, "banner": banner},
                raw=banner,
                duration_ms=0.0,
            )
        except (socket.timeout, ConnectionRefusedError) as e:
            return ToolResult(success=False, error=f"Connection failed: {e}")
        except Exception as e:
            return ToolResult(success=False, error=str(e))
```

Enregistrement :
```python
# rao/tools/__init__.py
from rao.tools.plugin import registry
from rao.tools.banner_grabber import BannerGrabber

registry.register(BannerGrabber())
```

Usage :
```python
from rao.tools.plugin import registry

grabber = registry.get("banner_grabber")
result = grabber.run("192.168.1.100", port=22, timeout=5)
if result:
    print(result.data["banner"])
```

---

## Distribution d'un plugin externe

Un plugin peut être distribué comme package Python indépendant :

```toml
# pyproject.toml de votre package
[project]
name = "rao-plugin-nessus"
dependencies = ["rao-framework>=0.1.0"]

[project.entry-points."rao.plugins"]
nessus_importer = "rao_plugin_nessus:NessusImporter"
```

> **Note :** Le support des entry-points pour auto-découverte est prévu dans une version future. Pour l'instant, l'enregistrement manuel dans `rao/tools/__init__.py` est requis.
